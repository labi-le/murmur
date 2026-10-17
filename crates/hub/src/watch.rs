//! Automatic reload of the main configuration file.
//!
//! `murmur --watch-config -f <path>` watches the resolved configuration path and applies it again
//! after every settled change, through the same entry point a `SIGHUP` uses
//! ([`crate::hub::parse`]): the file is parsed again, the startup CLI overrides are reapplied and
//! the external controller is reconfigured. That entry point also holds
//! [`crate::hub::lock_config_operation`], the lock every `PUT` and `PATCH /configs` update takes,
//! because a parse writes the live general globals for its duration and rolls them back when it
//! returns; the rollback of a rejected file therefore cannot undo an API update. A reload whose
//! apply reported a failure is not recorded as applied, so the same file is retried once the
//! failure clears. Watch mode is off by default, so a deployment that
//! relies on `PUT /configs` for runtime changes is unaffected; while it is on, that endpoint still
//! applies its own `path` or `payload` and leaves the watcher where it was, which means the next
//! real file change replaces those API-only settings.
//!
//! The watcher follows the file's parent directory and filters events down to the target, so an
//! editor's atomic replacement keeps working, a sibling file does not reload anything, and the
//! target may be deleted and recreated. Reads and opens are ignored: they are this process's own
//! I/O, not a configuration change.
//!
//! The path is canonicalized once, at startup. `-f` names the file the process actually read, and
//! when that name is a symlink the watcher follows it to the real file's directory; replacing the
//! symlink itself afterwards is therefore not observed. Replace the target file instead.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, Result};
use notify::event::{AccessKind, AccessMode};
use notify::Watcher as _;
use tokio::sync::mpsc;

use crate::hub;

/// How long the target must stay quiet after an event before the reload runs. Editors and config
/// generators write in bursts (truncate, write, chmod, rename over the target); every intermediate
/// state would otherwise be its own reload.
const QUIET_PERIOD: Duration = Duration::from_millis(250);

/// One pending tick is enough: the reload reads the file itself, so a burst that overflows this
/// queue still applies the last content written.
const TICK_QUEUE: usize = 1;

/// The main configuration file, watched through its parent directory.
#[derive(Debug)]
pub struct ConfigWatcher {
    target: PathBuf,
    ticks: mpsc::Receiver<()>,
    // Dropped with this struct, which stops notify's thread: one watcher per process, released
    // with the process.
    _watcher: notify::RecommendedWatcher,
}

impl ConfigWatcher {
    /// Starts watching the parent directory of `path`.
    ///
    /// Returns an error when `path` cannot be resolved or the platform watcher cannot be created.
    pub async fn new(path: &str) -> Result<Self> {
        let target = tokio::fs::canonicalize(path)
            .await
            .with_context(|| format!("watch mode cannot resolve the configuration file {path}"))?;
        let parent = target
            .parent()
            .with_context(|| format!("the configuration file {} has no parent directory", target.display()))?
            .to_path_buf();

        let (ticks_tx, ticks) = mpsc::channel(TICK_QUEUE);
        let callback_target = target.clone();
        let mut watcher = notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
            if !target_changed(&event, &callback_target) {
                return;
            }
            // notify calls this on its own thread, outside any Tokio context; the queue is the
            // coalescing point, and a full one means the reload is already pending.
            let _ = ticks_tx.try_send(());
        })
        .context("watch mode cannot create a filesystem watcher")?;
        watcher
            .watch(&parent, notify::RecursiveMode::NonRecursive)
            .with_context(|| format!("watch mode cannot watch {}", parent.display()))?;

        Ok(Self { target, ticks, _watcher: watcher })
    }

    /// The resolved configuration file this watcher reports on.
    #[must_use]
    pub fn target(&self) -> &Path {
        &self.target
    }

    /// Resolves after the target has been quiet for [`QUIET_PERIOD`], starting at the next change.
    ///
    /// cancel-safe: `recv` leaves a queued tick in the channel when this future is dropped, and the
    /// quiet period restarts from zero, so a burst never loses its last event.
    pub async fn settled(&mut self) {
        if self.ticks.recv().await.is_none() {
            // Only reachable while this watcher is being dropped, when nothing can arrive any more.
            std::future::pending::<()>().await;
        }
        loop {
            tokio::time::sleep(QUIET_PERIOD).await;
            if self.ticks.try_recv().is_err() {
                return;
            }
        }
    }
}

/// Whether an event means the watched file may have new content.
///
/// The same rule the provider-file watcher applies: our own reads must not feed themselves, so an
/// access event only counts when a write was closed, and an event without paths (a watcher-level
/// error) counts as a possible change.
fn target_changed(event: &notify::Result<notify::Event>, target: &Path) -> bool {
    match event {
        Ok(event) => {
            (event.paths.is_empty() || event.paths.iter().any(|path| path == target))
                && (!event.kind.is_access()
                    || matches!(event.kind, notify::EventKind::Access(AccessKind::Close(AccessMode::Write))))
        }
        Err(_) => true,
    }
}

/// What one [`reload_from_disk`] call did.
#[derive(Debug)]
pub enum Reload {
    /// The file was read and its configuration applied.
    Applied,
    /// The bytes matched the last successfully applied file, so nothing ran.
    Unchanged,
    /// The file could not be read, its configuration did not parse, or applying it reported a
    /// failure. A read or parse failure leaves the running configuration untouched; an apply
    /// failure may have left it partially applied, which is what clears the cache of applied
    /// content.
    Failed(anyhow::Error),
}

/// Reads `path` and applies it through [`crate::hub::parse`], the reload path a `SIGHUP` takes.
///
/// `last_applied` holds the bytes of the last file that applied successfully. Identical contents
/// are skipped. A file that cannot be read or does not parse leaves the cache alone: nothing ran,
/// so the running configuration is still what the cache remembers. A file whose parse succeeded
/// and whose apply then reported a failure (a listener that could not bind, a controller that could
/// not) clears the cache, because that apply may already have closed or replaced parts: restoring
/// the last-known-good file has to reapply it. `force` bypasses the equality check: an operator's
/// `SIGHUP` reapplies the disk state even when the file did not change, which is also what undoes
/// an API-only change.
#[must_use]
pub async fn reload_from_disk(
    path: &Path,
    options: &[hub::Option],
    last_applied: &mut Option<Vec<u8>>,
    force: bool,
) -> Reload {
    let bytes = match tokio::fs::read(path).await {
        Ok(bytes) => bytes,
        Err(err) => return Reload::Failed(anyhow::anyhow!("cannot read {}: {err}", path.display())),
    };
    if !force && last_applied.as_deref() == Some(bytes.as_slice()) {
        return Reload::Unchanged;
    }
    match hub::parse(&bytes, options).await {
        Ok(()) => {
            *last_applied = Some(bytes);
            Reload::Applied
        }
        Err(hub::ReloadError::Rejected(err)) => {
            // Nothing was applied: the running configuration still matches `last_applied`, so the
            // cache stays and a later save of those same bytes is still skipped.
            Reload::Failed(err)
        }
        Err(hub::ReloadError::PartiallyApplied(err)) => {
            // The apply may already have closed or replaced listeners before it reported the
            // failure, so the running state is no longer the file `last_applied` remembers.
            // Forget it: restoring the last-known-good file has to reapply it.
            *last_applied = None;
            Reload::Failed(err)
        }
    }
}

#[cfg(test)]
mod tests {
    use murmur_log::LogLevel;
    use tokio::time::timeout;

    use super::*;

    /// How long a wait for a real filesystem event may take: the event itself plus the quiet
    /// period, with room for a loaded build host.
    const EVENT_WINDOW: Duration = Duration::from_secs(10);
    /// How long a wait that must stay silent runs: long enough to notice an event the predicate
    /// should have dropped, short enough not to stall the suite.
    const SILENCE_WINDOW: Duration = Duration::from_millis(500);

    /// A valid configuration whose bytes are unique per marker, so a test can compare the content
    /// it wrote with the content the reload applied.
    fn config_with(marker: &str) -> String {
        format!("mode: rule\n# {marker}\n")
    }

    /// The reload reconfigures the controller listeners too, so it may not interleave with the
    /// tests that assert on theirs.
    async fn lock_controller_listeners() -> tokio::sync::MutexGuard<'static, ()> {
        crate::route::server::CONTROLLER_LISTENERS.lock().await
    }

    /// A directory under the system temp directory, removed when the fixture drops.
    struct Fixture {
        dir: PathBuf,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("murmur-config-watch-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("the fixture directory must be creatable");
            Self { dir }
        }

        fn path(&self, name: &str) -> PathBuf {
            self.dir.join(name)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    async fn start_watching(path: &Path) -> ConfigWatcher {
        ConfigWatcher::new(path.to_str().expect("the fixture path must be utf-8"))
            .await
            .expect("the fixture must be watchable")
    }

    /// `main.rs` installs the system resolver as its first statement, before any parse; a parse
    /// inside a test process needs the same pre-init.
    fn init_runtime() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(murmur_dns::system::init);
    }

    /// Writes `content` through a sibling file and a rename, the way an editor or a configuration
    /// generator replaces a file.
    fn write_atomically(path: &Path, content: &str) {
        let replacement = path.with_extension("replacement");
        std::fs::write(&replacement, content).expect("the replacement must be writable");
        std::fs::rename(&replacement, path).expect("the replacement must be renamed over the target");
    }

    /// A rewrite and an atomic replacement of the target are reported; a sibling write and a read
    /// of the target are not.
    #[tokio::test]
    async fn reports_target_changes_and_ignores_siblings_and_reads() {
        let fixture = Fixture::new("events");
        let target = fixture.path("config.yaml");
        std::fs::write(&target, "mode: rule\n").expect("the target must be writable");
        let mut watch = start_watching(&target).await;
        assert_eq!(watch.target(), std::fs::canonicalize(&target).expect("the target must resolve").as_path());

        std::fs::write(fixture.path("sibling.yaml"), "mode: rule\n").expect("the sibling must be writable");
        assert!(
            timeout(SILENCE_WINDOW, watch.settled()).await.is_err(),
            "a write to a sibling file must not be reported"
        );
        let _ = tokio::fs::read(&target).await.expect("the target must be readable");
        assert!(timeout(SILENCE_WINDOW, watch.settled()).await.is_err(), "reading the target must not be reported");

        std::fs::write(&target, "mode: rule\n").expect("the target must be writable");
        timeout(EVENT_WINDOW, watch.settled()).await.expect("a rewrite of the target must be reported");

        write_atomically(&target, "mode: rule\n");
        timeout(EVENT_WINDOW, watch.settled()).await.expect("an atomic replacement must be reported");
    }

    /// A target that disappears and comes back is still watched, and a read of the missing file
    /// changes nothing.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_target_that_disappears_and_returns_is_still_watched() {
        let _listeners = lock_controller_listeners().await;
        init_runtime();
        let fixture = Fixture::new("recreate");
        let target = fixture.path("config.yaml");
        let seeded = config_with("seeded");
        std::fs::write(&target, &seeded).expect("the target must be writable");
        let mut watch = start_watching(&target).await;
        let mut applied: Option<Vec<u8>> = None;
        assert!(matches!(reload_from_disk(watch.target(), &[], &mut applied, false).await, Reload::Applied));
        assert_eq!(applied.as_deref(), Some(seeded.as_bytes()));

        std::fs::remove_file(&target).expect("the target must be removable");
        timeout(EVENT_WINDOW, watch.settled()).await.expect("removing the target must be reported");
        assert!(
            matches!(reload_from_disk(watch.target(), &[], &mut applied, false).await, Reload::Failed(_)),
            "a missing configuration file must be rejected"
        );
        assert_eq!(applied.as_deref(), Some(seeded.as_bytes()), "a failed read must not clear the last applied bytes");

        let recreated = config_with("recreated");
        write_atomically(&target, &recreated);
        timeout(EVENT_WINDOW, watch.settled()).await.expect("recreating the target must be reported");
        assert!(
            matches!(reload_from_disk(watch.target(), &[], &mut applied, false).await, Reload::Applied),
            "the recreated configuration must be applied"
        );
        assert_eq!(applied.as_deref(), Some(recreated.as_bytes()));
    }

    /// End to end through the real parse: a rewritten file is applied, an identical rewrite is
    /// skipped, a malformed file is rejected with the last good configuration kept, and a later
    /// valid save recovers.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_rewritten_file_reaches_the_running_configuration() {
        let _listeners = lock_controller_listeners().await;
        init_runtime();
        let fixture = Fixture::new("reload");
        let target = fixture.path("config.yaml");
        let first = config_with("first");
        std::fs::write(&target, &first).expect("the target must be writable");
        let mut watch = start_watching(&target).await;
        let mut applied: Option<Vec<u8>> = None;

        assert!(matches!(reload_from_disk(watch.target(), &[], &mut applied, false).await, Reload::Applied));
        assert_eq!(applied.as_deref(), Some(first.as_bytes()), "the file on disk must be the applied configuration");

        let second = config_with("second");
        write_atomically(&target, &second);
        timeout(EVENT_WINDOW, watch.settled()).await.expect("the replacement must be reported");
        assert!(matches!(reload_from_disk(watch.target(), &[], &mut applied, false).await, Reload::Applied));
        assert_eq!(applied.as_deref(), Some(second.as_bytes()));

        write_atomically(&target, &second);
        timeout(EVENT_WINDOW, watch.settled()).await.expect("the second replacement must be reported");
        assert!(
            matches!(reload_from_disk(watch.target(), &[], &mut applied, false).await, Reload::Unchanged),
            "the same bytes must not be applied twice"
        );
        assert_eq!(applied.as_deref(), Some(second.as_bytes()));

        write_atomically(&target, "mode: [\n");
        timeout(EVENT_WINDOW, watch.settled()).await.expect("the broken replacement must be reported");
        assert!(matches!(reload_from_disk(watch.target(), &[], &mut applied, false).await, Reload::Failed(_)));
        assert_eq!(
            applied.as_deref(),
            Some(second.as_bytes()),
            "a rejected file leaves the running configuration and the cache alone"
        );

        let third = config_with("third");
        write_atomically(&target, &third);
        timeout(EVENT_WINDOW, watch.settled()).await.expect("the recovery must be reported");
        assert!(matches!(reload_from_disk(watch.target(), &[], &mut applied, false).await, Reload::Applied));
        assert_eq!(applied.as_deref(), Some(third.as_bytes()), "a later valid save must recover");
    }

    /// A burst of writes coalesces into one wake-up, and a file written while a reload was already
    /// pending is still the one that runs.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_burst_of_writes_coalesces_without_losing_the_last_one() {
        let _listeners = lock_controller_listeners().await;
        init_runtime();
        let fixture = Fixture::new("burst");
        let target = fixture.path("config.yaml");
        let seeded = config_with("seeded");
        std::fs::write(&target, &seeded).expect("the target must be writable");
        let mut watch = start_watching(&target).await;
        let mut applied: Option<Vec<u8>> = None;
        assert!(matches!(reload_from_disk(watch.target(), &[], &mut applied, false).await, Reload::Applied));

        let burst = ["first", "second", "last"].map(config_with);
        for content in &burst {
            std::fs::write(&target, content).expect("the target must be writable");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        timeout(EVENT_WINDOW, watch.settled()).await.expect("the burst must be reported");
        assert!(
            timeout(SILENCE_WINDOW, watch.settled()).await.is_err(),
            "the burst left an event behind, which would reload it a second time"
        );
        assert!(matches!(reload_from_disk(watch.target(), &[], &mut applied, false).await, Reload::Applied));
        let last = burst.last().expect("the burst has a last save");
        assert_eq!(applied.as_deref(), Some(last.as_bytes()), "the last save of the burst must win");

        // A save that lands while the previous reload is already pending still wins.
        std::fs::write(&target, &seeded).expect("the target must be writable");
        timeout(EVENT_WINDOW, watch.settled()).await.expect("the new save must be reported");
        let newer = config_with("newer");
        std::fs::write(&target, &newer).expect("the target must be writable");
        assert!(matches!(reload_from_disk(watch.target(), &[], &mut applied, false).await, Reload::Applied));
        assert_eq!(applied.as_deref(), Some(newer.as_bytes()), "a newer save must not be lost behind the pending one");
    }

    /// A configuration that names the mixed listener's port.
    fn config_with_port(port: u16) -> String {
        format!("mixed-port: {port}\nmode: rule\n")
    }

    /// A configuration whose general section parses and whose proxy does not: the parse writes the
    /// live general globals through the update hook and then fails.
    const FAILS_AFTER_THE_GENERAL_SECTION: &str = "log-level: debug\nproxies:\n  - name: p\n    type: no-such-type\n";

    /// A listener that cannot bind fails the apply, and the file is not recorded as applied: the
    /// same bytes are retried once the port is free.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_configuration_that_could_not_bind_is_not_cached_as_applied() {
        let _listeners = lock_controller_listeners().await;
        init_runtime();
        let fixture = Fixture::new("bind");
        let target = fixture.path("config.yaml");
        let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("the port must be occupiable");
        let port = occupied.local_addr().expect("the occupied socket has an address").port();
        let blocked = config_with_port(port);
        std::fs::write(&target, &blocked).expect("the target must be writable");
        let watch = start_watching(&target).await;
        let mut applied: Option<Vec<u8>> = None;

        assert!(
            matches!(reload_from_disk(watch.target(), &[], &mut applied, false).await, Reload::Failed(_)),
            "a listener that cannot bind must fail the apply"
        );
        assert!(applied.is_none(), "a failed apply must not be recorded as the applied content");

        drop(occupied);
        assert!(matches!(reload_from_disk(watch.target(), &[], &mut applied, false).await, Reload::Applied));
        assert_eq!(applied.as_deref(), Some(blocked.as_bytes()), "the retry must apply the same bytes");
    }

    /// A runtime change made over the API survives a watched reload, including one whose file is
    /// rejected: the reload waits for the update, and the rollback a rejected parse performs cannot
    /// reach a change that was made before it started.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_watched_reload_waits_for_an_api_update() {
        let _listeners = lock_controller_listeners().await;
        init_runtime();
        let fixture = Fixture::new("api");
        let target = fixture.path("config.yaml");
        std::fs::write(&target, FAILS_AFTER_THE_GENERAL_SECTION).expect("the target must be writable");
        let watch = start_watching(&target).await;

        // The API paths hold this lock for their whole update; this stands in for one of them.
        let operation = hub::lock_config_operation().await;
        murmur_log::set_level(LogLevel::WARNING);

        let reload_target = watch.target().to_path_buf();
        let reload = tokio::spawn(async move {
            let mut applied: Option<Vec<u8>> = None;
            let outcome = reload_from_disk(&reload_target, &[], &mut applied, false).await;
            (outcome, applied)
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(!reload.is_finished(), "the reload must wait for the API update to finish");
        drop(operation);

        let (outcome, applied) = timeout(EVENT_WINDOW, reload)
            .await
            .expect("the reload must finish")
            .expect("the reload task must not panic");
        assert!(matches!(outcome, Reload::Failed(_)), "the configuration must be rejected");
        assert!(applied.is_none());
        assert_eq!(murmur_log::level(), LogLevel::WARNING, "a rejected reload must not undo the API's change");
    }

    /// A file that is already running is skipped when it is saved byte-identically, so a setting
    /// changed over the API is not replaced by an unchanged file.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_unchanged_save_keeps_the_api_configuration() {
        let _listeners = lock_controller_listeners().await;
        init_runtime();
        let fixture = Fixture::new("seeded");
        let target = fixture.path("config.yaml");
        let running = config_with("running");
        std::fs::write(&target, &running).expect("the target must be writable");
        let mut watch = start_watching(&target).await;
        let mut applied = Some(running.clone().into_bytes());

        // Stand in for a runtime change made over the API.
        murmur_log::set_level(LogLevel::WARNING);

        write_atomically(&target, &running);
        timeout(EVENT_WINDOW, watch.settled()).await.expect("the save must be reported");
        assert!(matches!(reload_from_disk(watch.target(), &[], &mut applied, false).await, Reload::Unchanged));
        assert_eq!(murmur_log::level(), LogLevel::WARNING, "an unchanged save must not replace an API setting");
    }

    /// A probe that returns a loopback port nothing holds.
    async fn free_port() -> u16 {
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("the probe must bind");
        let port = probe.local_addr().expect("the probe has an address").port();
        drop(probe);
        port
    }

    /// Restoring the last known good file after a failed apply reapplies it: the failure may already
    /// have closed the old listener, so the cache must not claim that file is still running.
    #[tokio::test(flavor = "multi_thread")]
    async fn restoring_the_last_good_file_after_a_failed_apply_reapplies_it() {
        let _listeners = lock_controller_listeners().await;
        init_runtime();
        let fixture = Fixture::new("restore");
        let target = fixture.path("config.yaml");
        let good_port = free_port().await;
        let good = config_with_port(good_port);
        std::fs::write(&target, &good).expect("the target must be writable");
        let watch = start_watching(&target).await;
        let mut applied: Option<Vec<u8>> = None;
        assert!(matches!(reload_from_disk(watch.target(), &[], &mut applied, false).await, Reload::Applied));

        let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("a port must be occupiable");
        let blocked = config_with_port(occupied.local_addr().expect("the socket has an address").port());
        std::fs::write(&target, &blocked).expect("the target must be writable");
        assert!(matches!(reload_from_disk(watch.target(), &[], &mut applied, false).await, Reload::Failed(_)));
        assert!(applied.is_none(), "a failed apply must forget the cached content");

        std::fs::write(&target, &good).expect("the target must be writable");
        assert!(
            matches!(reload_from_disk(watch.target(), &[], &mut applied, false).await, Reload::Applied),
            "the restored file must be reapplied, not reported as unchanged"
        );
        assert_eq!(applied.as_deref(), Some(good.as_bytes()));
    }

    /// A controller address that cannot bind fails the reload and is not cached; once the address is
    /// free the same file applies and the controller answers.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_controller_that_cannot_bind_fails_the_reload_and_is_retried() {
        let _listeners = lock_controller_listeners().await;
        init_runtime();
        let fixture = Fixture::new("controller");
        let target = fixture.path("config.yaml");
        let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("a port must be occupiable");
        let port = occupied.local_addr().expect("the socket has an address").port();
        let blocked = format!("external-controller: 127.0.0.1:{port}\n");
        std::fs::write(&target, &blocked).expect("the target must be writable");
        let watch = start_watching(&target).await;
        let mut applied: Option<Vec<u8>> = None;

        assert!(
            matches!(reload_from_disk(watch.target(), &[], &mut applied, false).await, Reload::Failed(_)),
            "a controller that cannot bind must fail the apply"
        );
        assert!(applied.is_none());

        drop(occupied);
        assert!(matches!(reload_from_disk(watch.target(), &[], &mut applied, false).await, Reload::Applied));
        assert_eq!(applied.as_deref(), Some(blocked.as_bytes()));
        let mut answered = false;
        for _ in 0..100 {
            if tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                answered = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(answered, "the reloaded controller must accept a connection");
    }
}
