//!
//! Keeps a vehicle's contents up to date in the background.
//!
//! Background tasks own `Arc<Fetcher<V>>`; the watcher callback keeps only a weak reference
//! to avoid a cycle with the watcher stored in the fetcher, and schedules onto its captured runtime.
//!
//! The `BundleFile` factory's return type has exactly three methods and no crate equivalent, so
//! [`BundleFileHandle`] below covers it entirely: a read-position-carrying read, the `mod_time`
//! field the initial read consumes, and `close` (an explicit call rather than an implicit `Drop`,
//! so an implementor can release the archive the entry is served from).
//!
//! The `Vehicle` trait (from an earlier wave) returns `Vec<u8>` rather than a nullable byte
//! slice, so the explicit "no data" sentinel the HTTP vehicle and the local-file and bundle-file
//! reads use on a read failure or a body-less 304 response cannot be distinguished from a
//! genuinely empty successful read; both collapse to an empty buffer.

use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use chrono::{DateTime, Utc};
use notify::Watcher as _;
use parking_lot::{Mutex as SyncMutex, RwLock};
use tokio_util::sync::CancellationToken;

use murmur_common::time::{duration_from_nanos, duration_to_nanos, zero_time, TimeDuration};
use murmur_common::utils::hash::{make_hash, HashType};
use murmur_component::slowdown::backoff::Backoff;
use murmur_constant::provider::interface::{Vehicle, VehicleType};
use murmur_log::{debugln, errorln, infoln, warnln};

pub type Parser<V> = Arc<dyn Fn(&[u8]) -> Result<V> + Send + Sync>;

pub trait BundleFileHandle: Read + Send {
    /// Narrowed to the one metadata field the initial read needs.
    fn mod_time(&self) -> Result<DateTime<Utc>>;
    fn close(&mut self) -> Result<()>;
}

pub type BundleFile = Arc<dyn Fn() -> Result<Box<dyn BundleFileHandle>> + Send + Sync>;

fn since_ns(t: DateTime<Utc>) -> TimeDuration {
    (Utc::now() - t).num_nanoseconds().unwrap_or(TimeDuration::MAX)
}

pub struct Fetcher<V> {
    ctx: CancellationToken,
    name: String,
    vehicle: Arc<dyn Vehicle>,
    bundle_file: Option<BundleFile>,
    updated_at: RwLock<Option<DateTime<Utc>>>,
    hash: RwLock<HashType>,
    parser: Parser<V>,
    interval: Duration,
    on_update: Option<Arc<dyn Fn(V) + Send + Sync>>,
    watcher: RwLock<Option<notify::RecommendedWatcher>>,
    load_buf_mutex: SyncMutex<()>,
    backoff: Backoff,
}

impl<V> core::fmt::Debug for Fetcher<V> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Fetcher")
            .field("name", &self.name)
            .field("vehicle", &self.vehicle.type_())
            .field("interval", &self.interval)
            .field("updated_at", &self.updated_at.read())
            .field("hash", &self.hash.read())
            .field("backoff_attempt", &self.backoff.attempt())
            .finish_non_exhaustive()
    }
}

impl<V: Clone + Default + Send + Sync + 'static> Fetcher<V> {
    pub fn name(&self) -> String {
        self.name.clone()
    }

    pub fn vehicle(&self) -> Arc<dyn Vehicle> {
        Arc::clone(&self.vehicle)
    }

    pub fn vehicle_type(&self) -> VehicleType {
        self.vehicle.type_()
    }

    pub fn updated_at(&self) -> DateTime<Utc> {
        self.updated_at.read().unwrap_or_else(zero_time)
    }

    pub async fn initial(self: &Arc<Self>) -> Result<V> {
        let vehicle_path = self.vehicle.path();
        if let Ok(metadata) = tokio::fs::metadata(&vehicle_path).await {
            let mod_time: DateTime<Utc> = metadata.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH).into();
            let buf = tokio::fs::read(&vehicle_path).await.unwrap_or_default();
            let result = self.load_buf(&buf, make_hash(&buf), false);
            *self.updated_at.write() = Some(mod_time);

            if let Ok((contents, _)) = result {
                self.start_pull_loop(since_ns(mod_time) > duration_to_nanos(self.interval))?;
                return Ok(contents);
            }
        }

        if let Some(bundle_file) = self.bundle_file.clone() {
            match bundle_file() {
                Ok(mut file) => {
                    let mut buf = Vec::new();
                    let _ = file.read_to_end(&mut buf);
                    let mod_time = file.mod_time().ok();
                    let _ = file.close();
                    let result = self.load_buf(&buf, make_hash(&buf), true);
                    *self.updated_at.write() = mod_time;

                    match result {
                        Ok((contents, _)) => {
                            infoln!("[Provider] {} extract successful from bundle file", self.name());
                            let force_update = mod_time.is_none_or(|t| since_ns(t) > duration_to_nanos(self.interval));
                            self.start_pull_loop(force_update)?;
                            return Ok(contents);
                        }
                        Err(err) => {
                            warnln!("[Provider] {} read bundle file error: {err}", self.name());
                        }
                    }
                }
                Err(err) => {
                    warnln!("[Provider] {} read bundle file error: {err}", self.name());
                }
            }
        }

        let update_outcome = self.update().await;
        self.start_pull_loop(false)?;
        let (contents, _) = update_outcome?;
        Ok(contents)
    }

    pub async fn update(&self) -> Result<(V, bool)> {
        let old_hash = *self.hash.read();
        let (buf, hash) = self.vehicle.read(&self.ctx, old_hash).await.inspect_err(|_| self.backoff.add_attempt())?;
        self.load_buf(&buf, hash, self.vehicle.type_() != VehicleType::FILE)
    }

    pub fn side_update(&self, buf: &[u8]) -> Result<(V, bool)> {
        self.load_buf(buf, make_hash(buf), true)
    }

    fn load_buf(&self, buf: &[u8], hash: HashType, update_file: bool) -> Result<(V, bool)> {
        let _guard = self.load_buf_mutex.lock();

        let now = Utc::now();
        if self.hash.read().equal(hash) {
            if update_file {
                touch_now(&self.vehicle.path());
            }
            *self.updated_at.write() = Some(now);
            self.backoff.reset();
            return Ok((V::default(), true));
        }

        if buf.is_empty() {
            return Ok((V::default(), true));
        }

        let contents = (self.parser)(buf).inspect_err(|_| self.backoff.add_attempt())?;
        self.backoff.reset();

        if update_file {
            self.vehicle.write(buf)?;
        }
        *self.updated_at.write() = Some(now);
        *self.hash.write() = hash;

        if let Some(on_update) = self.on_update.as_ref() {
            on_update(contents.clone());
        }

        Ok((contents, false))
    }

    pub fn close(&self) -> Result<()> {
        self.ctx.cancel();
        self.watcher.write().take();
        Ok(())
    }

    async fn pull_loop(self: Arc<Self>, force_update: bool) {
        let interval_ns = duration_to_nanos(self.interval);
        let mut current_interval_ns = interval_ns - since_ns(self.updated_at());
        if current_interval_ns > interval_ns {
            current_interval_ns = interval_ns;
        }

        if force_update {
            warnln!("[Provider] {} not updated for a long time, force refresh", self.name());
            self.update_with_log().await;
        }
        let attempt = self.backoff.attempt();
        if attempt > 0.0 {
            let duration_ns = duration_to_nanos(self.backoff.for_attempt(attempt));
            if duration_ns < current_interval_ns {
                current_interval_ns = duration_ns;
            }
        }

        loop {
            tokio::select! {
                () = tokio::time::sleep(duration_from_nanos(current_interval_ns)) => {
                    self.update_with_log().await;
                    current_interval_ns = interval_ns;
                    let attempt = self.backoff.attempt();
                    if attempt > 0.0 {
                        let duration_ns = duration_to_nanos(self.backoff.for_attempt(attempt));
                        if duration_ns < current_interval_ns {
                            current_interval_ns = duration_ns;
                        }
                    }
                }
                () = self.ctx.cancelled() => {
                    return;
                }
            }
        }
    }

    fn start_pull_loop(self: &Arc<Self>, force_update: bool) -> Result<()> {
        if self.vehicle.type_() == VehicleType::FILE {
            let path = std::path::absolute(self.vehicle.path())?;
            let parent =
                path.parent().ok_or_else(|| anyhow::anyhow!("file provider path has no parent: {}", path.display()))?;
            let target = path.clone();
            // notify invokes this callback on its own thread, outside the Tokio context.
            let runtime = tokio::runtime::Handle::current();
            let handler_self = Arc::downgrade(self);
            let mut watcher = notify::recommended_watcher(move |event: notify::Result<notify::Event>| {
                if !file_event_needs_update(&event, &target) {
                    return;
                }
                let Some(task_self) = handler_self.upgrade() else {
                    return;
                };
                let path = task_self.vehicle.path();
                runtime.spawn(async move {
                    task_self.update_callback(&path).await;
                });
            })?;
            // Editors and rule updaters replace the inode; its parent watch survives those renames.
            watcher.watch(parent, notify::RecursiveMode::NonRecursive)?;
            *self.watcher.write() = Some(watcher);
        } else if self.interval > Duration::ZERO {
            tokio::spawn(Arc::clone(self).pull_loop(force_update));
        }
        Ok(())
    }

    async fn update_callback(&self, _path: &str) {
        self.update_with_log().await;
    }

    async fn update_with_log(&self) {
        match self.update().await {
            Err(err) => {
                errorln!("[Provider] {} pull error: {err}", self.name());
            }
            Ok((_, same)) => {
                if same {
                    debugln!("[Provider] {}'s content doesn't change", self.name());
                } else {
                    infoln!("[Provider] {}'s content update", self.name());
                }
            }
        }
    }
}

fn file_event_needs_update(event: &notify::Result<notify::Event>, target: &std::path::Path) -> bool {
    use notify::event::{AccessKind, AccessMode};

    // Do not let our own reads trigger more reads; retain write-close notifications.
    match event {
        Ok(event) => {
            (event.paths.is_empty() || event.paths.iter().any(|path| path == target))
                && (!event.kind.is_access()
                    || matches!(event.kind, notify::EventKind::Access(AccessKind::Close(AccessMode::Write))))
        }
        Err(_) => true,
    }
}

fn touch_now(path: &str) {
    let Ok(file) = std::fs::File::options().write(true).open(path) else {
        return;
    };
    let now = std::time::SystemTime::now();
    let times = std::fs::FileTimes::new().set_accessed(now).set_modified(now);
    let _ = file.set_times(times);
}

pub fn new_fetcher<V: Clone + Default + Send + Sync + 'static>(
    name: &str,
    interval: Duration,
    vehicle: Arc<dyn Vehicle>,
    bundle_file: Option<BundleFile>,
    parser: Parser<V>,
    on_update: Option<Arc<dyn Fn(V) + Send + Sync>>,
) -> Arc<Fetcher<V>> {
    let min_backoff = Duration::from_secs(10).min(interval);
    Arc::new(Fetcher {
        ctx: CancellationToken::new(),
        name: name.to_owned(),
        bundle_file,
        vehicle,
        parser,
        on_update,
        interval,
        updated_at: RwLock::new(None),
        hash: RwLock::new(HashType::default()),
        watcher: RwLock::new(None),
        load_buf_mutex: SyncMutex::new(()),
        backoff: Backoff { factor: 2.0, jitter: false, min: min_backoff, max: interval, ..Backoff::default() },
    })
}

#[cfg(test)]
mod tests {
    use portable_atomic::AtomicU64;

    use super::*;
    use crate::vehicle::FileVehicle;

    struct TestFile(std::path::PathBuf);

    impl TestFile {
        fn new() -> Self {
            static NEXT_ID: AtomicU64 = AtomicU64::new(0);
            let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("clock").as_nanos();
            let dir = std::env::temp_dir().join(format!("murmur-file-watcher-{}-{stamp}-{id}", std::process::id()));
            std::fs::create_dir(&dir).expect("create isolated provider directory");
            Self(dir.join("provider.txt"))
        }
    }

    impl Drop for TestFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(self.0.parent().expect("provider directory"));
        }
    }

    #[test]
    fn file_watcher_ignores_reads_but_refreshes_after_writes() {
        use notify::event::{AccessKind, AccessMode, CreateKind, DataChange, ModifyKind, RemoveKind};
        use notify::{Event, EventKind};
        let target = std::path::Path::new("provider.txt");

        for kind in [
            EventKind::Access(AccessKind::Read),
            EventKind::Access(AccessKind::Open(AccessMode::Any)),
            EventKind::Access(AccessKind::Open(AccessMode::Read)),
            EventKind::Access(AccessKind::Close(AccessMode::Read)),
        ] {
            assert!(
                !file_event_needs_update(&Ok(Event::new(kind).add_path(target.to_path_buf())), target),
                "ignore {kind:?}",
            );
        }
        for kind in [
            EventKind::Access(AccessKind::Close(AccessMode::Write)),
            EventKind::Modify(ModifyKind::Data(DataChange::Content)),
            EventKind::Create(CreateKind::File),
            EventKind::Remove(RemoveKind::File),
            EventKind::Any,
            EventKind::Other,
        ] {
            assert!(
                file_event_needs_update(&Ok(Event::new(kind).add_path(target.to_path_buf())), target),
                "refresh on {kind:?}",
            );
            assert!(
                !file_event_needs_update(&Ok(Event::new(kind).add_path("sibling.txt".into())), target),
                "ignore sibling {kind:?}",
            );
        }
        assert!(file_event_needs_update(&Err(notify::Error::generic("watch error")), target));
        assert!(file_event_needs_update(&Ok(Event::new(EventKind::Other)), target));
    }

    #[tokio::test]
    async fn file_watcher_publishes_parsed_changes_from_notify_thread() {
        let file = TestFile::new();
        std::fs::write(&file.0, b"17").expect("write initial provider");
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let fetcher = new_fetcher(
            "file-watcher-regression",
            Duration::ZERO,
            Arc::new(FileVehicle::new(file.0.to_str().expect("UTF-8 temporary path"))),
            None,
            Arc::new(|buf| Ok(std::str::from_utf8(buf)?.parse::<u32>()?)),
            Some(Arc::new(move |value| {
                let _ = tx.send(value);
            })),
        );

        assert_eq!(fetcher.initial().await.expect("load and watch provider"), 17);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.expect("initial parsed content published"),
            Some(17),
        );

        std::fs::write(&file.0, b"42").expect("rewrite watched provider");
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.expect("notify publishes changed content"),
            Some(42),
        );

        fetcher.close().expect("close live watcher");
        fetcher.close().expect("close is idempotent");
        let weak = Arc::downgrade(&fetcher);
        drop(fetcher);
        tokio::time::timeout(Duration::from_secs(5), async {
            while weak.strong_count() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("in-flight updates release the closed fetcher");
    }

    #[tokio::test]
    async fn file_watcher_survives_successive_atomic_replacements() {
        let file = TestFile::new();
        std::fs::write(&file.0, b"17").expect("write initial provider");
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let fetcher = new_fetcher(
            "file-watcher-replacement",
            Duration::ZERO,
            Arc::new(FileVehicle::new(file.0.to_str().expect("UTF-8 temporary path"))),
            None,
            Arc::new(|buf| Ok(std::str::from_utf8(buf)?.parse::<u32>()?)),
            Some(Arc::new(move |value| {
                let _ = tx.send(value);
            })),
        );
        assert_eq!(fetcher.initial().await.expect("load and watch provider"), 17);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.expect("initial parsed content published"),
            Some(17),
        );

        let replacement = file.0.with_extension("replacement");
        for (bytes, expected) in [(b"42", 42), (b"99", 99), (b"17", 17)] {
            std::fs::write(&replacement, bytes).expect("write replacement provider");
            std::fs::rename(&replacement, &file.0).expect("atomically replace watched provider");
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(5), rx.recv())
                    .await
                    .expect("notify publishes replacement content"),
                Some(expected),
            );
        }
        fetcher.close().expect("close replacement watcher");
    }

    #[tokio::test]
    async fn dropping_file_fetcher_releases_its_watcher_without_close() {
        let file = TestFile::new();
        std::fs::write(&file.0, b"17").expect("write initial provider");
        let fetcher = new_fetcher(
            "file-watcher-drop",
            Duration::ZERO,
            Arc::new(FileVehicle::new(file.0.to_str().expect("UTF-8 temporary path"))),
            None,
            Arc::new(|buf| Ok(std::str::from_utf8(buf)?.parse::<u32>()?)),
            None,
        );
        assert_eq!(fetcher.initial().await.expect("load and watch provider"), 17);

        let weak = Arc::downgrade(&fetcher);
        drop(fetcher);
        assert!(weak.upgrade().is_none(), "watcher callback must not own the fetcher that owns it");
    }
}
