use portable_atomic::AtomicU64;
use std::collections::HashMap;
use std::io;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwapOption;
use chrono::{DateTime, TimeDelta, Utc};
use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;

use crate::padding::padding::PaddingFactory;
use crate::skiplist::skiplist::{new_skip_list, SkipList};
use crate::util::routine::start_routine;
use crate::util::type_::DialOutFunc;
use murmur_common_net::io::Stream as NetStream;

use super::session::{err_closed_pipe, Session};
use super::stream::StreamConn;

pub struct Client {
    die: CancellationToken,

    dial_out: Box<DialOutFunc>,

    session_counter: AtomicU64,

    idle_session: Mutex<SkipList<u64, Arc<Session>>>,

    sessions: Mutex<HashMap<u64, Arc<Session>>>,

    padding: Arc<ArcSwapOption<PaddingFactory>>,

    metadata: String,
    idle_session_timeout: Duration,
    min_idle_session: i32,
    disable_reuse: bool,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("min_idle_session", &self.min_idle_session)
            .field("idle_session_timeout", &self.idle_session_timeout)
            .field("disable_reuse", &self.disable_reuse)
            .finish_non_exhaustive()
    }
}

/// Builds the client. It is shared so the session and stream hooks reach the same one.
pub fn new_client(
    ctx: &CancellationToken,
    dial_out: Box<DialOutFunc>,
    padding: Arc<ArcSwapOption<PaddingFactory>>,
    metadata: String,
    idle_session_check_interval: Duration,
    idle_session_timeout: Duration,
    min_idle_session: i32,
    disable_reuse: bool,
) -> Arc<Client> {
    let idle_session_timeout =
        if idle_session_timeout <= Duration::from_secs(5) { Duration::from_secs(30) } else { idle_session_timeout };
    let idle_session_check_interval = if idle_session_check_interval <= Duration::from_secs(5) {
        Duration::from_secs(30)
    } else {
        idle_session_check_interval
    };
    let client = Arc::new(Client {
        die: ctx.child_token(),
        dial_out,
        session_counter: AtomicU64::new(0),
        idle_session: Mutex::new(new_skip_list::<u64, Arc<Session>>()),
        sessions: Mutex::new(HashMap::new()),
        padding,
        metadata,
        idle_session_timeout,
        min_idle_session,
        disable_reuse,
    });
    if !client.disable_reuse {
        let cleanup = Arc::clone(&client);
        start_routine(client.die.clone(), idle_session_check_interval, move || cleanup.idle_cleanup());
    }
    client
}

impl Client {
    pub async fn create_stream(self: &Arc<Self>, ctx: &CancellationToken) -> anyhow::Result<Box<dyn NetStream>> {
        if self.die.is_cancelled() {
            return Err(err_closed_pipe().into());
        }

        let session = match if self.disable_reuse { None } else { self.get_idle_session() } {
            Some(session) => session,
            None => self.create_session(ctx).await.map_err(|err| anyhow::anyhow!("failed to create session: {err}"))?,
        };
        let stream = match session.open_stream().await {
            Ok(stream) => stream,
            Err(err) => {
                let _ = session.close();
                return Err(anyhow::anyhow!("failed to create stream: {err}"));
            }
        };

        let client = Arc::clone(self);
        let hook_session = Arc::clone(&session);
        stream.set_die_hook(Box::new(move || {
            if hook_session.is_closed() {
                return;
            }
            if client.disable_reuse {
                let _ = hook_session.close();
                return;
            }
            if client.die.is_cancelled() {
                let _ = hook_session.close();
                return;
            }
            let mut idle_session = client.idle_session.lock();
            hook_session.set_idle_since(Utc::now());
            idle_session.insert(u64::MAX - hook_session.seq(), Arc::clone(&hook_session));
        }));

        Ok(Box::new(StreamConn::new(stream)))
    }

    fn get_idle_session(&self) -> Option<Arc<Session>> {
        let session = {
            let mut idle_session = self.idle_session.lock();
            if idle_session.is_empty() {
                return None;
            }
            let it = idle_session.iterate();
            let session = it.value();
            let key = it.key();
            let _ = idle_session.remove(&key);
            session
        };
        Some(session)
    }

    async fn create_session(self: &Arc<Self>, ctx: &CancellationToken) -> anyhow::Result<Arc<Session>> {
        let underlying = (self.dial_out)(ctx).await?;

        let session = Arc::new(Session::client(underlying, Arc::clone(&self.padding), self.metadata.clone()));
        session.set_seq(self.session_counter.fetch_add(1, Ordering::SeqCst) + 1);

        let client = Arc::clone(self);
        let hook_session = Arc::clone(&session);
        session.set_die_hook(Box::new(move || {
            if !client.disable_reuse {
                let mut idle_session = client.idle_session.lock();
                let _ = idle_session.remove(&(u64::MAX - hook_session.seq()));
            }
            let _ = client.sessions.lock().remove(&hook_session.seq());
        }));

        self.sessions.lock().insert(session.seq(), Arc::clone(&session));

        session.run().await;
        Ok(session)
    }

    pub fn close(&self) -> io::Result<()> {
        self.die.cancel();

        let sessions: Vec<Arc<Session>> = {
            let mut sessions = self.sessions.lock();
            std::mem::take(&mut *sessions).into_values().collect()
        };

        for session in sessions {
            let _ = session.close();
        }

        Ok(())
    }

    pub fn idle_cleanup(&self) {
        let timeout = TimeDelta::from_std(self.idle_session_timeout).unwrap_or(TimeDelta::MAX);
        let exp_time = Utc::now().checked_sub_signed(timeout).unwrap_or(DateTime::<Utc>::MIN_UTC);
        self.idle_cleanup_exp_time(exp_time);
    }

    #[expect(
        clippy::significant_drop_tightening,
        reason = "the iterator borrows the pool guard, so the guard has to outlive the scan"
    )]
    pub fn idle_cleanup_exp_time(&self, exp_time: DateTime<Utc>) {
        let mut active_count = 0;
        let mut session_to_close: Vec<Arc<Session>> = Vec::new();
        let mut expired_keys: Vec<u64> = Vec::new();

        {
            let idle_session = self.idle_session.lock();
            let mut it = idle_session.iterate();
            while it.is_not_end() {
                let session = it.value();
                let key = it.key();
                it.move_to_next();

                if session.idle_since().is_some_and(|t| t >= exp_time) {
                    active_count += 1;
                    continue;
                }

                if active_count < self.min_idle_session {
                    session.set_idle_since(Utc::now());
                    active_count += 1;
                    continue;
                }

                session_to_close.push(session);
                expired_keys.push(key);
            }
        }

        if !expired_keys.is_empty() {
            let mut idle_session = self.idle_session.lock();
            for key in expired_keys {
                let _ = idle_session.remove(&key);
            }
        }

        for session in session_to_close {
            let _ = session.close();
        }
    }
}
