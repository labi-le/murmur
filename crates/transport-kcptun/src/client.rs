//! Deviations, forced by the crate's types:
//!
//! * `CancellationToken` carries its own cancel handle, so `close` cancels `ctx` directly.
//! * a one-shot initializer sets up the mux set, the scavenger and the round-robin cursor; Rust
//!   needs interior mutability for that, so the three live behind an atomic, a
//!   `parking_lot::Mutex` and an `OnceLock`. The connection lock guards the blocking
//!   create call; it is a `tokio::sync::Mutex` so the lock survives the `.await` and the future
//!   stays `Send`.
//! * the session slot is `None` when the session has expired.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Once, OnceLock};
use std::time::Duration;

use anyhow::Result;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use murmur_common_net::io::{old_addr_to_socket_addr, OldPacketConnAsDatagram, Stream, StreamAsOldConn};
use murmur_log::debugln;
use murmur_std_compat::net::{Addr, Conn as NetConn, PacketConn};

use super::common::{kcp, smux, Config, SCAVENGE_PERIOD};
use super::comp::new_comp_stream;

pub const MODE: &str = "kcptun";

pub type DialFn = Box<
    dyn Fn(CancellationToken) -> Pin<Box<dyn Future<Output = Result<(Box<dyn PacketConn>, Box<dyn Addr>)>> + Send>>
        + Send
        + Sync,
>;

/// A session wrapper with an expiry date.
#[derive(Clone)]
struct TimedSession {
    session: Option<Arc<dyn smux::Session>>,
    expiry_date: DateTime<Utc>,
}

pub struct Client {
    once: Once,
    config: Config,
    block: Option<Arc<dyn kcp::BlockCrypt>>,
    ctx: CancellationToken,
    muxes: Mutex<Vec<TimedSession>>,
    rr: AtomicU16,
    conn_mu: tokio::sync::Mutex<()>,
    ch_scavenger: OnceLock<mpsc::Sender<TimedSession>>,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Client").field("config", &self.config).finish_non_exhaustive()
    }
}

impl Client {
    #[must_use]
    pub fn new(mut config: Config) -> Self {
        config.fill_defaults();
        let block = config.new_block();
        Self {
            once: Once::new(),
            config,
            block,
            ctx: CancellationToken::new(),
            muxes: Mutex::new(Vec::new()),
            rr: AtomicU16::new(0),
            conn_mu: tokio::sync::Mutex::new(()),
            ch_scavenger: OnceLock::new(),
        }
    }

    pub fn close(&self) -> Result<()> {
        self.ctx.cancel();
        Ok(())
    }

    /// cancel-safe: a dropped future only drops the session it was building; nothing shared
    /// is touched before the dial returns.
    async fn create_conn(&self, ctx: &CancellationToken, dial: &DialFn) -> Result<Arc<dyn smux::Session>> {
        let (conn, addr) = dial(ctx.clone()).await?;

        let raddr = match old_addr_to_socket_addr(addr.as_ref()) {
            Ok(raddr) => raddr,
            Err(err) => {
                let _ = conn.close();
                return Err(err.into());
            }
        };
        let config = self.config.clone();
        let convid = rand::random::<u32>();
        let kcpconn = kcp::new_conn4(
            convid,
            raddr,
            self.block.clone(),
            config.data_shard,
            config.parity_shard,
            true,
            Box::new(OldPacketConnAsDatagram(conn)),
        )?;
        kcpconn.set_stream_mode(true);
        kcpconn.set_write_delay(false);
        kcpconn.set_no_delay(config.no_delay, config.interval, config.resend, config.no_congestion);
        kcpconn.set_window_size(config.snd_wnd, config.rcv_wnd);
        kcpconn.set_mtu(config.mtu);
        kcpconn.set_ack_no_delay(config.ack_nodelay);
        kcpconn.set_rate_limit(config.rate_limit.cast_unsigned());

        let _ = kcpconn.set_dscp(config.dscp);
        let _ = kcpconn.set_read_buffer(config.sock_buf);
        let _ = kcpconn.set_write_buffer(config.sock_buf);
        let mut smux_config = smux::default_config();
        smux_config.version = config.smux_ver;
        smux_config.max_receive_buffer = i64::from(config.smux_buf);
        smux_config.max_stream_buffer = i64::from(config.stream_buf);
        smux_config.max_frame_size = config.frame_size;
        smux_config.keep_alive_interval = Duration::from_secs(i64::from(config.keep_alive).cast_unsigned());
        if smux_config.keep_alive_interval >= smux_config.keep_alive_timeout {
            smux_config.keep_alive_timeout = 3 * smux_config.keep_alive_interval;
        }

        if let Err(err) = smux::verify_config(&smux_config) {
            let _ = murmur_common_net::io::close_stream(&*kcpconn);
            return Err(err);
        }

        let mut net_conn: Box<dyn Stream> = kcpconn;
        if !config.no_comp {
            net_conn = Box::new(new_comp_stream(net_conn));
        }
        smux::client(net_conn, &smux_config).map(Arc::from)
    }

    /// cancel-safe: the slot list is written only after the dial returns, so dropping this
    /// future leaves it consistent; the connection lock is a tokio mutex released on drop.
    #[expect(
        clippy::significant_drop_tightening,
        reason = "each slot guard outlives the entry borrowed from it, so neither lock can be released before the clone completes"
    )]
    pub async fn open_stream(&self, ctx: &CancellationToken, dial: &DialFn) -> Result<Box<dyn NetConn>> {
        let numconn = u16::try_from(self.config.conn)
            .map_err(|_| anyhow::anyhow!("kcptun: conn must be between 1 and 65535, got {}", self.config.conn))?;
        let slots = usize::from(numconn);
        self.once.call_once(|| {
            let (tx, rx) = mpsc::channel(128);
            if self.config.auto_expire > 0 {
                tokio::spawn(scavenger(self.ctx.clone(), rx, self.config.clone()));
            }
            let _ = self.ch_scavenger.set(tx);

            *self.muxes.lock() = vec![TimedSession { session: None, expiry_date: DateTime::<Utc>::MIN_UTC }; slots];
            self.rr.store(0, Ordering::SeqCst);
        });

        let session = {
            let _guard = self.conn_mu.lock().await;
            let idx = (self.rr.load(Ordering::SeqCst) % numconn) as usize;

            let (current, expiry_date) = {
                let muxes = self.muxes.lock();
                let Some(entry) = muxes.get(idx) else {
                    return Err(anyhow::anyhow!("kcptun: no session slot at index {idx}"));
                };
                (entry.session.clone(), entry.expiry_date)
            };

            let needs_reconnect = match &current {
                None => true,
                Some(session) => session.is_closed() || (self.config.auto_expire > 0 && Utc::now() > expiry_date),
            };

            let session = if needs_reconnect {
                let session = self.create_conn(ctx, dial).await?;
                let item = TimedSession {
                    session: Some(Arc::clone(&session)),
                    expiry_date: Utc::now() + ChronoDuration::seconds(i64::from(self.config.auto_expire)),
                };
                {
                    let mut muxes = self.muxes.lock();
                    let Some(slot) = muxes.get_mut(idx) else {
                        return Err(anyhow::anyhow!("kcptun: no session slot at index {idx}"));
                    };
                    slot.clone_from(&item);
                }
                if self.config.auto_expire > 0 {
                    if let Some(tx) = self.ch_scavenger.get() {
                        let _ = tx.send(item).await;
                    }
                }
                Some(session)
            } else {
                current
            };

            self.rr.fetch_add(1, Ordering::SeqCst);
            session
        };

        let Some(session) = session else {
            return Err(anyhow::anyhow!("kcptun: session slot holds no session"));
        };
        session.open_stream().await.map(|s| -> Box<dyn NetConn> { Box::new(StreamAsOldConn::new(s)) })
    }
}

/// `scavenger`: closes expired sessions.
///
/// cancel-safe: the session list is local, so a dropped tick leaves the slot list untouched.
async fn scavenger(ctx: CancellationToken, mut ch: mpsc::Receiver<TimedSession>, config: Config) {
    let period = Duration::from_secs(SCAVENGE_PERIOD);
    let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
    let mut session_list: Vec<TimedSession> = Vec::new();
    loop {
        tokio::select! {
            item = ch.recv() => {
                // A blocking read would wait forever once the client drops the channel; this task exits.
                let Some(item) = item else {
                    return;
                };
                session_list.push(TimedSession {
                    session: item.session,
                    expiry_date: item.expiry_date
                        + ChronoDuration::seconds(i64::from(config.scavenge_ttl)),
                });
            }
            _ = ticker.tick() => {
                let mut new_list: Vec<TimedSession> = Vec::new();
                for s in &session_list {
                    let Some(session) = &s.session else {
                        continue;
                    };
                    if session.is_closed() {
                        debugln!(
                            "scavenger: session normally closed: {}",
                            session.local_addr().map_or_else(|e| e.to_string(), |a| a.to_string())
                        );
                    } else if Utc::now() > s.expiry_date {
                        let _ = session.close();
                        debugln!(
                            "scavenger: session closed due to ttl: {}",
                            session.local_addr().map_or_else(|e| e.to_string(), |a| a.to_string())
                        );
                    } else {
                        new_list.push(s.clone());
                    }
                }
                session_list = new_list;
            }
            () = ctx.cancelled() => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unreachable_dial() -> DialFn {
        Box::new(|_ctx| Box::pin(async { Err(anyhow::anyhow!("the test dial must not be reached")) }))
    }

    /// Bug #108: `numconn` took only the low 16 bits of `conn` while `slots` took the whole `i32`,
    /// so a multiple of 65536 divided by zero and a negative value asked for a ~4 GiB slot vector.
    #[tokio::test]
    async fn open_stream_rejects_a_conn_outside_the_u16_range() {
        for conn in [65_536, 131_072, -1] {
            let config = Config { conn, ..Config::default() };
            let client = Client::new(config);
            let ctx = CancellationToken::new();

            let err = client
                .open_stream(&ctx, &unreachable_dial())
                .await
                .err()
                .unwrap_or_else(|| panic!("conn {conn} must be rejected before any dial"));

            assert!(err.to_string().contains("conn"), "conn {conn}: {err}");
        }
    }

    #[tokio::test]
    async fn open_stream_dials_when_conn_is_within_the_u16_range() {
        let config = Config { conn: 2, ..Config::default() };
        let client = Client::new(config);
        let ctx = CancellationToken::new();

        let err = client.open_stream(&ctx, &unreachable_dial()).await.err().expect("the stubbed dial fails");

        assert!(err.to_string().contains("the test dial must not be reached"), "{err}");
    }
}
