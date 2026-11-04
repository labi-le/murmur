use std::collections::HashMap;
use std::fmt;
use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::TrySendError;
use tokio_util::sync::CancellationToken;

use murmur_common_net::io::{old_addr_to_socket_addr, StreamAsOldConn};
use murmur_std_compat::net::{Addr, Conn as NetConn, Listener as NetListener, PacketConn};

use super::auth::Aead;
use super::config::Config;
use super::conn::{err_net_closed, new_conn, Conn};
use super::packet::{PacketReader, PacketWriter};
use super::segment::COMMAND_TERMINATE;

#[async_trait]
pub(crate) trait IoWriter: Send + Sync {
    async fn write(&self, b: &[u8]) -> io::Result<usize>;
}

pub(crate) trait IoCloser: Send + Sync {
    fn close(&self) -> io::Result<()>;
}

pub struct Listener {
    inner: Arc<ListenerInner>,
}

impl fmt::Debug for Listener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Listener").field("inner", &self.inner).finish_non_exhaustive()
    }
}

impl fmt::Debug for ListenerInner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ListenerInner").finish_non_exhaustive()
    }
}

/// Stays on the old [`PacketConn`]/`&dyn Addr` interface throughout, rather than bridging to the
/// new `Datagram` (`SocketAddr`-keyed) trait internally: the caller's `PacketConn` (mekya's
/// `WrappedPacketConn`) is not itself backed by a real socket — it recovers the `ServerSession` a
/// write is addressed to by downcasting the exact `Box<dyn Addr>` it handed out from `read_from`
/// (its `recover_session`, where the address type is the session itself).
/// Round-tripping that address through a `SocketAddr` and back into a fresh `UdpAddr` loses that
/// identity, so every reply silently failed with "use of closed network connection" — reproduced
/// by `murmur_transport_mekya::client::tests::round_trip`, which never received an echo because
/// the server's own KCP acks could never be routed back to the session that sent them.
struct ListenerInner {
    pc: Arc<dyn PacketConn>,
    cfg: Config,
    reader: PacketReader,
    security: Option<Arc<dyn Aead>>,
    mu: Mutex<Option<HashMap<SessionId, Conn>>>,
    packets: mpsc::Sender<PacketPayload>,
    accept_tx: mpsc::Sender<Conn>,
    accept_rx: tokio::sync::Mutex<mpsc::Receiver<Conn>>,
    closed: CancellationToken,
    once: std::sync::Once,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SessionId {
    addr: String,
    conv: u16,
}

struct PacketPayload {
    payload: Vec<u8>,
    addr: Arc<dyn Addr>,
}

#[cfg_attr(
    not(test),
    expect(
        clippy::unused_async,
        reason = "`listen` is the transport's public entry point and every caller awaits it; \
                  dropping `async` would change that signature"
    )
)]
pub async fn listen(ctx: &CancellationToken, pc: Box<dyn PacketConn>, cfg: Config) -> anyhow::Result<Listener> {
    let security = cfg.security()?;
    let (packets, packets_rx) = mpsc::channel(1024);
    let (accept_tx, accept_rx) = mpsc::channel(1024);
    let inner = Arc::new(ListenerInner {
        pc: Arc::from(pc),
        reader: PacketReader { security: Some(Arc::clone(&security)), header: Some(cfg.packet_header()) },
        security: Some(security),
        cfg,
        mu: Mutex::new(Some(HashMap::new())),
        packets,
        accept_tx,
        accept_rx: tokio::sync::Mutex::new(accept_rx),
        closed: CancellationToken::new(),
        once: std::sync::Once::new(),
    });
    tokio::spawn(read_loop(Arc::clone(&inner)));
    tokio::spawn(packet_loop(Arc::clone(&inner), packets_rx));
    {
        let ctx = ctx.clone();
        let inner = Arc::clone(&inner);
        let closed = inner.closed.clone();
        tokio::spawn(async move {
            tokio::select! {
                () = ctx.cancelled() => inner.close(),
                () = closed.cancelled() => {}
            }
        });
    }
    Ok(Listener { inner })
}

async fn read_loop(inner: Arc<ListenerInner>) {
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let Ok((n, addr)) = inner.pc.read_from(&mut buf).await else {
            inner.close();
            return;
        };
        let payload = buf.get(..n).unwrap_or_default().to_vec();
        match inner.packets.try_send(PacketPayload { payload, addr: Arc::from(addr) }) {
            Ok(()) | Err(TrySendError::Full(_)) => {}
            Err(TrySendError::Closed(_)) => return,
        }
    }
}

async fn packet_loop(inner: Arc<ListenerInner>, mut packets: mpsc::Receiver<PacketPayload>) {
    loop {
        tokio::select! {
            packet = packets.recv() => {
                let Some(packet) = packet else {
                    return;
                };
                ListenerInner::on_receive(Arc::clone(&inner), packet.payload, packet.addr).await;
            }
            () = inner.closed.cancelled() => return,
        }
    }
}

impl ListenerInner {
    async fn on_receive(inner: Arc<Self>, payload: Vec<u8>, addr: Arc<dyn Addr>) {
        let segments = inner.reader.read(&payload);
        let Some(first) = segments.first() else {
            return;
        };
        let conversation = first.conversation();
        let id = SessionId { addr: addr.string(), conv: conversation };

        let mut accepted = None;
        let conn = {
            let mut guard = inner.mu.lock();
            let Some(sessions) = guard.as_mut() else {
                return;
            };
            let conn = if let Some(conn) = sessions.get(&id).cloned() {
                conn
            } else {
                if first.command() == COMMAND_TERMINATE {
                    return;
                }
                let Ok(local_addr) = inner.pc.local_addr().and_then(|a| old_addr_to_socket_addr(a.as_ref())) else {
                    return;
                };
                let Ok(remote_addr) = old_addr_to_socket_addr(addr.as_ref()) else {
                    return;
                };
                let writer = PacketConnWriter {
                    pc: Arc::clone(&inner.pc),
                    addr: Arc::clone(&addr),
                    remove: Some(Arc::new(remove_session(Arc::downgrade(&inner), id.clone()))),
                };
                let packet_writer = PacketWriter {
                    security: inner.security.clone(),
                    header: Some(inner.cfg.packet_header()),
                    writer: Box::new(writer.clone()),
                };
                let conn = new_conn(
                    local_addr,
                    remote_addr,
                    conversation,
                    packet_writer,
                    Some(Box::new(writer)),
                    inner.cfg.clone(),
                );
                sessions.insert(id, conn.clone());
                accepted = Some(conn.clone());
                conn
            };
            drop(guard);
            conn
        };

        if let Some(accepted) = accepted {
            tokio::select! {
                sent = inner.accept_tx.send(accepted.clone()) => {
                    if sent.is_err() {
                        let _ = accepted.close();
                        return;
                    }
                }
                () = inner.closed.cancelled() => {
                    let _ = accepted.close();
                    return;
                }
            }
        }

        conn.input(segments);
    }

    fn remove(&self, id: &SessionId) {
        if let Some(sessions) = self.mu.lock().as_mut() {
            sessions.remove(id);
        }
    }

    fn close(&self) {
        self.once.call_once(|| {
            self.closed.cancel();
            let _ = self.pc.close();
            let sessions = {
                let mut sessions = self.mu.lock();
                sessions.take()
            };
            if let Some(sessions) = sessions {
                for conn in sessions.into_values() {
                    conn.terminate();
                }
            }
        });
    }
}

fn remove_session(inner: std::sync::Weak<ListenerInner>, id: SessionId) -> impl Fn() + Send + Sync {
    move || {
        if let Some(inner) = inner.upgrade() {
            inner.remove(&id);
        }
    }
}

#[derive(Clone)]
pub(crate) struct PacketConnWriter {
    pc: Arc<dyn PacketConn>,
    addr: Arc<dyn Addr>,
    remove: Option<Arc<dyn Fn() + Send + Sync>>,
}

#[async_trait]
impl IoWriter for PacketConnWriter {
    async fn write(&self, b: &[u8]) -> io::Result<usize> {
        self.pc.write_to(b, self.addr.as_ref()).await
    }
}

impl IoCloser for PacketConnWriter {
    fn close(&self) -> io::Result<()> {
        if let Some(remove) = &self.remove {
            remove();
        }
        Ok(())
    }
}

#[async_trait]
impl NetListener for Listener {
    // cancel-safe: takes its item from a queue/channel, so a dropped call leaves the item queued for the next one.
    async fn accept(&self) -> io::Result<Box<dyn NetConn>> {
        let mut accepted = self.inner.accept_rx.lock().await;
        let conn = tokio::select! {
            conn = accepted.recv() => conn,
            () = self.inner.closed.cancelled() => None,
        };
        drop(accepted);
        match conn {
            Some(conn) => Ok(Box::new(StreamAsOldConn::new(conn))),
            None => Err(err_net_closed()),
        }
    }

    fn close(&self) -> io::Result<()> {
        self.inner.close();
        Ok(())
    }

    fn addr(&self) -> io::Result<Box<dyn Addr>> {
        self.inner.pc.local_addr()
    }
}
