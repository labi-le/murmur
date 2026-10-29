use std::any::Any;
use std::collections::HashMap;
use std::fmt;
use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use murmur_std_compat::net::{Addr, PacketConn as NetPacketConn};

use super::deadline::{new_pipe_deadlines, PipeDeadlines};
use super::server::ServerSession;

fn err_net_closed() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "use of closed network connection")
}

fn err_deadline_exceeded() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "i/o timeout")
}

fn err_context_canceled() -> io::Error {
    io::Error::other("context canceled")
}

#[derive(Debug)]
pub(crate) struct Packet {
    addr: Arc<ServerSession>,
    data: Vec<u8>,
}

/// `Box<dyn Addr>` bridge exposing a shared [`ServerSession`] as its own address.
#[derive(Debug)]
struct SessionAddr(Arc<ServerSession>);

/// `Box<dyn Addr>` bridge for a shared generic [`Addr`], returning the same address value from
/// `LocalAddr` on every call.
#[derive(Debug)]
struct AddrRef(Arc<dyn Addr>);

impl Addr for AddrRef {
    fn network(&self) -> &str {
        self.0.network()
    }

    fn string(&self) -> String {
        self.0.string()
    }

    fn addr_port(&self) -> Option<murmur_std_compat::net::AddrPort> {
        self.0.addr_port()
    }

    fn raw_addr(&self) -> Option<&dyn Addr> {
        self.0.raw_addr()
    }

    fn as_iface_prefix(&self) -> Option<ipnet::IpNet> {
        self.0.as_iface_prefix()
    }

    fn as_sock_addr(&self) -> Option<murmur_std_compat::net::SockAddr> {
        self.0.as_sock_addr()
    }
}

impl Addr for SessionAddr {
    fn network(&self) -> &str {
        self.0.network()
    }

    fn string(&self) -> String {
        self.0.string()
    }
}

/// Recovers the [`ServerSession`] behind a possibly wrapped `Addr`, peeling [`SessionAddr`] and
/// [`AddrRef`] the way their old `as_any` implementations delegated to the address they wrap.
fn recover_session(addr: &dyn Addr) -> Option<Arc<ServerSession>> {
    let any: &dyn Any = addr;
    if let Some(session_addr) = any.downcast_ref::<SessionAddr>() {
        return Some(Arc::clone(&session_addr.0));
    }
    if let Some(addr_ref) = any.downcast_ref::<AddrRef>() {
        return recover_session(&*addr_ref.0);
    }
    None
}

#[derive(Debug)]
struct WrappedPacketConnState {
    sessions: Option<HashMap<Vec<u8>, Arc<ServerSession>>>,
}

pub(crate) struct WrappedPacketConn {
    ctx: CancellationToken,
    state: Mutex<WrappedPacketConnState>,
    read_tx: mpsc::Sender<Packet>,
    read_rx: tokio::sync::Mutex<mpsc::Receiver<Packet>>,
    local: Arc<dyn Addr>,
    deadlines: PipeDeadlines,
}

impl fmt::Debug for WrappedPacketConn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WrappedPacketConn")
            .field("ctx", &self.ctx)
            .field("state", &self.state)
            .field("local", &self.local)
            .finish_non_exhaustive()
    }
}

pub(crate) fn new_wrapped_packet_conn(ctx: &CancellationToken, local: Arc<dyn Addr>) -> Arc<WrappedPacketConn> {
    let (read_tx, read_rx) = mpsc::channel(16);
    Arc::new(WrappedPacketConn {
        ctx: ctx.child_token(),
        state: Mutex::new(WrappedPacketConnState { sessions: Some(HashMap::new()) }),
        read_tx,
        read_rx: tokio::sync::Mutex::new(read_rx),
        local,
        deadlines: new_pipe_deadlines(),
    })
}

impl WrappedPacketConn {
    pub(crate) fn add_session(self: &Arc<Self>, session: Arc<ServerSession>) -> io::Result<()> {
        if self.ctx.is_cancelled() {
            return Err(err_net_closed());
        }
        {
            let mut state = self.state.lock();
            let Some(sessions) = state.sessions.as_mut() else {
                return Err(err_net_closed());
            };
            sessions.insert(session.session_id().to_vec(), Arc::clone(&session));
            drop(state);
        }
        let this = Arc::clone(self);
        tokio::spawn(async move { this.read_session(session).await });
        Ok(())
    }

    async fn read_session(&self, session: Arc<ServerSession>) {
        let mut buf = vec![0u8; 2000];
        loop {
            let n = match session.read(&mut buf).await {
                Ok(n) if n <= buf.len() => n,
                _ => break,
            };
            let (payload, _) = buf.split_at(n);
            let payload = payload.to_vec();
            tokio::select! {
                () = self.ctx.cancelled() => break,
                result = self.read_tx.send(Packet { addr: Arc::clone(&session), data: payload }) => {
                    if result.is_err() {
                        break;
                    }
                }
            }
        }
        self.remove_session_if(session.session_id(), &session);
    }

    /// Drops `session_id` only while it still maps to `session`, so the removal that follows a
    /// closed session can never take a replacement created under the same id with it.
    pub(crate) fn remove_session_if(&self, session_id: &[u8], session: &Arc<ServerSession>) {
        let mut state = self.state.lock();
        let Some(sessions) = state.sessions.as_mut() else {
            return;
        };
        if sessions.get(session_id).is_some_and(|stored| Arc::ptr_eq(stored, session)) {
            sessions.remove(session_id);
        }
        drop(state);
    }

    #[cfg(test)]
    pub(crate) fn session_count(&self) -> usize {
        self.state.lock().sessions.as_ref().map_or(0, HashMap::len)
    }
}

#[async_trait]
impl NetPacketConn for WrappedPacketConn {
    async fn read_from(&self, p: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        let mut rx = self.read_rx.lock().await;
        let read_deadline = self.deadlines.read.wait();
        let result = tokio::select! {
            () = self.ctx.cancelled() => Err(err_context_canceled()),
            () = read_deadline.wait() => Err(err_deadline_exceeded()),
            packet = rx.recv() => {
                let Some(packet) = packet else {
                    return Err(err_context_canceled());
                };
                let n = p.len().min(packet.data.len());
                let (dst, _) = p.split_at_mut(n);
                let (src, _) = packet.data.split_at(n);
                dst.copy_from_slice(src);
                if n < packet.data.len() {
                    return Err(io::Error::new(io::ErrorKind::InvalidInput, "short buffer"));
                }
                let addr: Box<dyn Addr> = Box::new(SessionAddr(packet.addr));
                Ok((n, addr))
            }
        };
        drop(rx);
        result
    }

    async fn write_to(&self, p: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        if self.ctx.is_cancelled() {
            return Err(err_context_canceled());
        }
        if self.deadlines.write.wait().is_closed() {
            return Err(err_deadline_exceeded());
        }
        let Some(session) = recover_session(addr) else {
            return Err(err_net_closed());
        };
        let session = {
            let state = self.state.lock();
            state.sessions.as_ref().and_then(|sessions| sessions.get(session.session_id()).cloned())
        };
        let Some(session) = session else {
            return Err(err_net_closed());
        };
        session.write(p).await
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        Ok(Box::new(AddrRef(Arc::clone(&self.local))))
    }

    fn close(&self) -> io::Result<()> {
        self.ctx.cancel();
        let sessions: Vec<Arc<ServerSession>> = {
            let mut state = self.state.lock();
            let sessions = state.sessions.take().unwrap_or_default();
            drop(state);
            sessions.into_values().collect()
        };
        for session in sessions {
            session.close();
        }
        Ok(())
    }
}

/// Local newtype so `Arc<WrappedPacketConn>` can satisfy the foreign `PacketConn` trait (Rust's
/// orphan rule forbids implementing a foreign trait directly for `Arc<LocalType>`), letting the
/// same pointer be used both as a `PacketConn` and as an owned server field.
#[derive(Clone)]
pub(crate) struct SharedPacketConn(pub(crate) Arc<WrappedPacketConn>);

#[async_trait]
impl NetPacketConn for SharedPacketConn {
    async fn read_from(&self, p: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        self.0.read_from(p).await
    }

    async fn write_to(&self, p: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        self.0.write_to(p, addr).await
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.0.local_addr()
    }

    fn close(&self) -> io::Result<()> {
        self.0.close()
    }
}
