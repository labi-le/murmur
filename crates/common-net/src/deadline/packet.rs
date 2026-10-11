use std::any::Any;
use std::fmt;
use std::future::Future;
use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::time::Instant;

use crate::io::DeadlineToken;
use crate::packet::packet::{ReaderWithUpstream, WithUpstream, WriterWithUpstream};
use murmur_common::atomic::type_::Bool;
use murmur_std_compat::net::{Addr, PacketConn};

use super::conn::err_deadline_exceeded;

pub struct NetPacketConn {
    pub(crate) packet_conn: Arc<dyn PacketConn>,
    pub(crate) has_deadline: Bool,
    pub(crate) deadline_token: DeadlineToken,
    pub(crate) disable_pipe: Bool,
    pub(crate) in_read: Bool,
}

impl fmt::Debug for NetPacketConn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NetPacketConn").finish_non_exhaustive()
    }
}

impl NetPacketConn {
    pub(crate) fn new(packet_conn: Arc<dyn PacketConn>) -> Self {
        Self {
            packet_conn,
            has_deadline: Bool::default(),
            deadline_token: DeadlineToken::new(),
            disable_pipe: Bool::default(),
            in_read: Bool::default(),
        }
    }

    /// the `select` over the pipe deadline, around a read the caller drives.
    pub(crate) async fn with_read_deadline<T, F>(&self, read: F) -> io::Result<T>
    where
        F: Future<Output = io::Result<T>>,
    {
        // NOT cancel-safe: dropping this future drops the caller's read, and the `!has_deadline`
        // branch can leave `in_read` latched.
        if self.disable_pipe.load() {
            return read.await;
        }
        if !self.has_deadline.load() {
            self.in_read.store(true);
            let result = read.await;
            self.in_read.store(false);
            return result;
        }

        let token = self.deadline_token.token();
        if token.is_cancelled() {
            return Err(err_deadline_exceeded());
        }
        tokio::select! {
            result = read => result,
            () = token.cancelled() => Err(err_deadline_exceeded()),
        }
    }

    pub const fn need_additional_read_deadline(&self) -> bool {
        false
    }
}

/// Wraps a packet conn in the deadline layer.
///
/// The caller picks [`crate::deadline::packet_enhance::new_enhance_packet_conn`],
/// [`crate::deadline::packet_sing::new_sing_packet_conn`] or
/// [`crate::deadline::packet_sing::new_enhance_sing_packet_conn`] from the type it holds.
pub fn new_net_packet_conn(pc: Arc<dyn PacketConn>) -> Arc<dyn PacketConn> {
    Arc::new(NetPacketConn::new(pc))
}

#[async_trait]
impl PacketConn for NetPacketConn {
    async fn read_from(&self, p: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        self.with_read_deadline(self.packet_conn.read_from(p)).await
    }

    async fn write_to(&self, p: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        self.packet_conn.write_to(p, addr).await
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.packet_conn.local_addr()
    }

    fn close(&self) -> io::Result<()> {
        self.packet_conn.close()
    }

    fn set_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.packet_conn.set_deadline(deadline)
    }

    fn set_write_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.packet_conn.set_write_deadline(deadline)
    }

    /// A deadline set while a read is already parked cannot interrupt that read, so that case hands
    /// the deadline to the wrapped conn and stops racing the token.
    fn set_read_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        if self.disable_pipe.load() {
            return self.packet_conn.set_read_deadline(deadline);
        } else if self.in_read.load() {
            self.disable_pipe.store(true);
            return self.packet_conn.set_read_deadline(deadline);
        }
        self.deadline_token.set(deadline);
        self.has_deadline.store(deadline.is_some());
        Ok(())
    }
}

impl WithUpstream for NetPacketConn {
    fn upstream(&self) -> Option<&dyn Any> {
        Some(self.packet_conn.as_ref())
    }
}

impl ReaderWithUpstream for NetPacketConn {
    fn reader_replaceable(&self) -> bool {
        self.disable_pipe.load() || !self.has_deadline.load()
    }
}

impl WriterWithUpstream for NetPacketConn {
    fn writer_replaceable(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use std::future::pending;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use murmur_std_compat::net::UdpAddr;

    use super::*;

    /// A conn whose read never completes, so only a read deadline can end it.
    struct NeverReadyPacketConn;

    #[async_trait]
    impl PacketConn for NeverReadyPacketConn {
        async fn read_from(&self, _buf: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
            pending().await
        }

        async fn write_to(&self, _buf: &[u8], _addr: &dyn Addr) -> io::Result<usize> {
            Ok(0)
        }

        fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(UdpAddr::from(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))))
        }

        fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    fn exceeded<T, E>(result: &Result<io::Result<T>, E>) -> bool {
        matches!(result, Ok(Err(err)) if err.kind() == io::ErrorKind::TimedOut)
    }

    #[tokio::test]
    async fn an_elapsed_read_deadline_ends_the_read_with_deadline_exceeded() {
        let conn = new_net_packet_conn(Arc::new(NeverReadyPacketConn));
        conn.set_read_deadline(Some(Instant::now() - Duration::from_secs(1))).expect("set the read deadline");

        let mut buf = [0u8; 1500];
        let result = tokio::time::timeout(Duration::from_secs(2), conn.read_from(&mut buf)).await;
        assert!(exceeded(&result), "an elapsed read deadline must end the read, got {result:?}");
    }

    #[tokio::test]
    async fn a_future_read_deadline_ends_the_read_when_it_elapses_and_not_before() {
        let conn = new_net_packet_conn(Arc::new(NeverReadyPacketConn));
        conn.set_read_deadline(Some(Instant::now() + Duration::from_millis(600))).expect("set the read deadline");

        let mut buf = [0u8; 1500];
        let early = tokio::select! {
            result = conn.read_from(&mut buf) => Some(result),
            () = tokio::time::sleep(Duration::from_millis(100)) => None,
        };
        assert!(early.is_none(), "a read deadline 600ms out must not end the read after 100ms");

        let result = tokio::time::timeout(Duration::from_secs(5), conn.read_from(&mut buf)).await;
        assert!(exceeded(&result), "the read deadline must end the read once it elapses, got {result:?}");
    }

    #[tokio::test]
    async fn clearing_the_read_deadline_leaves_the_read_unbounded() {
        let conn = new_net_packet_conn(Arc::new(NeverReadyPacketConn));
        conn.set_read_deadline(Some(Instant::now() + Duration::from_millis(200))).expect("set the read deadline");
        conn.set_read_deadline(None).expect("clear the read deadline");

        let mut buf = [0u8; 1500];
        let result = tokio::time::timeout(Duration::from_millis(500), conn.read_from(&mut buf)).await;
        assert!(result.is_err(), "a cleared read deadline must leave the read unbounded, got {result:?}");
    }
}
