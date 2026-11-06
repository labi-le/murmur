use std::any::Any;
use std::fmt;
use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::time::Instant;

use crate::packet::datagram::{enhance_datagram_as_old_enhance_packet_conn, EnhanceDatagram};
use crate::packet::packet::{
    EnhancePacketConn as EnhancePacketConnTrait, ReaderWithUpstream, WaitReadFrom, WithUpstream, WriterWithUpstream,
};
use murmur_std_compat::net::{Addr, PacketConn};

use super::conn::err_deadline_exceeded;
use super::packet::NetPacketConn;

/// The enhanced packet-conn union, wrapping a `NetPacketConn` and an `EnhancePacketConnTrait`.
pub struct EnhancePacketConn {
    pub(crate) net_packet_conn: Arc<NetPacketConn>,
    enhance_packet_conn: Arc<dyn EnhancePacketConnTrait>,
}

impl fmt::Debug for EnhancePacketConn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnhancePacketConn").finish_non_exhaustive()
    }
}

/// The caller hands in a [`Datagram`](crate::io::Datagram)-shaped value.
///
/// The old `PacketConn` half [`NetPacketConn`] still needs internally is bridged via
/// [`enhance_datagram_as_old_enhance_packet_conn`]; the output stays the old
/// [`EnhancePacketConnTrait`] shape until the remaining deadline-wrapped consumers convert.
pub fn new_enhance_packet_conn(pc: Arc<dyn EnhanceDatagram>) -> Arc<dyn EnhancePacketConnTrait> {
    let pc = enhance_datagram_as_old_enhance_packet_conn(pc);
    let net_packet_conn = Arc::new(NetPacketConn::new(Arc::clone(&pc).into_packet_conn()));
    Arc::new(EnhancePacketConn::new(net_packet_conn, pc))
}

impl EnhancePacketConn {
    pub(crate) fn new(
        net_packet_conn: Arc<NetPacketConn>,
        enhance_packet_conn: Arc<dyn EnhancePacketConnTrait>,
    ) -> Self {
        Self { net_packet_conn, enhance_packet_conn }
    }
}

#[async_trait]
impl PacketConn for EnhancePacketConn {
    async fn read_from(&self, p: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        self.net_packet_conn.read_from(p).await
    }

    async fn write_to(&self, p: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        self.net_packet_conn.write_to(p, addr).await
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.net_packet_conn.local_addr()
    }

    fn close(&self) -> io::Result<()> {
        self.net_packet_conn.close()
    }

    fn set_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.net_packet_conn.set_deadline(deadline)
    }

    fn set_write_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.net_packet_conn.set_write_deadline(deadline)
    }

    fn set_read_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.net_packet_conn.set_read_deadline(deadline)
    }
}

#[async_trait]
impl WaitReadFrom for EnhancePacketConn {
    // NOT cancel-safe: a dropped wait abandons the caller's read.
    async fn wait_read_from(
        &self,
    ) -> (Vec<u8>, Option<Box<dyn FnOnce() + Send>>, Option<Box<dyn Addr>>, io::Result<()>) {
        let net_packet_conn = &self.net_packet_conn;
        let token = net_packet_conn.deadline_token.token();
        if net_packet_conn.has_deadline.load() && token.is_cancelled() {
            return (Vec::new(), None, None, Err(err_deadline_exceeded()));
        }
        tokio::select! {
            result = self.enhance_packet_conn.wait_read_from() => result,
            () = token.cancelled() => (Vec::new(), None, None, Err(err_deadline_exceeded())),
        }
    }
}

impl WithUpstream for EnhancePacketConn {
    fn upstream(&self) -> Option<&dyn Any> {
        self.net_packet_conn.upstream()
    }
}

impl ReaderWithUpstream for EnhancePacketConn {
    fn reader_replaceable(&self) -> bool {
        self.net_packet_conn.reader_replaceable()
    }
}

impl WriterWithUpstream for EnhancePacketConn {
    fn writer_replaceable(&self) -> bool {
        self.net_packet_conn.writer_replaceable()
    }
}

#[cfg(test)]
mod tests {
    use std::future::pending;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::Duration;

    use crate::io::Datagram;
    use crate::packet::datagram::new_enhance_datagram;

    use super::*;

    struct NeverReadyDatagram;

    #[async_trait]
    impl Datagram for NeverReadyDatagram {
        async fn recv_from(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            pending().await
        }

        async fn send_to(&self, _buf: &[u8], _addr: SocketAddr) -> io::Result<usize> {
            Ok(0)
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        }

        fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn wait_read_from_honours_deadline_set_during_and_after_an_unbounded_parked_read() {
        let conn = new_enhance_packet_conn(new_enhance_datagram(Arc::new(NeverReadyDatagram)));
        let reader = Arc::clone(&conn);
        let wait_task = tokio::spawn(async move { reader.wait_read_from().await.3 });

        tokio::time::sleep(Duration::from_millis(20)).await;
        conn.set_read_deadline(Some(Instant::now() + Duration::from_millis(30)))
            .expect("arm deadline while wait_read_from is parked");

        let first = tokio::time::timeout(Duration::from_secs(1), wait_task)
            .await
            .expect("parked wait_read_from must wake when the deadline elapses")
            .expect("wait task panicked");
        assert_eq!(first.expect_err("timed-out wait must fail").kind(), io::ErrorKind::TimedOut);

        conn.set_read_deadline(Some(Instant::now() + Duration::from_millis(30)))
            .expect("re-arm deadline for the next wait_read_from");
        let (_, _, _, second) = tokio::time::timeout(Duration::from_secs(1), conn.wait_read_from())
            .await
            .expect("subsequent wait_read_from must still time out instead of hanging with disable_pipe");
        assert_eq!(second.expect_err("second wait must fail").kind(), io::ErrorKind::TimedOut);
    }
}
