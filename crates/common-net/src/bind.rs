use std::fmt;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use parking_lot::Mutex;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use murmur_compat::sing_buf::UDP_BUFFER_SIZE;
use murmur_std_compat::net::{Addr, Conn, PacketConn, UdpAddr};

use crate::io::{ExtendedStream, Stream};
use crate::{old_enhance_packet_conn_as_enhance_datagram, EnhanceDatagram};

use super::packet_file::new_enhance_packet_conn;

type ReadFuture = Pin<Box<dyn Future<Output = io::Result<(Vec<u8>, usize)>> + Send>>;
type WriteFuture = Pin<Box<dyn Future<Output = io::Result<usize>> + Send>>;

/// The in-flight read and the staging buffer it owns. `Stream` is `Sync`, so the non-`Sync`
/// futures it hands out live behind a lock.
#[derive(Default)]
struct BindReadState {
    buffer: Vec<u8>,
    future: Option<ReadFuture>,
}

/// A conn whose reads take one packet and whose writes go to one address.
pub struct BindPacketConn {
    enhance_datagram: Arc<dyn EnhanceDatagram>,
    r_addr: SocketAddr,
    read_state: Mutex<BindReadState>,
    write_future: Mutex<Option<WriteFuture>>,
}

impl fmt::Debug for BindPacketConn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BindPacketConn").field("r_addr", &self.r_addr).finish_non_exhaustive()
    }
}

impl BindPacketConn {
    fn new(datagram: Arc<dyn EnhanceDatagram>, r_addr: SocketAddr) -> Self {
        Self {
            enhance_datagram: datagram,
            r_addr,
            read_state: Mutex::new(BindReadState::default()),
            write_future: Mutex::new(None),
        }
    }

    pub async fn wait_read(&self) -> (Vec<u8>, Option<Box<dyn FnOnce() + Send>>, io::Result<()>) {
        let (data, put, _addr, err) = self.enhance_datagram.wait_read_from().await;
        (data, put, err)
    }
}

impl AsyncRead for BindPacketConn {
    /// Reads, taking one packet's payload.
    #[expect(clippy::expect_used, reason = "the future is inserted above in this same call")]
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut state = this.read_state.lock();
        if state.future.is_none() {
            let datagram = Arc::clone(&this.enhance_datagram);
            let mut read_buf = core::mem::take(&mut state.buffer);
            if read_buf.is_empty() {
                read_buf = vec![0u8; UDP_BUFFER_SIZE as usize];
            }
            state.future = Some(Box::pin(async move {
                let (n, _addr) = datagram.recv_from(&mut read_buf).await?;
                Ok((read_buf, n))
            }));
        }

        let future = state.future.as_mut().expect("the read future was just set");
        let poll = match future.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => {
                state.future = None;
                Poll::Ready(Err(err))
            }
            Poll::Ready(Ok((read_buf, n))) => {
                state.future = None;
                let n = core::cmp::min(buf.remaining(), n);
                buf.put_slice(read_buf.get(..n).unwrap_or_default());
                state.buffer = read_buf;
                Poll::Ready(Ok(()))
            }
        };
        drop(state);
        poll
    }
}

impl AsyncWrite for BindPacketConn {
    /// Writes, sending the slice to the bound remote address.
    #[expect(clippy::expect_used, reason = "the future is inserted above in this same call")]
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let mut write_future = this.write_future.lock();
        if write_future.is_none() {
            let datagram = Arc::clone(&this.enhance_datagram);
            let r_addr = this.r_addr;
            let data = buf.to_vec();
            *write_future = Some(Box::pin(async move { datagram.send_to(&data, r_addr).await }));
        }

        let future = write_future.as_mut().expect("the write future was just set");
        let poll = match future.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                *write_future = None;
                Poll::Ready(result)
            }
        };
        drop(write_future);
        poll
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl Stream for BindPacketConn {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        match self.enhance_datagram.local_addr() {
            Ok(addr) => Ok(addr),
            // The unspecified IPv4 address stands in when the local address is null.
            Err(_) => Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)),
        }
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.r_addr)
    }

    /// This conn embeds `EnhanceDatagram` and has no half-close of its
    /// own, so unlike a real half-closeable `Stream` its only real close is the whole-conn one
    /// reached through [`Conn::close`] below, not `shutdown_write`/`shutdown_read`.
    fn old_conn(&self) -> Option<&dyn Conn> {
        Some(self)
    }
}

// S11: remove in U8, when the final old-`Conn` bridge is deleted.
impl Conn for BindPacketConn {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        Ok(Box::new(UdpAddr::from(Stream::local_addr(self)?)))
    }
    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        Ok(Box::new(UdpAddr::from(self.r_addr)))
    }
    fn close(&self) -> io::Result<()> {
        self.enhance_datagram.close()
    }
}

impl ExtendedStream for BindPacketConn {}

pub fn new_bind_packet_conn(pc: Arc<dyn PacketConn>, r_addr: SocketAddr) -> Box<dyn Stream> {
    let datagram = old_enhance_packet_conn_as_enhance_datagram(new_enhance_packet_conn(pc));
    Box::new(BindPacketConn::new(datagram, r_addr))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use async_trait::async_trait;

    use crate::io::{close_stream, Datagram};
    use crate::WaitReadFromDatagram;

    use super::*;

    #[derive(Default)]
    struct FakeDatagram {
        closed: AtomicBool,
    }

    #[async_trait]
    impl Datagram for FakeDatagram {
        async fn recv_from(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            std::future::pending().await
        }
        async fn send_to(&self, buf: &[u8], _addr: SocketAddr) -> io::Result<usize> {
            Ok(buf.len())
        }
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        }
        fn close(&self) -> io::Result<()> {
            self.closed.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    #[async_trait]
    impl WaitReadFromDatagram for FakeDatagram {
        async fn wait_read_from(
            &self,
        ) -> (Vec<u8>, Option<Box<dyn FnOnce() + Send>>, Option<SocketAddr>, io::Result<()>) {
            (Vec::new(), None, None, Ok(()))
        }
    }

    #[test]
    fn shutdown_write_leaves_the_underlying_datagram_open() {
        let fake = Arc::new(FakeDatagram::default());
        let datagram = Arc::clone(&fake);
        let conn = BindPacketConn::new(datagram, "127.0.0.1:1".parse().unwrap());
        conn.shutdown_write().unwrap();
        assert!(!fake.closed.load(Ordering::SeqCst), "a relay's half-close must not close the whole conn");
    }

    #[test]
    fn whole_conn_teardown_still_closes_the_underlying_datagram() {
        let fake = Arc::new(FakeDatagram::default());
        let datagram = Arc::clone(&fake);
        let conn = BindPacketConn::new(datagram, "127.0.0.1:1".parse().unwrap());
        close_stream(&conn).unwrap();
        assert!(fake.closed.load(Ordering::SeqCst), "whole-conn teardown must still reach the real close");
    }
}
