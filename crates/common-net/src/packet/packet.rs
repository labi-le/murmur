use std::any::Any;
use std::io;
use std::sync::Arc;

use async_trait::async_trait;

use murmur_common_pool as pool;
use murmur_std_compat::net::{Addr, PacketConn};

#[cfg(not(target_os = "windows"))]
use super::packet_posix::EnhanceUDPConn;
#[cfg(target_os = "windows")]
use super::packet_windows::EnhanceUDPConn;
#[async_trait]
pub trait WaitReadFrom: Send + Sync {
    async fn wait_read_from(
        &self,
    ) -> (Vec<u8>, Option<Box<dyn FnOnce() + Send>>, Option<Box<dyn Addr>>, io::Result<()>);
}

/// Exposes an optional inner value of the wrapper chain.
pub trait WithUpstream: Send + Sync {
    fn upstream(&self) -> Option<&dyn Any>;
}

/// Reports whether the reader half can be replaced.
pub trait ReaderWithUpstream: Send + Sync {
    fn reader_replaceable(&self) -> bool;
}

/// Reports whether the writer half can be replaced.
pub trait WriterWithUpstream: Send + Sync {
    fn writer_replaceable(&self) -> bool;
}

/// The `PacketConn`-with-waiter view of a value.
///
/// A `dyn` value hands out its `PacketConn` half explicitly, so call sites never depend on
/// trait-object upcasting.
pub trait EnhancePacketConn: PacketConn + WaitReadFrom + Send + Sync {
    fn as_packet_conn(&self) -> &dyn PacketConn;

    fn into_packet_conn(self: Arc<Self>) -> Arc<dyn PacketConn>;
}

// Compatibility bridge: the trait only re-erases a value that already carries both halves.
impl<T: PacketConn + WaitReadFrom + 'static> EnhancePacketConn for T {
    fn as_packet_conn(&self) -> &dyn PacketConn {
        self
    }

    fn into_packet_conn(self: Arc<Self>) -> Arc<dyn PacketConn> {
        self
    }
}

pub(crate) struct EnhancePacketConnImpl {
    packet_conn: Arc<dyn PacketConn>,
}

impl EnhancePacketConnImpl {
    pub(crate) fn new(packet_conn: Arc<dyn PacketConn>) -> Self {
        Self { packet_conn }
    }
}

#[async_trait]
impl PacketConn for EnhancePacketConnImpl {
    async fn read_from(&self, buf: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        self.packet_conn.read_from(buf).await
    }

    async fn write_to(&self, buf: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        self.packet_conn.write_to(buf, addr).await
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.packet_conn.local_addr()
    }

    fn close(&self) -> io::Result<()> {
        self.packet_conn.close()
    }
}

#[async_trait]
impl WaitReadFrom for EnhancePacketConnImpl {
    // cancel-safe: forwards to the wrapped conn's `wait_read_from` and owns no state of its own, so dropping this future is exactly dropping the inner call.
    async fn wait_read_from(
        &self,
    ) -> (Vec<u8>, Option<Box<dyn FnOnce() + Send>>, Option<Box<dyn Addr>>, io::Result<()>) {
        wait_read_from(&*self.packet_conn).await
    }
}

impl WithUpstream for EnhancePacketConnImpl {
    fn upstream(&self) -> Option<&dyn Any> {
        Some(self.packet_conn.as_ref())
    }
}

impl ReaderWithUpstream for EnhancePacketConnImpl {
    fn reader_replaceable(&self) -> bool {
        true
    }
}

impl WriterWithUpstream for EnhancePacketConnImpl {
    fn writer_replaceable(&self) -> bool {
        true
    }
}

/// Wraps `pc` in the enhancement layer the relay needs.
///
/// Only the concrete-UDP-socket case is detected here, by an identity test on the erased value; a
/// caller that statically holds one of the other kinds has its own branch: an
/// `Arc<dyn EnhancePacketConn>` comes back unchanged and a `SingPacketConn` goes through
/// `new_enhance_sing_packet_conn`.
///
/// This is an identity test, not `as_socket()`: only a wrapper whose own type embeds a concrete
/// UDP socket answers the socket accessor, so `as_socket()` would accept an already-enhanced conn
/// and wrap it again. The bare-socket path needs the underlying socket and would then miss on
/// every read.
pub fn new_enhance_packet_conn(pc: Arc<dyn PacketConn>) -> Arc<dyn EnhancePacketConn> {
    let concrete: &dyn Any = pc.as_ref();
    if concrete.is::<tokio::net::UdpSocket>() {
        return Arc::new(EnhanceUDPConn::new(pc));
    }
    Arc::new(EnhancePacketConnImpl::new(pc))
}

// NOT cancel-safe: a dropped call has already consumed datagram framing from the socket, so a later read would start mid-frame; every `select!` arm that awaits it drops it only while the connection is being torn down.
pub async fn wait_read_from(
    pc: &dyn PacketConn,
) -> (Vec<u8>, Option<Box<dyn FnOnce() + Send>>, Option<Box<dyn Addr>>, io::Result<()>) {
    let mut read_buf = pool::get(pool::UDP_BUFFER_SIZE);
    let (read_n, addr, err) = match pc.read_from(&mut read_buf).await {
        Ok((read_n, addr)) => (read_n, Some(addr), Ok(())),
        Err(err) => (0, None, Err(err)),
    };
    if read_n == 0 {
        let _ = pool::put(read_buf);
        return (Vec::new(), None, addr, err);
    }
    // Returns the pooled block itself, truncated to the payload, instead of a fresh copy; `put`
    // is `None` because there is no separate allocation left to recycle here. The caller is
    // responsible for returning `data` to `pool` once it is done with it.
    read_buf.truncate(read_n);
    (read_buf, None, addr, err)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use super::*;
    use murmur_std_compat::net::UdpAddr;

    struct FixedPayloadConn {
        payload: Vec<u8>,
    }

    #[async_trait]
    impl PacketConn for FixedPayloadConn {
        async fn read_from(&self, buf: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
            let n = self.payload.len();
            buf[..n].copy_from_slice(&self.payload);
            let addr: Box<dyn Addr> = Box::new(UdpAddr::from(SocketAddr::from((Ipv4Addr::LOCALHOST, 9))));
            Ok((n, addr))
        }

        async fn write_to(&self, _buf: &[u8], _addr: &dyn Addr) -> io::Result<usize> {
            unimplemented!()
        }

        fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
            unimplemented!()
        }

        fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn wait_read_from_returns_pooled_buffer_without_extra_copy() {
        let payload = b"hello pooled world".to_vec();
        let conn = FixedPayloadConn { payload: payload.clone() };
        let (data, put, addr, result) = wait_read_from(&conn).await;

        assert!(result.is_ok());
        assert!(addr.is_some());
        assert_eq!(data, payload);
        assert!(put.is_none(), "the pooled block itself is returned as `data`; there is nothing left for `put`");

        // The returned Vec must still be the pool's block (a power-of-two capacity), so the
        // caller can hand it straight back with `pool::put` once it is done reading `data`.
        pool::put(data).expect("caller must be able to recycle the returned buffer");
    }
}
