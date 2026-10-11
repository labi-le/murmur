use std::any::Any;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Once};
use std::task::{Context, Poll};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio_util::sync::CancellationToken;

use murmur_common_net::io::{ExtendedStream, Stream};
use murmur_common_net::packet::packet::{ReaderWithUpstream, WaitReadFrom, WithUpstream, WriterWithUpstream};
use murmur_common_net::sing::{ExtendedConn, UpstreamNode};
use murmur_compat::sing_buf::Buffer;
use murmur_constant::adapters::{
    Chain, Conn as ConstantConn, Connection, PacketConn as ConstantPacketConn, ProxyAdapter,
};
use murmur_constant::metadata::Metadata;
use murmur_std_compat::net::{Addr, PacketConn};

use anyhow::Result;

/// `closeCallbackConn`'s `closeFunc func()`.
pub type CloseFunc = Box<dyn Fn() + Send + Sync>;

struct CloseCallbackConn {
    conn: Box<dyn ConstantConn>,
    close_func: CloseFunc,
    close_once: Once,
}

impl AsyncRead for CloseCallbackConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().conn).poll_read(cx, buf)
    }
}

impl AsyncWrite for CloseCallbackConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.get_mut().conn).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().conn).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().conn).poll_shutdown(cx)
    }
}

impl Stream for CloseCallbackConn {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.conn.local_addr()
    }

    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.conn.peer_addr()
    }

    fn shutdown_read(&self) -> io::Result<()> {
        self.conn.shutdown_read()
    }

    fn shutdown_write(&self) -> io::Result<()> {
        self.conn.shutdown_write()
    }

    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        self.conn.as_socket()
    }

    fn old_conn(&self) -> Option<&dyn murmur_std_compat::net::Conn> {
        self.conn.old_conn()
    }
}

impl ExtendedStream for CloseCallbackConn {
    fn reader_replaceable(&self) -> bool {
        true
    }

    fn writer_replaceable(&self) -> bool {
        true
    }
}

/// The close callback fires explicitly; `Stream` has no `close()` (§2: cleanup is
/// `Drop`-driven, the same substitution `adapter::outbound::base::AutoCloseProxyAdapter` already
/// makes on the GC-finalizer close), so the callback now fires when the last owner drops this conn.
impl Drop for CloseCallbackConn {
    fn drop(&mut self) {
        self.close_once.call_once(|| (self.close_func)());
    }
}

impl UpstreamNode for CloseCallbackConn {
    fn reader_replaceable(&self) -> Option<bool> {
        Some(true)
    }

    fn writer_replaceable(&self) -> Option<bool> {
        Some(true)
    }
}

impl Connection for CloseCallbackConn {
    fn chains(&self) -> Chain {
        self.conn.chains()
    }

    fn provider_chains(&self) -> Chain {
        self.conn.provider_chains()
    }

    fn append_to_chains(&self, adapter: Arc<dyn ProxyAdapter>) {
        self.conn.append_to_chains(adapter);
    }

    fn remote_destination(&self) -> String {
        self.conn.remote_destination()
    }
}

#[async_trait]
impl ExtendedConn for CloseCallbackConn {
    /// Reads into the buffer, which the erased conn cannot reach; the read goes
    /// through the async half, as `common::net::sing` does on an erased conn.
    async fn read_buffer(&mut self, buffer: &mut Buffer) -> io::Result<()> {
        match self.conn.read(buffer.free_bytes()).await {
            Ok(n) => {
                buffer.truncate(n);
                Ok(())
            }
            Err(err) => {
                buffer.truncate(0);
                Err(err)
            }
        }
    }

    /// Writes the buffer; see [`Self::read_buffer`].
    async fn write_buffer(&mut self, buffer: &mut Buffer) -> io::Result<()> {
        let result = self.conn.write_all(buffer.bytes()).await;
        buffer.release();
        result
    }
}

#[must_use]
pub fn new_close_callback_conn(conn: Box<dyn ConstantConn>, callback: CloseFunc) -> Box<dyn ConstantConn> {
    Box::new(CloseCallbackConn { conn, close_func: callback, close_once: Once::new() })
}

struct CloseCallbackPacketConn {
    packet_conn: Arc<dyn ConstantPacketConn>,
    close_func: CloseFunc,
    close_once: Once,
}

#[async_trait]
impl PacketConn for CloseCallbackPacketConn {
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
        self.close_once.call_once(|| (self.close_func)());
        self.packet_conn.close()
    }
}

#[async_trait]
impl WaitReadFrom for CloseCallbackPacketConn {
    // cancel-safe: forwards to the wrapped conn's `wait_read_from` and owns no state of its own, so dropping this future is exactly dropping the inner call.
    async fn wait_read_from(
        &self,
    ) -> (Vec<u8>, Option<Box<dyn FnOnce() + Send>>, Option<Box<dyn Addr>>, io::Result<()>) {
        self.packet_conn.wait_read_from().await
    }
}

#[async_trait]
impl ConstantPacketConn for CloseCallbackPacketConn {
    async fn resolve_udp(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<()> {
        self.packet_conn.resolve_udp(ctx, metadata).await
    }
}

impl Connection for CloseCallbackPacketConn {
    fn chains(&self) -> Chain {
        self.packet_conn.chains()
    }

    fn provider_chains(&self) -> Chain {
        self.packet_conn.provider_chains()
    }

    fn append_to_chains(&self, adapter: Arc<dyn ProxyAdapter>) {
        self.packet_conn.append_to_chains(adapter);
    }

    fn remote_destination(&self) -> String {
        self.packet_conn.remote_destination()
    }
}

impl WithUpstream for CloseCallbackPacketConn {
    fn upstream(&self) -> Option<&dyn Any> {
        Some(self.packet_conn.as_packet_conn())
    }
}

impl ReaderWithUpstream for CloseCallbackPacketConn {
    fn reader_replaceable(&self) -> bool {
        true
    }
}

impl WriterWithUpstream for CloseCallbackPacketConn {
    fn writer_replaceable(&self) -> bool {
        true
    }
}

pub fn new_close_callback_packet_conn(
    conn: Arc<dyn ConstantPacketConn>,
    callback: CloseFunc,
) -> Arc<dyn ConstantPacketConn> {
    Arc::new(CloseCallbackPacketConn { packet_conn: conn, close_func: callback, close_once: Once::new() })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::io::DuplexStream;

    use super::*;

    struct MockConn(DuplexStream);

    impl AsyncRead for MockConn {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for MockConn {
        fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
        }
    }

    impl Stream for MockConn {
        fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
            Err(io::Error::other("mock: no local addr"))
        }

        fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
            Err(io::Error::other("mock: no peer addr"))
        }
    }

    impl ExtendedStream for MockConn {}

    impl Connection for MockConn {
        fn chains(&self) -> Chain {
            Chain::default()
        }

        fn provider_chains(&self) -> Chain {
            Chain::default()
        }

        fn append_to_chains(&self, _adapter: Arc<dyn ProxyAdapter>) {}

        fn remote_destination(&self) -> String {
            String::new()
        }
    }

    fn new_mock() -> Box<dyn ConstantConn> {
        let (a, _b) = tokio::io::duplex(64);
        Box::new(MockConn(a))
    }

    /// A conn that is only ever dropped (no explicit `close()` call, the path every `Stream`
    /// consumer takes since `Stream` itself has no `close()`) must still fire `close_func` once.
    #[tokio::test]
    async fn close_func_fires_once_on_drop_alone() {
        let fired = Arc::new(AtomicUsize::new(0));
        let fired_task = Arc::clone(&fired);
        let conn = CloseCallbackConn {
            conn: new_mock(),
            close_func: Box::new(move || {
                fired_task.fetch_add(1, Ordering::SeqCst);
            }),
            close_once: Once::new(),
        };
        drop(conn);
        assert_eq!(fired.load(Ordering::SeqCst), 1, "close_func must fire exactly once on drop alone");
    }
}
