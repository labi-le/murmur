//! A `quinn::AsyncUdpSocket` over a `murmur_std_compat::net::PacketConn`, the packet conn slot of
//! the QUIC transport: the proxy-aware packet conn the dialer produced is what carries the QUIC
//! session, obfuscator/hop/wechat/faketcp wrappers included.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use parking_lot::Mutex;
use quinn::udp::RecvMeta;
use tokio::io::ReadBuf;
use tokio::sync::mpsc;
use tokio_util::sync::{CancellationToken, PollSender};

use murmur_common_net::io::old_addr_to_socket_addr;
use murmur_std_compat::net::{PacketConn, UdpAddr};

const CHANNEL_CAPACITY: usize = 2048;
const MAX_DATAGRAM_SIZE: usize = 65535;

/// Bridges a `PacketConn` onto `quinn`'s socket interface. One task feeds the receive channel and
/// one drains the send channel, so both directions stay driven by the `PacketConn`'s own async API.
pub(super) struct PacketConnSocket {
    local_addr: SocketAddr,
    send: Mutex<PollSender<(Vec<u8>, SocketAddr)>>,
    recv: Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
    closed: CancellationToken,
}

impl std::fmt::Debug for PacketConnSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PacketConnSocket").field("local_addr", &self.local_addr).finish_non_exhaustive()
    }
}

impl PacketConnSocket {
    pub(super) fn new(conn: Arc<dyn PacketConn>) -> io::Result<Arc<Self>> {
        let local_addr = old_addr_to_socket_addr(conn.local_addr()?.as_ref())?;
        let (recv_tx, recv_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(CHANNEL_CAPACITY);
        let (send_tx, mut send_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(CHANNEL_CAPACITY);
        let closed = CancellationToken::new();

        let recv_closed = closed.clone();
        let recv_conn = Arc::clone(&conn);
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_DATAGRAM_SIZE];
            loop {
                let Ok((n, addr)) = recv_conn.read_from(&mut buf).await else { break };
                let Ok(addr) = old_addr_to_socket_addr(addr.as_ref()) else { continue };
                let Some(packet) = buf.get(..n) else { break };
                if recv_tx.send((packet.to_vec(), addr)).await.is_err() {
                    break;
                }
            }
            recv_closed.cancel();
        });

        let send_closed = closed.clone();
        tokio::spawn(async move {
            while let Some((data, addr)) = send_rx.recv().await {
                if send_closed.is_cancelled() || conn.write_to(&data, &UdpAddr::from(addr)).await.is_err() {
                    break;
                }
            }
            send_closed.cancel();
        });

        Ok(Arc::new(Self { local_addr, send: Mutex::new(PollSender::new(send_tx)), recv: Mutex::new(recv_rx), closed }))
    }
}

impl quinn::AsyncUdpSocket for PacketConnSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(SendPoller(self))
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        if self.closed.is_cancelled() {
            return Err(closed());
        }
        let mut guard = self.send.lock();
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        match guard.poll_reserve(&mut cx) {
            Poll::Ready(Ok(())) => {
                guard.send_item((transmit.contents.to_vec(), transmit.destination)).map_err(|_| closed())
            }
            Poll::Ready(Err(_)) => Err(closed()),
            Poll::Pending => Err(io::Error::new(io::ErrorKind::WouldBlock, "packet conn send buffer is full")),
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut rx = self.recv.lock();
        match rx.poll_recv(cx) {
            Poll::Ready(Some((data, addr))) => {
                let Some(buf) = bufs.first_mut() else {
                    return Poll::Ready(Err(missing_recv_buffer()));
                };
                let Some(meta) = meta.first_mut() else {
                    return Poll::Ready(Err(missing_recv_buffer()));
                };
                let len = data.len().min(buf.len());
                let (Some(dst), Some(src)) = (buf.get_mut(..len), data.get(..len)) else {
                    return Poll::Ready(Err(missing_recv_buffer()));
                };
                ReadBuf::new(dst).put_slice(src);
                *meta = RecvMeta { addr, len, stride: len, ecn: None, dst_ip: None };
                Poll::Ready(Ok(1))
            }
            Poll::Ready(None) => Poll::Ready(Err(closed())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "packet conn closed")
}

/// `quinn` always passes one receive buffer and one matching metadata slot.
fn missing_recv_buffer() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "async udp socket has no buffer to receive into")
}

#[derive(Debug)]
struct SendPoller(Arc<PacketConnSocket>);

impl quinn::UdpPoller for SendPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        if self.0.closed.is_cancelled() {
            return Poll::Ready(Err(closed()));
        }
        self.0.send.lock().poll_reserve(cx).map_err(|_| closed())
    }
}
