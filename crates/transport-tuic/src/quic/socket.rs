//! A `quinn::AsyncUdpSocket` over a `murmur_std_compat::net::PacketConn`: the proxy-aware packet
//! conn the dialer (or the listener) produced is what carries the session, so `quinn` never owns
//! a socket of its own.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use parking_lot::Mutex;
use quinn::udp::RecvMeta;
use tokio::io::ReadBuf;
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;

use murmur_common_net::io::old_addr_to_socket_addr;
use murmur_std_compat::net::{PacketConn, UdpAddr};

const CHANNEL_DEPTH: usize = 1024;

pub(crate) struct PacketConnSocket {
    local_addr: SocketAddr,
    send: Mutex<PollSender<(Vec<u8>, SocketAddr)>>,
    recv: Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
}

impl std::fmt::Debug for PacketConnSocket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PacketConnSocket").field("local_addr", &self.local_addr).finish_non_exhaustive()
    }
}

impl PacketConnSocket {
    #[expect(clippy::unnecessary_wraps, reason = "the fallible shape of this constructor is its pub(crate) signature")]
    pub(crate) fn new(conn: Arc<dyn PacketConn>, local_addr: SocketAddr) -> io::Result<Arc<Self>> {
        let (recv_tx, recv_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(CHANNEL_DEPTH);
        let (send_tx, mut send_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(CHANNEL_DEPTH);

        let recv_conn = Arc::clone(&conn);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            while let Ok((n, addr)) = recv_conn.read_from(&mut buf).await {
                let Ok(addr) = old_addr_to_socket_addr(addr.as_ref()) else { continue };
                let Some(payload) = buf.get(..n) else { continue };
                let payload = payload.to_vec();
                if recv_tx.send((payload, addr)).await.is_err() {
                    break;
                }
            }
        });

        tokio::spawn(async move {
            while let Some((data, addr)) = send_rx.recv().await {
                if conn.write_to(&data, &UdpAddr::from(addr)).await.is_err() {
                    break;
                }
            }
        });

        Ok(Arc::new(Self { local_addr, send: Mutex::new(PollSender::new(send_tx)), recv: Mutex::new(recv_rx) }))
    }
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "packet conn closed")
}

impl quinn::AsyncUdpSocket for PacketConnSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(SendPoller(self))
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        let mut guard = self.send.lock();
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        match guard.poll_reserve(&mut cx) {
            Poll::Ready(Ok(())) => {
                guard.send_item((transmit.contents.to_vec(), transmit.destination)).map_err(|_| closed())
            }
            Poll::Ready(Err(_)) | Poll::Pending => {
                Err(io::Error::new(io::ErrorKind::WouldBlock, "packet conn send buffer is full"))
            }
        }
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut rx = self.recv.lock();
        match rx.poll_recv(cx) {
            Poll::Ready(Some((data, addr))) => {
                let len = data.len().min(bufs.first().map_or(0, |buf| buf.len()));
                if let Some(buf) = bufs.first_mut() {
                    let dst = buf.get_mut(..len).unwrap_or_default();
                    let src = data.get(..len).unwrap_or_default();
                    ReadBuf::new(dst).put_slice(src);
                }
                if let Some(meta) = meta.first_mut() {
                    *meta = RecvMeta { addr, len, stride: len, ecn: None, dst_ip: None };
                }
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

#[derive(Debug)]
struct SendPoller(Arc<PacketConnSocket>);

impl quinn::UdpPoller for SendPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.send.lock().poll_reserve(cx).map_err(|_| closed())
    }
}
