//! A `quinn::AsyncUdpSocket` over a `murmur_std_compat::net::PacketConn`, standing in for the
//! The proxy-aware packet conn the dialer produced is what
//! carries the QUIC session.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use murmur_log::debugln;
use parking_lot::Mutex;
use quinn::udp::RecvMeta;
use tokio::io::ReadBuf;
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;

use murmur_common_net::io::old_addr_to_socket_addr;
use murmur_std_compat::net::{Addr, PacketConn, UdpAddr};

/// Bridges a `PacketConn` onto `quinn`'s socket interface. One task reads into a channel and one
/// drains the send channel, so both directions stay driven by the `PacketConn`'s own async API.
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
fn socket_addr_of(addr: &dyn Addr) -> io::Result<SocketAddr> {
    old_addr_to_socket_addr(addr)
}

impl PacketConnSocket {
    pub(crate) fn new(conn: Arc<dyn PacketConn>) -> io::Result<Arc<Self>> {
        let local_addr = socket_addr_of(conn.local_addr()?.as_ref())?;
        let (recv_tx, recv_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(1024);
        let (send_tx, mut send_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(1024);

        let recv_conn = Arc::clone(&conn);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            while let Ok((n, addr)) = recv_conn.read_from(&mut buf).await {
                let Ok(addr) = socket_addr_of(addr.as_ref()) else { continue };
                let Some(data) = buf.get(..n) else { continue };
                if recv_tx.send((data.to_vec(), addr)).await.is_err() {
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

    /// Fills as many of `bufs` as the receive channel holds datagrams for, so one poll can hand
    /// quinn a whole batch instead of waking it once per packet. A datagram that does not fit the
    /// buffer offered is dropped rather than truncated: a QUIC packet is never larger than the
    /// path MTU, so an oversized one is not a packet this connection could have parsed, and the
    /// peer's own retransmission covers losing it.
    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut rx = self.recv.lock();
        let mut filled = 0;
        while let Poll::Ready(Some((data, addr))) = rx.poll_recv(cx) {
            let (Some(buf), Some(meta_slot)) = (bufs.get_mut(filled), meta.get_mut(filled)) else {
                break;
            };
            if data.len() > buf.len() {
                debugln!("ShadowQuic dropped a {} byte datagram that does not fit a receive buffer", data.len());
                continue;
            }
            let len = data.len();
            ReadBuf::new(buf).put_slice(&data);
            *meta_slot = RecvMeta { addr, len, stride: len, ecn: None, dst_ip: None };
            filled += 1;
        }
        if filled > 0 {
            return Poll::Ready(Ok(filled));
        }
        match rx.poll_recv(cx) {
            Poll::Ready(None) => Poll::Ready(Err(closed())),
            Poll::Ready(Some(_)) | Poll::Pending => Poll::Pending,
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "packet conn closed")
}

#[derive(Debug)]
struct SendPoller(Arc<PacketConnSocket>);

impl quinn::UdpPoller for SendPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        self.0.send.lock().poll_reserve(cx).map_err(|_| closed())
    }
}
