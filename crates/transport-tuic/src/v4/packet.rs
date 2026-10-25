use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Once};

use async_trait::async_trait;
use bytes::Bytes;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex as TokioMutex;

use super::protocol;
use crate::quic::Conn as QuicConn;
use crate::types::type_ as types;
use murmur_common::atomic::type_::Bool as AtomicBool2;
use murmur_common_net::bufconn::BufferedConn;
use murmur_common_net::io::{old_addr_to_socket_addr, socket_addr_from_udp_addr, Datagram};
use murmur_common_net::packet::datagram::WaitReadFromDatagram;
use murmur_common_pool as pool;
use murmur_std_compat::net::Conn;

/// A never-cancelled token, standing in at the call sites that never cancel.
static BACKGROUND: std::sync::LazyLock<tokio_util::sync::CancellationToken> =
    std::sync::LazyLock::new(tokio_util::sync::CancellationToken::new);

fn err_net_closed() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "use of closed network connection")
}

/// `anyhow::Error` does not implement `std::error::Error`, so `io::Error::other` cannot take one
/// directly; this rebuilds an opaque `io::Error` from its message the way the rest of this
/// package already handles a mixed io/anyhow error boundary.
fn anyhow_to_io(err: &anyhow::Error) -> io::Error {
    io::Error::other(err.to_string())
}

#[derive(Debug, thiserror::Error)]
#[error("DATAGRAM frame too large (maximum: {max_datagram_payload_size} bytes)")]
pub struct DatagramTooLargeError {
    pub max_datagram_payload_size: i64,
}

/// The deferred-close callback, cloned into the background task `close` spawns.
pub(crate) type DeferQuicConnFn = Arc<dyn Fn(Arc<dyn QuicConn>, Option<anyhow::Error>) + Send + Sync>;

/// The plain defer callback, cloned into the background task `close` spawns.
pub(crate) type CloseDeferFn = Arc<dyn Fn() + Send + Sync>;

pub(crate) struct QuicStreamPacketConn {
    conn_id: u32,
    quic_conn: Arc<dyn QuicConn>,
    input_conn: Arc<TokioMutex<Option<BufferedConn>>>,

    udp_relay_mode: types::UdpRelayMode,
    max_udp_relay_packet_size: usize,

    defer_quic_conn_fn: Option<DeferQuicConnFn>,
    close_defer_fn: Option<CloseDeferFn>,
    write_closed: Option<Arc<AtomicBool2>>,

    closed: AtomicBool,
    close_once: Once,
}

/// The packet-conn struct literal at each of this crate's two call sites.
pub(crate) fn new_quic_stream_packet_conn(
    conn_id: u32,
    quic_conn: Arc<dyn QuicConn>,
    input_conn: Option<BufferedConn>,
    udp_relay_mode: types::UdpRelayMode,
    max_udp_relay_packet_size: usize,
    defer_quic_conn_fn: Option<DeferQuicConnFn>,
    close_defer_fn: Option<CloseDeferFn>,
    write_closed: Option<Arc<AtomicBool2>>,
) -> QuicStreamPacketConn {
    QuicStreamPacketConn {
        conn_id,
        quic_conn,
        input_conn: Arc::new(TokioMutex::new(input_conn)),
        udp_relay_mode,
        max_udp_relay_packet_size,
        defer_quic_conn_fn,
        close_defer_fn,
        write_closed,
        closed: AtomicBool::new(false),
        close_once: Once::new(),
    }
}

/// Closes the packet conn once in the background: `Datagram::close` below is a
/// sync fn, while this does real network I/O (opening a uni stream
/// to send `Dissociate`). Every call site already discards the close error, so scheduling the
/// work and returning `Ok(())` at once keeps every observable branch without blocking a sync fn
/// on network I/O.
async fn close_impl(
    conn_id: u32,
    quic_conn: &Arc<dyn QuicConn>,
    input_conn: &TokioMutex<Option<BufferedConn>>,
) -> anyhow::Result<()> {
    let mut guard = input_conn.lock().await;
    if let Some(conn) = guard.take() {
        let _ = conn.close();
        drop(guard);

        let mut buf = pool::get_buffer();
        if let Err(err) = protocol::new_dissociate(conn_id).write_to(&mut buf) {
            pool::put_buffer(buf);
            return Err(err.into());
        }
        let mut stream = match quic_conn.open_uni_stream(&BACKGROUND).await {
            Ok(stream) => stream,
            Err(err) => {
                pool::put_buffer(buf);
                return Err(err);
            }
        };
        let write_result = stream.write_all(&buf).await;
        pool::put_buffer(buf);
        write_result?;
        stream.close()?;
    }
    Ok(())
}

impl QuicStreamPacketConn {
    /// Writes one datagram, split out so the deferred
    /// call in [`Self::write_to_deferred`] can run over the settled result.
    async fn write_to_impl(&self, p: &[u8], addr: SocketAddr) -> io::Result<usize> {
        let mut buf = pool::get_buffer();
        let address = protocol::new_address_addr_port(addr);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "the packet length field is a `u16` on the wire; keeping the truncation preserves the bytes sent for a payload that would exceed it"
        )]
        let len = p.len() as u16;
        if let Err(err) = protocol::new_packet(self.conn_id, len, address, Bytes::copy_from_slice(p)).write_to(&mut buf)
        {
            pool::put_buffer(buf);
            return Err(err);
        }
        if self.udp_relay_mode == types::UdpRelayMode::QUIC {
            let mut stream = match self.quic_conn.open_uni_stream(&BACKGROUND).await {
                Ok(stream) => stream,
                Err(err) => {
                    pool::put_buffer(buf);
                    return Err(anyhow_to_io(&err));
                }
            };
            let write_result = stream.write_all(&buf).await;
            pool::put_buffer(buf);
            let _ = stream.close();
            write_result?;
        } else {
            let result = self.quic_conn.send_datagram(&buf).map_err(|err| anyhow_to_io(&err));
            pool::put_buffer(buf);
            result?;
        }
        Ok(p.len())
    }
}

#[async_trait]
impl Datagram for QuicStreamPacketConn {
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut guard = self.input_conn.lock().await;
        match guard.as_mut() {
            Some(input_conn) => {
                let packet = protocol::read_packet(input_conn).await.map_err(|err| anyhow_to_io(&err))?;
                let n = buf.len().min(packet.data.len());
                if let (Some(dst), Some(src)) = (buf.get_mut(..n), packet.data.get(..n)) {
                    dst.copy_from_slice(src);
                }
                Ok((n, socket_addr_from_udp_addr(&packet.addr.udp_addr())))
            }
            None => Err(err_net_closed()),
        }
    }

    async fn send_to(&self, p: &[u8], addr: SocketAddr) -> io::Result<usize> {
        if self.udp_relay_mode != types::UdpRelayMode::QUIC && p.len() > self.max_udp_relay_packet_size {
            return Err(io::Error::other(DatagramTooLargeError {
                max_datagram_payload_size: i64::try_from(self.max_udp_relay_packet_size).unwrap_or(i64::MAX),
            }));
        }
        if self.closed.load(Ordering::SeqCst) {
            return Err(err_net_closed());
        }
        if let Some(write_closed) = &self.write_closed {
            if write_closed.load() {
                let _ = self.close();
                return Err(err_net_closed());
            }
        }
        let result = self.write_to_impl(p, addr).await;
        if let Some(defer_quic_conn_fn) = &self.defer_quic_conn_fn {
            let err = result.as_ref().err().map(|e| anyhow::Error::from(io::Error::new(e.kind(), e.to_string())));
            defer_quic_conn_fn(Arc::clone(&self.quic_conn), err);
        }
        result
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        old_addr_to_socket_addr(self.quic_conn.local_addr().as_ref())
    }

    fn close(&self) -> io::Result<()> {
        self.close_once.call_once(|| {
            self.closed.store(true, Ordering::SeqCst);
            let conn_id = self.conn_id;
            let quic_conn = Arc::clone(&self.quic_conn);
            let input_conn = Arc::clone(&self.input_conn);
            let defer_quic_conn_fn = self.defer_quic_conn_fn.clone();
            let close_defer_fn = self.close_defer_fn.clone();
            tokio::spawn(async move {
                let result = close_impl(conn_id, &quic_conn, &input_conn).await;
                if let Some(close_defer_fn) = close_defer_fn {
                    close_defer_fn();
                }
                if let Some(defer_quic_conn_fn) = defer_quic_conn_fn {
                    defer_quic_conn_fn(quic_conn, result.err());
                }
            });
        });
        Ok(())
    }
}

#[async_trait]
impl WaitReadFromDatagram for QuicStreamPacketConn {
    // NOT cancel-safe: a dropped call has already consumed datagram framing from the socket, so a later read would start mid-frame; every `select!` arm that awaits it drops it only while the connection is being torn down.
    async fn wait_read_from(&self) -> (Vec<u8>, Option<Box<dyn FnOnce() + Send>>, Option<SocketAddr>, io::Result<()>) {
        let mut guard = self.input_conn.lock().await;
        match guard.as_mut() {
            Some(input_conn) => match protocol::read_packet(input_conn).await {
                Ok(packet) => {
                    let addr = socket_addr_from_udp_addr(&packet.addr.udp_addr());
                    (packet.data.to_vec(), None, Some(addr), Ok(()))
                }
                Err(err) => (Vec::new(), None, None, Err(anyhow_to_io(&err))),
            },
            None => (Vec::new(), None, None, Err(err_net_closed())),
        }
    }
}
