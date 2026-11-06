use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Once, Weak};

use async_trait::async_trait;
use bytes::Bytes;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex as AsyncMutex;

use crate::quic::Conn as QuicConn;
use crate::types;
use murmur_common::atomic::type_::Bool as AtomicBoolValue;
use murmur_common_net::bufconn::BufferedConn;
use murmur_common_net::io::{old_addr_to_socket_addr, socket_addr_from_udp_addr, Datagram};
use murmur_common_net::packet::datagram::WaitReadFromDatagram;
use murmur_common_pool as pool;
use murmur_std_compat::net::Conn as NetConn;

use super::frag::frag_write_native;
use super::protocol::{self, DatagramTooLargeError, PACKET_OVER_HEAD};

/// A never-cancelled token, standing in at the call sites that never cancel.
static BACKGROUND: std::sync::LazyLock<tokio_util::sync::CancellationToken> =
    std::sync::LazyLock::new(tokio_util::sync::CancellationToken::new);

pub(crate) type DeferQuicConnFn = Arc<dyn Fn(&Arc<dyn QuicConn>, Option<&anyhow::Error>) + Send + Sync>;

pub(crate) type CloseDeferFn = Arc<dyn Fn() + Send + Sync>;

fn closed_err() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "use of closed network connection")
}

/// Folds a network-origin error down to the one root cause it carries before it is boxed into
/// `anyhow::Error`.
fn anyhow_to_io(err: anyhow::Error) -> io::Error {
    match err.downcast::<io::Error>() {
        Ok(io_err) => io_err,
        Err(err) => io::Error::other(err),
    }
}

fn is_net_error(err: &anyhow::Error) -> bool {
    err.downcast_ref::<io::Error>().is_some()
}

pub(crate) struct QuicStreamPacketConn {
    pub(crate) conn_id: u16,
    pub(crate) quic_conn: Arc<dyn QuicConn>,
    input_conn: AsyncMutex<Option<BufferedConn>>,

    pub(crate) udp_relay_mode: types::type_::UdpRelayMode,
    pub(crate) max_udp_relay_packet_size: usize,

    pub(crate) defer_quic_conn_fn: Option<DeferQuicConnFn>,
    pub(crate) close_defer_fn: Option<CloseDeferFn>,
    pub(crate) write_closed: Option<Arc<AtomicBoolValue>>,

    close_once: Once,
    closed: AtomicBool,

    de_fragger: super::frag::DeFragger,

    self_weak: Weak<Self>,
}

impl QuicStreamPacketConn {
    pub(crate) fn new(
        conn_id: u16,
        quic_conn: Arc<dyn QuicConn>,
        input_conn: Option<BufferedConn>,
        udp_relay_mode: types::type_::UdpRelayMode,
        max_udp_relay_packet_size: usize,
        defer_quic_conn_fn: Option<DeferQuicConnFn>,
        close_defer_fn: Option<CloseDeferFn>,
        write_closed: Option<Arc<AtomicBoolValue>>,
    ) -> Arc<Self> {
        Arc::new_cyclic(|weak| Self {
            conn_id,
            quic_conn,
            input_conn: AsyncMutex::new(input_conn),
            udp_relay_mode,
            max_udp_relay_packet_size,
            defer_quic_conn_fn,
            close_defer_fn,
            write_closed,
            close_once: Once::new(),
            closed: AtomicBool::new(false),
            de_fragger: super::frag::DeFragger::default(),
            self_weak: Weak::clone(weak),
        })
    }

    async fn close_body(&self) -> anyhow::Result<()> {
        let mut guard = self.input_conn.lock().await;
        if let Some(input_conn) = guard.take() {
            let _ = input_conn.close();
            drop(guard);

            let mut buf = pool::get_buffer();
            protocol::new_dissociate(self.conn_id).write_to(&mut buf);
            let stream_result = self.quic_conn.open_uni_stream(&BACKGROUND).await;
            let mut stream = match stream_result {
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

    /// The once-only close, plus the deferred close callbacks. `Close` blocks the caller until
    /// this finishes and returns its error; `Datagram::close` is a synchronous trait method here,
    /// so the actual dissociate-notify write runs as a background task instead of blocking the
    /// caller, and the once-cached close error is dropped along with the synchronous wait.
    fn start_close(&self) {
        self.close_once.call_once(|| {
            self.closed.store(true, Ordering::SeqCst);
            if let Some(this) = self.self_weak.upgrade() {
                tokio::spawn(async move {
                    let result = this.close_body().await;
                    if let Some(defer_quic_conn_fn) = &this.defer_quic_conn_fn {
                        defer_quic_conn_fn(&this.quic_conn, result.as_ref().err());
                    }
                    if let Some(close_defer_fn) = &this.close_defer_fn {
                        close_defer_fn();
                    }
                });
            }
        });
    }

    /// Writes one datagram, past the fast-reject checks.
    async fn write_to_inner(&self, p: &[u8], addr: SocketAddr) -> anyhow::Result<usize> {
        let mut buf = pool::get_buffer();
        let address = protocol::new_address_addr_port(addr);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "the packet id is the low 16 bits of the random u32, matching the fixed-width wire field"
        )]
        let pkt_id = rand::random::<u32>() as u16;
        #[expect(
            clippy::cast_possible_truncation,
            reason = "`send_to` rejects payloads above 0xffff, so the length fits the 16-bit wire field"
        )]
        let packet =
            protocol::new_packet(self.conn_id, pkt_id, 1, 0, p.len() as u16, address, Bytes::copy_from_slice(p));
        if self.udp_relay_mode == types::type_::UdpRelayMode::QUIC {
            packet.write_to(&mut buf);
            let stream_result = self.quic_conn.open_uni_stream(&BACKGROUND).await;
            let mut stream = match stream_result {
                Ok(stream) => stream,
                Err(err) => {
                    pool::put_buffer(buf);
                    return Err(err);
                }
            };
            let write_result = stream.write_all(&buf).await;
            let _ = stream.close();
            write_result?;
        } else {
            let mut send_result = if p.len() > self.max_udp_relay_packet_size {
                frag_write_native(&*self.quic_conn, packet.clone(), &mut buf, self.max_udp_relay_packet_size).await
            } else {
                packet.write_to(&mut buf);
                self.quic_conn.send_datagram(&buf[..])
            };
            if let Err(err) = &send_result {
                if let Some(too_large) = err.downcast_ref::<DatagramTooLargeError>() {
                    // A frame budget at or below the TUIC overhead leaves no capacity to fragment
                    // into, so the original too-large error is kept rather than retried with a
                    // zero fragment size.
                    let capacity = usize::try_from(too_large.max_datagram_payload_size)
                        .unwrap_or(0)
                        .checked_sub(*PACKET_OVER_HEAD)
                        .filter(|frag_size| *frag_size > 0);
                    if let Some(frag_size) = capacity {
                        send_result = frag_write_native(&*self.quic_conn, packet.clone(), &mut buf, frag_size).await;
                    }
                }
            }
            send_result?;
        }
        pool::put_buffer(buf);
        Ok(p.len())
    }
}

impl QuicStreamPacketConn {
    fn local_addr_inner(&self) -> io::Result<SocketAddr> {
        old_addr_to_socket_addr(self.quic_conn.local_addr().as_ref())
    }

    fn close_inner(&self) {
        self.start_close();
    }

    /// `SetDeadline` is left unimplemented and always answers `Ok(())`. Kept as an inherent
    /// method (not part of [`Datagram`]) solely for [`super::client::RefPacketConn`], the one
    /// remaining legacy packet-conn consumer.
    #[expect(
        clippy::unnecessary_wraps,
        clippy::unused_self,
        reason = "the deadline API keeps a `&self` receiver and an `io::Result` even though the body is a no-op"
    )]
    pub(crate) fn set_deadline(&self, _deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        Ok(())
    }

    /// Sets the read deadline. The read-side field races the close
    /// path too; here a `try_lock` folds "another reader holds it right now" and "it was already
    /// closed" into the same no-op, since a deadline registered while a read is mid-flight is only
    /// ever set from the same call sequence in this package (set-then-read, never concurrently from
    /// another task).
    pub(crate) fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        if let Ok(guard) = self.input_conn.try_lock() {
            if let Some(input_conn) = guard.as_ref() {
                return input_conn.set_read_deadline(deadline);
            }
        }
        Ok(())
    }

    /// `SetWriteDeadline` is left unimplemented and always answers `Ok(())`.
    #[expect(
        clippy::unnecessary_wraps,
        clippy::unused_self,
        reason = "the deadline API keeps a `&self` receiver and an `io::Result` even though the body is a no-op"
    )]
    pub(crate) fn set_write_deadline(&self, _deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        Ok(())
    }
}

#[async_trait]
impl Datagram for QuicStreamPacketConn {
    #[expect(
        clippy::significant_drop_tightening,
        reason = "the input lock guard must stay alive across the read loop; inlining it into the `let`-`else` scrutinee would end its borrow immediately"
    )]
    async fn recv_from(&self, p: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut guard = self.input_conn.lock().await;
        let Some(input_conn) = guard.as_mut() else {
            return Err(closed_err());
        };
        loop {
            let packet = protocol::read_packet(input_conn).await.map_err(anyhow_to_io)?;
            if let Some(packet) = self.de_fragger.feed(packet) {
                let n = p.len().min(packet.data.len());
                let (dst, _) = p.split_at_mut(n);
                let (src, _) = packet.data.split_at(n);
                dst.copy_from_slice(src);
                return Ok((n, socket_addr_from_udp_addr(&packet.addr.udp_addr())));
            }
        }
    }

    async fn send_to(&self, p: &[u8], addr: SocketAddr) -> io::Result<usize> {
        if p.len() > 0xffff {
            return Err(io::Error::other(DatagramTooLargeError { max_datagram_payload_size: 0xffff }));
        }
        if self.closed.load(Ordering::SeqCst) {
            return Err(closed_err());
        }
        if let Some(write_closed) = &self.write_closed {
            if write_closed.load() {
                self.close_inner();
                return Err(closed_err());
            }
        }
        let result = self.write_to_inner(p, addr).await;
        if let Some(defer_quic_conn_fn) = &self.defer_quic_conn_fn {
            defer_quic_conn_fn(&self.quic_conn, result.as_ref().err());
        }
        result.map_err(anyhow_to_io)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.local_addr_inner()
    }

    fn close(&self) -> io::Result<()> {
        self.close_inner();
        Ok(())
    }
}

#[async_trait]
impl WaitReadFromDatagram for QuicStreamPacketConn {
    #[expect(
        clippy::significant_drop_tightening,
        reason = "the input lock guard must stay alive across the read loop; inlining it into the `let`-`else` scrutinee would end its borrow immediately"
    )]
    // NOT cancel-safe: a dropped call has already consumed datagram framing from the socket, so a later read would start mid-frame; every `select!` arm that awaits it drops it only while the connection is being torn down.
    async fn wait_read_from(&self) -> (Vec<u8>, Option<Box<dyn FnOnce() + Send>>, Option<SocketAddr>, io::Result<()>) {
        let mut guard = self.input_conn.lock().await;
        let Some(input_conn) = guard.as_mut() else {
            return (Vec::new(), None, None, Err(closed_err()));
        };
        loop {
            let packet = match protocol::read_packet(input_conn).await {
                Ok(packet) => packet,
                Err(err) => return (Vec::new(), None, None, Err(anyhow_to_io(err))),
            };
            if let Some(packet) = self.de_fragger.feed(packet) {
                let addr = socket_addr_from_udp_addr(&packet.addr.udp_addr());
                return (packet.data.to_vec(), None, Some(addr), Ok(()));
            }
        }
    }
}

/// The network-error guard, reused by `client.rs`.
pub(crate) fn is_net_error_ref(err: Option<&anyhow::Error>) -> bool {
    err.is_some_and(is_net_error)
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use parking_lot::Mutex as StdMutex;

    use super::*;

    /// A QUIC conn that rejects any datagram frame larger than the budget it was given, which is
    /// what drives the packet conn's `DatagramTooLargeError` retry path.
    struct BudgetQuicConn {
        budget: usize,
        sent: StdMutex<Vec<Vec<u8>>>,
    }

    #[async_trait::async_trait]
    impl QuicConn for BudgetQuicConn {
        fn local_addr(&self) -> Box<dyn murmur_std_compat::net::Addr> {
            unimplemented!("the send path never reads the local address")
        }

        fn remote_addr(&self) -> Box<dyn murmur_std_compat::net::Addr> {
            unimplemented!("the send path never reads the remote address")
        }

        fn close_with_error(&self, _code: u64, _reason: &str) -> anyhow::Result<()> {
            anyhow::bail!("the send path never closes the connection")
        }

        fn config(&self) -> murmur_quic::Config {
            unimplemented!("the send path never reads the config")
        }

        fn connection_stats(&self) -> murmur_quic::ConnectionStats {
            unimplemented!("the send path never reads the stats")
        }

        fn connection_state(&self) -> murmur_quic::ConnectionState {
            unimplemented!("the send path never reads the connection state")
        }

        fn context(&self) -> tokio_util::sync::CancellationToken {
            unimplemented!("the send path never reads the context")
        }

        async fn handshake_complete(&self) {}

        fn export_keying_material(&self, _label: &[u8], _context: &[u8], _length: usize) -> anyhow::Result<Vec<u8>> {
            anyhow::bail!("the send path never exports keying material")
        }

        async fn open_stream(
            &self,
            _ctx: &tokio_util::sync::CancellationToken,
        ) -> anyhow::Result<Box<dyn murmur_quic::Stream>> {
            anyhow::bail!("the send path never opens a stream")
        }

        async fn open_uni_stream(
            &self,
            _ctx: &tokio_util::sync::CancellationToken,
        ) -> anyhow::Result<Box<dyn murmur_quic::SendStream>> {
            anyhow::bail!("the send path never opens a uni stream")
        }

        async fn accept_stream(
            &self,
            _ctx: &tokio_util::sync::CancellationToken,
        ) -> anyhow::Result<Box<dyn murmur_quic::Stream>> {
            anyhow::bail!("the send path never accepts a stream")
        }

        async fn accept_uni_stream(
            &self,
            _ctx: &tokio_util::sync::CancellationToken,
        ) -> anyhow::Result<Box<dyn murmur_quic::ReceiveStream>> {
            anyhow::bail!("the send path never accepts a uni stream")
        }

        fn send_datagram(&self, data: &[u8]) -> anyhow::Result<()> {
            if data.len() > self.budget {
                return Err(DatagramTooLargeError {
                    max_datagram_payload_size: i64::try_from(self.budget).unwrap_or(i64::MAX),
                }
                .into());
            }
            self.sent.lock().push(data.to_vec());
            Ok(())
        }

        async fn receive_datagram(&self, _ctx: &tokio_util::sync::CancellationToken) -> anyhow::Result<Vec<u8>> {
            anyhow::bail!("the send path never receives a datagram")
        }
    }

    fn new_packet_conn(quic_conn: Arc<dyn QuicConn>, max_udp_relay_packet_size: usize) -> Arc<QuicStreamPacketConn> {
        QuicStreamPacketConn::new(
            1,
            quic_conn,
            None,
            types::type_::UdpRelayMode::NATIVE,
            max_udp_relay_packet_size,
            None,
            None,
            None,
        )
    }

    /// A transport budget with no room above the TUIC overhead has no capacity to fragment into, so
    /// the retry must be skipped and the original too-large error kept rather than dividing by zero.
    #[tokio::test]
    async fn a_retry_with_no_room_above_the_tuic_overhead_keeps_the_original_error() {
        let conn = Arc::new(BudgetQuicConn { budget: *PACKET_OVER_HEAD, sent: StdMutex::new(Vec::new()) });
        let quic_conn = Arc::clone(&conn);
        let pc = new_packet_conn(quic_conn, 1500);
        let addr: SocketAddr = "198.51.100.7:9".parse().expect("the test address parses");

        let err = pc.send_to(&[7u8; 1000], addr).await.expect_err("a frame over the budget must fail");

        assert!(
            err.to_string().contains("DATAGRAM frame too large"),
            "the original too-large error must be kept, got: {err}"
        );
        assert!(conn.sent.lock().is_empty(), "a budget with no room above the overhead must not send a fragment");
    }

    /// The retry still runs when the budget does leave room: the payload is fragmented and the
    /// fragments reassemble to the original.
    #[tokio::test]
    async fn a_retry_with_room_above_the_tuic_overhead_fragments_the_payload() {
        let conn = Arc::new(BudgetQuicConn { budget: *PACKET_OVER_HEAD + 512, sent: StdMutex::new(Vec::new()) });
        let quic_conn = Arc::clone(&conn);
        let pc = new_packet_conn(quic_conn, 1500);
        let addr: SocketAddr = "198.51.100.7:9".parse().expect("the test address parses");
        let payload = vec![7u8; 1000];

        let sent_len = pc.send_to(&payload, addr).await.expect("the payload is fragmented and sent");
        assert_eq!(sent_len, payload.len());

        let sent = conn.sent.lock().clone();
        assert_eq!(sent.len(), 2, "1000 bytes at a 512 byte capacity is two fragments");
        let mut reassembled = Vec::new();
        for frame in &sent {
            let mut cursor = io::Cursor::new(&frame[..]);
            let parsed = protocol::read_packet(&mut cursor).await.expect("the frame parses");
            assert_eq!(parsed.frag_total, 2);
            reassembled.extend_from_slice(&parsed.data);
        }
        assert_eq!(reassembled, payload);
    }
}
