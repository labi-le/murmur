//! Real-socket (loopback UDP, tokio) integration tests for the session layer.
// Test code is exempt from the production panic posture: the bans on `unwrap`,
// `expect`, `panic`, indexing and casts exist to keep a long-lived server process
// alive, and a failing test is supposed to abort. Style tiers are exempt for the
// same reason -- the scaffolding around an assertion is not product code.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::unreachable,
    clippy::todo,
    clippy::unimplemented,
    clippy::pedantic,
    clippy::nursery
)]

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

use murmur_common_net::io::Datagram;
use murmur_kcp::crypt::SimpleXorCrypt;
use murmur_kcp::{new_conn4, serve_conn, BlockCrypt};

async fn bound_socket() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0").await.expect("bind loopback udp socket")
}

/// Wraps a real UDP socket and randomly drops/duplicates/reorders outgoing packets, to prove
/// KCP's ARQ actually retransmits rather than merely forwarding bytes.
struct LossyDatagram {
    inner: UdpSocket,
    drop_pct: u8,
    dup_pct: u8,
    reorder_pct: u8,
    sent: AtomicU64,
}

#[async_trait]
impl Datagram for LossyDatagram {
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.inner.recv_from(buf).await
    }

    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<usize> {
        self.sent.fetch_add(1, Ordering::Relaxed);
        let roll = || rand::rng().random_range(0..100);

        if roll() < self.drop_pct {
            return Ok(buf.len());
        }

        if roll() < self.reorder_pct {
            let data = buf.to_vec();
            let sock_addr = self.inner.local_addr()?;
            let delayed = UdpSocket::bind("0.0.0.0:0").await?;
            let _ = sock_addr;
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(15)).await;
                let _ = delayed.send_to(&data, addr).await;
            });
            return Ok(buf.len());
        }

        let n = self.inner.send_to(buf, addr).await?;
        if roll() < self.dup_pct {
            let _ = self.inner.send_to(buf, addr).await;
        }
        Ok(n)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn close(&self) -> io::Result<()> {
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn round_trip_full_duplex_multi_segment() {
    let server_sock = bound_socket().await;
    let server_addr = server_sock.local_addr().unwrap();
    let listener = serve_conn(None, 0, 0, Box::new(server_sock)).expect("serve_conn");

    let client_sock = bound_socket().await;
    let mut client = new_conn4(0xdead_beef, server_addr, None, 0, 0, true, Box::new(client_sock)).expect("new_conn4");

    let accept_fut = listener.accept_kcp();
    let client_payload = vec![0x42u8; 64 * 1024 + 137];
    let write_fut = client.write_all(&client_payload);

    let (accepted, write_result) =
        tokio::time::timeout(Duration::from_secs(10), futures::future::join(accept_fut, write_fut))
            .await
            .expect("round trip timed out");
    write_result.expect("client write_all");
    let mut server_side = accepted.expect("accept_kcp");

    let mut received = vec![0u8; client_payload.len()];
    tokio::time::timeout(Duration::from_secs(10), server_side.read_exact(&mut received))
        .await
        .expect("server read timed out")
        .expect("server read_exact");
    assert_eq!(received, client_payload, "server must receive exactly what the client sent");

    let server_payload = vec![0x99u8; 32 * 1024 + 7];
    tokio::time::timeout(Duration::from_secs(10), server_side.write_all(&server_payload))
        .await
        .expect("server write timed out")
        .expect("server write_all");

    let mut client_received = vec![0u8; server_payload.len()];
    tokio::time::timeout(Duration::from_secs(10), client.read_exact(&mut client_received))
        .await
        .expect("client read timed out")
        .expect("client read_exact");
    assert_eq!(client_received, server_payload, "client must receive exactly what the server sent");
}

#[tokio::test(flavor = "multi_thread")]
async fn survives_packet_loss_reorder_and_duplication() {
    let server_sock = bound_socket().await;
    let server_addr = server_sock.local_addr().unwrap();
    let lossy_server =
        LossyDatagram { inner: server_sock, drop_pct: 12, dup_pct: 8, reorder_pct: 10, sent: AtomicU64::new(0) };
    let listener = serve_conn(None, 0, 0, Box::new(lossy_server)).expect("serve_conn");

    let client_sock = bound_socket().await;
    let mut client = new_conn4(1, server_addr, None, 0, 0, true, Box::new(client_sock)).expect("new_conn4");
    client.set_no_delay(1, 20, 2, 1);

    let accept_fut = listener.accept_kcp();
    let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 256) as u8).collect();
    let write_fut = client.write_all(&payload);

    let (accepted, write_result) =
        tokio::time::timeout(Duration::from_secs(30), futures::future::join(accept_fut, write_fut))
            .await
            .expect("lossy round trip timed out");
    write_result.expect("client write_all under loss");
    let mut server_side = accepted.expect("accept_kcp under loss");

    let mut received = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(30), server_side.read_exact(&mut received))
        .await
        .expect("server read under loss timed out")
        .expect("server read_exact under loss");
    assert_eq!(received, payload, "ARQ retransmission must still deliver every byte despite loss/reorder/dup");
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypted_round_trip_with_simple_xor_cipher() {
    let key = b"a shared kcptun-style pre-shared key";
    let block: Arc<dyn BlockCrypt> = Arc::new(SimpleXorCrypt::new(key));

    let server_sock = bound_socket().await;
    let server_addr = server_sock.local_addr().unwrap();
    let listener = serve_conn(Some(Arc::clone(&block)), 0, 0, Box::new(server_sock)).expect("serve_conn");

    let client_sock = bound_socket().await;
    let mut client = new_conn4(7, server_addr, Some(block), 0, 0, true, Box::new(client_sock)).expect("new_conn4");

    let accept_fut = listener.accept_kcp();
    let payload = b"the quick brown fox jumps over the lazy dog, repeatedly, to fill a few segments"
        .iter()
        .cycle()
        .take(5000)
        .copied()
        .collect::<Vec<u8>>();
    let write_fut = client.write_all(&payload);

    let (accepted, write_result) =
        tokio::time::timeout(Duration::from_secs(10), futures::future::join(accept_fut, write_fut))
            .await
            .expect("encrypted round trip timed out");
    write_result.expect("client write_all");
    let mut server_side = accepted.expect("accept_kcp");

    let mut received = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(10), server_side.read_exact(&mut received))
        .await
        .expect("server read timed out")
        .expect("server read_exact");
    assert_eq!(received, payload, "encrypted packets must decrypt to exactly the original bytes");
}

/// A socket that never yields an inbound packet and records how often it was closed, so a
/// dropped client session's ownership of it can be observed directly. Its `alive` marker is only
/// held by the session once it is moved in, which is what makes the leak visible.
struct PendingDatagram {
    close_calls: Arc<AtomicUsize>,
    alive: Arc<()>,
}

#[async_trait]
impl Datagram for PendingDatagram {
    // cancel-safe: `pending` never resolves and holds no state, so cancelling the await inside
    // `client_read_loop`'s `select!` arm loses nothing.
    async fn recv_from(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        std::future::pending().await
    }

    async fn send_to(&self, buf: &[u8], _addr: SocketAddr) -> io::Result<usize> {
        Ok(buf.len())
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok("127.0.0.1:0".parse().unwrap())
    }

    fn close(&self) -> io::Result<()> {
        self.close_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_a_client_session_closes_its_socket_and_stops_its_workers() {
    let close_calls = Arc::new(AtomicUsize::new(0));
    let sock = PendingDatagram { close_calls: Arc::clone(&close_calls), alive: Arc::new(()) };
    let alive = Arc::downgrade(&sock.alive);
    let client =
        new_conn4(0xdead_beef, "127.0.0.1:9".parse().unwrap(), None, 0, 0, true, Box::new(sock)).expect("new_conn4");
    tokio::time::sleep(Duration::from_millis(50)).await;

    drop(client);

    assert_eq!(close_calls.load(Ordering::SeqCst), 1, "dropping the last session handle must close the socket");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while alive.upgrade().is_some() && tokio::time::Instant::now() < deadline {
        tokio::task::yield_now().await;
    }
    assert!(alive.upgrade().is_none(), "the session's background tasks must exit, releasing the socket");
}
