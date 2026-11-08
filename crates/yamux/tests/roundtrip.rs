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

use std::time::Duration;

use murmur_yamux::{client, default_config, server};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test(flavor = "multi_thread")]
async fn concurrent_streams_half_close_and_session_close() {
    let (client_conn, server_conn) = tokio::io::duplex(64 * 1024);

    let client_session = client(client_conn, default_config()).await.expect("client session");
    let server_session = server(server_conn, default_config()).await.expect("server session");

    let accept_session = server_session.clone();
    let accept_task = tokio::spawn(async move {
        let mut streams = Vec::new();
        for _ in 0..3 {
            streams.push(accept_session.accept_stream().await.expect("accept stream"));
        }
        streams
    });

    let mut client_streams = Vec::new();
    for _ in 0..3 {
        client_streams.push(client_session.open_stream().await.expect("open stream"));
    }
    let mut server_streams = accept_task.await.expect("accept task");

    for (i, (c, s)) in client_streams.iter_mut().zip(server_streams.iter_mut()).enumerate() {
        let payload = format!("hello from client on stream {i}");
        c.write_all(payload.as_bytes()).await.expect("client write");
        let mut buf = vec![0u8; payload.len()];
        s.read_exact(&mut buf).await.expect("server read");
        assert_eq!(buf, payload.as_bytes());

        let reply = format!("hello from server on stream {i}");
        s.write_all(reply.as_bytes()).await.expect("server write");
        let mut buf2 = vec![0u8; reply.len()];
        c.read_exact(&mut buf2).await.expect("client read");
        assert_eq!(buf2, reply.as_bytes());
    }

    assert_eq!(client_session.num_streams(), 3);
    assert_eq!(server_session.num_streams(), 3);

    client_streams[0].shutdown().await.expect("client half-close");
    let mut eof_buf = [0u8; 1];
    let n = server_streams[0].read(&mut eof_buf).await.expect("server observes EOF");
    assert_eq!(n, 0, "server should see EOF after client half-close");

    let after_close = b"server can still write after peer half-close";
    server_streams[0].write_all(after_close).await.expect("server write after half-close");
    let mut buf3 = vec![0u8; after_close.len()];
    client_streams[0].read_exact(&mut buf3).await.expect("client reads after its own half-close");
    assert_eq!(buf3, after_close);

    client_session.close().await.expect("client close");
    server_session.close().await.expect("server close");

    assert!(client_session.is_closed());
    assert!(server_session.is_closed());

    tokio::time::sleep(Duration::from_millis(50)).await;
    let err = client_session.open_stream().await.expect_err("open after close must fail");
    assert!(!err.to_string().is_empty());

    let mut leftover = [0u8; 1];
    let server_result = server_streams[1].read(&mut leftover).await;
    assert!(server_result.is_err() || server_result.unwrap() == 0, "peer must observe session close");
}

/// the `*Stream` has no destructor, so a peer that half-closes its write side and then drops the
/// stream must not send a reset: the remote write half remains open.
#[tokio::test(flavor = "multi_thread")]
async fn drop_after_peer_half_close_leaves_peer_writable() {
    let (client_conn, server_conn) = tokio::io::duplex(64 * 1024);
    let client_session = client(client_conn, default_config()).await.expect("client session");
    let server_session = server(server_conn, default_config()).await.expect("server session");

    let accept_session = server_session.clone();
    let accept_task = tokio::spawn(async move { accept_session.accept_stream().await.expect("accept stream") });

    let mut client_stream = client_session.open_stream().await.expect("open stream");
    let mut server_stream = accept_task.await.expect("accept stream");

    client_stream.write_all(b"request").await.expect("client write");

    let mut buf = [0u8; 7];
    server_stream.read_exact(&mut buf).await.expect("server read");
    server_stream.shutdown().await.expect("server half-close");
    let mut eof = [0u8; 1];
    assert_eq!(client_stream.read(&mut eof).await.expect("client observes EOF"), 0);
    drop(server_stream);

    client_stream.write_all(b"late").await.expect("client write after peer drop");
    let mut late = [0u8; 4];
    let read = tokio::time::timeout(Duration::from_millis(250), client_stream.read(&mut late)).await;
    assert!(!matches!(read, Ok(Err(_))), "peer half-close must not reset the still-open half");
}

/// The counterpart: a stream dropped with both halves still open is an abort, and the peer
/// learns about it as a reset read error rather than a silent end of stream.
#[tokio::test(flavor = "multi_thread")]
async fn drop_with_open_halves_resets_the_peer() {
    let (client_conn, server_conn) = tokio::io::duplex(64 * 1024);
    let client_session = client(client_conn, default_config()).await.expect("client session");
    let server_session = server(server_conn, default_config()).await.expect("server session");

    let accept_session = server_session.clone();
    let accept_task = tokio::spawn(async move { accept_session.accept_stream().await.expect("accept stream") });

    let mut client_stream = client_session.open_stream().await.expect("open stream");
    let mut server_stream = accept_task.await.expect("accept task");
    client_stream.write_all(b"request").await.expect("client write");

    let mut buf = [0u8; 7];
    server_stream.read_exact(&mut buf).await.expect("server read");
    drop(client_stream);

    let mut next = [0u8; 1];
    let err = tokio::time::timeout(Duration::from_secs(5), server_stream.read(&mut next))
        .await
        .expect("reset within 5s")
        .expect_err("aborted stream must not report a clean EOF");
    assert!(err.to_string().contains("reset"), "expected a reset error, got: {err}");
}

/// A peer cannot lift flow control by crediting the send window past `max_stream_window_size`:
/// the update is refused and the stream is reset, rather than the window being inflated to the
/// peer's number. The peer is driven by hand here, so the local reader has nothing else on the
/// wire; the frame layout is the one in `src/frame.rs`.
#[tokio::test(flavor = "multi_thread")]
async fn an_oversized_window_update_resets_the_stream() {
    const TYPE_WINDOW_UPDATE: u8 = 1;
    const FLAG_RST: u16 = 8;

    let (client_conn, mut peer) = tokio::io::duplex(64 * 1024);
    let session = client(client_conn, default_config()).await.expect("client session");
    let mut stream = session.open_stream().await.expect("open stream");

    let mut syn = [0u8; 12];
    peer.read_exact(&mut syn).await.expect("the open announces its window");
    assert_eq!(syn[1], TYPE_WINDOW_UPDATE, "the open frame is a window update");
    let id = u32::from_be_bytes(syn[4..8].try_into().expect("four stream id bytes"));

    peer.write_all(&[0, TYPE_WINDOW_UPDATE, 0, 0, 0, 0, 0, 1, 0xFF, 0xFF, 0xFF, 0xFF])
        .await
        .expect("send an unbounded window update");

    let mut reset = [0u8; 12];
    tokio::time::timeout(Duration::from_secs(5), peer.read_exact(&mut reset))
        .await
        .expect("a window update past the ceiling must reset the stream")
        .expect("read the reset");
    assert_eq!(reset[1], TYPE_WINDOW_UPDATE, "the reset is a window update frame");
    assert_eq!(u16::from_be_bytes(reset[2..4].try_into().expect("two flag bytes")), FLAG_RST);
    assert_eq!(u32::from_be_bytes(reset[4..8].try_into().expect("four stream id bytes")), id);

    let err = stream.write_all(&vec![0u8; 1 << 20]).await.expect_err("a reset stream refuses writes");
    assert!(err.to_string().contains("stream reset"), "expected a reset error, got: {err}");
}
