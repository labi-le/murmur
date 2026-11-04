//! A deliberately minimal, private smux implementation scoped to the version-1 protocol: frame
//! shape (`frame.rs`), session-level recv/send tasks and receive token bucket (`session.rs`),
//! and per-stream `AsyncRead`/`AsyncWrite` with half-close (`stream.rs`).
//!
//! A separate, general-purpose smux crate is being built independently; once it lands, this
//! module is meant to be deleted and replaced with a dependency on that crate.

mod frame;
mod session;
mod stream;

pub(crate) use session::{client_session, server_session};

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::session::Session;

    async fn pair() -> (impl Session, impl Session) {
        let (client_conn, server_conn) = tokio::io::duplex(64 * 1024);
        let client = super::client_session(Box::new(client_conn)).await.unwrap();
        let server = super::server_session(Box::new(server_conn)).await.unwrap();
        (client, server)
    }

    #[tokio::test]
    async fn receive_window_blocks_the_writer_until_the_reader_drains() {
        const TOTAL: usize = 8 << 20;
        const CHUNK: usize = 1 << 20;
        let (client, server) = pair().await;

        // Twice the receive window, so both writes below stall mid-frame and only finish because
        // the opposite side keeps consuming.
        let writer = tokio::spawn(async move {
            let mut stream = client.open(Duration::from_secs(5)).await.unwrap();
            stream.write_all(&vec![7u8; TOTAL]).await.unwrap();
            (client, stream)
        });

        let mut server_stream = server.accept().await.unwrap();
        let mut received = Vec::new();
        while received.len() < TOTAL {
            let mut buf = vec![0u8; CHUNK.min(TOTAL - received.len())];
            tokio::time::timeout(Duration::from_secs(10), server_stream.read_exact(&mut buf))
                .await
                .expect("server read within 10s")
                .expect("server read");
            assert!(buf.iter().all(|&b| b == 7));
            received.extend_from_slice(&buf);
        }
        let (client, mut client_stream) = writer.await.expect("writer task");
        assert_eq!(received.len(), TOTAL);
        assert_eq!(client.num_streams(), 1);

        let echoer = tokio::spawn(async move {
            server_stream.write_all(&received).await.unwrap();
            server_stream
        });
        let mut echoed = Vec::new();
        while echoed.len() < TOTAL {
            let mut buf = vec![0u8; CHUNK.min(TOTAL - echoed.len())];
            tokio::time::timeout(Duration::from_secs(10), client_stream.read_exact(&mut buf))
                .await
                .expect("client read within 10s")
                .expect("client read");
            echoed.extend_from_slice(&buf);
        }
        let _server_stream = echoer.await.expect("echo task");
        assert_eq!(echoed.len(), TOTAL);
    }

    #[tokio::test]
    async fn concurrent_streams_keep_their_own_sequences() {
        const STREAMS: usize = 4;
        const PAYLOAD: usize = 1 << 20;
        let (client, server) = pair().await;

        let mut client_streams = Vec::new();
        let mut server_streams = Vec::new();
        for _ in 0..STREAMS {
            client_streams.push(client.open(Duration::from_secs(5)).await.unwrap());
            server_streams.push(server.accept().await.unwrap());
        }
        assert_eq!(client.num_streams(), STREAMS);
        assert_eq!(server.num_streams(), STREAMS);

        for (i, (client_stream, server_stream)) in client_streams.iter_mut().zip(server_streams.iter_mut()).enumerate()
        {
            let tag = i as u8;
            client_stream.write_all(&vec![tag; PAYLOAD]).await.unwrap();
            let mut buf = vec![0u8; PAYLOAD];
            server_stream.read_exact(&mut buf).await.unwrap();
            assert!(buf.iter().all(|&b| b == tag), "stream {i} received another stream's bytes");
            server_stream.write_all(&buf).await.unwrap();
            client_stream.read_exact(&mut buf).await.unwrap();
            assert!(buf.iter().all(|&b| b == tag), "stream {i} got another stream's echo");
        }

        assert_eq!(client.num_streams(), STREAMS);
        assert_eq!(server.num_streams(), STREAMS);
    }

    #[tokio::test]
    async fn half_close_lets_peer_read_eof_and_still_write_back() {
        let (client, server) = pair().await;

        let mut client_stream = client.open(Duration::from_secs(5)).await.unwrap();
        let mut server_stream = server.accept().await.unwrap();

        client_stream.write_all(b"hello").await.unwrap();
        client_stream.shutdown().await.unwrap();

        let mut buf = Vec::new();
        server_stream.read_to_end(&mut buf).await.unwrap();
        assert_eq!(buf, b"hello");

        server_stream.write_all(b"still alive").await.unwrap();
        let mut ack = vec![0u8; b"still alive".len()];
        client_stream.read_exact(&mut ack).await.unwrap();
        assert_eq!(ack, b"still alive");
    }

    #[tokio::test]
    async fn session_close_unblocks_pending_accept_and_reads() {
        let (client, server) = pair().await;

        let mut client_stream = client.open(Duration::from_secs(5)).await.unwrap();

        let _server_stream = server.accept().await.unwrap();
        let accept_task = tokio::spawn(async move { server.accept().await.is_err() });

        tokio::time::sleep(Duration::from_millis(50)).await;
        client.close().await.unwrap();
        assert!(client.is_closed());

        let mut buf = [0u8; 1];
        let n = client_stream.read(&mut buf).await.unwrap();
        assert_eq!(n, 0);

        let unblocked = tokio::time::timeout(Duration::from_secs(5), accept_task).await.expect("accept must not hang");
        assert!(unblocked.unwrap(), "pending accept must observe the peer session closing");
    }
}
