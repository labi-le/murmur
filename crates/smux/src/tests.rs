use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use murmur_common_net::io::Stream as NetStream;

use crate::{client, default_config, server, verify_config, Config, Session};

async fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback listener");
    let addr = listener.local_addr().expect("listener local addr");
    let (client_result, accept_result) = tokio::join!(TcpStream::connect(addr), listener.accept());
    let (server_conn, _) = accept_result.expect("accept loopback");
    (client_result.expect("connect loopback"), server_conn)
}

fn boxed(stream: TcpStream) -> Box<dyn NetStream> {
    Box::new(stream)
}

/// Caps every vectored write at `CHUNK` bytes, so the writer loop has to drain an
/// iovec across several `poll_write_vectored` calls instead of landing it in one.
struct ShortWriteStream {
    inner: TcpStream,
}

const CHUNK: usize = 64;

impl AsyncWrite for ShortWriteStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, &buf[..buf.len().min(CHUNK)])
    }

    fn poll_write_vectored(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let limit: usize = bufs.iter().take_while(|b| !b.is_empty()).map(|b| b.len()).sum();
        if limit == 0 {
            return std::task::Poll::Ready(Ok(0));
        }
        let capped: Vec<std::io::IoSlice<'_>> = bufs.iter().take_while(|b| !b.is_empty()).copied().collect();
        let this = self.get_mut();
        let want = limit.min(CHUNK);
        let mut written = 0;
        for buf in &capped {
            if written >= want {
                break;
            }
            let take = (want - written).min(buf.len());
            match std::pin::Pin::new(&mut this.inner).poll_write(cx, &buf[..take]) {
                std::task::Poll::Pending => return std::task::Poll::Pending,
                std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                std::task::Poll::Ready(Ok(0)) => break,
                std::task::Poll::Ready(Ok(n)) => written += n,
            }
        }
        std::task::Poll::Ready(Ok(written))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        true
    }
}

impl AsyncRead for ShortWriteStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl NetStream for ShortWriteStream {
    fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }

    fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.inner.peer_addr()
    }
}

#[tokio::test]
async fn vectored_writer_drains_frame_across_short_writes() {
    let (client_tcp, server_tcp) = tcp_pair().await;
    let mut config = default_config();
    config.max_frame_size = 1024;

    let client_session = client(Box::new(ShortWriteStream { inner: client_tcp }), &config).expect("client session");
    let server_session = server(boxed(server_tcp), &config).expect("server session");

    let payload: Vec<u8> = (0..config.max_frame_size as usize * 2 + 5).map(|i| i as u8).collect();
    let expected = payload.clone();

    let client_task = tokio::spawn(async move {
        let mut st = client_session.open_stream().await.expect("open stream");
        tokio::time::timeout(Duration::from_secs(5), st.write_all(&payload))
            .await
            .expect("write timeout")
            .expect("write");
        st.shutdown().await.expect("close");
    });

    let server_task = tokio::spawn(async move {
        let mut st = server_session.accept_stream(None).await.expect("accept stream");
        let mut received = vec![0u8; expected.len()];
        tokio::time::timeout(Duration::from_secs(5), st.read_exact(&mut received))
            .await
            .expect("read timeout")
            .expect("read");
        assert_eq!(received, expected);
    });

    client_task.await.expect("client task");
    server_task.await.expect("server task");
}

#[tokio::test]
async fn round_trip_larger_than_max_frame_size() {
    let (client_tcp, server_tcp) = tcp_pair().await;
    let mut config = default_config();
    config.max_frame_size = 4096;

    let client_session = client(boxed(client_tcp), &config).expect("client session");
    let server_session = server(boxed(server_tcp), &config).expect("server session");

    let client_task = tokio::spawn(async move {
        let mut st = client_session.open_stream().await.expect("open stream");
        let payload = vec![0xABu8; config.max_frame_size as usize * 3 + 17];
        tokio::time::timeout(Duration::from_secs(5), st.write_all(&payload))
            .await
            .expect("write timeout")
            .expect("write");

        let mut reply = vec![0u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(5), st.read_exact(&mut reply))
            .await
            .expect("read timeout")
            .expect("read");
        assert_eq!(reply, payload);
    });

    let server_task = tokio::spawn(async move {
        let mut st = tokio::time::timeout(Duration::from_secs(5), server_session.accept_stream(None))
            .await
            .expect("accept timeout")
            .expect("accept stream");

        let mut received = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            let n = tokio::time::timeout(Duration::from_secs(5), st.read(&mut chunk))
                .await
                .expect("read timeout")
                .expect("read");
            if n == 0 {
                break;
            }
            received.extend_from_slice(&chunk[..n]);
            if received.len() >= 4096 * 3 + 17 {
                break;
            }
        }
        tokio::time::timeout(Duration::from_secs(5), st.write_all(&received))
            .await
            .expect("write timeout")
            .expect("write");
    });

    client_task.await.expect("client task");
    server_task.await.expect("server task");
}

#[tokio::test]
async fn concurrent_streams_do_not_cross_talk() {
    const STREAMS: usize = 8;

    let (client_tcp, server_tcp) = tcp_pair().await;
    let config = default_config();

    let client_session = client(boxed(client_tcp), &config).expect("client session");
    let server_session: std::sync::Arc<dyn Session> =
        std::sync::Arc::from(server(boxed(server_tcp), &config).expect("server session"));

    let mut echo_tasks = Vec::new();
    for _ in 0..STREAMS {
        let server_session = std::sync::Arc::clone(&server_session);
        echo_tasks.push(tokio::spawn(async move {
            let mut st = tokio::time::timeout(Duration::from_secs(5), server_session.accept_stream(None))
                .await
                .expect("accept timeout")
                .expect("accept stream");
            let mut buf = vec![0u8; 4096];
            loop {
                let n = tokio::time::timeout(Duration::from_secs(5), st.read(&mut buf))
                    .await
                    .expect("read timeout")
                    .expect("read");
                if n == 0 {
                    break;
                }
                tokio::time::timeout(Duration::from_secs(5), st.write_all(&buf[..n]))
                    .await
                    .expect("write timeout")
                    .expect("write");
            }
        }));
    }

    let mut client_tasks = Vec::new();
    for i in 0..STREAMS {
        let client_session = client_session.as_ref();
        let mut st = client_session.open_stream().await.expect("open stream");
        client_tasks.push(tokio::spawn(async move {
            let payload = vec![i as u8; 4096 + i];
            tokio::time::timeout(Duration::from_secs(5), st.write_all(&payload))
                .await
                .expect("write timeout")
                .expect("write");

            let mut reply = vec![0u8; payload.len()];
            tokio::time::timeout(Duration::from_secs(5), st.read_exact(&mut reply))
                .await
                .expect("read timeout")
                .expect("read");
            assert_eq!(reply, payload, "stream {i} received foreign data");
            tokio::time::timeout(Duration::from_secs(5), st.shutdown())
                .await
                .expect("shutdown timeout")
                .expect("shutdown");
        }));
    }

    for task in client_tasks {
        task.await.expect("client stream task");
    }
    for task in echo_tasks {
        let _ = task.await;
    }
}

#[tokio::test]
async fn keepalive_timeout_closes_unresponsive_session() {
    let (client_tcp, mut server_tcp) = tcp_pair().await;

    tokio::spawn(async move {
        let mut sink = [0u8; 256];
        loop {
            match server_tcp.read(&mut sink).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
        }
    });

    let mut config = default_config();
    config.keep_alive_interval = Duration::from_millis(30);
    config.keep_alive_timeout = Duration::from_millis(100);

    let session = client(boxed(client_tcp), &config).expect("client session");

    let closed = tokio::time::timeout(Duration::from_secs(2), async {
        while !session.is_closed() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(closed.is_ok(), "session should close once keep-alive timeout elapses on an unresponsive peer");
}

#[test]
fn verify_config_rejects_bad_version() {
    let mut config = default_config();
    config.version = 3;
    assert!(verify_config(&config).is_err());
}

#[test]
fn verify_config_rejects_zero_keepalive_interval() {
    let mut config = default_config();
    config.keep_alive_interval = Duration::ZERO;
    assert!(verify_config(&config).is_err());
}

#[test]
fn verify_config_rejects_timeout_shorter_than_interval() {
    let mut config = default_config();
    config.keep_alive_interval = Duration::from_secs(10);
    config.keep_alive_timeout = Duration::from_secs(5);
    assert!(verify_config(&config).is_err());
}

#[test]
fn verify_config_accepts_disabled_keepalive_with_zero_interval() {
    let mut config = default_config();
    config.keep_alive_disabled = true;
    config.keep_alive_interval = Duration::ZERO;
    assert!(verify_config(&config).is_ok());
}

#[test]
fn verify_config_rejects_non_positive_max_frame_size() {
    let mut config = default_config();
    config.max_frame_size = 0;
    assert!(verify_config(&config).is_err());
}

#[test]
fn verify_config_rejects_max_frame_size_over_65535() {
    let mut config = default_config();
    config.max_frame_size = 65536;
    assert!(verify_config(&config).is_err());
}

#[test]
fn verify_config_rejects_non_positive_max_receive_buffer() {
    let mut config = default_config();
    config.max_receive_buffer = 0;
    assert!(verify_config(&config).is_err());
}

#[test]
fn verify_config_rejects_max_receive_buffer_over_i32_max() {
    let mut config = default_config();
    config.max_receive_buffer = i64::from(i32::MAX) + 1;
    assert!(verify_config(&config).is_err());
}

#[test]
fn verify_config_rejects_non_positive_max_stream_buffer() {
    let mut config = default_config();
    config.max_stream_buffer = 0;
    assert!(verify_config(&config).is_err());
}

#[test]
fn verify_config_rejects_max_stream_buffer_over_max_receive_buffer() {
    let mut config = default_config();
    config.max_stream_buffer = config.max_receive_buffer + 1;
    assert!(verify_config(&config).is_err());
}

#[test]
fn verify_config_accepts_default() {
    let config: Config = default_config();
    assert!(verify_config(&config).is_ok());
}
