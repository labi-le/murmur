// Test code is exempt from the production panic posture: the bans on `unwrap`,
// `expect`, `panic`, indexing and casts exist to keep a long-lived server process
// alive, and a failing test is supposed to abort. Style tiers are exempt for the
// same reason -- the scaffolding around an assertion is not product code.
#![cfg_attr(
    test,
    allow(
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
    )
)]

pub mod auth;
pub mod config;
pub mod conn;
pub mod header;
pub mod listener;
pub mod packet;
pub mod segment;

#[cfg(test)]
mod tests {
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Duration;

    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
    use tokio::net::UdpSocket;
    use tokio::time::Instant;
    use tokio_util::sync::CancellationToken;

    use murmur_common_net::io::StreamAsOldConn;
    use murmur_std_compat::net::{Addr, Conn as NetConn, Listener as NetListener, UdpAddr};

    use super::config::Config;
    use super::conn::{dial, Conn};
    use super::listener::listen;

    #[tokio::test]
    async fn round_trip() {
        let ctx = CancellationToken::new();
        let pc = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listener = listen(&ctx, Box::new(pc), Config::default()).await.unwrap();
        let addr = listener.addr().unwrap();

        let server = async {
            let mut conn = listener.accept().await.unwrap();
            echo(&mut conn, 64 * 1024).await.unwrap();
            let _ = conn.close();
        };
        let client = async {
            let mut conn = dial_client(addr.string(), Config::default()).await;
            conn.set_deadline(Some(Instant::now() + Duration::from_secs(5))).unwrap();

            let payload = vec![b'x'; 64 * 1024];
            conn.write_all(&payload).await.unwrap();
            let mut got = vec![0u8; payload.len()];
            conn.read_exact(&mut got).await.unwrap();
            assert_eq!(payload, got);
            let _ = conn.close();
        };

        let ((), ()) = tokio::join!(server, client);
        let _ = listener.close();
    }

    #[tokio::test]
    async fn full_duplex() {
        let ctx = CancellationToken::new();
        let pc = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listener = listen(&ctx, Box::new(pc), Config::default()).await.unwrap();
        let addr = listener.addr().unwrap();

        let server = async {
            let mut conn = listener.accept().await.unwrap();
            let payload = vec![b's'; 128 * 1024];
            exchange(&mut conn, &payload, b'c').await.unwrap();
            let _ = conn.close();
        };
        let client = async {
            let mut conn = dial_client(addr.string(), Config::default()).await;
            conn.set_deadline(Some(Instant::now() + Duration::from_secs(5))).unwrap();
            let payload = vec![b'c'; 128 * 1024];
            exchange(&mut conn, &payload, b's').await.unwrap();
            let _ = conn.close();
        };

        let ((), ()) = tokio::join!(server, client);
        let _ = listener.close();
    }

    #[tokio::test]
    async fn round_trip_headers() {
        for header in ["srtp", "utp", "wechat-video", "dtls", "wireguard"] {
            let ctx = CancellationToken::new();
            let pc = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let cfg = Config { header: header.to_owned(), ..Config::default() };
            let listener = listen(&ctx, Box::new(pc), cfg.clone()).await.unwrap();
            let addr = listener.addr().unwrap();

            let server = async {
                let mut conn = listener.accept().await.unwrap();
                echo(&mut conn, 32 * 1024).await.unwrap();
                let _ = conn.close();
            };
            let client = async {
                let mut conn = dial_client(addr.string(), cfg).await;
                conn.set_deadline(Some(Instant::now() + Duration::from_secs(5))).unwrap();

                let payload = vec![b'h'; 32 * 1024];
                conn.write_all(&payload).await.unwrap();
                let mut got = vec![0u8; payload.len()];
                conn.read_exact(&mut got).await.unwrap();
                assert_eq!(payload, got);
                let _ = conn.close();
            };

            let ((), ()) = tokio::join!(server, client);
            let _ = listener.close();
        }
    }

    async fn dial_client(addr: String, cfg: Config) -> StreamAsOldConn<Conn> {
        let raw = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        raw.connect(addr).await.unwrap();
        dial(Box::new(UdpConn { socket: raw }), cfg).await.unwrap()
    }

    async fn echo<C: AsyncRead + AsyncWrite + Unpin>(conn: &mut C, len: usize) -> anyhow::Result<()> {
        let mut buf = vec![0u8; len];
        conn.read_exact(&mut buf).await?;
        conn.write_all(&buf).await?;
        Ok(())
    }

    async fn exchange<C: AsyncRead + AsyncWrite + Unpin>(conn: &mut C, payload: &[u8], want: u8) -> anyhow::Result<()> {
        let (mut reader, mut writer) = tokio::io::split(conn);
        let read = async {
            let mut got = vec![0u8; payload.len()];
            reader.read_exact(&mut got).await?;
            require_payload(&got, want)
        };
        let write = async {
            writer.write_all(payload).await?;
            Ok::<(), anyhow::Error>(())
        };
        let (read, write) = tokio::join!(read, write);
        read?;
        write?;
        Ok(())
    }

    fn require_payload(payload: &[u8], want: u8) -> anyhow::Result<()> {
        for (i, got) in payload.iter().enumerate() {
            if *got != want {
                return Err(anyhow::anyhow!("unexpected byte at {i}: got {got:?}, want {want:?}"));
            }
        }
        Ok(())
    }

    struct UdpConn {
        socket: UdpSocket,
    }

    impl AsyncRead for UdpConn {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            self.socket.poll_recv(cx, buf)
        }
    }

    impl AsyncWrite for UdpConn {
        fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            self.socket.poll_send(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl NetConn for UdpConn {
        fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
            let addr = self.socket.local_addr()?;
            Ok(Box::new(UdpAddr::from(addr)))
        }

        fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
            let addr = self.socket.peer_addr()?;
            Ok(Box::new(UdpAddr::from(addr)))
        }

        fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }
}
