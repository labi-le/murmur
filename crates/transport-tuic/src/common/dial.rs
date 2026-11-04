use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use futures::future::BoxFuture;
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;

use murmur_component::dialer::bind::parse_addr_port;
use murmur_component::dialer::dialer::new_dialer;
use murmur_component::dialer::options::{with_net_dialer, with_options, NetDialerFunc, Option as DialerOption};
use murmur_std_compat::net::{Addr, Conn as NetConn, PacketConn};

use crate::quic::{self, ClientTls, CongestionOption, Conn as QuicConn};

#[async_trait]
pub trait PacketDialer: Send + Sync {
    async fn listen_packet(
        &self,
        ctx: &CancellationToken,
        network: &str,
        address: &str,
        r_addr_port: SocketAddr,
    ) -> anyhow::Result<Box<dyn PacketConn>>;
}

pub async fn dial_quic(
    ctx: &CancellationToken,
    address: &str,
    opts: Vec<DialerOption>,
    p_dialer: Arc<dyn PacketDialer>,
    remote: SocketAddr,
    tls: Arc<ClientTls>,
    conf: Arc<quic::Config>,
    congestion: CongestionOption,
) -> anyhow::Result<(Arc<dyn PacketConn>, Arc<dyn QuicConn>)> {
    let created: Arc<Mutex<Option<(Arc<dyn PacketConn>, Arc<dyn QuicConn>)>>> = Arc::new(Mutex::new(None));

    let net_dialer = {
        let created = Arc::clone(&created);
        NetDialerFunc::new(
            move |ctx: CancellationToken,
                  _network: String,
                  address: String|
                  -> BoxFuture<'static, anyhow::Result<Box<dyn murmur_common_net::io::Stream>>> {
                let created = Arc::clone(&created);
                let p_dialer = Arc::clone(&p_dialer);
                let tls = Arc::clone(&tls);
                let conf = Arc::clone(&conf);
                let congestion = congestion.clone();
                Box::pin(async move {
                    // the dialer will resolve the domain to ip
                    let addr_port =
                        parse_addr_port(&address).ok_or_else(|| anyhow::anyhow!("invalid address: {address}"))?;
                    let packet_conn: Arc<dyn PacketConn> =
                        Arc::from(p_dialer.listen_packet(&ctx, "udp", "", addr_port).await?);

                    let quic_conn = match quic::dial(
                        &ctx,
                        Arc::clone(&packet_conn),
                        remote,
                        tls,
                        conf.as_ref().clone(),
                        congestion,
                    )
                    .await
                    {
                        Ok(quic_conn) => quic_conn,
                        Err(err) => {
                            let _ = packet_conn.close();
                            return Err(err);
                        }
                    };

                    *created.lock() = Some((Arc::clone(&packet_conn), Arc::clone(&quic_conn)));
                    let nc: Box<dyn NetConn> = Box::new(QuicNetConn { conn: quic_conn, pc: packet_conn });
                    let stream: Box<dyn murmur_common_net::io::Stream> =
                        Box::new(murmur_common_net::io::OldConnAsStream(nc));
                    Ok(stream)
                })
            },
        )
    };

    let d = new_dialer(vec![with_options(opts), with_net_dialer(Arc::new(net_dialer))]);
    let _ = d.dial_context(ctx, "udp", address).await?;

    let (pc, quic_conn) = created.lock().take().ok_or_else(|| anyhow::anyhow!("quic: dialer returned no conn"))?;
    Ok((pc, quic_conn))
}

pub struct QuicNetConn {
    conn: Arc<dyn QuicConn>,
    pc: Arc<dyn PacketConn>,
}

impl std::fmt::Debug for QuicNetConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicNetConn")
            .field("local_addr", &self.conn.local_addr())
            .field("remote_addr", &self.conn.remote_addr())
            .finish_non_exhaustive()
    }
}

impl QuicNetConn {
    pub fn new(conn: Arc<dyn QuicConn>, pc: Arc<dyn PacketConn>) -> Self {
        Self { conn, pc }
    }
}

/// Only reachable if the connection itself is driven as a byte stream, which nothing here does.
fn unsupported(op: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, format!("should not call {op} on quicNetConn"))
}

impl AsyncRead for QuicNetConn {
    fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(unsupported("Read")))
    }
}

impl AsyncWrite for QuicNetConn {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(unsupported("Write")))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl NetConn for QuicNetConn {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        Ok(self.conn.local_addr())
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        Ok(self.conn.remote_addr())
    }

    fn close(&self) -> io::Result<()> {
        let result = self.conn.close_with_error(0, "").map_err(io::Error::other);
        let _ = self.pc.close();
        result
    }

    fn close_read(&self) -> io::Result<()> {
        Ok(())
    }

    fn close_write(&self) -> io::Result<()> {
        Ok(())
    }

    fn set_deadline(&self, _deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        Err(unsupported("SetDeadline"))
    }

    fn set_read_deadline(&self, _deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        Err(unsupported("SetReadDeadline"))
    }

    fn set_write_deadline(&self, _deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        Err(unsupported("SetWriteDeadline"))
    }
}
