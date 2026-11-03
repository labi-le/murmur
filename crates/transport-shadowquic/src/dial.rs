use std::io;
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
use murmur_quic::jls::{Conn, TransportFactory};
use murmur_quic::{Config, TlsConfig};
use murmur_std_compat::net::{Addr, Conn as NetConn, PacketConn, UdpAddr};

#[async_trait]
pub trait PacketDialer: Send + Sync {
    async fn listen_packet(
        &self,
        ctx: &CancellationToken,
        network: &str,
        address: &str,
        r_addr_port: std::net::SocketAddr,
    ) -> anyhow::Result<Box<dyn PacketConn>>;
}

#[derive(Debug, Clone, Default)]
pub struct DialQuicOption {
    pub early: bool,
    pub connection_id_length: i32,
}

///
/// The quic mirror is supplied by the caller (`transport_factory`) rather than
/// built here, so the caller decides which QUIC implementation backs the dial.
pub async fn dial_quic(
    ctx: &CancellationToken,
    address: &str,
    opts: Vec<DialerOption>,
    p_dialer: Arc<dyn PacketDialer>,
    tls_conf: Arc<dyn TlsConfig>,
    conf: Arc<Config>,
    option: DialQuicOption,
    transport_factory: Arc<dyn TransportFactory>,
) -> anyhow::Result<(Arc<dyn PacketConn>, Arc<dyn Conn>)> {
    let created: Arc<Mutex<Option<(Arc<dyn PacketConn>, Arc<dyn Conn>)>>> = Arc::new(Mutex::new(None));

    let net_dialer = {
        let created = Arc::clone(&created);
        NetDialerFunc::new(
            move |ctx: CancellationToken,
                  _network: String,
                  address: String|
                  -> BoxFuture<'static, anyhow::Result<Box<dyn murmur_common_net::io::Stream>>> {
                let created = Arc::clone(&created);
                let p_dialer = Arc::clone(&p_dialer);
                let tls_conf = Arc::clone(&tls_conf);
                let conf = Arc::clone(&conf);
                let transport_factory = Arc::clone(&transport_factory);
                let option = option.clone();
                Box::pin(async move {
                    let addr_port =
                        parse_addr_port(&address).ok_or_else(|| anyhow::anyhow!("invalid address: {address}"))?;
                    let udp_addr = UdpAddr::from(addr_port);
                    let packet_conn: Arc<dyn PacketConn> =
                        Arc::from(p_dialer.listen_packet(&ctx, "udp", "", addr_port).await?);

                    let transport =
                        transport_factory.new_transport(Arc::clone(&packet_conn), option.connection_id_length);
                    transport.set_created_conn(true);
                    transport.set_single_use(true);

                    let quic_conn = if option.early {
                        transport.dial_early(&ctx, &udp_addr, &*tls_conf, &conf).await
                    } else {
                        transport.dial(&ctx, &udp_addr, &*tls_conf, &conf).await
                    };
                    let quic_conn = match quic_conn {
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
    conn: Arc<dyn Conn>,
    pc: Arc<dyn PacketConn>,
}

impl std::fmt::Debug for QuicNetConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicNetConn")
            .field("local_addr", &self.conn.local_addr())
            .field("pc_local_addr", &self.pc.local_addr())
            .finish_non_exhaustive()
    }
}

impl AsyncRead for QuicNetConn {
    fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::other("should not call Read on quicNetConn")))
    }
}

impl AsyncWrite for QuicNetConn {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::Error::other("should not call Write on quicNetConn")))
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
        let err = self.conn.close_with_error(0, "");
        let _ = self.pc.close();
        err
    }

    fn close_read(&self) -> io::Result<()> {
        Ok(())
    }

    fn close_write(&self) -> io::Result<()> {
        Ok(())
    }

    fn set_deadline(&self, _deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        Err(io::Error::other("should not call SetDeadline on quicNetConn"))
    }

    fn set_read_deadline(&self, _deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        Err(io::Error::other("should not call SetReadDeadline on quicNetConn"))
    }

    fn set_write_deadline(&self, _deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        Err(io::Error::other("should not call SetWriteDeadline on quicNetConn"))
    }
}
