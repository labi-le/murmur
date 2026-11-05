use std::io;
use std::sync::Arc;

use futures::future::BoxFuture;
use tokio_util::sync::CancellationToken;

use crate::congestion::{set_brutal_congestion_controller, set_congestion_controller};
use crate::extension_brutal::{
    read_brutal_negotiation_response, write_brutal_negotiation_request, BRUTAL_NEGOTIATION_TIMEOUT,
};
use crate::packet::new_association;
use crate::protocol::{
    metadata_addr, unspecified_addr, write_request, COMMAND_ASSOCIATE_DATAGRAM, COMMAND_ASSOCIATE_STREAM,
    COMMAND_CONNECT,
};
use crate::state::{new_conn_state, ConnState, UdpMode};
use crate::stream_conn::new_quic_stream_conn;
use murmur_common_net::io::{close_stream, StreamAsOldConn};
use murmur_constant::metadata::Metadata;
use murmur_quic::jls::Conn as JlsConn;
use murmur_std_compat::net::{Addr, Conn as NetConn, PacketConn};

fn err_closed() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "use of closed network connection")
}

pub type DialFunc =
    Arc<dyn Fn(CancellationToken) -> BoxFuture<'static, anyhow::Result<Arc<dyn JlsConn>>> + Send + Sync>;

pub struct ClientOption {
    pub dial: Option<DialFunc>,
    pub udp_over_stream: bool,
    pub congestion_controller: String,
    pub send_bps: u64,
    pub receive_bps: u64,
    pub cwnd: i32,
    pub bbr_profile: String,
}

impl std::fmt::Debug for ClientOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientOption")
            .field("dial", &self.dial.is_some())
            .field("udp_over_stream", &self.udp_over_stream)
            .field("congestion_controller", &self.congestion_controller)
            .field("send_bps", &self.send_bps)
            .field("receive_bps", &self.receive_bps)
            .field("cwnd", &self.cwnd)
            .field("bbr_profile", &self.bbr_profile)
            .finish()
    }
}

impl ClientOption {
    const fn brutal_enabled(&self) -> bool {
        self.send_bps > 0 || self.receive_bps > 0
    }
}

struct ClientInner {
    conn: Option<Arc<ConnState>>,
    closed: bool,
}

pub struct Client {
    option: Option<Arc<ClientOption>>,
    inner: tokio::sync::Mutex<ClientInner>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client").field("option", &self.option).finish_non_exhaustive()
    }
}

#[must_use]
pub fn new_client(option: Option<Arc<ClientOption>>) -> Client {
    Client { option, inner: tokio::sync::Mutex::new(ClientInner { conn: None, closed: false }) }
}

/// Aborts the timeout task that would otherwise cancel `ctx` after the Brutal negotiation
/// timeout.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl Client {
    async fn get_conn(&self, ctx: &CancellationToken) -> anyhow::Result<Arc<ConnState>> {
        let mut inner = self.inner.lock().await;
        if inner.closed {
            return Err(err_closed().into());
        }
        if let Some(conn) = &inner.conn {
            if !conn.closed() {
                return Ok(Arc::clone(conn));
            }
        }
        let Some(option) = &self.option else {
            return Err(anyhow::anyhow!("shadowquic: dial function is nil"));
        };
        let Some(dial) = option.dial.as_ref() else {
            return Err(anyhow::anyhow!("shadowquic: dial function is nil"));
        };
        let option = Arc::clone(option);

        let quic_conn = dial(ctx.clone()).await?;
        set_congestion_controller(&*quic_conn, &option.congestion_controller, option.cwnd, &option.bbr_profile);
        let state = new_conn_state(quic_conn);
        inner.conn = Some(Arc::clone(&state));
        drop(inner);

        if option.brutal_enabled() {
            // Brutal is an optional upgrade; keep the connection usable while it is negotiated.
            tokio::spawn(Self::negotiate_brutal(option, Arc::clone(&state)));
        }
        Ok(state)
    }

    async fn negotiate_brutal(option: Arc<ClientOption>, state: Arc<ConnState>) {
        let ctx = state.ctx.child_token();
        let timeout_ctx = ctx.clone();
        let timeout_task = tokio::spawn(async move {
            // cancel-safe: the guard aborts this timer when the negotiation ends, so the wake it
            // skips is the one nobody was waiting for any more.
            tokio::time::sleep(BRUTAL_NEGOTIATION_TIMEOUT).await;
            timeout_ctx.cancel();
        });
        let _abort_timeout = AbortOnDrop(timeout_task);

        let Ok(mut stream) = state.quic_conn.open_stream_sync(&ctx).await else {
            return;
        };
        let _ = stream.set_deadline(Some(tokio::time::Instant::now() + BRUTAL_NEGOTIATION_TIMEOUT));

        if write_brutal_negotiation_request(&mut stream, option.receive_bps).await.is_err() {
            let _ = stream.close();
            return;
        }
        let Ok((rx, rx_auto)) = read_brutal_negotiation_response(&mut stream).await else {
            let _ = stream.close();
            return;
        };
        let mut actual_tx = rx;
        if actual_tx == 0 || actual_tx > option.send_bps {
            actual_tx = option.send_bps;
        }
        if !rx_auto && actual_tx > 0 {
            set_brutal_congestion_controller(&*state.quic_conn, actual_tx);
        } else {
            set_congestion_controller(&*state.quic_conn, "bbr", option.cwnd, &option.bbr_profile);
        }
        let _ = stream.close();
    }

    pub async fn dial_context(&self, ctx: &CancellationToken, metadata: &Metadata) -> anyhow::Result<Box<dyn NetConn>> {
        let state = self.get_conn(ctx).await?;
        let target = metadata_addr(metadata)?;
        let stream = state.quic_conn.open_stream_sync(ctx).await?;
        let l_addr: Arc<dyn Addr> = Arc::from(state.quic_conn.local_addr());
        let r_addr: Arc<dyn Addr> = Arc::from(state.quic_conn.remote_addr());
        let mut conn = new_quic_stream_conn(stream, l_addr, r_addr, None);
        if let Err(err) = write_request(&mut *conn, COMMAND_CONNECT, &target).await {
            let _ = close_stream(&*conn);
            return Err(err.into());
        }
        Ok(Box::new(StreamAsOldConn::new(conn)))
    }

    pub async fn listen_packet(
        &self,
        ctx: &CancellationToken,
        _metadata: &Metadata,
    ) -> anyhow::Result<Box<dyn PacketConn>> {
        let state = self.get_conn(ctx).await?;
        let mut stream = state.quic_conn.open_stream_sync(ctx).await?;
        let (mode, command) = match &self.option {
            Some(option) if option.udp_over_stream => (UdpMode::Stream, COMMAND_ASSOCIATE_STREAM),
            _ => (UdpMode::Datagram, COMMAND_ASSOCIATE_DATAGRAM),
        };
        if let Err(err) = write_request(&mut stream, command, &unspecified_addr()).await {
            let _ = stream.close();
            return Err(err.into());
        }
        Ok(Box::new(crate::packet::AssociationHandle(new_association(state, stream, mode))))
    }

    pub async fn close(&self) -> io::Result<()> {
        let mut inner = self.inner.lock().await;
        inner.closed = true;
        let result = inner.conn.as_ref().map(|conn| conn.close_with_error(0, "client closed"));
        drop(inner);
        result.unwrap_or(Ok(()))
    }
}
