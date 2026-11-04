use std::io;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use crate::brutal::{
    read_brutal_response, set_brutal_options, write_brutal_request, RawSocket, BRUTAL_EXCHANGE_DOMAIN,
};
use crate::client_conn::{new_client_conn, new_client_packet_conn};
use crate::padding::new_padding_conn;
use crate::protocol::{self, Request, PROTOCOL_H2MUX, PROTOCOL_SMUX, PROTOCOL_YAMUX, VERSION_0, VERSION_1};
use crate::protocol_conn::new_protocol_conn;
use crate::session::{new_client_session, MuxConn, Session};
use murmur_log::warnln;
use murmur_sing::metadata::Socksaddr;
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;

/// The dialer surface, restricted to the one method the mux client actually calls.
///
/// Callers adapt their own dialer, e.g. `component-proxydialer`'s `SingDialer`, rather than this
/// crate depending on any particular app-level dialer.
#[async_trait]
pub trait Dialer: Send + Sync {
    /// Dials the carrier and returns the raw-socket handle the brutal options need; the
    /// carrier is type-erased by the time it reaches the mux session, so the socket has to travel
    /// alongside it. `ctx` is the caller's context, which is handed to the
    /// carrier dial and must not be replaced with a fresh token.
    async fn dial_context(&self, ctx: &CancellationToken, destination: &Socksaddr) -> io::Result<Dialed>;
}

/// A freshly dialled mux carrier plus, when it has one, the OS socket underneath it.
pub struct Dialed {
    pub conn: Box<dyn MuxConn>,
    pub socket: RawSocket,
}

impl core::fmt::Debug for Dialed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Dialed").field("socket", &self.socket).finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Default)]
pub struct BrutalOptions {
    pub enabled: bool,
    pub send_bps: u64,
    pub receive_bps: u64,
}

pub struct Options {
    pub dialer: Arc<dyn Dialer>,
    pub protocol: u8,
    pub max_connections: usize,
    pub min_streams: usize,
    pub max_streams: usize,
    pub padding: bool,
    pub tcp_timeout: Duration,
    pub brutal: BrutalOptions,
}

impl core::fmt::Debug for Options {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Options")
            .field("protocol", &self.protocol)
            .field("max_connections", &self.max_connections)
            .field("min_streams", &self.min_streams)
            .field("max_streams", &self.max_streams)
            .field("padding", &self.padding)
            .field("tcp_timeout", &self.tcp_timeout)
            .field("brutal", &self.brutal)
            .finish_non_exhaustive()
    }
}

pub struct Client {
    dialer: Arc<dyn Dialer>,
    protocol: u8,
    max_connections: usize,
    min_streams: usize,
    max_streams: usize,
    padding: bool,
    tcp_timeout: Duration,
    brutal: BrutalOptions,
    connections: tokio::sync::Mutex<Vec<Arc<dyn Session>>>,
}

impl core::fmt::Debug for Client {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Client")
            .field("protocol", &self.protocol)
            .field("max_connections", &self.max_connections)
            .field("min_streams", &self.min_streams)
            .field("max_streams", &self.max_streams)
            .field("padding", &self.padding)
            .field("tcp_timeout", &self.tcp_timeout)
            .field("brutal", &self.brutal)
            .finish_non_exhaustive()
    }
}

pub fn new_client(options: Options) -> io::Result<Client> {
    match options.protocol {
        PROTOCOL_SMUX | PROTOCOL_YAMUX | PROTOCOL_H2MUX => {}
        other => return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("unknown protocol: {other}"))),
    }
    let min_streams = if options.max_streams == 0 && options.max_connections == 0 { 8 } else { options.min_streams };
    let tcp_timeout = if options.tcp_timeout.is_zero() { Duration::from_secs(5) } else { options.tcp_timeout };
    Ok(Client {
        dialer: options.dialer,
        protocol: options.protocol,
        max_connections: options.max_connections,
        min_streams,
        max_streams: options.max_streams,
        padding: options.padding,
        tcp_timeout,
        brutal: options.brutal,
        connections: tokio::sync::Mutex::new(Vec::new()),
    })
}

impl Client {
    pub async fn dial_context(
        &self,
        ctx: &CancellationToken,
        network: &str,
        destination: Socksaddr,
    ) -> io::Result<Box<dyn MuxConn>> {
        match network {
            "tcp" => {
                let stream = self.open_stream(ctx).await?;
                Ok(Box::new(new_client_conn(stream, destination)))
            }
            "udp" => {
                let stream = self.open_stream(ctx).await?;
                Ok(Box::new(new_client_packet_conn(stream, destination, false)))
            }
            other => Err(io::Error::new(io::ErrorKind::InvalidInput, format!("unknown network: {other}"))),
        }
    }

    pub async fn listen_packet(
        &self,
        ctx: &CancellationToken,
        destination: Socksaddr,
    ) -> io::Result<Box<dyn murmur_sing::network::PacketConn>> {
        let stream = self.open_stream(ctx).await?;
        Ok(Box::new(new_client_packet_conn(stream, destination, true)))
    }

    pub async fn reset(&self) {
        let mut connections = self.connections.lock().await;
        for session in connections.drain(..) {
            let _ = session.close().await;
        }
    }

    pub async fn close(&self) -> io::Result<()> {
        self.reset().await;
        Ok(())
    }

    async fn open_stream(&self, ctx: &CancellationToken) -> io::Result<Box<dyn crate::session::MuxStream>> {
        let mut last_err: Option<io::Error> = None;
        for _ in 0..2 {
            let session = match self.offer(ctx).await {
                Ok(session) => session,
                Err(err) => {
                    last_err = Some(err);
                    continue;
                }
            };
            match session.open(self.tcp_timeout).await {
                Ok(stream) => return Ok(crate::error::wrap_stream(stream)),
                Err(err) => {
                    last_err = Some(err);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| io::Error::other("sing-mux: failed to open a stream")))
    }

    async fn offer(&self, ctx: &CancellationToken) -> io::Result<Arc<dyn Session>> {
        let mut connections = self.connections.lock().await;
        let mut live = Vec::with_capacity(connections.len());
        for session in connections.drain(..) {
            if session.is_closed() {
                let _ = session.close().await;
            } else {
                live.push(session);
            }
        }
        *connections = live;

        if self.brutal.enabled {
            if let Some(session) = connections.first() {
                return Ok(Arc::clone(session));
            }
            return self.offer_new(ctx, &mut connections).await;
        }

        let candidate = connections
            .iter()
            .filter(|session| session.can_take_new_request())
            .min_by_key(|session| session.num_streams())
            .cloned();
        let Some(session) = candidate else {
            return self.offer_new(ctx, &mut connections).await;
        };
        let num_streams = session.num_streams();
        if num_streams == 0 {
            return Ok(session);
        }
        if self.max_connections > 0 {
            if connections.len() >= self.max_connections || num_streams < self.min_streams {
                return Ok(session);
            }
        } else if self.max_streams > 0 && num_streams < self.max_streams {
            return Ok(session);
        }
        self.offer_new(ctx, &mut connections).await
    }

    async fn offer_new(
        &self,
        ctx: &CancellationToken,
        connections: &mut Vec<Arc<dyn Session>>,
    ) -> io::Result<Arc<dyn Session>> {
        let destination = protocol::destination();
        let dialed = tokio::time::timeout(self.tcp_timeout, self.dialer.dial_context(ctx, &destination))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "sing-mux: dial timed out"))??;
        let Dialed { conn, socket } = dialed;
        let version = if self.padding { VERSION_1 } else { VERSION_0 };
        let conn = new_protocol_conn(conn, Request { version, protocol: self.protocol, padding: self.padding });
        let conn: Box<dyn MuxConn> = if self.padding { new_padding_conn(conn) } else { conn };
        let session = new_client_session(conn, self.protocol).await?;
        if self.brutal.enabled {
            if let Err(err) = self.brutal_exchange(&session, socket).await {
                let _ = session.close().await;
                return Err(err);
            }
        }
        connections.push(Arc::clone(&session));
        Ok(session)
    }

    /// Exchanges brutal-mode options. A failed option set is only logged and the session
    /// kept, so a missing kernel module or a carrier that is not a plain socket degrades to
    /// unbrutaled traffic instead of dropping the connection.
    async fn brutal_exchange(&self, session: &Arc<dyn Session>, socket: RawSocket) -> io::Result<()> {
        let stream = session.open(self.tcp_timeout).await?;
        let stream = crate::error::wrap_stream(stream);
        let mut conn = new_client_conn(stream, Socksaddr::fqdn(BRUTAL_EXCHANGE_DOMAIN, 0));
        write_brutal_request(&mut conn, self.brutal.receive_bps).await?;
        let server_receive_bps = read_brutal_response(&mut conn).await?;
        let _ = conn.shutdown().await;
        let send_bps = self.brutal.send_bps.min(server_receive_bps);
        if let Err(err) = set_brutal_options(socket, send_bps) {
            warnln!("sing-mux: failed to enable TCP Brutal at client: {err}");
        }
        Ok(())
    }
}
