use std::net::SocketAddr;
use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use crate::cipher;
use crate::io::{ClientDialer, SystemDialer};
use crate::model::{AddrSpec, ModelError, Request, Response, CMD_CONNECT, CMD_UDP_ASSOCIATE, REPLY_SUCCESS};
use crate::mux::ClientMux;
use crate::session::{self, SessionStream, Transport};
use crate::trafficpattern::{self, Config, PatternError};

#[derive(thiserror::Error, Debug)]
pub enum ClientError {
    #[error("underlay error: {0}")]
    Underlay(#[from] crate::underlay::UnderlayError),
    #[error("session error: {0}")]
    Session(#[from] session::SessionError),
    #[error("model error: {0}")]
    Model(#[from] ModelError),
    #[error("server rejected the request with reply code {0}")]
    Rejected(u8),
    #[error("invalid multiplexing level: {0}")]
    InvalidMultiplexing(String),
    #[error("invalid handshake mode: {0}")]
    InvalidHandshakeMode(String),
    #[error("traffic pattern error: {0}")]
    TrafficPattern(#[from] PatternError),
}

pub type Result<T, E = ClientError> = std::result::Result<T, E>;

pub use crate::io::{AsyncReadWrite, Stream};

/// The multiplexing level, matching the wire's enum names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum MultiplexLevel {
    /// `MULTIPLEXING_DEFAULT` (0) and the unset config string both leave the multiplex factor
    /// at its `1` initializer, so the default multiplexes.
    #[default]
    Default,
    /// `MULTIPLEXING_OFF` (1) is the only level that zeroes the factor.
    Off,
    Low,
    Middle,
    High,
}

impl MultiplexLevel {
    #[must_use]
    pub fn factor(self) -> u32 {
        match self {
            Self::Default | Self::Low => 1,
            Self::Off => 0,
            Self::Middle => 2,
            Self::High => 3,
        }
    }

    /// The config-string lookup.
    pub fn from_config(value: &str) -> Result<Self> {
        match value {
            "MULTIPLEXING_DEFAULT" => Ok(Self::Default),
            "MULTIPLEXING_OFF" => Ok(Self::Off),
            "MULTIPLEXING_LOW" => Ok(Self::Low),
            "MULTIPLEXING_MIDDLE" => Ok(Self::Middle),
            "MULTIPLEXING_HIGH" => Ok(Self::High),
            other => Err(ClientError::InvalidMultiplexing(other.to_owned())),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum HandshakeMode {
    #[default]
    Standard,
    NoWait,
}

impl HandshakeMode {
    /// The config-string lookup.
    pub fn from_config(value: &str) -> Result<Self> {
        match value {
            "HANDSHAKE_DEFAULT" | "HANDSHAKE_STANDARD" => Ok(Self::Standard),
            "HANDSHAKE_NO_WAIT" => Ok(Self::NoWait),
            other => Err(ClientError::InvalidHandshakeMode(other.to_owned())),
        }
    }
}

/// Constructible from the `MieruOption` outbound.
///
/// `server` is the configured host (a name or an IP literal, resolved by `dialer`) and
/// `port_start`/`port_end` mirror its `port` or `port-range`. `username`/`password` mirror
/// `username`/`password`, `transport` (`"TCP"` -> [`Transport::Stream`], `"UDP"` ->
/// [`Transport::Packet`]), `multiplex`, `handshake_mode` and `traffic_pattern` mirror the
/// corresponding config fields.
#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub server: String,
    pub port_start: u16,
    pub port_end: u16,
    pub username: String,
    pub password: String,
    pub transport: Transport,
    pub multiplex: MultiplexLevel,
    pub handshake_mode: HandshakeMode,
    pub traffic_pattern: Option<Config>,
}

/// A dialed session: the byte stream plus the underlay socket's addresses, i.e. the addresses a
/// caller presenting it as a socket needs.
pub struct DialedSession {
    pub stream: Stream,
    pub local_addr: Option<SocketAddr>,
    pub peer_addr: Option<SocketAddr>,
}

impl core::fmt::Debug for DialedSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DialedSession")
            .field("local_addr", &self.local_addr)
            .field("peer_addr", &self.peer_addr)
            .finish_non_exhaustive()
    }
}

pub struct Client {
    mux: Arc<ClientMux>,
    handshake_mode: HandshakeMode,
}

impl core::fmt::Debug for Client {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Client").field("handshake_mode", &self.handshake_mode).finish_non_exhaustive()
    }
}

impl Client {
    #[must_use]
    pub fn new(config: ClientConfig) -> Self {
        Self::with_dialer(config, Arc::new(SystemDialer))
    }

    /// The `dialer` is the caller's, so the underlay connection carries its interface binding and
    /// routing mark, and the dialer-proxy chain in front of it stays intact.
    pub fn with_dialer(config: ClientConfig, dialer: Arc<dyn ClientDialer>) -> Self {
        let ports = (config.port_start..=config.port_end).collect();
        // the credential is hashed before it reaches the mux, and the server derives every key
        // from that same hash,
        // so the mux is handed the hashed credential rather than the configured password.
        let credential = cipher::hash_password(config.password.as_bytes(), config.username.as_bytes()).to_vec();
        let mux = ClientMux::new(
            config.server,
            ports,
            credential,
            config.username,
            config.transport,
            config.multiplex.factor(),
            dialer,
            config.traffic_pattern,
        );
        Self { mux, handshake_mode: config.handshake_mode }
    }

    /// Builds the client config: the configured `traffic-pattern` decoded and validated, or
    /// `None` when the option is unset. A pattern asking for low-entropy payload coding is
    /// refused rather than accepted and then not applied, since nothing here would encode it.
    pub fn parse_traffic_pattern(encoded: &str) -> Result<Option<Config>> {
        if encoded.is_empty() {
            return Ok(None);
        }
        let config = Config::new(Some(trafficpattern::decode(encoded)?))?;
        if config.low_entropy_enabled() {
            return Err(ClientError::TrafficPattern(PatternError::Invalid(
                "lowEntropy.mode is not supported: low-entropy payload coding has no Rust implementation".to_owned(),
            )));
        }
        Ok(Some(config))
    }

    /// Dials a session and performs the CONNECT (TCP) or UDP_ASSOCIATE (UDP)
    /// handshake against `dest`, returning a byte stream ready for application data.
    pub async fn dial_context(&self, ctx: &CancellationToken, dest: AddrSpec, command: u8) -> Result<DialedSession> {
        let session = self.mux.dial(ctx).await?;
        let local_addr = session.local_addr();
        let peer_addr = session.peer_addr();
        let request = Request { command, dst_addr: dest };
        let stream: Stream = match self.handshake_mode {
            HandshakeMode::Standard => {
                session.write(&request.encode()).await?;
                let mut stream = SessionStream::new(session);
                let response = Response::read_from(&mut stream).await?;
                if response.reply_code != REPLY_SUCCESS {
                    return Err(ClientError::Rejected(response.reply_code));
                }
                Box::pin(stream)
            }
            HandshakeMode::NoWait => Box::pin(SessionStream::with_pending_request(session, request.encode())),
        };
        Ok(DialedSession { stream, local_addr, peer_addr })
    }

    pub async fn dial_connect(&self, ctx: &CancellationToken, dest: AddrSpec) -> Result<DialedSession> {
        self.dial_context(ctx, dest, CMD_CONNECT).await
    }

    pub async fn dial_udp_associate(&self, ctx: &CancellationToken, dest: AddrSpec) -> Result<DialedSession> {
        self.dial_context(ctx, dest, CMD_UDP_ASSOCIATE).await
    }

    pub async fn close(&self) {
        self.mux.close().await;
    }
}
