use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::io::ServerEndpoint;
use crate::model::Request;
use crate::mux::ServerMux;
use crate::session::SessionStream;
use crate::trafficpattern::{self, Config, PatternError};
use crate::underlay::UnderlayError;

const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Constructible from the `MieruOption` inbound.
///
/// `endpoints` are the listeners the inbound's own listen config already bound (one per
/// configured port), `users` maps name -> password and
/// `traffic_pattern` its `traffic-pattern`.
pub struct Server {
    mux: ServerMux,
}

impl core::fmt::Debug for Server {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Server").finish_non_exhaustive()
    }
}

impl Server {
    /// `endpoints` come from the caller because the listeners are theirs to make: the caller
    /// supplies the listener factories for the same reason.
    pub fn new(
        users: &HashMap<String, String>,
        endpoints: Vec<ServerEndpoint>,
        user_hint_is_mandatory: bool,
        traffic_pattern: Option<Config>,
    ) -> Result<Self, UnderlayError> {
        let mux = ServerMux::new(users, endpoints, user_hint_is_mandatory, traffic_pattern)?;
        Ok(Self { mux })
    }

    /// Builds the server config: the configured `traffic-pattern` decoded and validated, or
    /// `None` when the option is unset. A pattern asking for low-entropy payload coding is
    /// refused rather than accepted and then not applied, since nothing here would encode it.
    pub fn parse_traffic_pattern(encoded: &str) -> Result<Option<Config>, PatternError> {
        if encoded.is_empty() {
            return Ok(None);
        }
        let config = Config::new(Some(trafficpattern::decode(encoded)?))?;
        if config.low_entropy_enabled() {
            return Err(PatternError::Invalid(
                "lowEntropy.mode is not supported: low-entropy payload coding has no Rust implementation".to_owned(),
            ));
        }
        Ok(Some(config))
    }

    /// Pulls the next ready session and reads exactly one [`Request`] off it (10s deadline). The
    /// caller is responsible for writing the canned [`crate::model::Response`] and then treating
    /// the returned stream as a plain byte stream for CONNECT, or wrapping it in
    /// [`crate::model::UdpAssociateWrapper`] for `UDP_ASSOCIATE`.
    // NOT cancel-safe: the accepted connection is consumed by a handshake or request read that is already writing or reading on it, so a dropped call loses that connection rather than leaving it queued.
    pub async fn accept(&self) -> Option<(SessionStream, Request)> {
        loop {
            let session = self.mux.accept().await?;
            session.set_read_deadline(Some(std::time::Instant::now() + REQUEST_READ_TIMEOUT));
            let mut stream = SessionStream::new(Arc::clone(&session));
            match Request::read_from(&mut stream).await {
                Ok(request) => {
                    session.set_read_deadline(None);
                    return Some((stream, request));
                }
                Err(_) => {
                    let _ = session.close().await;
                }
            }
        }
    }

    pub fn bound_addrs(&self) -> &[SocketAddr] {
        self.mux.bound_addrs()
    }

    pub fn close(&self) {
        self.mux.close();
    }
}
