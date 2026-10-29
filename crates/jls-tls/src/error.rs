//! Error types for the mini TLS 1.3 + JLS engine.

use std::io;

/// Wire-level or protocol-level failure in the handshake or record layer.
///
/// Kept distinct from I/O errors (`io::Error`) so callers can tell a transport
/// failure (peer closed the socket) apart from a malformed/rejected message.
#[derive(thiserror::Error, Debug)]
pub enum TlsError {
    #[error("tls: io error: {0}")]
    Io(#[from] io::Error),
    #[error("tls: protocol error: {0}")]
    Protocol(String),
    #[error("tls: peer sent a fatal alert (level={level}, description={description})")]
    PeerAlert { level: u8, description: u8 },
    #[error("tls: post-handshake key update is not supported by this engine")]
    KeyUpdateUnsupported,
}

impl TlsError {
    pub(crate) fn protocol(msg: impl Into<String>) -> Self {
        Self::Protocol(msg.into())
    }
}

pub(crate) type Result<T, E = TlsError> = std::result::Result<T, E>;

/// Failure mode of [`crate::server_handshake`].
///
/// Split by whether the server had already written to the client when the
/// failure happened. Bytes the client sent are only safe to replay to a
/// fallback destination while the server's own flight is still empty; otherwise
/// the fallback would end up mixing two protocols on one connection.
#[derive(thiserror::Error, Debug)]
pub enum ServerHandshakeError {
    /// JLS authentication did not succeed for any configured user (the
    /// `ClientHello.random` failed to decrypt for every configured user, or the
    /// SNI presented by the client did not match the configured `server_name`).
    /// Carries every byte read from the underlying stream so far, the way
    /// [`Self::Replayable`] does.
    #[error("tls: jls authentication failed")]
    AuthFailed { consumed: Vec<u8> },
    /// Any other failure that happened before a single byte was written back:
    /// a client that never sent a `ClientHello` at all (a camouflage probe such
    /// as an HTTP request), a truncated or malformed record, EOF.
    #[error("tls: handshake failed before any response was written: {source}")]
    Replayable {
        consumed: Vec<u8>,
        #[source]
        source: anyhow::Error,
    },
    /// A failure at or after the first byte of the server flight. The client
    /// has already seen TLS records, so there is nothing to fall back to.
    #[error(transparent)]
    Irreversible(anyhow::Error),
}

impl ServerHandshakeError {
    /// The client's bytes read so far, for the failures where replaying them to
    /// a fallback destination is safe.
    #[must_use]
    pub fn replayable_prefix(self) -> Option<Vec<u8>> {
        match self {
            Self::AuthFailed { consumed } | Self::Replayable { consumed, .. } => Some(consumed),
            Self::Irreversible(_) => None,
        }
    }
}

impl From<TlsError> for ServerHandshakeError {
    fn from(err: TlsError) -> Self {
        Self::Irreversible(err.into())
    }
}
