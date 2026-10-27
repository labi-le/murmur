//! The [`Session`] trait is the contract every underlying multiplexer satisfies.
//!
//! The multiplexers are `smux`, `yamux` and `h2mux`; boxed streams are [`MuxStream`], and the
//! underlying carrier connection each multiplexer wraps is [`MuxConn`].

use std::io;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::protocol::{PROTOCOL_H2MUX, PROTOCOL_SMUX, PROTOCOL_YAMUX};

/// The connection used as the carrier a multiplexer session is opened over.
///
/// `Sync` is required for the same reason as [`MuxStream`]: outbound wiring hands the pre-session
/// carrier to `murmur_common_net::io::Stream` too (padding/protocol negotiation happen before the
/// mux session exists, so the carrier is briefly a plain `Stream` in its own right).
pub trait MuxConn: AsyncRead + AsyncWrite + Send + Sync + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin + ?Sized> MuxConn for T {}

/// The connection used for one multiplexed stream. `Sync` is required because callers hand these
/// to `murmur_common_net::io::Stream`, which is `Send + Sync`.
pub trait MuxStream: AsyncRead + AsyncWrite + Send + Sync + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin + ?Sized> MuxStream for T {}

#[async_trait]
pub trait Session: Send + Sync {
    // NOT cancel-safe: the open request is on the wire and the stream is already registered, so a
    // dropped `open` leaves a stream on both sides that no handle ever removes.
    async fn open(&self, tcp_timeout: Duration) -> io::Result<Box<dyn MuxStream>>;
    // cancel-safe: the accept is a `tokio::sync::mpsc::Receiver::recv` under a lock, both of which
    // tokio documents as cancel-safe, so a stream nobody took stays queued.
    async fn accept(&self) -> io::Result<Box<dyn MuxStream>>;
    fn num_streams(&self) -> usize;
    async fn close(&self) -> io::Result<()>;
    fn is_closed(&self) -> bool;
    fn can_take_new_request(&self) -> bool;
}

pub async fn new_client_session(conn: Box<dyn MuxConn>, protocol: u8) -> io::Result<Arc<dyn Session>> {
    match protocol {
        PROTOCOL_H2MUX => Ok(Arc::new(crate::h2mux::H2MuxClientSession::new(conn).await?)),
        PROTOCOL_SMUX => Ok(Arc::new(crate::smux::client_session(conn).await?)),
        PROTOCOL_YAMUX => Ok(Arc::new(crate::yamux_session::client_session(conn).await?)),
        other => Err(io::Error::new(io::ErrorKind::InvalidInput, format!("unexpected protocol {other}"))),
    }
}

pub async fn new_server_session(conn: Box<dyn MuxConn>, protocol: u8) -> io::Result<Arc<dyn Session>> {
    match protocol {
        PROTOCOL_H2MUX => Ok(Arc::new(crate::h2mux::H2MuxServerSession::new(conn))),
        PROTOCOL_SMUX => Ok(Arc::new(crate::smux::server_session(conn).await?)),
        PROTOCOL_YAMUX => Ok(Arc::new(crate::yamux_session::server_session(conn).await?)),
        other => Err(io::Error::new(io::ErrorKind::InvalidInput, format!("unexpected protocol {other}"))),
    }
}
