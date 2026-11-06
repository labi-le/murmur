//! Adapts the `murmur-yamux` crate onto this crate's [`crate::session::Session`].

use std::io;
use std::time::Duration;

use async_trait::async_trait;
use murmur_yamux::{client as yamux_client, default_config, server as yamux_server, Session as YamuxCoreSession};

use crate::session::{MuxConn, MuxStream, Session};

struct YamuxSession(YamuxCoreSession);

/// Builds the client half over `murmur-yamux`.
pub(crate) async fn client_session(conn: Box<dyn MuxConn>) -> io::Result<impl Session> {
    Ok(YamuxSession(yamux_client(conn, default_config()).await?))
}

/// Builds the server half over `murmur-yamux`.
pub(crate) async fn server_session(conn: Box<dyn MuxConn>) -> io::Result<impl Session> {
    Ok(YamuxSession(yamux_server(conn, default_config()).await?))
}

#[async_trait]
impl Session for YamuxSession {
    async fn open(&self, tcp_timeout: Duration) -> io::Result<Box<dyn MuxStream>> {
        match tokio::time::timeout(tcp_timeout, self.0.open_stream()).await {
            Ok(result) => Ok(Box::new(result?)),
            Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "yamux: open stream timed out")),
        }
    }

    // cancel-safe: forwards to the wrapped acceptor and only boxes the result, so a dropped call leaves the inner listener as it was.
    async fn accept(&self) -> io::Result<Box<dyn MuxStream>> {
        Ok(Box::new(self.0.accept_stream().await?))
    }

    fn num_streams(&self) -> usize {
        self.0.num_streams()
    }

    async fn close(&self) -> io::Result<()> {
        self.0.close().await
    }

    fn is_closed(&self) -> bool {
        self.0.is_closed()
    }

    fn can_take_new_request(&self) -> bool {
        true
    }
}
