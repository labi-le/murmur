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
        clippy::nursery,
        reason = "test scaffolding is not product code, and a failing test should abort"
    )
)]

mod alloc;
mod frame;
mod session;
mod shaper;
mod stream;

#[cfg(test)]
mod tests;

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tokio::time::Instant;

use murmur_common_net::io::{close_stream, Stream as NetStream};

use session::SessionInner;
pub use stream::SmuxStream;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub version: i32,
    pub keep_alive_disabled: bool,
    pub keep_alive_interval: Duration,
    pub keep_alive_timeout: Duration,
    pub max_frame_size: i32,
    pub max_receive_buffer: i64,
    pub max_stream_buffer: i64,
}

#[must_use]
pub const fn default_config() -> Config {
    Config {
        version: 1,
        keep_alive_disabled: false,
        keep_alive_interval: Duration::from_secs(10),
        keep_alive_timeout: Duration::from_secs(30),
        max_frame_size: 32768,
        max_receive_buffer: 4194304,
        max_stream_buffer: 65536,
    }
}

pub fn verify_config(config: &Config) -> Result<()> {
    if !(config.version == 1 || config.version == 2) {
        return Err(anyhow!("unsupported protocol version"));
    }
    if !config.keep_alive_disabled {
        if config.keep_alive_interval == Duration::ZERO {
            return Err(anyhow!("keep-alive interval must be positive"));
        }
        if config.keep_alive_timeout < config.keep_alive_interval {
            return Err(anyhow!("keep-alive timeout must be larger than keep-alive interval"));
        }
    }
    if config.max_frame_size <= 0 {
        return Err(anyhow!("max frame size must be positive"));
    }
    if config.max_frame_size > 65535 {
        return Err(anyhow!("max frame size must not be larger than 65535"));
    }
    if config.max_receive_buffer <= 0 {
        return Err(anyhow!("max receive buffer must be positive"));
    }
    if config.max_receive_buffer > i64::from(i32::MAX) {
        return Err(anyhow!("max receive buffer cannot be larger than 2147483647"));
    }
    if config.max_stream_buffer <= 0 {
        return Err(anyhow!("max stream buffer must be positive"));
    }
    if config.max_stream_buffer > config.max_receive_buffer {
        return Err(anyhow!("max stream buffer must not be larger than max receive buffer"));
    }
    if config.max_stream_buffer > i64::from(i32::MAX) {
        return Err(anyhow!("max stream buffer cannot be larger than 2147483647"));
    }
    Ok(())
}

pub trait Stream: NetStream {}

#[async_trait]
pub trait Session: Send + Sync {
    async fn open_stream(&self) -> Result<Box<dyn Stream>>;
    /// Accepts a stream under the accept deadline; `None` blocks until a stream arrives.
    async fn accept_stream(&self, deadline: Option<Instant>) -> Result<Box<dyn Stream>>;
    fn is_closed(&self) -> bool;
    fn close(&self) -> io::Result<()>;
    fn local_addr(&self) -> io::Result<SocketAddr>;
    fn remote_addr(&self) -> io::Result<SocketAddr>;
    fn num_streams(&self) -> usize;
}

pub async fn accept(session: &dyn Session) -> Result<Box<dyn Stream>> {
    session.accept_stream(None).await
}

struct SessionHandle(std::sync::Arc<SessionInner>);

#[async_trait]
impl Session for SessionHandle {
    async fn open_stream(&self) -> Result<Box<dyn Stream>> {
        let st = self.0.open_stream().await?;
        Ok(Box::new(SmuxStream::new(st)))
    }
    async fn accept_stream(&self, deadline: Option<Instant>) -> Result<Box<dyn Stream>> {
        let st = self.0.accept_stream(deadline).await?;
        Ok(Box::new(SmuxStream::new(st)))
    }

    fn is_closed(&self) -> bool {
        self.0.is_closed()
    }

    fn close(&self) -> io::Result<()> {
        self.0.close();
        Ok(())
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.0.local_addr)
    }

    fn remote_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.0.peer_addr)
    }

    fn num_streams(&self) -> usize {
        self.0.num_streams()
    }
}

fn new_session(conn: Box<dyn NetStream>, config: &Config, is_client: bool) -> Result<Box<dyn Session>> {
    if let Err(err) = verify_config(config) {
        let _ = close_stream(&*conn);
        return Err(err);
    }
    let inner = SessionInner::start(conn, config.clone(), is_client);
    Ok(Box::new(SessionHandle(inner)))
}

pub fn client(conn: Box<dyn NetStream>, config: &Config) -> Result<Box<dyn Session>> {
    new_session(conn, config, true)
}

pub fn server(conn: Box<dyn NetStream>, config: &Config) -> Result<Box<dyn Session>> {
    new_session(conn, config, false)
}
