use std::fmt;
use std::future::Future;
use std::time::Duration;

use http::StatusCode;
use tokio_util::sync::CancellationToken;

use super::tunnel_dial::TunnelHttpTransport;

#[derive(Debug)]
struct HttpStatusError {
    status: StatusCode,
    reason: String,
}

impl fmt::Display for HttpStatusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.reason.is_empty() {
            write!(f, "bad status")
        } else {
            write!(f, "bad status: {} {}", self.status.as_u16(), self.reason)
        }
    }
}

impl std::error::Error for HttpStatusError {}

pub(crate) fn is_retryable_status_code(code: StatusCode) -> bool {
    code == StatusCode::REQUEST_TIMEOUT || code == StatusCode::TOO_MANY_REQUESTS || code.as_u16() >= 500
}

pub(crate) fn status_error(status: StatusCode, reason: &str) -> anyhow::Error {
    anyhow::Error::new(HttpStatusError { status, reason: reason.to_owned() })
}

///
/// Deviation: `TunnelHttpTransport` dials fresh HTTP/1.1 connections per request instead of a
/// pooled HTTP transport (see `tunnel_dial.rs`), so there is no idle-connection pool left to
/// drain; kept as a documented no-op call site so the retry-loop shape is preserved.
pub(crate) async fn close_idle_connections(_client: &TunnelHttpTransport) {}

///
/// Deviation: this crate dials sockets directly through `NetDialer` rather than through hyper's
/// own connector, so a dial failure never surfaces as `hyper::Error`; it is always the
/// `std::io::Error` returned by the dialer, matched here by kind.
pub(crate) fn is_dial_error(err: &anyhow::Error) -> bool {
    for cause in err.chain() {
        if let Some(io_err) = cause.downcast_ref::<std::io::Error>() {
            if matches!(
                io_err.kind(),
                std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::HostUnreachable
            ) {
                return true;
            }
        }
    }
    false
}

///
/// Deviation: cancellation and deadline errors and the timeout
/// trait are matched structurally; this crate has no single cancellation-error type
/// (cancellation is observed via `CancellationToken`, not surfaced as an error), so it matches
/// the equivalent messages produced by `component::tls::utls::Conn::handshake_context` and hyper.
pub(crate) fn is_retryable_http_transport_error(err: &anyhow::Error) -> bool {
    let message = err.to_string();
    if message.contains("context canceled") || message.contains("context deadline exceeded") {
        return false;
    }

    for cause in err.chain() {
        if let Some(status_err) = cause.downcast_ref::<HttpStatusError>() {
            return is_retryable_status_code(status_err.status);
        }
        if let Some(io_err) = cause.downcast_ref::<std::io::Error>() {
            if matches!(
                io_err.kind(),
                std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::NotConnected
            ) {
                return true;
            }
        }
        if let Some(hyper_err) = cause.downcast_ref::<hyper::Error>() {
            if hyper_err.is_timeout() || hyper_err.is_closed() || hyper_err.is_incomplete_message() {
                return true;
            }
        }
    }

    message.to_lowercase().contains("server closed idle connection")
}

// The drain-then-reset semantics have no direct `tokio::time::Timer::reset` equivalent;
// callers hold a `tokio::time::Sleep` reset via
// `Sleep::as_mut().reset(Instant::now() + d)` instead, so this helper is not implemented (see
// `tunnel_conn_poll.rs`, which resets its own `Sleep` directly).

pub(crate) async fn retry_persistent<F, Fut>(
    closed: &CancellationToken,
    closed_err: Option<&(dyn Fn() -> anyhow::Error + Send + Sync)>,
    min_backoff: Duration,
    max_backoff: Duration,
    mut f: F,
) -> anyhow::Result<()>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = anyhow::Result<()>>,
{
    let max_backoff = max_backoff.max(min_backoff);
    let mut backoff = min_backoff;
    loop {
        match f().await {
            Ok(()) => return Ok(()),
            Err(err) if is_dial_error(&err) || is_retryable_http_transport_error(&err) => {
                wait_retry(closed, closed_err, backoff).await?;
                backoff = next_backoff(backoff, min_backoff, max_backoff);
            }
            Err(err) => return Err(err),
        }
    }
}

// cancel-safe: it only waits out the backoff and reports the close error if the conn went away.
pub(crate) async fn wait_retry(
    closed: &CancellationToken,
    closed_err: Option<&(dyn Fn() -> anyhow::Error + Send + Sync)>,
    backoff: Duration,
) -> anyhow::Result<()> {
    tokio::select! {
        () = tokio::time::sleep(backoff) => Ok(()),
        () = closed.cancelled() => Err(closed_err.map_or_else(
            || anyhow::Error::from(std::io::Error::from(std::io::ErrorKind::BrokenPipe)),
            |f| f(),
        )),
    }
}

pub(crate) fn next_backoff(current: Duration, min: Duration, max: Duration) -> Duration {
    let current = current.max(min);
    if current >= max / 2 {
        max
    } else {
        current * 2
    }
}
