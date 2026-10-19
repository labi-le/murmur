//! The camouflage relay is rate limited so a JLS listener pointed at a real
//! website cannot be used to amplify traffic against that site.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::num::NonZeroU64;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use parking_lot::Mutex;
use tokio::io::{AsyncRead, ReadBuf};
use tokio_util::sync::CancellationToken;

use murmur_std_compat::net::{Addr, Conn};

const BITS_PER_BYTE: u64 = 8;
const RATE_LIMIT_CYCLE: Duration = Duration::from_millis(10);
const MAX_RATE_LIMIT_BURST_BYTES: usize = 64 * 1024;
const NANOS_PER_SECOND: u64 = 1_000_000_000;

type Delay = Pin<Box<dyn Future<Output = io::Result<()>> + Send + Sync>>;

pub struct BitRateLimiter {
    /// The rate divides by this, so zero is not a value it can hold;
    /// "no limit" is expressed by not building a limiter at all.
    rate_bps: NonZeroU64,
    next: Mutex<tokio::time::Instant>,
}

impl core::fmt::Debug for BitRateLimiter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BitRateLimiter").field("rate_bps", &self.rate_bps).finish_non_exhaustive()
    }
}

impl BitRateLimiter {
    #[must_use]
    pub fn new(rate_bps: NonZeroU64) -> Self {
        Self { rate_bps, next: Mutex::new(tokio::time::Instant::now()) }
    }

    /// The reservation is taken when the future is created, so a caller that caches the future
    /// cannot re-book the same delay twice.
    pub fn wait_n(&self, cancel: &CancellationToken, n: usize) -> Delay {
        let delay = self.reserve_n(tokio::time::Instant::now(), n);
        if delay.is_zero() {
            return Box::pin(std::future::ready(Ok(())));
        }
        let cancel = cancel.clone();
        Box::pin(async move {
            tokio::select! {
                () = tokio::time::sleep(delay) => Ok(()),
                () = cancel.cancelled() => Err(io::Error::new(io::ErrorKind::BrokenPipe, "jls: rate limited conn closed")),
            }
        })
    }

    fn reserve_n(&self, now: tokio::time::Instant, n: usize) -> Duration {
        let interval = Duration::from_nanos(
            (n as u64).saturating_mul(BITS_PER_BYTE).saturating_mul(NANOS_PER_SECOND) / self.rate_bps.get(),
        );
        let mut next = self.next.lock();
        let ready = if *next < now { now } else { *next };
        *next = ready + interval;
        drop(next);
        ready.saturating_duration_since(now)
    }
}

///
/// the version is synchronous, so a read charges the limiter after the bytes
/// are already in the caller's buffer and a write charges it before the write.
/// The poll-based port keeps that ordering by holding the in-flight charge as
/// state: a read that has delivered its bytes still owes the limiter, and a
/// write that has been charged still owes the inner conn its chunk.
pub(crate) struct RateLimitedConn {
    conn: Box<dyn Conn>,
    cancel: CancellationToken,
    read_limiter: BitRateLimiter,
    write_limiter: BitRateLimiter,
    burst: usize,
    read_charge: Option<Delay>,
    write_charge: Option<(usize, Delay)>,
    /// Staging area for the truncated read window. A read is capped at one burst,
    /// which `ReadBuf::take` cannot express without taking a second mutable
    /// borrow of the caller's buffer, so the capped read lands here first.
    read_window: Vec<u8>,
}

/// A zero `rate_bps` means "no limit", and the conn then comes back unwrapped.
#[must_use]
pub fn new_rate_limited_conn(conn: Box<dyn Conn>, rate_bps: u64) -> Box<dyn Conn> {
    let Some(rate_bps) = NonZeroU64::new(rate_bps) else {
        return conn;
    };
    Box::new(RateLimitedConn {
        conn,
        cancel: CancellationToken::new(),
        read_limiter: BitRateLimiter::new(rate_bps),
        write_limiter: BitRateLimiter::new(rate_bps),
        burst: burst_for(rate_bps.get()),
        read_charge: None,
        write_charge: None,
        read_window: Vec::new(),
    })
}

/// The burst: one cycle's worth of bytes at `rate_bps`, never below a byte and never above
/// [`MAX_RATE_LIMIT_BURST_BYTES`].
#[expect(
    clippy::cast_possible_truncation,
    reason = "cycle nanos fit u64; every supported target's usize holds the clamped 64 KiB burst"
)]
fn burst_for(rate_bps: u64) -> usize {
    let per_cycle = (NANOS_PER_SECOND / RATE_LIMIT_CYCLE.as_nanos() as u64).max(1);
    (rate_bps / BITS_PER_BYTE / per_cycle).clamp(1, MAX_RATE_LIMIT_BURST_BYTES as u64) as usize
}

impl AsyncRead for RateLimitedConn {
    /// the caller's buffer is truncated to the
    /// burst, and the bytes are charged to the read limiter once delivered.
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if let Some(mut charge) = this.read_charge.take() {
            match charge.as_mut().poll(cx) {
                Poll::Pending => {
                    this.read_charge = Some(charge);
                    return Poll::Pending;
                }
                Poll::Ready(result) => result?,
            }
        }

        let capped = this.burst.min(buf.remaining());
        this.read_window.clear();
        this.read_window.resize(capped, 0);
        let mut window = ReadBuf::new(&mut this.read_window);
        match Pin::new(&mut *this.conn).poll_read(cx, &mut window) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Ready(Ok(())) => {}
        }
        let filled = window.filled().len();
        let (filled_bytes, _) = this.read_window.split_at(filled);
        buf.put_slice(filled_bytes);
        if filled == 0 {
            return Poll::Ready(Ok(()));
        }
        this.read_charge = Some(this.read_limiter.wait_n(&this.cancel, filled));
        Poll::Ready(Ok(()))
    }
}

impl tokio::io::AsyncWrite for RateLimitedConn {
    /// charge first, then write at most one
    /// burst. The remaining chunks of a longer buffer are the caller's to
    /// resubmit, which is what `AsyncWrite`'s partial-write contract expects.
    ///
    /// A resumed charge was booked for a chunk larger than the buffer this poll
    /// was handed; writing the smaller buffer is charged slightly over, never
    /// under, so the configured rate stays a ceiling.
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let charged = if let Some((charged, mut charge)) = this.write_charge.take() {
            match charge.as_mut().poll(cx) {
                Poll::Pending => {
                    this.write_charge = Some((charged, charge));
                    return Poll::Pending;
                }
                Poll::Ready(result) => {
                    result?;
                    charged
                }
            }
        } else {
            let chunk = buf.len().min(this.burst);
            if chunk == 0 {
                return Poll::Ready(Ok(0));
            }
            let mut charge = this.write_limiter.wait_n(&this.cancel, chunk);
            match charge.as_mut().poll(cx) {
                Poll::Pending => {
                    this.write_charge = Some((chunk, charge));
                    return Poll::Pending;
                }
                Poll::Ready(result) => {
                    result?;
                    chunk
                }
            }
        };
        let chunk = charged.min(buf.len());
        if chunk == 0 {
            return Poll::Ready(Ok(0));
        }
        let (chunk_bytes, _) = buf.split_at(chunk);
        Pin::new(&mut *this.conn).poll_write(cx, chunk_bytes)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().conn).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().conn).poll_shutdown(cx)
    }
}

impl Conn for RateLimitedConn {
    /// cancelling first releases a caller parked
    /// inside a limiter delay, which a plain inner `close` would not.
    fn close(&self) -> io::Result<()> {
        self.cancel.cancel();
        self.conn.close()
    }

    fn close_read(&self) -> io::Result<()> {
        self.conn.close_read()
    }

    fn close_write(&self) -> io::Result<()> {
        self.conn.close_write()
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.conn.local_addr()
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.conn.remote_addr()
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.conn.set_deadline(deadline)
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.conn.set_read_deadline(deadline)
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.conn.set_write_deadline(deadline)
    }
}

impl murmur_common_net::io::Stream for RateLimitedConn {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        murmur_common_net::io::old_addr_to_socket_addr(self.conn.local_addr()?.as_ref())
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        murmur_common_net::io::old_addr_to_socket_addr(self.conn.remote_addr()?.as_ref())
    }

    fn shutdown_read(&self) -> io::Result<()> {
        self.conn.close_read()
    }

    fn shutdown_write(&self) -> io::Result<()> {
        self.conn.close_write()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_is_clamped_into_range() {
        assert_eq!(burst_for(0), 1, "an unwrapped conn never consults the burst");
        assert_eq!(burst_for(1), 1);
        assert_eq!(burst_for(u64::MAX), MAX_RATE_LIMIT_BURST_BYTES);
        assert_eq!(burst_for(BITS_PER_BYTE * 100), 1);
        assert_eq!(burst_for(BITS_PER_BYTE * 100 * 1024), 1024);
    }

    /// Books `n*8/rate_bps` seconds of delay per call and chains the next reservation onto it,
    /// so a burst of identical charges stretches out linearly instead of collapsing onto one
    /// instant.
    #[tokio::test]
    async fn reserve_n_chains_reservations() {
        let limiter = BitRateLimiter::new(NonZeroU64::new(BITS_PER_BYTE * 1000).expect("a non-zero rate"));
        let start = tokio::time::Instant::now();
        let first = limiter.reserve_n(start, 100);
        let second = limiter.reserve_n(start, 100);
        assert_eq!(first, Duration::ZERO);
        assert_eq!(second, Duration::from_millis(100));
        assert_eq!(limiter.reserve_n(start, 100), Duration::from_millis(200));
    }
}
