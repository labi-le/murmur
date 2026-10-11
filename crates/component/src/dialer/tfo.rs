//! A TFO dial returns immediately: the dial happens on the first write, which carries the
//! early data.

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock};
use std::task::{Context, Poll};

use futures::future::BoxFuture;
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;
use tokio::time::{sleep_until, timeout_at, Instant};
use tokio_util::sync::CancellationToken;

use murmur_common::atomic::type_::{new_bool, Bool};
use murmur_common_net::io::{ExtendedStream, Stream};
use murmur_common_net::sing::{EarlyConn, UpstreamNode};

use super::dialer::DEFAULT_TCP_TIMEOUT;

use super::control::StdDialer;

/// Whether TFO is disabled; on Windows the platform check decides it.
pub static DISABLE_TFO: LazyLock<Bool> = LazyLock::new(|| {
    #[cfg(target_os = "windows")]
    {
        new_bool(super::tfo_windows::disable_tfo())
    }
    #[cfg(not(target_os = "windows"))]
    {
        new_bool(false)
    }
});

type DialFn =
    Arc<dyn Fn(CancellationToken, Vec<u8>) -> BoxFuture<'static, anyhow::Result<Box<dyn Stream>>> + Send + Sync>;

pub struct TfoConn {
    conn: Arc<Mutex<Option<Box<dyn Stream>>>>,
    closed: AtomicBool,
    dialed_tx: mpsc::Sender<bool>,
    dialed_rx: Mutex<mpsc::Receiver<bool>>,
    cancel: CancellationToken,
    deadline: Instant,
    ctx_done: Mutex<Option<Pin<Box<dyn Future<Output = ()> + Send>>>>,
    dial_fn: DialFn,
    dialing: Mutex<Option<BoxFuture<'static, anyhow::Result<()>>>>,
}

impl std::fmt::Debug for TfoConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TfoConn").finish_non_exhaustive()
    }
}

impl TfoConn {
    fn new(cancel: CancellationToken, deadline: Instant, dial_fn: DialFn) -> Self {
        let (dialed_tx, dialed_rx) = mpsc::channel(1);
        Self {
            conn: Arc::new(Mutex::new(None)),
            closed: AtomicBool::new(false),
            dialed_tx,
            dialed_rx: Mutex::new(dialed_rx),
            cancel,
            deadline,
            ctx_done: Mutex::new(None),
            dial_fn,
            dialing: Mutex::new(None),
        }
    }

    fn ctx_done(&self, cx: &mut Context<'_>) -> bool {
        let mut slot = self.ctx_done.lock();
        if slot.is_none() {
            let cancel = self.cancel.clone();
            let deadline = self.deadline;
            *slot = Some(Box::pin(async move {
                // cancel-safe: both arms are tokio primitives and the block holds no state.
                tokio::select! {
                    () = cancel.cancelled() => {}
                    () = sleep_until(deadline) => {}
                }
            }));
        }
        match slot.as_mut() {
            Some(done) => done.as_mut().poll(cx).is_ready(),
            None => false,
        }
    }
}

impl AsyncRead for TfoConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.closed.load(Ordering::SeqCst) {
            return Poll::Ready(Err(closed_pipe_error()));
        }

        if this.conn.lock().is_none() {
            let dialed = {
                let mut rx = this.dialed_rx.lock();
                Pin::new(&mut *rx).poll_recv(cx)
            };
            if dialed.is_pending() {
                if this.ctx_done(cx) {
                    return Poll::Ready(Err(unexpected_eof_error()));
                }
                return Poll::Pending;
            }
        }

        let mut guard = this.conn.lock();
        let Some(conn) = guard.as_mut() else {
            return Poll::Ready(Err(unexpected_eof_error()));
        };
        let poll = Pin::new(&mut **conn).poll_read(cx, buf);
        drop(guard);
        poll
    }
}

impl AsyncWrite for TfoConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.closed.load(Ordering::SeqCst) {
            return Poll::Ready(Err(closed_pipe_error()));
        }

        if this.conn.lock().is_none() {
            let mut dialing = this.dialing.lock();
            if dialing.is_none() {
                *dialing =
                    Some(tfo_dial_future(&this.conn, &this.dialed_tx, &this.dial_fn, &this.cancel, buf.to_vec()));
            }
            let Some(mut future) = dialing.take() else {
                return Poll::Pending;
            };
            return match future.as_mut().poll(cx) {
                Poll::Ready(result) => match result {
                    Ok(()) => Poll::Ready(Ok(buf.len())),
                    Err(err) => Poll::Ready(Err(to_io_error(err))),
                },
                Poll::Pending => {
                    *dialing = Some(future);
                    Poll::Pending
                }
            };
        }

        let mut guard = this.conn.lock();
        let Some(conn) = guard.as_mut() else {
            return Poll::Ready(Err(closed_pipe_error()));
        };
        let poll = Pin::new(&mut **conn).poll_write(cx, buf);
        drop(guard);
        poll
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut guard = this.conn.lock();
        match guard.as_mut() {
            Some(conn) => Pin::new(&mut **conn).poll_flush(cx),
            None => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut guard = this.conn.lock();
        match guard.as_mut() {
            Some(conn) => Pin::new(&mut **conn).poll_shutdown(cx),
            None => Poll::Ready(Ok(())),
        }
    }
}

impl Stream for TfoConn {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        let guard = self.conn.lock();
        match guard.as_ref() {
            Some(conn) => conn.local_addr(),
            None => Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)),
        }
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        let guard = self.conn.lock();
        match guard.as_ref() {
            Some(conn) => conn.peer_addr(),
            None => Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)),
        }
    }

    /// While the dial is still pending there is no inner connection to shut down, so this marks
    /// the conn closed and cancels the pending dial; once the connection exists it is closed too.
    /// Once dialed, the inner connection's own `shutdown_read` is reached directly and
    /// `closed`/`cancel` are left alone, so the other direction keeps working.
    fn shutdown_read(&self) -> io::Result<()> {
        let guard = self.conn.lock();
        if let Some(conn) = guard.as_ref() {
            conn.shutdown_read()
        } else {
            self.closed.store(true, Ordering::SeqCst);
            self.cancel.cancel();
            Ok(())
        }
    }

    fn shutdown_write(&self) -> io::Result<()> {
        let guard = self.conn.lock();
        if let Some(conn) = guard.as_ref() {
            conn.shutdown_write()
        } else {
            self.closed.store(true, Ordering::SeqCst);
            self.cancel.cancel();
            Ok(())
        }
    }
}

fn closed_pipe_error() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "io: read/write on closed pipe")
}

fn unexpected_eof_error() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF")
}

fn to_io_error(err: anyhow::Error) -> io::Error {
    match err.downcast::<io::Error>() {
        Ok(err) => err,
        Err(err) => io::Error::other(err.to_string()),
    }
}

/// Installs the conn, then releases the waiting readers on `dialed`.
fn tfo_dial_future(
    conn: &Arc<Mutex<Option<Box<dyn Stream>>>>,
    dialed_tx: &mpsc::Sender<bool>,
    dial_fn: &DialFn,
    ctx: &CancellationToken,
    early_data: Vec<u8>,
) -> BoxFuture<'static, anyhow::Result<()>> {
    let conn = Arc::clone(conn);
    let dialed_tx = dialed_tx.clone();
    let dial_fn = Arc::clone(dial_fn);
    let ctx = ctx.clone();
    Box::pin(async move {
        let dialed = dial_fn(ctx, early_data).await?;
        *conn.lock() = Some(dialed);
        let _ = dialed_tx.try_send(true);
        Ok(())
    })
}

/// Only this conn reports a need for an additional read deadline.
pub trait NeedAdditionalReadDeadline {
    fn need_additional_read_deadline(&self) -> bool;
}

impl NeedAdditionalReadDeadline for TfoConn {
    fn need_additional_read_deadline(&self) -> bool {
        self.conn.lock().is_none()
    }
}

impl ExtendedStream for TfoConn {
    fn reader_replaceable(&self) -> bool {
        self.conn.lock().is_some()
    }

    fn writer_replaceable(&self) -> bool {
        self.conn.lock().is_some()
    }
}

impl EarlyConn for TfoConn {
    fn need_handshake(&self) -> bool {
        self.conn.lock().is_none()
    }
}

impl UpstreamNode for TfoConn {
    fn early_conn(&self) -> Option<&dyn EarlyConn> {
        Some(self)
    }

    fn reader_replaceable(&self) -> Option<bool> {
        Some(ExtendedStream::reader_replaceable(self))
    }

    fn writer_replaceable(&self) -> Option<bool> {
        Some(ExtendedStream::writer_replaceable(self))
    }
}

/// Returns the conn before any dial happens.
pub(crate) fn dial_tfo(net_dialer: &StdDialer, network: &str, address: &str) -> Box<dyn Stream> {
    let timeout = DEFAULT_TCP_TIMEOUT;
    let cancel = CancellationToken::new();
    let timeout_cancel = cancel.clone();
    let deadline = Instant::now() + timeout;
    tokio::spawn(async move {
        tokio::time::sleep(timeout).await;
        timeout_cancel.cancel();
    });

    let dialer = net_dialer.clone();
    let network = network.to_owned();
    let address = address.to_owned();
    let dial_fn: DialFn = Arc::new(move |ctx: CancellationToken, early_data: Vec<u8>| {
        let dialer = dialer.clone();
        let network = network.clone();
        let address = address.clone();
        Box::pin(async move { dial_tfo_context(&dialer, &ctx, deadline, &network, &address, &early_data).await })
    });

    Box::new(TfoConn::new(cancel, deadline, dial_fn))
}

/// Dials with early data; a zero-length buffer dials without TFO.
async fn dial_tfo_context(
    dialer: &StdDialer,
    ctx: &CancellationToken,
    deadline: Instant,
    network: &str,
    address: &str,
    early_data: &[u8],
) -> anyhow::Result<Box<dyn Stream>> {
    if early_data.is_empty() {
        return dial_until(dialer, ctx, deadline, network, address).await;
    }

    if !network.starts_with("tcp") {
        let mut conn = dial_until(dialer, ctx, deadline, network, address).await?;
        if let Err(err) = write_until(&mut conn, ctx, deadline, early_data).await {
            let _ = conn.shutdown_read();
            let _ = conn.shutdown_write();
            return Err(err);
        }
        return Ok(conn);
    }

    let mut ld = dialer.clone();
    let previous_context = ld.control_context.take();
    let previous = ld.control.clone();
    ld.control_context = Some(Arc::new(move |ctx, network, address, fd| {
        let previous_context = previous_context.clone();
        let previous = previous.clone();
        let ctx = ctx.clone();
        Box::pin(async move {
            if let Some(previous_context) = &previous_context {
                previous_context(&ctx, network.clone(), address.clone(), fd).await?;
            } else if let Some(previous) = &previous {
                previous(network.clone(), address.clone(), fd).await?;
            }

            set_tfo_dialer(fd).map_err(|err| anyhow::anyhow!("setsockopt({TFO_DIALER_SOCKOPT}): {err}"))
        })
    }));

    let mut conn = dial_until(&ld, ctx, deadline, network, address).await?;
    if let Err(err) = write_until(&mut conn, ctx, deadline, early_data).await {
        let _ = conn.shutdown_read();
        let _ = conn.shutdown_write();
        return Err(err);
    }
    Ok(conn)
}

async fn dial_until(
    dialer: &StdDialer,
    ctx: &CancellationToken,
    deadline: Instant,
    network: &str,
    address: &str,
) -> anyhow::Result<Box<dyn Stream>> {
    match timeout_at(deadline, dialer.dial_context(ctx, network, address)).await {
        Ok(result) => result,
        Err(_) => Err(context_error()),
    }
}

// NOT cancel-safe: a write cut short mid-buffer leaves part of the early data on the wire, so the
// caller closes the connection instead of resuming it.
async fn write_until(
    conn: &mut Box<dyn Stream>,
    ctx: &CancellationToken,
    deadline: Instant,
    early_data: &[u8],
) -> anyhow::Result<()> {
    tokio::select! {
        result = conn.write_all(early_data) => result.map_err(Into::into),
        () = ctx.cancelled() => Err(if Instant::now() >= deadline { context_error() } else { anyhow::anyhow!("context canceled") }),
    }
}

fn context_error() -> anyhow::Error {
    anyhow::Error::new(io::Error::new(io::ErrorKind::TimedOut, "context deadline exceeded"))
}

/// `setsockopt` with an `int` value, on Unix and Windows alike.
#[cfg(any(target_os = "linux", target_os = "android", target_os = "macos", target_os = "freebsd"))]
#[expect(
    unsafe_code,
    reason = "`setsockopt` is a raw FFI call; the SAFETY comment below states the descriptor and buffer invariants"
)]
fn setsockopt_int(fd: usize, name: libc::c_int, value: libc::c_int) -> io::Result<()> {
    let fd = libc::c_int::try_from(fd)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "socket descriptor does not fit an int"))?;
    #[expect(
        clippy::cast_possible_truncation,
        reason = "a `socklen_t` describes a length in bytes and is never narrower than the `int` above it"
    )]
    // SAFETY: `fd` is a live socket and `value` outlives the call.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            name,
            std::ptr::addr_of!(value).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `TCP_FASTOPEN_FORCE_ENABLE` on Darwin; `libc` does not export it.
#[cfg(target_os = "macos")]
const TCP_FASTOPEN_FORCE_ENABLE: libc::c_int = 0x218;

/// The TFO dialer socket option on Linux.
#[cfg(any(target_os = "linux", target_os = "android"))]
const TFO_DIALER_SOCKOPT: &str = "TCP_FASTOPEN_CONNECT";

#[cfg(any(target_os = "linux", target_os = "android"))]
fn set_tfo_dialer(fd: usize) -> anyhow::Result<()> {
    Ok(setsockopt_int(fd, libc::TCP_FASTOPEN_CONNECT, 1)?)
}

/// The TFO dialer socket option on Darwin: it only lifts the kernel's brutal TFO backoff, the
/// early data itself still rides a `connectx` that has no socket-option equivalent.
#[cfg(target_os = "macos")]
const TFO_DIALER_SOCKOPT: &str = "TCP_FASTOPEN_FORCE_ENABLE";

#[cfg(target_os = "macos")]
fn set_tfo_dialer(fd: usize) -> anyhow::Result<()> {
    Ok(setsockopt_int(fd, TCP_FASTOPEN_FORCE_ENABLE, 1)?)
}

/// The TFO dialer socket option on FreeBSD.
#[cfg(target_os = "freebsd")]
const TFO_DIALER_SOCKOPT: &str = "TCP_FASTOPEN";

#[cfg(target_os = "freebsd")]
fn set_tfo_dialer(fd: usize) -> anyhow::Result<()> {
    Ok(setsockopt_int(fd, libc::TCP_FASTOPEN, 1)?)
}

/// The TFO dialer socket option on Windows.
#[cfg(windows)]
const TFO_DIALER_SOCKOPT: &str = "TCP_FASTOPEN";

#[cfg(windows)]
#[expect(
    unsafe_code,
    reason = "`setsockopt` is a raw FFI call; the SAFETY comment below states the handle and buffer invariants"
)]
fn set_tfo_dialer(fd: usize) -> anyhow::Result<()> {
    use windows_sys::Win32::Networking::WinSock::{setsockopt, IPPROTO_TCP, TCP_FASTOPEN};

    let value: i32 = 1;
    // SAFETY: `fd` is a live socket handle and `value` outlives the call.
    let rc = unsafe {
        setsockopt(
            fd,
            IPPROTO_TCP,
            TCP_FASTOPEN,
            std::ptr::addr_of!(value).cast(),
            i32::try_from(size_of::<i32>()).unwrap_or(i32::MAX),
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

/// Off the four targets with a socket option, the option is refused. The dialer degrades to the
/// plain dial-and-write it already performs after `connect`, mirroring how the listener path skips
/// `TCP_FASTOPEN` off Linux, rather than failing the whole proxy dial.
#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos", target_os = "freebsd", windows)))]
const TFO_DIALER_SOCKOPT: &str = "TCP_FASTOPEN";

#[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos", target_os = "freebsd", windows)))]
fn set_tfo_dialer(_fd: usize) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{context_error, to_io_error, DialFn, TfoConn};

    #[test]
    fn context_error_survives_to_io_error_as_timed_out() {
        let io_err = to_io_error(context_error());
        assert_eq!(io_err.kind(), std::io::ErrorKind::TimedOut, "dial timeout must surface as TimedOut, not Other");
    }

    /// Regression for `agent://ReviewS9Ssr`'s finding: `StreamAsOldConn::close()` used to reach
    /// only `shutdown_read`/`shutdown_write`, so a `TfoConn` bridged through `StreamAsOldConn`
    /// never had its own `shutdown_read`/`shutdown_write` (which cancels the pending dial) called
    /// from the right place. `TfoConn` is a native [`Stream`](murmur_common_net::io::Stream)
    /// after the dialer's `Conn` -> `Stream` migration (no `OldConnAsStream` hop is needed or
    /// possible: `TfoConn` never implemented the old `Conn` trait to begin with), so this bridges
    /// it directly, the same way `component::dialer::tfo::dial_tfo`'s callers do.
    #[tokio::test]
    async fn close_through_stream_as_old_conn_bridge_cancels_the_pending_dial() {
        use murmur_common_net::io::StreamAsOldConn;
        use murmur_std_compat::net::Conn as _;
        use tokio_util::sync::CancellationToken;

        let cancel = CancellationToken::new();
        let dial_fn: DialFn =
            std::sync::Arc::new(|_cancel, _early_data| Box::pin(async { Err(anyhow::anyhow!("unused")) }));
        let tfo =
            TfoConn::new(cancel.clone(), tokio::time::Instant::now() + std::time::Duration::from_secs(60), dial_fn);
        let bridged: Box<dyn murmur_std_compat::net::Conn> = Box::new(StreamAsOldConn::new(tfo));

        assert!(!cancel.is_cancelled());
        bridged.close().expect("close");
        assert!(
            cancel.is_cancelled(),
            "StreamAsOldConn::close must reach TfoConn::shutdown_read/write and cancel the pending dial"
        );
    }
}
