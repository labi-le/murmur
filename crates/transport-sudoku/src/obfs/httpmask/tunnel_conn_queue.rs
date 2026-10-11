//! The queued conn is embedded by value and its `Read`/`Write` are promoted onto the poll conn
//! and the stream-split conn.
//!
//! Rust has no field promotion, and both conn types run background tasks
//! (pull and push loops and their stream equivalents) that need to reach the *other* channel
//! half concurrently with the conn's own `Read`/`Write` — so this crate shares one `Arc<QueuedConn>`
//! between the outer conn and its background tasks, and uses `parking_lot::Mutex` (locked only for
//! the duration of a single poll) in place of the read and write locks to keep `poll_read`/`poll_write`
//! usable through `&self`.

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use parking_lot::Mutex;
use tokio::sync::{mpsc, Mutex as AsyncMutex};
use tokio_util::sync::CancellationToken;

use std::net::SocketAddr;

pub(crate) const QUEUED_CONN_PAYLOAD_QUEUE_DEPTH: usize = 64;

#[derive(Clone)]
struct StoredIoError {
    kind: io::ErrorKind,
    message: String,
}

impl StoredIoError {
    fn from_error(err: &anyhow::Error) -> Self {
        match err.downcast_ref::<io::Error>() {
            Some(io_err) => Self { kind: io_err.kind(), message: io_err.to_string() },
            None => Self { kind: io::ErrorKind::Other, message: err.to_string() },
        }
    }

    fn to_io(&self) -> io::Error {
        io::Error::new(self.kind, self.message.clone())
    }

    fn to_anyhow(&self) -> anyhow::Error {
        anyhow::Error::from(self.to_io())
    }
}

pub(crate) fn err_closed_pipe() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "io: read/write on closed pipe")
}

type WriteFuture = Pin<Box<dyn Future<Output = io::Result<usize>> + Send>>;

/// The queued conn provides a connection-like interface backed by internal channels.
///
/// It is used by HTTP tunnel modes (stream/poll) to bridge HTTP request/response bodies to
/// a byte-stream API while preserving write half-close semantics.
pub(crate) struct QueuedConn {
    pub(crate) rxc_tx: mpsc::Sender<Bytes>,
    rxc_rx: Mutex<mpsc::Receiver<Bytes>>,

    write_ch_tx: mpsc::Sender<Bytes>,
    pub(crate) write_ch_rx: AsyncMutex<mpsc::Receiver<Bytes>>,

    pub(crate) closed: CancellationToken,
    pub(crate) write_closed: CancellationToken,
    write_done: CancellationToken,
    read_eof: CancellationToken,

    write_err: Mutex<Option<StoredIoError>>,
    close_err: Mutex<Option<StoredIoError>>,

    read_buf: Mutex<Bytes>,
    write_future: Mutex<Option<WriteFuture>>,

    local_addr: SocketAddr,
    remote_addr: SocketAddr,
}

impl QueuedConn {
    pub(crate) fn new() -> Self {
        let (rxc_tx, rxc_rx) = mpsc::channel(QUEUED_CONN_PAYLOAD_QUEUE_DEPTH);
        let (write_ch_tx, write_ch_rx) = mpsc::channel(QUEUED_CONN_PAYLOAD_QUEUE_DEPTH);
        Self {
            rxc_tx,
            rxc_rx: Mutex::new(rxc_rx),
            write_ch_tx,
            write_ch_rx: AsyncMutex::new(write_ch_rx),
            closed: CancellationToken::new(),
            write_closed: CancellationToken::new(),
            write_done: CancellationToken::new(),
            read_eof: CancellationToken::new(),
            write_err: Mutex::new(None),
            close_err: Mutex::new(None),
            read_buf: Mutex::new(Bytes::new()),
            write_future: Mutex::new(None),
            local_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        }
    }

    // cancel-safe: the half-close was already signalled, so the wait only reports how the write
    // side ended.
    pub(crate) async fn close_write(&self) -> anyhow::Result<()> {
        self.write_closed.cancel();

        if self.write_done.is_cancelled() {
            return self.completed_write_err();
        }
        tokio::select! {
            () = self.write_done.cancelled() => self.completed_write_err(),
            () = self.closed.cancelled() => Err(self.closed_err()),
        }
    }

    pub(crate) fn completed_write_err(&self) -> anyhow::Result<()> {
        let stored = self.write_err.lock().clone();
        match stored {
            Some(stored) => Err(stored.to_anyhow()),
            None => Ok(()),
        }
    }

    pub(crate) fn complete_write(&self, err: Option<anyhow::Error>) {
        if let Some(err) = err {
            let mut guard = self.write_err.lock();
            if guard.is_none() {
                *guard = Some(StoredIoError::from_error(&err));
            }
        }
        self.write_done.cancel();
    }

    pub(crate) fn mark_read_eof(&self) {
        self.read_eof.cancel();
    }

    pub(crate) fn close_with_error(&self, err: Option<anyhow::Error>) {
        if self.closed.is_cancelled() {
            return;
        }
        let err = err.unwrap_or_else(|| anyhow::Error::from(err_closed_pipe()));
        let mut guard = self.close_err.lock();
        if guard.is_none() {
            *guard = Some(StoredIoError::from_error(&err));
        }
        drop(guard);
        self.closed.cancel();
    }

    pub(crate) fn closed_err(&self) -> anyhow::Error {
        let stored = self.close_err.lock().clone();
        match stored {
            Some(stored) => stored.to_anyhow(),
            None => anyhow::Error::from(err_closed_pipe()),
        }
    }

    fn closed_err_io(&self) -> io::Error {
        let stored = self.close_err.lock().clone();
        match stored {
            Some(stored) => stored.to_io(),
            None => err_closed_pipe(),
        }
    }

    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub(crate) fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    pub(crate) fn poll_read(&self, cx: &mut Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut read_buf = self.read_buf.lock();
        let mut rxc_rx = self.rxc_rx.lock();

        if read_buf.is_empty() {
            if let Ok(chunk) = rxc_rx.try_recv() {
                *read_buf = chunk;
            }
        }

        if read_buf.is_empty() {
            match rxc_rx.poll_recv(cx) {
                Poll::Ready(Some(chunk)) => *read_buf = chunk,
                Poll::Ready(None) => return Poll::Ready(Err(self.closed_err_io())),
                Poll::Pending => {
                    let mut read_eof = std::pin::pin!(self.read_eof.cancelled());
                    if read_eof.as_mut().poll(cx).is_ready() {
                        return match rxc_rx.try_recv() {
                            Ok(chunk) => {
                                *read_buf = chunk;
                                let n = buf.remaining().min(read_buf.len());
                                buf.put_slice(&read_buf.split_to(n));
                                drop(read_buf);
                                drop(rxc_rx);
                                Poll::Ready(Ok(()))
                            }
                            Err(_) => Poll::Ready(Ok(())),
                        };
                    }
                    let mut closed = std::pin::pin!(self.closed.cancelled());
                    if closed.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(Err(self.closed_err_io()));
                    }
                    return Poll::Pending;
                }
            }
        }

        let n = buf.remaining().min(read_buf.len());
        buf.put_slice(&read_buf.split_to(n));
        drop(read_buf);
        drop(rxc_rx);
        Poll::Ready(Ok(()))
    }

    pub(crate) fn poll_write(&self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if self.closed.is_cancelled() {
            return Poll::Ready(Err(self.closed_err_io()));
        }
        if self.write_closed.is_cancelled() {
            return Poll::Ready(Err(err_closed_pipe()));
        }

        let mut write_future = self.write_future.lock();
        let future = write_future.get_or_insert_with(|| {
            let tx = self.write_ch_tx.clone();
            let payload = Bytes::copy_from_slice(buf);
            let len = payload.len();
            let closed = self.closed.clone();
            let closed_err = self.closed_err_io();
            let fut: WriteFuture = Box::pin(async move {
                // cancel-safe: a cancelled send only drops a chunk for a conn that is already
                // closing or gone.
                tokio::select! {
                    res = tx.send(payload) => res.map(|()| len).map_err(|_| err_closed_pipe()),
                    () = closed.cancelled() => Err(closed_err),
                }
            });
            fut
        });
        match future.as_mut().poll(cx) {
            Poll::Ready(result) => {
                *write_future = None;
                drop(write_future);
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncRead, AsyncReadExt as _, ReadBuf};

    use super::*;

    struct QueuedConnReader<'a>(&'a QueuedConn);

    impl AsyncRead for QueuedConnReader<'_> {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            self.0.poll_read(cx, buf)
        }
    }

    #[tokio::test]
    async fn queued_conn_read_eof_drains_buffered_payload() {
        let conn = QueuedConn::new();
        conn.rxc_tx.try_send(Bytes::from_static(b"final payload")).expect("queue payload");
        conn.mark_read_eof();

        let mut got = vec![0u8; "final payload".len()];
        QueuedConnReader(&conn).read_exact(&mut got).await.expect("read final payload");
        assert_eq!(got, b"final payload", "final payload mismatch");

        let mut one = [0u8; 1];
        let n = QueuedConnReader(&conn).read(&mut one).await.expect("read after final payload");
        assert_eq!(n, 0, "read after final payload = {n}, want EOF");
    }
}
