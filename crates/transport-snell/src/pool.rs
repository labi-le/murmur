//! A pool of half-closed Snell connections reused across requests.

use std::fmt;
use std::future::{poll_fn, Future};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;

use murmur_component::pool::pool;
use murmur_std_compat::net::{Addr, Conn as NetConn};

use super::snell::{half_close, is_zero_chunk, Snell, END_SIGNAL};

const POOL_CONN_NEW: i32 = 0;
const POOL_CONN_REUSABLE: i32 = 1;
const POOL_CONN_CLOSED: i32 = 2;

pub struct Pool {
    pool: pool::Pool<Snell>,
}

impl fmt::Debug for Pool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pool").finish_non_exhaustive()
    }
}

impl Pool {
    // NOT cancel-safe: on a pool miss the wrapped `get_context` may already be opening a connection, which a dropped call abandons.
    pub async fn get(self: &Arc<Self>) -> anyhow::Result<PoolConn> {
        self.get_context(&CancellationToken::new()).await
    }

    pub async fn get_context(self: &Arc<Self>, ctx: &CancellationToken) -> anyhow::Result<PoolConn> {
        let elm = self.pool.get_context(ctx.clone()).await?;
        Ok(PoolConn::new(elm, Arc::clone(self)))
    }

    pub async fn put(&self, mut conn: Snell) {
        if half_close(&mut conn).await.is_err() {
            let _ = conn.close();
            return;
        }

        self.put_conn(conn);
    }

    fn put_conn(&self, conn: Snell) {
        self.pool.put(conn);
    }
}

/// The one-shot close flag plus the values it memoizes.
struct CloseWriteState {
    started: bool,
    reusable: bool,
    err: Option<String>,
}

/// The one-shot close flag plus the error it records.
struct CloseState {
    started: bool,
    err: Option<String>,
}

pub struct PoolConn {
    inner: Arc<PoolConnInner>,
}

impl fmt::Debug for PoolConn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PoolConn").finish_non_exhaustive()
    }
}

struct PoolConnInner {
    /// The embedded `Snell`; `close` takes `&self` while the half-close write needs
    /// `&mut`, so the conn sits behind the lock the pool return also takes it out of.
    snell: Mutex<Option<Snell>>,
    pool: Arc<Pool>,
    close_write_once: tokio::sync::Mutex<CloseWriteState>,
    close_once: tokio::sync::Mutex<CloseState>,
    reusable_state: AtomicI32,
    peer_closed: AtomicBool,
}

impl PoolConn {
    pub(crate) fn new(snell: Snell, pool: Arc<Pool>) -> Self {
        Self {
            inner: Arc::new(PoolConnInner {
                snell: Mutex::new(Some(snell)),
                pool,
                close_write_once: tokio::sync::Mutex::new(CloseWriteState {
                    started: false,
                    reusable: false,
                    err: None,
                }),
                close_once: tokio::sync::Mutex::new(CloseState { started: false, err: None }),
                reusable_state: AtomicI32::new(POOL_CONN_NEW),
                peer_closed: AtomicBool::new(false),
            }),
        }
    }

    pub fn mark_reusable(&self) {
        let _ = self.inner.reusable_state.compare_exchange(
            POOL_CONN_NEW,
            POOL_CONN_REUSABLE,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
    }

    ///
    /// `murmur_std_compat::net::Conn::close` cannot await the half-close write, so an owned caller
    /// drives this directly and the trait method defers it to a task.
    pub async fn close_async(&mut self) -> io::Result<()> {
        pool_conn_close(&self.inner).await
    }

    pub async fn close_write_async(&mut self) -> io::Result<()> {
        let (_, err) = pool_conn_close_write(&self.inner).await;
        err
    }

    fn lock(&self) -> parking_lot::MutexGuard<'_, Option<Snell>> {
        self.inner.snell.lock()
    }
}

/// Reads from the pooled conn; a zero chunk reads as EOF.
fn poll_pool_conn_read(inner: &PoolConnInner, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
    let mut guard = inner.snell.lock();
    let Some(snell) = guard.as_mut() else {
        return Poll::Ready(Err(io::Error::other("snell: pool conn closed")));
    };
    let result = match Pin::new(snell).poll_read(cx, buf) {
        Poll::Ready(Err(err)) if is_zero_chunk(&err) => {
            inner.peer_closed.store(true, Ordering::SeqCst);
            Poll::Ready(Ok(()))
        }
        other @ (Poll::Ready(_) | Poll::Pending) => other,
    };
    drop(guard);
    result
}

impl AsyncRead for PoolConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        poll_pool_conn_read(&self.get_mut().inner, cx, buf)
    }
}

impl AsyncWrite for PoolConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let inner = &self.get_mut().inner;
        let mut guard = inner.snell.lock();
        match guard.as_mut() {
            Some(snell) => Pin::new(snell).poll_write(cx, buf),
            None => Poll::Ready(Err(io::Error::other("snell: pool conn closed"))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let inner = &self.get_mut().inner;
        let mut guard = inner.snell.lock();
        match guard.as_mut() {
            Some(snell) => Pin::new(snell).poll_flush(cx),
            None => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let inner = &self.get_mut().inner;
        let mut guard = inner.snell.lock();
        match guard.as_mut() {
            Some(snell) => Pin::new(snell).poll_shutdown(cx),
            None => Poll::Ready(Ok(())),
        }
    }
}

impl NetConn for PoolConn {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        match self.lock().as_ref() {
            Some(snell) => snell.local_addr(),
            None => Err(io::Error::other("snell: pool conn closed")),
        }
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        match self.lock().as_ref() {
            Some(snell) => snell.remote_addr(),
            None => Err(io::Error::other("snell: pool conn closed")),
        }
    }

    fn close(&self) -> io::Result<()> {
        let inner = Arc::clone(&self.inner);
        tokio::spawn(async move {
            let _ = pool_conn_close(&inner).await;
        });
        Ok(())
    }

    fn close_read(&self) -> io::Result<()> {
        match self.lock().as_ref() {
            Some(snell) => snell.close_read(),
            None => Err(io::Error::other("snell: pool conn closed")),
        }
    }

    fn close_write(&self) -> io::Result<()> {
        let inner = Arc::clone(&self.inner);
        tokio::spawn(async move {
            let _ = pool_conn_close_write(&inner).await;
        });
        Ok(())
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        match self.lock().as_ref() {
            Some(snell) => snell.set_deadline(deadline),
            None => Err(io::Error::other("snell: pool conn closed")),
        }
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        match self.lock().as_ref() {
            Some(snell) => snell.set_read_deadline(deadline),
            None => Err(io::Error::other("snell: pool conn closed")),
        }
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        match self.lock().as_ref() {
            Some(snell) => snell.set_write_deadline(deadline),
            None => Err(io::Error::other("snell: pool conn closed")),
        }
    }
}

async fn pool_conn_close_write(inner: &PoolConnInner) -> (bool, io::Result<()>) {
    let mut state = inner.close_write_once.lock().await;
    if state.started {
        return match &state.err {
            Some(err) => (state.reusable, Err(io::Error::other(err.clone()))),
            None => (state.reusable, Ok(())),
        };
    }
    state.started = true;

    if inner.reusable_state.swap(POOL_CONN_CLOSED, Ordering::SeqCst) != POOL_CONN_REUSABLE {
        let err = match inner.snell.lock().as_ref() {
            Some(snell) => snell.close(),
            None => Ok(()),
        };
        state.reusable = false;
        state.err = err.as_ref().err().map(ToString::to_string);
        drop(state);
        return (false, err);
    }

    state.reusable = true;
    let err = poll_fn(|cx| poll_write_zero_chunk(&inner.snell, cx)).await;
    state.err = err.as_ref().err().map(ToString::to_string);
    drop(state);
    (true, err)
}

/// Write the zero-length end signal through the conn the pool holds behind its lock.
fn poll_write_zero_chunk(snell: &Mutex<Option<Snell>>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
    let mut guard = snell.lock();
    match guard.as_mut() {
        Some(snell) => match Pin::new(snell).poll_write(cx, END_SIGNAL) {
            Poll::Ready(result) => Poll::Ready(result.map(|_| ())),
            Poll::Pending => Poll::Pending,
        },
        None => Poll::Ready(Err(io::Error::other("snell: pool conn closed"))),
    }
}

/// Closes the pooled conn once.
async fn pool_conn_close(inner: &PoolConnInner) -> io::Result<()> {
    let mut state = inner.close_once.lock().await;
    if state.started {
        return match &state.err {
            Some(err) => Err(io::Error::other(err.clone())),
            None => Ok(()),
        };
    }
    state.started = true;

    let (reusable, close_write_err) = pool_conn_close_write(inner).await;
    if let Err(err) = close_write_err {
        state.err = Some(err.to_string());
        if let Some(snell) = inner.snell.lock().as_ref() {
            let _ = snell.close();
        }
        drop(state);
        return Err(err);
    }
    drop(state);
    if !reusable {
        return Ok(());
    }

    if !inner.peer_closed.load(Ordering::SeqCst) {
        if let Some(snell) = inner.snell.lock().as_ref() {
            let _ = snell.close();
        }
        return Ok(());
    }

    // A read deadline breaks a stalled bidirectional copy between client and server; it is
    // cleared before the connection is reused so a timeout does not leak into the next request.
    let snell = {
        let mut guard = inner.snell.lock();
        match guard.as_mut() {
            Some(snell) => {
                let _ = snell.set_read_deadline(None);
                snell.reply = false;
                guard.take()
            }
            None => None,
        }
    };
    if let Some(snell) = snell {
        inner.pool.put_conn(snell);
    }
    Ok(())
}

pub fn new_pool<F, Fut>(factory: F) -> Arc<Pool>
where
    F: Fn(CancellationToken) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = anyhow::Result<Snell>> + Send + 'static,
{
    let p = pool::new::<Snell, _, _>(
        factory,
        vec![
            pool::with_age(15000),
            pool::with_size(10),
            pool::with_evict(|item: Snell| {
                let _ = item.close();
            }),
        ],
    );

    Arc::new(Pool { pool: p })
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::task::{Context, Poll};

    use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

    use crate::snell::{Snell, SnellConn, COMMAND_CONNECT_V2, COMMAND_TUNNEL, VERSION};
    use murmur_common_net::io::OldConnAsStream;
    use murmur_transport_shadowsocks::shadowaead::stream::ErrZeroChunk;

    use super::*;

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum ReadError {
        ZeroChunk,
    }

    impl ReadError {
        /// The zero-chunk value is reported as the same `io::Error` a read hands back.
        fn to_io_error(self) -> io::Error {
            match self {
                ReadError::ZeroChunk => io::Error::other(ErrZeroChunk),
            }
        }
    }

    #[derive(Default)]
    struct RecordingConn {
        writes: AtomicUsize,
        reads: AtomicUsize,
        read_data: Mutex<Vec<u8>>,
        read_err: Option<ReadError>,
        closed: AtomicBool,
    }

    impl RecordingConn {
        fn new(read_data: Vec<u8>, read_err: Option<ReadError>) -> RecordingConn {
            RecordingConn { read_data: Mutex::new(read_data), read_err, ..Default::default() }
        }
    }

    struct SharedRecordingConn(Arc<RecordingConn>);

    impl AsyncRead for SharedRecordingConn {
        fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            let mut data = self.0.read_data.lock();
            self.0.reads.fetch_add(1, Ordering::SeqCst);
            if !data.is_empty() {
                let n = buf.remaining().min(data.len());
                buf.put_slice(&data[..n]);
                data.drain(..n);
                return Poll::Ready(Ok(()));
            }
            match self.0.read_err {
                Some(err) => Poll::Ready(Err(err.to_io_error())),
                None => Poll::Ready(Ok(())),
            }
        }
    }

    impl AsyncWrite for SharedRecordingConn {
        fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            self.0.writes.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl NetConn for SharedRecordingConn {
        fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(RecordingAddr("local")))
        }

        fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(RecordingAddr("remote")))
        }

        fn close(&self) -> io::Result<()> {
            self.0.closed.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    struct ZeroChunkConn;

    impl AsyncRead for ZeroChunkConn {
        fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Err(io::Error::other(ErrZeroChunk)))
        }
    }

    impl AsyncWrite for ZeroChunkConn {
        fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl NetConn for ZeroChunkConn {
        fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(RecordingAddr("local")))
        }

        fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(RecordingAddr("remote")))
        }

        fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    #[derive(Debug)]
    struct RecordingAddr(&'static str);

    impl Addr for RecordingAddr {
        fn network(&self) -> &str {
            self.0
        }

        fn string(&self) -> String {
            self.0.to_owned()
        }
    }

    struct TestPool {
        pool: Arc<Pool>,
        factory_calls: Arc<AtomicUsize>,
    }

    fn snell_with(conn: Arc<RecordingConn>) -> Snell {
        Snell::new(SnellConn::Plain(Box::new(OldConnAsStream(SharedRecordingConn(conn)))))
    }

    /// The factory's error case: reaching it at all fails the test.
    fn failing_factory_pool() -> Arc<Pool> {
        new_pool(|_ctx: CancellationToken| async { Err(anyhow::anyhow!("factory should not be called")) })
    }

    fn factory_pool(factory_conn: Arc<RecordingConn>) -> TestPool {
        let factory_calls = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&factory_calls);
        let pool = new_pool(move |_ctx: CancellationToken| {
            let factory_conn = Arc::clone(&factory_conn);
            let calls = Arc::clone(&calls);
            async move {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(snell_with(factory_conn))
            }
        });
        TestPool { pool, factory_calls }
    }

    async fn write<W>(conn: &mut W, data: &[u8]) -> io::Result<usize>
    where
        W: AsyncWrite + Unpin + ?Sized,
    {
        AsyncWriteExt::write(conn, data).await
    }

    async fn read_eof<W>(conn: &mut W) -> io::Result<usize>
    where
        W: AsyncRead + Unpin + ?Sized,
    {
        tokio::io::AsyncReadExt::read(conn, &mut [0u8; 1]).await
    }

    #[tokio::test]
    async fn test_pool_conn_close_is_idempotent() {
        let raw_conn = Arc::new(RecordingConn::new(vec![COMMAND_TUNNEL], Some(ReadError::ZeroChunk)));
        let pool = failing_factory_pool();
        let mut conn = PoolConn::new(snell_with(Arc::clone(&raw_conn)), Arc::clone(&pool));

        if let Err(err) = write(&mut conn, &[VERSION, COMMAND_CONNECT_V2, 0]).await {
            panic!("{err}");
        }
        conn.mark_reusable();
        match read_eof(&mut conn).await {
            Ok(0) => {}
            Ok(n) => panic!("expected peer half-close before pooling, got {n} bytes"),
            Err(err) => panic!("expected peer half-close before pooling, got {err}"),
        }
        if let Err(err) = conn.close_async().await {
            panic!("{err}");
        }
        if let Err(err) = conn.close_async().await {
            panic!("{err}");
        }

        assert_eq!(
            2,
            raw_conn.writes.load(Ordering::SeqCst),
            "close should send the request and one half-close record"
        );
        assert_eq!(2, raw_conn.reads.load(Ordering::SeqCst), "close should observe the peer half-close before pooling");

        let got = pool.get().await;
        assert!(got.is_ok(), "the closed connection should be back in the pool");
    }

    #[tokio::test]
    async fn test_pool_conn_close_before_request_closes_raw_connection() {
        let raw_conn = Arc::new(RecordingConn::default());
        let factory_conn = Arc::new(RecordingConn::default());
        let pool = factory_pool(Arc::clone(&factory_conn));
        let mut conn = PoolConn::new(snell_with(Arc::clone(&raw_conn)), Arc::clone(&pool.pool));

        if let Err(err) = conn.close_async().await {
            panic!("{err}");
        }
        if let Err(err) = conn.close_async().await {
            panic!("{err}");
        }

        assert_eq!(0, raw_conn.writes.load(Ordering::SeqCst), "close before request should not send half-close record");
        assert!(raw_conn.closed.load(Ordering::SeqCst), "close before request should close the raw connection");

        let mut got = match pool.pool.get().await {
            Ok(got) => got,
            Err(err) => panic!("{err}"),
        };
        if let Err(err) = write(&mut got, &[0]).await {
            panic!("{err}");
        }
        assert_eq!(1, pool.factory_calls.load(Ordering::SeqCst), "the pool should be empty");
        assert_eq!(
            1,
            factory_conn.writes.load(Ordering::SeqCst),
            "unstarted connection should not be returned to the pool"
        );
    }

    #[tokio::test]
    async fn test_pool_conn_close_after_request_before_reusable_closes_raw_connection() {
        let raw_conn = Arc::new(RecordingConn::default());
        let factory_conn = Arc::new(RecordingConn::default());
        let pool = factory_pool(Arc::clone(&factory_conn));
        let mut conn = PoolConn::new(snell_with(Arc::clone(&raw_conn)), Arc::clone(&pool.pool));

        if let Err(err) = write(&mut conn, &[VERSION, COMMAND_CONNECT_V2, 0]).await {
            panic!("{err}");
        }
        if let Err(err) = conn.close_async().await {
            panic!("{err}");
        }

        assert_eq!(1, raw_conn.writes.load(Ordering::SeqCst), "close before reusable should only send the request");
        assert!(raw_conn.closed.load(Ordering::SeqCst), "close before reusable should close the raw connection");

        let mut got = match pool.pool.get().await {
            Ok(got) => got,
            Err(err) => panic!("{err}"),
        };
        if let Err(err) = write(&mut got, &[0]).await {
            panic!("{err}");
        }
        assert_eq!(1, pool.factory_calls.load(Ordering::SeqCst), "the pool should be empty");
        assert_eq!(
            1,
            factory_conn.writes.load(Ordering::SeqCst),
            "connection closed before reusable should not be returned to the pool"
        );
    }

    #[tokio::test]
    async fn test_pool_conn_close_write_before_request_closes_raw_connection() {
        let raw_conn = Arc::new(RecordingConn::default());
        let factory_conn = Arc::new(RecordingConn::default());
        let pool = factory_pool(Arc::clone(&factory_conn));
        let mut conn = PoolConn::new(snell_with(Arc::clone(&raw_conn)), Arc::clone(&pool.pool));

        if let Err(err) = conn.close_write_async().await {
            panic!("{err}");
        }
        assert_eq!(
            0,
            raw_conn.writes.load(Ordering::SeqCst),
            "CloseWrite before request should not send half-close record"
        );
        assert!(raw_conn.closed.load(Ordering::SeqCst), "CloseWrite before request should close the raw connection");

        // MarkReusable must not revive a connection that already took the raw-close path.
        conn.mark_reusable();
        if let Err(err) = conn.close_async().await {
            panic!("{err}");
        }
        let mut got = match pool.pool.get().await {
            Ok(got) => got,
            Err(err) => panic!("{err}"),
        };
        if let Err(err) = write(&mut got, &[0]).await {
            panic!("{err}");
        }
        assert_eq!(
            1,
            factory_conn.writes.load(Ordering::SeqCst),
            "unstarted connection should not be returned to the pool"
        );
    }

    #[tokio::test]
    async fn test_pool_conn_close_write_does_not_return_connection_to_pool() {
        let raw_conn = Arc::new(RecordingConn::new(Vec::new(), Some(ReadError::ZeroChunk)));
        let factory_conn = Arc::new(RecordingConn::default());
        let pool = factory_pool(Arc::clone(&factory_conn));
        let snell = {
            let mut snell = snell_with(Arc::clone(&raw_conn));
            snell.reply = true;
            snell
        };
        let mut conn = PoolConn::new(snell, Arc::clone(&pool.pool));

        if let Err(err) = write(&mut conn, &[VERSION, COMMAND_CONNECT_V2, 0]).await {
            panic!("{err}");
        }
        conn.mark_reusable();
        if let Err(err) = conn.close_write_async().await {
            panic!("{err}");
        }

        let mut got = match pool.pool.get().await {
            Ok(got) => got,
            Err(err) => panic!("{err}"),
        };
        if let Err(err) = write(&mut got, &[0]).await {
            panic!("{err}");
        }
        assert_eq!(
            1,
            factory_conn.writes.load(Ordering::SeqCst),
            "CloseWrite should not put the active connection back into the pool"
        );
        assert_eq!(
            2,
            raw_conn.writes.load(Ordering::SeqCst),
            "CloseWrite should send the request and one half-close record"
        );

        match read_eof(&mut conn).await {
            Ok(0) => {}
            Ok(n) => panic!("expected peer half-close before pooling, got {n} bytes"),
            Err(err) => panic!("expected peer half-close before pooling, got {err}"),
        }
        if let Err(err) = conn.close_async().await {
            panic!("{err}");
        }
        let got = pool.pool.get().await;
        assert!(got.is_ok(), "Close should return the connection to the pool after CloseWrite");
        assert_eq!(
            2,
            raw_conn.writes.load(Ordering::SeqCst),
            "Close after CloseWrite should not send another half-close record"
        );
        assert_eq!(1, raw_conn.reads.load(Ordering::SeqCst), "Close should observe the peer half-close before pooling");
    }

    #[tokio::test]
    async fn test_pool_conn_close_without_peer_half_close_closes_raw_connection() {
        let raw_conn = Arc::new(RecordingConn::default());
        let factory_conn = Arc::new(RecordingConn::default());
        let pool = factory_pool(Arc::clone(&factory_conn));
        let mut conn = PoolConn::new(snell_with(Arc::clone(&raw_conn)), Arc::clone(&pool.pool));

        if let Err(err) = write(&mut conn, &[VERSION, COMMAND_CONNECT_V2, 0]).await {
            panic!("{err}");
        }
        conn.mark_reusable();
        if let Err(err) = conn.close_async().await {
            panic!("{err}");
        }

        assert!(
            raw_conn.closed.load(Ordering::SeqCst),
            "connection without peer half-close should close the raw connection"
        );
        let mut got = match pool.pool.get().await {
            Ok(got) => got,
            Err(err) => panic!("{err}"),
        };
        if let Err(err) = write(&mut got, &[0]).await {
            panic!("{err}");
        }
        assert_eq!(
            1,
            factory_conn.writes.load(Ordering::SeqCst),
            "connection without peer half-close should not be returned to the pool"
        );
    }

    #[tokio::test]
    async fn test_pool_conn_read_zero_chunk_returns_eof() {
        let pool = failing_factory_pool();
        let snell = {
            let mut snell = Snell::new(SnellConn::Plain(Box::new(OldConnAsStream(ZeroChunkConn))));
            snell.reply = true;
            snell
        };
        let mut conn = PoolConn::new(snell, pool);

        match read_eof(&mut conn).await {
            Ok(0) => {}
            Ok(n) => panic!("read length mismatch: {n}"),
            Err(err) => panic!("expected EOF for zero chunk, got {err}"),
        }
    }
}
