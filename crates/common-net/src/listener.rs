use std::any::Any;
use std::fmt;
use std::future::Future;
use std::io;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use futures::FutureExt as _;
use parking_lot::Mutex;
use tokio::sync::{mpsc, Notify};
use tokio_util::sync::CancellationToken;

use murmur_common::once::once_native::Once;
use murmur_common::shared_conn::SharedConn;
use murmur_std_compat::net::{Addr, Conn, Listener};

/// The connection handler of [`new_handle_context_listener`]. The conn is passed as a
/// [`SharedConn`], which the framework can also close when the handler fails.
pub type HandleFn = Arc<
    dyn Fn(CancellationToken, SharedConn) -> Pin<Box<dyn Future<Output = anyhow::Result<SharedConn>> + Send>>
        + Send
        + Sync,
>;

/// The panic log, which receives the value recovered from a panic.
pub type PanicLogFn = Arc<dyn Fn(&(dyn Any + Send)) + Send + Sync>;

fn err_net_closed() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "use of closed network connection")
}

/// The stored accept error, handed out again on every call.
#[derive(Debug)]
struct SharedError(Arc<io::Error>);

impl fmt::Display for SharedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for SharedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.0)
    }
}

pub struct HandleContextListener {
    listener: Arc<dyn Listener>,
    ctx: CancellationToken,
    /// The conns taken off the listener, cleared once the channel is closed.
    conns: Mutex<Option<mpsc::Receiver<Box<dyn Conn>>>>,
    conns_tx: mpsc::Sender<Box<dyn Conn>>,
    conn_ready: Arc<Notify>,
    closed: CancellationToken,
    err: Arc<Mutex<Option<Arc<io::Error>>>>,
    once: Once,
    handle: HandleFn,
    panic_log: PanicLogFn,
}

impl fmt::Debug for HandleContextListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandleContextListener").finish_non_exhaustive()
    }
}

impl HandleContextListener {
    fn init(&self) {
        let listener = Arc::clone(&self.listener);
        let ctx = self.ctx.clone();
        let conns_tx = self.conns_tx.clone();
        let conn_ready = Arc::clone(&self.conn_ready);
        let closed = self.closed.clone();
        let err = Arc::clone(&self.err);
        let handle = Arc::clone(&self.handle);
        let panic_log = Arc::clone(&self.panic_log);

        tokio::spawn(async move {
            loop {
                let conn = match listener.accept().await {
                    Ok(conn) => conn,
                    Err(accept_err) => {
                        // The error is stored and the channel closed.
                        *err.lock() = Some(Arc::new(accept_err));
                        closed.cancel();
                        return;
                    }
                };
                let ctx = ctx.clone();
                let conns_tx = conns_tx.clone();
                let conn_ready = Arc::clone(&conn_ready);
                let handle = Arc::clone(&handle);
                let panic_log = Arc::clone(&panic_log);
                tokio::spawn(async move {
                    let conn = SharedConn::from_boxed(conn);
                    let result = AssertUnwindSafe(handle(ctx, conn.clone())).catch_unwind().await;
                    match result {
                        Ok(Ok(handled)) => {
                            // the send on a closed channel panics into `recover`, which logs the
                            // race and closes the conn the handler was given.
                            if conns_tx.send(Box::new(handled)).await.is_err() {
                                panic_log(&"send on closed channel");
                                let _ = conn.close();
                            } else {
                                conn_ready.notify_one();
                            }
                        }
                        Ok(Err(_)) => {
                            // handle failed, close the underlying connection.
                            let _ = conn.close();
                        }
                        Err(payload) => {
                            panic_log(&*payload);
                            let _ = conn.close();
                        }
                    }
                });
            }
        });
    }

    /// The stored accept error, or an `ErrClosed` when the listener ended without one.
    fn replay_err(&self) -> io::Error {
        match self.err.lock().as_ref() {
            Some(err) => io::Error::new(err.kind(), SharedError(Arc::clone(err))),
            None => err_net_closed(),
        }
    }
}

#[async_trait]
impl Listener for HandleContextListener {
    // cancel-safe: a dropped wait re-checks the queue, so a queued conn is never lost.
    async fn accept(&self) -> io::Result<Box<dyn Conn>> {
        self.once.call_once(|| self.init());
        loop {
            {
                let mut guard = self.conns.lock();
                match guard.as_mut() {
                    Some(conns) => match conns.try_recv() {
                        Ok(conn) => return Ok(conn),
                        Err(mpsc::error::TryRecvError::Empty) => {}
                        Err(mpsc::error::TryRecvError::Disconnected) => return Err(self.replay_err()),
                    },
                    None => return Err(self.replay_err()),
                }
            }
            if self.closed.is_cancelled() {
                return Err(self.replay_err());
            }
            tokio::select! {
                () = self.conn_ready.notified() => {}
                () = self.closed.cancelled() => return Err(self.replay_err()),
            }
        }
    }

    fn close(&self) -> io::Result<()> {
        self.ctx.cancel();
        self.once.call_once(|| {
            // l.init has not been called yet, so close related resources directly.
            *self.err.lock() = Some(Arc::new(err_net_closed()));
            self.closed.cancel();
        });
        let result = self.listener.close();

        // The listener is closed now, so every conn left in the channel has to be closed too.
        let taken = self.conns.lock().take();
        if let Some(mut conns) = taken {
            while let Ok(conn) = conns.try_recv() {
                let panic_log = Arc::clone(&self.panic_log);
                tokio::spawn(async move {
                    if let Err(payload) = catch_unwind(AssertUnwindSafe(|| conn.close())) {
                        panic_log(&*payload);
                    }
                });
            }
        }
        result
    }

    fn addr(&self) -> io::Result<Box<dyn Addr>> {
        self.listener.addr()
    }
}

pub fn new_handle_context_listener(
    ctx: &CancellationToken,
    l: Box<dyn Listener>,
    handle: HandleFn,
    panic_log: PanicLogFn,
) -> HandleContextListener {
    let ctx = ctx.child_token();
    let (conns_tx, conns) = mpsc::channel(1);
    HandleContextListener {
        listener: Arc::from(l),
        ctx,
        conns: Mutex::new(Some(conns)),
        conns_tx,
        conn_ready: Arc::new(Notify::new()),
        closed: CancellationToken::new(),
        err: Arc::new(Mutex::new(None)),
        once: Once::new(),
        handle,
        panic_log,
    }
}
