use std::fmt;
use std::io;

use async_trait::async_trait;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;

use murmur_common::contextutils::after_func;
use murmur_common::shared_conn::SharedConn;
use murmur_compat::sing_buf::Buffer;
use murmur_std_compat::net::Conn;

use super::sing::{relay_inner, ExtendedConn, UpstreamNode};

impl UpstreamNode for SharedConn {}

#[async_trait]
impl ExtendedConn for SharedConn {
    async fn read_buffer(&mut self, buffer: &mut Buffer) -> io::Result<()> {
        Self::read_buffer(self, buffer).await
    }

    async fn write_buffer(&mut self, buffer: &mut Buffer) -> io::Result<()> {
        let result = Self::write_all(self, buffer.bytes()).await;
        buffer.release();
        result
    }
}

/// The completion signal returned by [`setup_context_for_conn`].
pub struct SetupContextDone {
    stop: Option<Box<dyn Fn() -> bool + Send + Sync>>,
    stopc: Option<oneshot::Receiver<()>>,
    ctx: CancellationToken,
}

impl fmt::Debug for SetupContextDone {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SetupContextDone").finish_non_exhaustive()
    }
}

impl SetupContextDone {
    /// Awaits the registered callback, then replaces the caller's
    /// error with the context error.
    pub async fn call(&mut self, input_err: &mut Option<anyhow::Error>) {
        let Some(stop) = self.stop.take() else {
            return;
        };
        if !stop() {
            if let Some(stopc) = self.stopc.take() {
                let _ = stopc.await;
            }
            if self.ctx.is_cancelled() && input_err.is_some() {
                *input_err = Some(anyhow::anyhow!("context canceled"));
            }
        }
    }
}

/// Closes the conn when `ctx` is cancelled before the returned handle is called. The caller's
/// conn becomes a [`SharedConn`] so the cancellation hook can reach it.
#[must_use]
pub fn setup_context_for_conn(ctx: &CancellationToken, conn: SharedConn) -> SetupContextDone {
    let (stopc, stopc_rx) = oneshot::channel();
    let stop = after_func(ctx, move || {
        let _ = conn.close();
        let _ = stopc.send(());
    });
    SetupContextDone { stop: Some(Box::new(stop)), stopc: Some(stopc_rx), ctx: ctx.clone() }
}

/// Relays both directions until one finishes or `ctx` is cancelled, returning an error when the
/// cancellation caused the stop.
pub async fn relay_context(
    ctx: &CancellationToken,
    left_conn: &mut dyn Conn,
    right_conn: &mut dyn Conn,
) -> anyhow::Result<()> {
    let cancelled = relay_inner(Some(ctx), left_conn, right_conn).await;
    if cancelled || ctx.is_cancelled() {
        return Err(anyhow::anyhow!("context canceled"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::AsyncWriteExt;

    use super::*;
    use crate::sing::pipe;

    const CANCEL_DELAY: Duration = Duration::from_millis(100);
    const WAIT_TIMEOUT: Duration = Duration::from_millis(100);
    const TIMEOUT_DELAY: Duration = Duration::from_millis(200);

    /// Reads one byte through the conn the context interrupter was set up for.
    async fn test_read(ctx: &CancellationToken, conn: SharedConn) -> Option<anyhow::Error> {
        let mut done = setup_context_for_conn(ctx, conn.clone());
        let mut buf = [0u8; 1];
        let mut err = SharedConn::read(&conn, &mut buf).await.err().map(anyhow::Error::new);
        done.call(&mut err).await;
        err
    }

    #[tokio::test]
    async fn setup_context_for_conn_with_cancel() {
        let (c1, c2) = pipe();
        let ctx = CancellationToken::new();
        let read_ctx = ctx.clone();
        let mut read_task =
            tokio::spawn(async move { test_read(&read_ctx, SharedConn::from_boxed(Box::new(c1))).await });

        tokio::select! {
            _ = &mut read_task => panic!("conn closed before cancel"),
            () = tokio::time::sleep(CANCEL_DELAY) => ctx.cancel(),
        }

        tokio::select! {
            result = &mut read_task => {
                let err = result.expect("the read task joins").expect("the read is canceled");
                assert_eq!("context canceled", err.to_string());
            }
            () = tokio::time::sleep(WAIT_TIMEOUT) => panic!("conn not be canceled"),
        }

        let _ = c2.close();
    }

    #[tokio::test]
    async fn setup_context_for_conn_with_timeout_1() {
        let (c1, c2) = pipe();
        let ctx = CancellationToken::new();
        let cancel_ctx = ctx.clone();
        let cancel_task = tokio::spawn(async move {
            tokio::time::sleep(CANCEL_DELAY).await;
            cancel_ctx.cancel();
        });
        let read_ctx = ctx.clone();
        let mut read_task =
            tokio::spawn(async move { test_read(&read_ctx, SharedConn::from_boxed(Box::new(c1))).await });

        tokio::select! {
            result = &mut read_task => {
                assert!(ctx.is_cancelled(), "conn closed before timeout");
                // A cancellation carries no deadline distinction here.
                let err = result.expect("the read task joins").expect("the read is canceled");
                assert_eq!("context canceled", err.to_string());
            }
            () = tokio::time::sleep(TIMEOUT_DELAY) => panic!("conn not be canceled"),
        }

        cancel_task.await.expect("the cancel task joins");
        let _ = c2.close();
    }

    #[tokio::test]
    async fn setup_context_for_conn_with_timeout_2() {
        let (c1, c2) = pipe();
        let ctx = CancellationToken::new();
        let cancel_ctx = ctx.clone();
        let cancel_task = tokio::spawn(async move {
            tokio::time::sleep(TIMEOUT_DELAY).await;
            cancel_ctx.cancel();
        });
        let read_ctx = ctx.clone();
        let mut read_task =
            tokio::spawn(async move { test_read(&read_ctx, SharedConn::from_boxed(Box::new(c1))).await });

        let mut c2 = c2;
        tokio::select! {
            _ = &mut read_task => panic!("conn closed before cancel"),
            () = tokio::time::sleep(CANCEL_DELAY) => {
                c2.write_all(&[0u8]).await.expect("the peer write succeeds");
            }
        }

        tokio::select! {
            result = &mut read_task => {
                let err = result.expect("the read task joins");
                assert!(!ctx.is_cancelled(), "the context was not cancelled in time");
                assert!(err.is_none(), "the read is not an error");
            }
            () = tokio::time::sleep(TIMEOUT_DELAY) => panic!("conn not be canceled"),
        }

        cancel_task.await.expect("the cancel task joins");
        let _ = c2.close();
    }

    #[tokio::test]
    async fn relay_context_with_cancel() {
        let (mut left_conn, left_peer) = pipe();
        let (mut right_conn, right_peer) = pipe();
        let ctx = CancellationToken::new();
        let relay_ctx = ctx.clone();
        let mut relay_task =
            tokio::spawn(async move { relay_context(&relay_ctx, &mut left_conn, &mut right_conn).await });

        tokio::select! {
            _ = &mut relay_task => panic!("relay stopped before cancel"),
            () = tokio::time::sleep(CANCEL_DELAY) => ctx.cancel(),
        }

        tokio::select! {
            result = &mut relay_task => {
                let err = result.expect("the relay task joins").expect_err("the relay is canceled");
                assert_eq!("context canceled", err.to_string());
            }
            () = tokio::time::sleep(WAIT_TIMEOUT) => panic!("relay was not canceled"),
        }

        let _ = left_peer.close();
        let _ = right_peer.close();
    }
}
