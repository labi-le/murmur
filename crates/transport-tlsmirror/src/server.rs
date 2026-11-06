use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use anyhow::{anyhow, Result};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use murmur_std_compat::net::Conn as NetConn;

use super::config::ServerConfig;
use super::conn::{new_hidden_conn, Conn};
use super::enrollment::enrollment_processor_for;
use super::mirror::{hrtb_hook, new_mirror_conn, FnHook, MessageHook, MirrorConn, SharedConn};
use super::record::{Record, RECORD_TYPE_HANDSHAKE};

// NOT cancel-safe: a dropped future leaves the mirror running; only the cancellation arms close it.
pub async fn serve_conn_ready(
    ctx: &CancellationToken,
    carrier_conn: Box<dyn NetConn>,
    forward_conn: Box<dyn NetConn>,
    cfg: ServerConfig,
) -> Result<Conn> {
    let (ready_tx, mut ready_rx) = mpsc::channel::<Conn>(1);
    let mirror = serve_conn(ctx, carrier_conn, forward_conn, cfg, move |hidden: Conn| {
        let _ = ready_tx.try_send(hidden);
    })?;
    tokio::select! {
        Some(hidden) = ready_rx.recv() => Ok(hidden),
        () = mirror.ctx().cancelled() => Err(anyhow!("context canceled")),
        () = ctx.cancelled() => {
            let _ = mirror.close();
            Err(anyhow!("context canceled"))
        }
    }
}

fn serve_conn(
    ctx: &CancellationToken,
    carrier_conn: Box<dyn NetConn>,
    forward_conn: Box<dyn NetConn>,
    cfg: ServerConfig,
    on_ready: impl Fn(Conn) + Send + Sync + 'static,
) -> Result<Arc<MirrorConn>> {
    let key = super::config::decode_primary_key(&cfg.primary_key).inspect_err(|_| {
        let _ = carrier_conn.close();
        let _ = forward_conn.close();
    })?;

    let hidden_cell: Arc<OnceLock<Conn>> = Arc::new(OnceLock::new());
    let activated = Arc::new(AtomicBool::new(false));
    let enrolled = Arc::new(AtomicBool::new(false));
    let on_ready = Arc::new(on_ready);

    let inbound_hook: Arc<dyn MessageHook> = {
        let cell = Arc::clone(&hidden_cell);
        let activated = Arc::clone(&activated);
        let on_ready = Arc::clone(&on_ready);
        Arc::new(FnHook(hrtb_hook(move |rec: &mut Record| {
            let cell = Arc::clone(&cell);
            let activated = Arc::clone(&activated);
            let on_ready = Arc::clone(&on_ready);
            Box::pin(async move {
                let Some(hidden) = cell.get().cloned() else {
                    return Err(anyhow!("tlsmirror: hidden conn is not set"));
                };
                let drop = hidden.handle_inbound_record(rec).await?;
                if drop && !activated.swap(true, Ordering::SeqCst) {
                    on_ready(hidden);
                }
                Ok(drop)
            })
        })))
    };

    let enrollment_hook: Arc<dyn MessageHook> = {
        let cell = Arc::clone(&hidden_cell);
        let cfg = cfg.clone();
        let key = key.clone();
        let enrolled = Arc::clone(&enrolled);
        Arc::new(FnHook(hrtb_hook(move |rec: &mut Record| {
            let cell = Arc::clone(&cell);
            let cfg = cfg.clone();
            let key = key.clone();
            let enrolled = Arc::clone(&enrolled);
            Box::pin(async move {
                if cfg.connection_enrolment.is_some()
                    && rec.record_type == RECORD_TYPE_HANDSHAKE
                    && !enrolled.load(Ordering::SeqCst)
                {
                    let Some(hidden) = cell.get().cloned() else {
                        return Err(anyhow!("tlsmirror: hidden conn is not set"));
                    };
                    let Ok((client_random, server_random)) = hidden.mirror().handshake_random() else {
                        return Ok(false);
                    };
                    if let Ok(remove) = enrollment_processor_for(&key).add(client_random, server_random, hidden.clone())
                    {
                        hidden.set_enrollment_remove(remove);
                        enrolled.store(true, Ordering::SeqCst);
                    }
                }
                Ok(false)
            })
        })))
    };

    let mirror = new_mirror_conn(
        ctx,
        SharedConn::new(carrier_conn),
        SharedConn::new(forward_conn),
        &cfg,
        Some(inbound_hook),
        Some(enrollment_hook),
        None,
        None,
    );
    let hidden = new_hidden_conn(ctx, Arc::clone(&mirror), key, true, cfg).inspect_err(|_| {
        mirror.client_conn.close();
        mirror.server_conn.close();
    })?;
    hidden_cell.set(hidden.clone()).ok();
    let hidden_for_close = hidden.clone();
    mirror.set_on_close(Arc::new(move || hidden_for_close.remove_enrollment()));
    mirror.set_on_s2c_message_tx(hidden.as_outbound_tx_hook());
    mirror.start();
    Ok(mirror)
}
