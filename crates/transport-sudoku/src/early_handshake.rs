use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{anyhow, Result};
use chrono::Utc;
use parking_lot::Mutex as SyncMutex;
use rand::rngs::OsRng;
use rand::TryRngCore;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::handshake::{build_client_obfs_conn, build_server_obfs_conn};
use super::kip::{
    decode_kip_client_hello_payload, decode_kip_server_hello_payload, new_kip_client_hello, read_kip_message,
    resolve_client_hello_table, write_kip_message, KipClientHello, KIP_HELLO_NONCE_SIZE, KIP_HELLO_PUB_SIZE,
    KIP_HELLO_USER_HASH_SIZE, KIP_TYPE_CLIENT_HELLO, KIP_TYPE_SERVER_HELLO,
};
use super::replay::ReplayAllowFunc;
use super::session_keys::{
    derive_psk_directional_bases, derive_session_directional_bases, generate_x25519_ephemeral, x25519_shared_secret,
};
use crate::crypto::record_conn::new_record_conn;
use crate::obfs::httpmask::early_handshake::{
    ClientEarlyHandshake, PreparedServerEarlyHandshake, TunnelServerEarlyHandshake,
};
use crate::obfs::sudoku::table::Table;
use murmur_common_net::io::Stream;
use x25519_dalek::{PublicKey, StaticSecret};

const EARLY_KIP_HANDSHAKE_TTL_SECS: i64 = 60;

#[derive(Debug, Clone, Default)]
pub(crate) struct EarlyCodecConfig {
    pub(crate) psk: String,
    pub(crate) aead: String,
    pub(crate) enable_pure_downlink: bool,
    pub(crate) padding_min: i32,
    pub(crate) padding_max: i32,
}

struct EarlyMemoryConnState {
    reader: Option<io::Cursor<Vec<u8>>>,
    write: Vec<u8>,
}

/// The early memory conn. Shared behind `Arc<Mutex<_>>` (as in
/// `handshake.rs`) so `written()` stays reachable after the conn has been boxed and wrapped by
/// [`build_client_obfs_conn`]/[`build_server_obfs_conn`].
#[derive(Clone)]
struct EarlyMemoryConn(Arc<SyncMutex<EarlyMemoryConnState>>);

impl EarlyMemoryConn {
    fn new(read_buf: Option<Vec<u8>>) -> Self {
        Self(Arc::new(SyncMutex::new(EarlyMemoryConnState {
            reader: read_buf.map(io::Cursor::new),
            write: Vec::new(),
        })))
    }

    fn written(&self) -> Vec<u8> {
        self.0.lock().write.clone()
    }
}

impl AsyncRead for EarlyMemoryConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut state = self.get_mut().0.lock();
        match state.reader.as_mut() {
            Some(reader) => Pin::new(reader).poll_read(cx, buf),
            None => Poll::Ready(Err(io::Error::new(io::ErrorKind::NotConnected, "use of closed network connection"))),
        }
    }
}
impl AsyncWrite for EarlyMemoryConn {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.get_mut().0.lock().write.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl Stream for EarlyMemoryConn {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "local"))
    }
    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "remote"))
    }
}

fn build_early_client_obfs_conn(raw: Box<dyn Stream>, cfg: &EarlyCodecConfig, table: &Arc<Table>) -> Box<dyn Stream> {
    build_client_obfs_conn(raw, table, cfg.padding_min, cfg.padding_max, cfg.enable_pure_downlink)
}

fn build_early_server_obfs_conn(raw: Box<dyn Stream>, cfg: &EarlyCodecConfig, table: &Arc<Table>) -> Box<dyn Stream> {
    let (_, directional, _) =
        build_server_obfs_conn(raw, table, cfg.padding_min, cfg.padding_max, cfg.enable_pure_downlink, false);
    Box::new(directional)
}

pub(crate) struct EarlyClientState {
    pub(crate) request_payload: Vec<u8>,

    cfg: EarlyCodecConfig,
    table: Arc<Table>,
    nonce: [u8; KIP_HELLO_NONCE_SIZE],
    ephemeral: StaticSecret,
    session_c2s: Vec<u8>,
    session_s2c: Vec<u8>,
    response_set: bool,
}

pub(crate) struct EarlyServerState {
    pub(crate) response_payload: Vec<u8>,
    pub(crate) user_hash: String,

    cfg: EarlyCodecConfig,
    table: Arc<Table>,
    session_c2s: Vec<u8>,
    session_s2c: Vec<u8>,
}

pub(crate) async fn new_early_client_state(
    cfg: EarlyCodecConfig,
    table: Arc<Table>,
    table_hint: u32,
    has_table_hint: bool,
    user_hash: [u8; KIP_HELLO_USER_HASH_SIZE],
    feats: u32,
) -> Result<EarlyClientState> {
    let ephemeral = generate_x25519_ephemeral().map_err(|err| anyhow!("ecdh generate failed: {err}"))?;

    let mut nonce = [0u8; KIP_HELLO_NONCE_SIZE];
    OsRng.try_fill_bytes(&mut nonce).map_err(|err| anyhow!("nonce generate failed: {err}"))?;

    let mut client_pub = [0u8; KIP_HELLO_PUB_SIZE];
    client_pub.copy_from_slice(PublicKey::from(&ephemeral).as_bytes());
    let hello = new_kip_client_hello(user_hash, nonce, client_pub, feats, table_hint, has_table_hint);

    let mem = EarlyMemoryConn::new(None);
    let obfs_conn = build_early_client_obfs_conn(Box::new(mem.clone()), &cfg, &table);
    let (psk_c2s, psk_s2c) = derive_psk_directional_bases(&cfg.psk);
    let mut rc = new_record_conn(obfs_conn, &cfg.aead, &psk_c2s, &psk_s2c)
        .map_err(|err| anyhow!("client early crypto setup failed: {err}"))?;
    write_kip_message(&mut rc, KIP_TYPE_CLIENT_HELLO, &hello.encode_payload())
        .await
        .map_err(|err| anyhow!("write early client hello failed: {err}"))?;

    Ok(EarlyClientState {
        request_payload: mem.written(),
        cfg,
        table,
        nonce,
        ephemeral,
        session_c2s: Vec::new(),
        session_s2c: Vec::new(),
        response_set: false,
    })
}

impl EarlyClientState {
    pub(crate) async fn process_response(&mut self, payload: &[u8]) -> Result<()> {
        let mem = EarlyMemoryConn::new(Some(payload.to_vec()));
        let obfs_conn = build_early_client_obfs_conn(Box::new(mem), &self.cfg, &self.table);
        let (psk_c2s, psk_s2c) = derive_psk_directional_bases(&self.cfg.psk);
        let mut rc = new_record_conn(obfs_conn, &self.cfg.aead, &psk_c2s, &psk_s2c)
            .map_err(|err| anyhow!("client early crypto setup failed: {err}"))?;

        let msg = read_kip_message(&mut rc).await.map_err(|err| anyhow!("read early server hello failed: {err}"))?;
        if msg.typ != KIP_TYPE_SERVER_HELLO {
            return Err(anyhow!("unexpected early handshake message: {}", msg.typ));
        }
        let sh = decode_kip_server_hello_payload(&msg.payload)
            .map_err(|err| anyhow!("decode early server hello failed: {err}"))?;
        if sh.nonce != self.nonce {
            return Err(anyhow!("early handshake nonce mismatch"));
        }

        let shared =
            x25519_shared_secret(&self.ephemeral, &sh.server_pub).map_err(|err| anyhow!("ecdh failed: {err}"))?;
        let (c2s, s2c) = derive_session_directional_bases(&self.cfg.psk, &shared, &self.nonce)
            .map_err(|err| anyhow!("derive session keys failed: {err}"))?;
        self.session_c2s = c2s;
        self.session_s2c = s2c;
        self.response_set = true;
        Ok(())
    }

    pub(crate) const fn ready(&self) -> bool {
        self.response_set
    }
}

pub(crate) async fn new_http_mask_client_early_handshake(
    cfg: EarlyCodecConfig,
    table: Arc<Table>,
    table_hint: u32,
    has_table_hint: bool,
    user_hash: [u8; KIP_HELLO_USER_HASH_SIZE],
    feats: u32,
) -> Result<ClientEarlyHandshake> {
    let state = new_early_client_state(cfg, table, table_hint, has_table_hint, user_hash, feats).await?;
    let state = Arc::new(SyncMutex::new(state));

    let request_payload = state.lock().request_payload.clone();
    let state_for_response = Arc::clone(&state);
    let state_for_ready = Arc::clone(&state);
    let state_for_wrap = state;

    Ok(ClientEarlyHandshake {
        request_payload,
        handle_response: Some(Arc::new(move |payload: &[u8]| {
            let payload = payload.to_vec();
            state_for_response.lock_arc_process(&payload)
        })),
        ready: Some(Arc::new(move || state_for_ready.lock().ready())),
        wrap_conn: Some(Arc::new(move |raw: Box<dyn Stream>| {
            let state = Arc::clone(&state_for_wrap);
            Box::pin(async move {
                let response_set = state.lock().response_set;
                if !response_set {
                    return Err(anyhow!("early handshake not completed"));
                }
                let (cfg, table, session_c2s, session_s2c) = {
                    let guard = state.lock();
                    (guard.cfg.clone(), Arc::clone(&guard.table), guard.session_c2s.clone(), guard.session_s2c.clone())
                };
                let obfs_conn = build_early_client_obfs_conn(raw, &cfg, &table);
                let rc = new_record_conn(obfs_conn, &cfg.aead, &session_c2s, &session_s2c)
                    .map_err(|err| anyhow!("setup client session crypto failed: {err}"))?;
                let rc: Box<dyn Stream> = Box::new(rc);
                Ok(rc)
            })
        })),
    })
}

/// `Fn(&[u8]) -> anyhow::Result<()>` cannot hold `&mut EarlyClientState` across `.await` directly;
/// this extension runs `process_response` under the shared lock via a short-lived block-on, since
/// the underlying work never actually awaits real I/O (it only touches in-memory buffers).
trait ProcessResponseExt {
    fn lock_arc_process(&self, payload: &[u8]) -> Result<()>;
}
impl ProcessResponseExt for Arc<SyncMutex<EarlyClientState>> {
    fn lock_arc_process(&self, payload: &[u8]) -> Result<()> {
        let mut guard = self.lock();
        futures::executor::block_on(guard.process_response(payload))
    }
}

pub(crate) async fn process_early_client_payload(
    cfg: &EarlyCodecConfig,
    tables: &[Arc<Table>],
    payload: &[u8],
    allow_replay: Option<&ReplayAllowFunc>,
) -> Result<EarlyServerState> {
    if payload.is_empty() {
        return Err(anyhow!("empty early payload"));
    }
    if tables.is_empty() {
        return Err(anyhow!("no tables configured"));
    }

    let mut first_err: Option<anyhow::Error> = None;
    for table in tables {
        match process_early_client_payload_for_table(cfg, tables, table, payload, allow_replay).await {
            Ok(state) => return Ok(state),
            Err(err) => {
                if first_err.is_none() {
                    first_err = Some(err);
                }
            }
        }
    }
    Err(first_err.unwrap_or_else(|| anyhow!("early handshake probe failed")))
}

async fn process_early_client_payload_for_table(
    cfg: &EarlyCodecConfig,
    tables: &[Arc<Table>],
    table: &Arc<Table>,
    payload: &[u8],
    allow_replay: Option<&ReplayAllowFunc>,
) -> Result<EarlyServerState> {
    let mem = EarlyMemoryConn::new(Some(payload.to_vec()));
    let obfs_conn = build_early_server_obfs_conn(Box::new(mem), cfg, table);
    let (psk_c2s, psk_s2c) = derive_psk_directional_bases(&cfg.psk);
    let mut rc = new_record_conn(obfs_conn, &cfg.aead, &psk_s2c, &psk_c2s)?;

    let msg = read_kip_message(&mut rc).await?;
    if msg.typ != KIP_TYPE_CLIENT_HELLO {
        return Err(anyhow!("unexpected handshake message: {}", msg.typ));
    }
    let ch: KipClientHello = decode_kip_client_hello_payload(&msg.payload)?;
    if (Utc::now().timestamp() - ch.timestamp.timestamp()).abs() > EARLY_KIP_HANDSHAKE_TTL_SECS {
        return Err(anyhow!("time skew/replay"));
    }

    let user_hash = hex::encode(ch.user_hash);
    if let Some(allow_replay) = allow_replay {
        if !allow_replay(&user_hash, ch.nonce, Utc::now()) {
            return Err(anyhow!("replay detected"));
        }
    }
    let resolved_table =
        resolve_client_hello_table(table, tables, &ch).map_err(|err| anyhow!("resolve table hint failed: {err}"))?;

    let server_ephemeral = generate_x25519_ephemeral().map_err(|err| anyhow!("ecdh generate failed: {err}"))?;
    let shared =
        x25519_shared_secret(&server_ephemeral, &ch.client_pub).map_err(|err| anyhow!("ecdh failed: {err}"))?;
    let (session_c2s, session_s2c) = derive_session_directional_bases(&cfg.psk, &shared, &ch.nonce)
        .map_err(|err| anyhow!("derive session keys failed: {err}"))?;

    let mut server_pub = [0u8; KIP_HELLO_PUB_SIZE];
    server_pub.copy_from_slice(PublicKey::from(&server_ephemeral).as_bytes());
    let server_hello = super::kip::KipServerHello {
        nonce: ch.nonce,
        server_pub,
        selected_feats: ch.features & super::kip::KIP_FEAT_ALL,
    };

    let resp_mem = EarlyMemoryConn::new(None);
    let resp_obfs = build_early_server_obfs_conn(Box::new(resp_mem.clone()), cfg, &resolved_table);
    let mut resp_conn = new_record_conn(resp_obfs, &cfg.aead, &psk_s2c, &psk_c2s)
        .map_err(|err| anyhow!("server early crypto setup failed: {err}"))?;
    write_kip_message(&mut resp_conn, KIP_TYPE_SERVER_HELLO, &server_hello.encode_payload())
        .await
        .map_err(|err| anyhow!("write early server hello failed: {err}"))?;

    Ok(EarlyServerState {
        response_payload: resp_mem.written(),
        user_hash,
        cfg: cfg.clone(),
        table: resolved_table,
        session_c2s,
        session_s2c,
    })
}

pub(crate) fn new_http_mask_server_early_handshake(
    cfg: EarlyCodecConfig,
    tables: Vec<Arc<Table>>,
    allow_replay: ReplayAllowFunc,
) -> TunnelServerEarlyHandshake {
    TunnelServerEarlyHandshake {
        prepare: Arc::new(move |payload: &[u8]| {
            let cfg = cfg.clone();
            let tables = tables.clone();
            let allow_replay = Arc::clone(&allow_replay);
            let payload = payload.to_vec();
            let state = futures::executor::block_on(process_early_client_payload(
                &cfg,
                &tables,
                &payload,
                Some(&allow_replay),
            ))?;
            Ok(PreparedServerEarlyHandshake {
                response_payload: state.response_payload,
                wrap_conn: Some(Arc::new(move |raw: Box<dyn Stream>| {
                    let cfg = state.cfg.clone();
                    let table = Arc::clone(&state.table);
                    let session_c2s = state.session_c2s.clone();
                    let session_s2c = state.session_s2c.clone();
                    Box::pin(async move {
                        let obfs_conn = build_early_server_obfs_conn(raw, &cfg, &table);
                        let rc = new_record_conn(obfs_conn, &cfg.aead, &session_s2c, &session_c2s)
                            .map_err(|err| anyhow!("setup server session crypto failed: {err}"))?;
                        let rc: Box<dyn Stream> = Box::new(rc);
                        Ok(rc)
                    })
                })),
                user_hash: state.user_hash,
            })
        }),
    }
}
