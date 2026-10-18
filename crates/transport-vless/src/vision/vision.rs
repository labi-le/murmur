//!
//! Two deviations, both forced by Rust's type system:
//! * The documented design identifies the conn carrying the TLS session by inspecting its concrete
//!   type, then reaches into that conn by reflection to alias its input buffers. A `Box<dyn Conn>`
//!   in this crate cannot be re-tested or reached into, so the caller reports the session through
//!   [`TlsConn`](murmur_component_tls::utls::TlsConn)'s typed capability, which every authenticated
//!   TLS conn (uTLS, `rustls` and REALITY) answers. The reference also accepts its encryption conn
//!   directly; the caller reports that as [`TlsConnCheck::NoTls`], which keeps Vision padding-only.
//! * The documented design takes the conn below TLS (what XTLS direct mode switches to) from inside
//!   that conn. Nothing in this crate exposes the conn under a TLS wrapper, so the caller supplies
//!   it; `None` keeps the conn in TLS mode, matching an absent conn below TLS. A conn that can prove
//!   its transport sits on a TLS record boundary — uTLS, REALITY, and `rustls` via its
//!   record-bounded reader — also supplies its undelivered plaintext through
//!   [`TlsBufferedIncoming`], so the read switch loses neither it nor the raw bytes after it.

use std::sync::Arc;

use anyhow::{anyhow, Result};
use thiserror::Error;
use uuid::Uuid;

use murmur_common::shared_conn::SharedConn;
use murmur_component_tls::utls::{self, TlsBufferedIncoming, TlsConn};
use murmur_log::warnln;

use super::conn::Conn;

#[derive(Debug, Error)]
#[error("tls connection not handshake complete")]
pub struct NotHandshakeCompleteError;

#[derive(Debug, Error)]
#[error("XTLS Vision based on TLS 1.3 outer connection")]
pub struct NotTls13Error;

/// Result of the `is_supported_tls_conn` conn-type check, evaluated eagerly by
/// the caller (see the module doc) instead of at `new_conn` time.
#[derive(Debug, Clone, Copy)]
pub enum TlsConnCheck {
    Unsupported,
    /// The conn is the VLESS encryption layer instead of a TLS session. The reference accepts its
    /// `*encryption.CommonConn` as a Vision transport, so Vision runs padding-only: there is no TLS
    /// record stream to filter and no direct-mode switch to make.
    NoTls,
    Supported {
        handshake_complete: bool,
        version: u16,
    },
}

impl TlsConnCheck {
    pub fn evaluate(tls_conn: &dyn TlsConn) -> Self {
        match tls_conn.tls_session_capability() {
            Some(capability) => {
                Self::Supported { handshake_complete: capability.handshake_complete, version: capability.version }
            }
            None => Self::Unsupported,
        }
    }
}

pub fn new_conn(
    conn: SharedConn,
    tls_check: TlsConnCheck,
    net_conn: Option<SharedConn>,
    buffered_incoming: Option<Arc<dyn TlsBufferedIncoming>>,
    user_uuid: Uuid,
) -> Result<Conn> {
    let reader = conn.clone();
    let writer = conn.clone();

    match tls_check {
        TlsConnCheck::Unsupported => {
            warnln!("vision: not a valid supported TLS connection");
            return Err(anyhow!("failed to use vision, maybe \"tls\" is not enable and \"encryption\" is empty"));
        }
        TlsConnCheck::NoTls => {
            if net_conn.is_some() || buffered_incoming.is_some() {
                return Err(anyhow!("vision: encryption-only conn cannot carry a TLS raw transport"));
            }
        }
        TlsConnCheck::Supported { handshake_complete, version } => {
            if !handshake_complete {
                warnln!("vision: TLS connection not handshake complete");
            } else if version != utls::VERSION_TLS13 {
                return Err(NotTls13Error.into());
            }
        }
    }

    Ok(Conn::new(conn, reader, writer, user_uuid, net_conn, buffered_incoming))
}

/// Whether the conn carries a supported, authenticated TLS session.
pub fn is_supported_tls_conn(tls_conn: &dyn TlsConn) -> bool {
    tls_conn.tls_session_capability().is_some()
}
