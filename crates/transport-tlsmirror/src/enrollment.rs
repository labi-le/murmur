//! `DialCtx` carries both cancellation and a per-dial key/value chain.
//!
//! The chain holds the connection-enrollment bypass flag and the loopback-protection key; there is
//! no crate-wide context type, so this package defines its own (deviation).
//! A single-connection listener exists only to hand a single already-open connection to a
//! server accept loop; this crate drives the same connection directly with `hyper_util`'s connection
//! API instead (deviation).

use std::convert::Infallible;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use anyhow::{anyhow, Result};
use bytes::Bytes;
use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use hkdf::Hkdf;
use http::{Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use sha2::Sha256;
use tokio_util::sync::CancellationToken;

use murmur_std_compat::net::Conn as NetConn;

use super::config::{decode_primary_key, ClientConfig};
use super::conn::Conn;
use super::crypto::derive_encryption_key;
use super::traffic::{new_traffic_http_transport, CarrierAlpn, SharedConn as TrafficSharedConn};

const ENROLLMENT_CONTROL_CONNECTION_POSTFIX: &str = ".tlsmirror-controlconnection.v2fly.arpa";

const ENROLLMENT_BASE32_ALPHABET: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";

fn enrollment_base32_digit(value: u32) -> char {
    ENROLLMENT_BASE32_ALPHABET.get((value & 0x1f) as usize).copied().map_or('0', char::from)
}

fn enrollment_base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &byte in data {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(enrollment_base32_digit(buffer >> bits));
        }
    }
    if bits > 0 {
        out.push(enrollment_base32_digit(buffer << (5 - bits)));
    }
    out
}

/// The dial context as used by this package.
///
/// A cancellation signal plus the per-dial key/value chain the bypass and loopback-protection
/// helpers install. Only one loopback-protection key is ever live on a given chain in this package,
/// so a single optional slot (rather than a general key/value chain) preserves observable behaviour.
#[derive(Clone, Debug, Default)]
pub struct DialCtx {
    cancel: CancellationToken,
    bypass_enrollment: bool,
    loopback_protection: Option<(Vec<u8>, bool)>,
}

impl DialCtx {
    #[must_use]
    pub const fn new(cancel: CancellationToken) -> Self {
        Self { cancel, bypass_enrollment: false, loopback_protection: None }
    }

    #[must_use]
    pub const fn token(&self) -> &CancellationToken {
        &self.cancel
    }

    // cancel-safe: pure delegation to the wrapped operation, which owns the state.
    pub async fn cancelled(&self) {
        self.cancel.cancelled().await;
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancel.is_cancelled()
    }

    /// The returned guard must be kept alive for the timeout to apply, standing in for a deferred
    /// cancel.
    #[must_use]
    pub fn with_timeout(&self, duration: Duration) -> (Self, TimeoutGuard) {
        let child_token = self.cancel.child_token();
        let mut child = self.clone();
        child.cancel = child_token.clone();
        let watcher_token = child_token;
        let handle = tokio::spawn(async move {
            // cancel-safe: aborting the guard drops this timer, which leaves the token uncancelled
            // and lets the caller's own scope decide when the dial ends.
            tokio::select! {
                () = tokio::time::sleep(duration) => watcher_token.cancel(),
                () = watcher_token.cancelled() => {}
            }
        });
        (child, TimeoutGuard(handle))
    }
}

/// The timer guard for [`DialCtx::with_timeout`]: dropping it aborts the pending timeout.
#[derive(Debug)]
pub struct TimeoutGuard(tokio::task::JoinHandle<()>);

impl Drop for TimeoutGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[must_use]
pub fn with_connection_enrollment_bypass(ctx: &DialCtx) -> DialCtx {
    let mut ctx = ctx.clone();
    ctx.bypass_enrollment = true;
    ctx
}

pub(crate) const fn is_connection_enrollment_bypassed(ctx: &DialCtx) -> bool {
    ctx.bypass_enrollment
}

#[must_use]
pub fn with_loopback_protection(ctx: &DialCtx, enrollment_id: &[u8]) -> DialCtx {
    let mut ctx = ctx.clone();
    ctx.loopback_protection = Some((enrollment_id.to_vec(), true));
    ctx
}

#[must_use]
pub fn with_secondary_loopback_protection(ctx: &DialCtx, enrollment_id: &[u8]) -> DialCtx {
    let mut ctx = ctx.clone();
    ctx.loopback_protection = Some((enrollment_id.to_vec(), false));
    ctx
}

tokio::task_local! {
    /// Ambient bypass/loopback state for a connection-enrollment control dial that loops back
    /// through the generic, `CancellationToken`-only proxy-dial chain: `stream_tls_conn` cannot
    /// see the `DialCtx` built in [`verify_connection_enrollment`] once the call re-enters it
    /// through that chain, so [`make_tls_mirror_dialer`]'s dialer closure scopes it here for the
    /// duration of the nested dial, and [`dial_ctx_for`] picks it back up.
    pub static AMBIENT_DIAL_CTX: DialCtx;
}

/// The dial context for `cancel`, restoring any ambient scope.
///
/// This crate threads a bare `CancellationToken` through the generic dial chain, so a re-entrant
/// `stream_tls_conn` call restores the [`AMBIENT_DIAL_CTX`] scope, if any, rather than always
/// starting a flagless `DialCtx`.
pub fn dial_ctx_for(cancel: &CancellationToken) -> DialCtx {
    AMBIENT_DIAL_CTX.try_with(Clone::clone).unwrap_or_else(|_| DialCtx::new(cancel.clone()))
}

#[must_use]
pub fn is_loopback_protection_enabled(ctx: &DialCtx, enrollment_id: &[u8]) -> bool {
    matches!(&ctx.loopback_protection, Some((key, enabled)) if key.as_slice() == enrollment_id && *enabled)
}

pub fn server_identifier_host(primary_key: &[u8]) -> Result<String> {
    let server_id = derive_enrollment_server_identifier(primary_key)?;
    Ok(format!("{}{ENROLLMENT_CONTROL_CONNECTION_POSTFIX}", enrollment_base32_encode(&server_id)))
}

fn error_response(status: StatusCode, message: &str) -> hyper::Response<Full<Bytes>> {
    let mut response = hyper::Response::new(Full::new(Bytes::from(format!("{message}\n"))));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(http::header::CONTENT_TYPE, http::HeaderValue::from_static("text/plain; charset=utf-8"));
    response
}

// cancel-safe: the connection and the hyper service are owned by this future, so a drop closes the
// connection; the cancellation arm only makes that close orderly.
pub async fn serve_enrollment_control_connection(
    ctx: &CancellationToken,
    conn: Box<dyn NetConn>,
    primary_key: &str,
) -> Result<()> {
    let key = decode_primary_key(primary_key).inspect_err(|_| {
        let _ = conn.close();
    })?;
    let processor = enrollment_processor_for(&key);
    let io = TokioIo::new(conn);

    let service = service_fn(move |req: Request<Incoming>| {
        let processor = Arc::clone(&processor);
        async move {
            let body = match req.into_body().collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(err) => {
                    return Ok::<_, Infallible>(error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &format!("failed to read request body: {err}"),
                    ));
                }
            };
            let parsed = match unmarshal_enrollment_confirmation_req(&body) {
                Ok(req) => req,
                Err(err) => {
                    return Ok(error_response(StatusCode::BAD_REQUEST, &format!("failed to unmarshal request: {err}")));
                }
            };
            let enrolled = match processor.verify(&parsed) {
                Ok(enrolled) => enrolled,
                Err(err) => {
                    return Ok(error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &format!("failed to verify connection enrollment: {err}"),
                    ));
                }
            };
            let response_body = marshal_enrollment_confirmation_resp(enrolled);
            let content_length = response_body.len();
            let mut response = hyper::Response::new(Full::new(Bytes::from(response_body)));
            *response.status_mut() = StatusCode::OK;
            response
                .headers_mut()
                .insert(http::header::CONTENT_TYPE, http::HeaderValue::from_static("application/octet-stream"));
            response.headers_mut().insert(http::header::CONTENT_LENGTH, http::HeaderValue::from(content_length));
            Ok(response)
        }
    });

    let builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
    let connection = builder.serve_connection(io, service);
    tokio::pin!(connection);
    tokio::select! {
        result = &mut connection => result.map_err(|err| anyhow!("{err}")),
        () = ctx.cancelled() => {
            connection.as_mut().graceful_shutdown();
            let _ = connection.await;
            Ok(())
        }
    }
}

pub(crate) async fn verify_connection_enrollment(hidden: &Conn, ctx: &DialCtx, cfg: &ClientConfig) -> Result<()> {
    let Some(dialer) = &cfg.enrollment_dialer else {
        return Err(anyhow!("tlsmirror: connection enrolment requires an enrollment dialer"));
    };
    let (client_random, server_random) = hidden.mirror().handshake_random()?;
    let server_id = derive_enrollment_server_identifier(hidden.primary_key())?;
    let host = format!("{}{ENROLLMENT_CONTROL_CONNECTION_POSTFIX}", enrollment_base32_encode(&server_id));

    let (request_ctx, _timeout_guard) = ctx.with_timeout(Duration::from_secs(30));

    let Some(connection_enrolment) = cfg.config.connection_enrolment.as_ref() else {
        return Err(anyhow!("verify_connection_enrollment is only called when connection_enrolment is set"));
    };
    let primary_egress_empty = connection_enrolment.primary_egress_outbound.is_empty();
    let control_ctx = if primary_egress_empty {
        with_secondary_loopback_protection(&request_ctx, &server_id)
    } else {
        with_loopback_protection(&request_ctx, &server_id)
    };
    let control_ctx = with_connection_enrollment_bypass(&control_ctx);
    let control_conn =
        AMBIENT_DIAL_CTX.scope(control_ctx.clone(), dialer(control_ctx, "tcp", format!("{host}:80"))).await?;

    let req_body = marshal_enrollment_confirmation_req(&EnrollmentConfirmationReq {
        server_identifier: server_id,
        client_random: client_random.to_vec(),
        server_random: server_random.to_vec(),
        client_identifier: Vec::new(),
        reply_address_tag: Vec::new(),
    });

    let transport = new_traffic_http_transport(TrafficSharedConn::new(control_conn), CarrierAlpn::Http2).await?;
    let request =
        Request::builder().method(Method::POST).uri(format!("http://{host}")).body(Full::new(Bytes::from(req_body)))?;
    let response = transport.round_trip(request).await?;
    if response.status() != StatusCode::OK {
        return Err(anyhow!("tlsmirror: unexpected enrollment response status {}", response.status()));
    }
    let body = response.into_body().collect().await?.to_bytes();
    let enrolled = unmarshal_enrollment_confirmation_resp(&body)?;
    if !enrolled {
        return Err(anyhow!("tlsmirror: connection enrollment failed"));
    }
    Ok(())
}

pub(crate) fn derive_enrollment_server_identifier(primary_key: &[u8]) -> Result<Vec<u8>> {
    derive_secondary_key(primary_key, ":connection-enrollment-server-identifier-av38NNGF-TJvRw7C3-p8KM8yKd")
}

fn derive_secondary_key(primary_key: &[u8], tag: &str) -> Result<Vec<u8>> {
    if primary_key.len() != 32 {
        return Err(anyhow!("tlsmirror: invalid primary key size"));
    }
    let hkdf = Hkdf::<Sha256>::from_prk(primary_key).map_err(|err| anyhow!("hkdf: invalid prk: {err}"))?;
    let mut key = vec![0u8; 16];
    hkdf.expand(format!("v2ray-sv77RCEY-e8AhYsbD-BmFC7XRK:tlsmirror-secondary{tag}").as_bytes(), &mut key)
        .map_err(|err| anyhow!("hkdf: expand failed: {err}"))?;
    Ok(key)
}

fn derive_enrollment_request_key(
    primary_key: &[u8],
    client_random: [u8; 32],
    server_random: [u8; 32],
) -> Result<Vec<u8>> {
    let (request_key, _mask) = derive_encryption_key(
        primary_key,
        client_random,
        server_random,
        ":connection-enrollment-re78HQNM-CmpRnPbr-PNJVRMhu",
    )?;
    Ok(request_key)
}

static ENROLLMENT_PROCESSORS: LazyLock<DashMap<Vec<u8>, Arc<EnrollmentProcessor>>> = LazyLock::new(DashMap::new);

pub(crate) struct EnrollmentProcessor {
    primary_key: Vec<u8>,
    active: DashMap<Vec<u8>, Conn>,
}

pub(crate) fn enrollment_processor_for(primary_key: &[u8]) -> Arc<EnrollmentProcessor> {
    Arc::clone(
        &*ENROLLMENT_PROCESSORS.entry(primary_key.to_vec()).or_insert_with(|| {
            Arc::new(EnrollmentProcessor { primary_key: primary_key.to_vec(), active: DashMap::new() })
        }),
    )
}

impl EnrollmentProcessor {
    pub(crate) fn add(
        self: &Arc<Self>,
        client_random: [u8; 32],
        server_random: [u8; 32],
        conn: Conn,
    ) -> Result<Box<dyn FnOnce() + Send>> {
        let request_key = derive_enrollment_request_key(&self.primary_key, client_random, server_random)?;
        match self.active.entry(request_key.clone()) {
            Entry::Occupied(_) => return Err(anyhow!("tlsmirror: enrollment connection already exists")),
            Entry::Vacant(slot) => {
                slot.insert(conn);
            }
        }
        let processor = Arc::clone(self);
        Ok(Box::new(move || {
            processor.active.remove(&request_key);
        }))
    }

    pub(crate) fn verify(&self, req: &EnrollmentConfirmationReq) -> Result<bool> {
        if req.client_random.len() != 32 || req.server_random.len() != 32 {
            return Err(anyhow!("tlsmirror: enrollment request is missing handshake random"));
        }
        let mut client_random = [0u8; 32];
        let mut server_random = [0u8; 32];
        client_random.copy_from_slice(&req.client_random);
        server_random.copy_from_slice(&req.server_random);
        let request_key = derive_enrollment_request_key(&self.primary_key, client_random, server_random)?;
        Ok(self.active.contains_key(&request_key))
    }
}

#[derive(Clone, Default)]
pub(crate) struct EnrollmentConfirmationReq {
    pub(crate) server_identifier: Vec<u8>,
    pub(crate) client_random: Vec<u8>,
    pub(crate) server_random: Vec<u8>,
    pub(crate) client_identifier: Vec<u8>,
    pub(crate) reply_address_tag: Vec<u8>,
}

fn marshal_enrollment_confirmation_req(req: &EnrollmentConfirmationReq) -> Vec<u8> {
    let out = Vec::new();
    let out = append_proto_bytes(out, 1, &req.server_identifier);
    let out = append_proto_bytes(out, 2, &req.client_random);
    let out = append_proto_bytes(out, 3, &req.server_random);
    let out = append_proto_bytes(out, 4, &req.client_identifier);
    append_proto_bytes(out, 5, &req.reply_address_tag)
}

fn advance_past(data: &[u8], n: usize) -> Result<&[u8]> {
    data.get(n..).ok_or_else(|| anyhow!("unexpected EOF"))
}

fn unmarshal_enrollment_confirmation_req(data: &[u8]) -> Result<EnrollmentConfirmationReq> {
    let mut req = EnrollmentConfirmationReq::default();
    let mut data = data;
    while !data.is_empty() {
        let (key, n) = consume_proto_varint(data)?;
        data = advance_past(data, n)?;
        let field = key >> 3;
        let wire_type = key & 0x7;
        if field == 0 {
            return Err(anyhow!("tlsmirror: invalid protobuf field number"));
        }
        if wire_type == 2 {
            let (size, n) = consume_proto_varint(data)?;
            data = advance_past(data, n)?;
            let size = usize::try_from(size).map_err(|_| anyhow!("unexpected EOF"))?;
            if data.len() < size {
                return Err(anyhow!("unexpected EOF"));
            }
            let (value, rest) = data.split_at(size);
            let value = value.to_vec();
            data = rest;
            match field {
                1 => req.server_identifier = value,
                2 => req.client_random = value,
                3 => req.server_random = value,
                4 => req.client_identifier = value,
                5 => req.reply_address_tag = value,
                _ => {}
            }
            continue;
        }
        let n = skip_proto_value(data, field, wire_type)?;
        data = advance_past(data, n)?;
    }
    Ok(req)
}

fn marshal_enrollment_confirmation_resp(enrolled: bool) -> Vec<u8> {
    if !enrolled {
        return Vec::new();
    }
    let out = append_proto_varint(Vec::new(), 1 << 3);
    append_proto_varint(out, 1)
}

fn unmarshal_enrollment_confirmation_resp(data: &[u8]) -> Result<bool> {
    let mut enrolled = false;
    let mut data = data;
    while !data.is_empty() {
        let (key, n) = consume_proto_varint(data)?;
        data = advance_past(data, n)?;
        let field = key >> 3;
        let wire_type = key & 0x7;
        if field == 0 {
            return Err(anyhow!("tlsmirror: invalid protobuf field number"));
        }
        if field == 1 && wire_type == 0 {
            let (value, n) = consume_proto_varint(data)?;
            data = advance_past(data, n)?;
            enrolled = value != 0;
            continue;
        }
        let n = skip_proto_value(data, field, wire_type)?;
        data = advance_past(data, n)?;
    }
    Ok(enrolled)
}

fn append_proto_bytes(out: Vec<u8>, field: u64, value: &[u8]) -> Vec<u8> {
    if value.is_empty() {
        return out;
    }
    let out = append_proto_varint(out, (field << 3) | 2);
    let mut out = append_proto_varint(out, value.len() as u64);
    out.extend_from_slice(value);
    out
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "each varint byte holds the low seven bits of `value`, and the last byte only sees `value` below 0x80"
)]
fn append_proto_varint(mut out: Vec<u8>, mut value: u64) -> Vec<u8> {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
    out
}

fn consume_proto_varint(data: &[u8]) -> Result<(u64, usize)> {
    let mut value: u64 = 0;
    for (i, &b) in data.iter().enumerate() {
        if i == 10 {
            return Err(anyhow!("tlsmirror: invalid protobuf varint"));
        }
        value |= u64::from(b & 0x7f) << (7 * i);
        if b < 0x80 {
            return Ok((value, i + 1));
        }
    }
    Err(anyhow!("unexpected EOF"))
}

/// Skips a protobuf value. The limit is not required for parity: protobuf's documented default recursion
/// limit is 10000, counted so that a total nesting depth of 10001 is accepted and the 10002nd level
/// rejected. `MAX_PROTO_GROUP_DEPTH` counts the same way, including the outermost group
/// `skip_proto_group` is called for, and `skip_proto_group` enforces the boundary iteratively
/// rather than by recursion, so a hostile peer cannot grow the tokio worker stack past its 2 MiB
/// budget.
const MAX_PROTO_GROUP_DEPTH: usize = 10_001;

fn skip_proto_value(data: &[u8], start_field: u64, wire_type: u64) -> Result<usize> {
    match wire_type {
        3 => skip_proto_group(data, start_field),
        other => skip_proto_scalar(data, other),
    }
}

fn skip_proto_scalar(data: &[u8], wire_type: u64) -> Result<usize> {
    match wire_type {
        0 => consume_proto_varint(data).map(|(_, n)| n),
        1 => {
            if data.len() < 8 {
                return Err(anyhow!("unexpected EOF"));
            }
            Ok(8)
        }
        2 => {
            let (size, n) = consume_proto_varint(data)?;
            let rest = advance_past(data, n)?;
            let size = usize::try_from(size).map_err(|_| anyhow!("unexpected EOF"))?;
            if rest.len() < size {
                return Err(anyhow!("unexpected EOF"));
            }
            Ok(n + size)
        }
        4 => Err(anyhow!("tlsmirror: unexpected protobuf end group")),
        5 => {
            if data.len() < 4 {
                return Err(anyhow!("unexpected EOF"));
            }
            Ok(4)
        }
        other => Err(anyhow!("tlsmirror: unsupported enrollment protobuf wire type {other}")),
    }
}

fn skip_proto_group(data: &[u8], start_field: u64) -> Result<usize> {
    let mut open_fields = vec![start_field];
    let mut consumed = 0usize;
    let mut cursor = data;
    loop {
        let (key, n) = consume_proto_varint(cursor)?;
        cursor = advance_past(cursor, n)?;
        consumed += n;
        let nested_field = key >> 3;
        let nested_wire_type = key & 0x7;
        if nested_field == 0 {
            return Err(anyhow!("tlsmirror: invalid protobuf field number"));
        }
        if nested_wire_type == 4 {
            let Some(expected) = open_fields.pop() else {
                return Err(anyhow!("tlsmirror: mismatched protobuf end group"));
            };
            if nested_field != expected {
                return Err(anyhow!("tlsmirror: mismatched protobuf end group"));
            }
            if open_fields.is_empty() {
                return Ok(consumed);
            }
            continue;
        }
        if nested_wire_type == 3 {
            if open_fields.len() >= MAX_PROTO_GROUP_DEPTH {
                return Err(anyhow!("tlsmirror: protobuf group nesting too deep"));
            }
            open_fields.push(nested_field);
            continue;
        }
        let n = skip_proto_scalar(cursor, nested_wire_type)?;
        cursor = advance_past(cursor, n)?;
        consumed += n;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A recursive decoder consumes one stack frame per nested `StartGroup` key with no depth
    /// limit; on a 2 MiB tokio worker stack a few hundred KB of `0x0b` (field 1, wire type 3) bytes
    /// would abort the whole process. `skip_proto_group` is iterative, so 200_000 such bytes (well
    /// past `MAX_PROTO_GROUP_DEPTH`) must return an error rather than growing any stack.
    #[test]
    fn skip_proto_value_group_nesting_well_past_the_limit_errors_without_recursing() {
        let data = vec![0x0b_u8; 200_000];
        let err = skip_proto_value(&data, 1, 3).expect_err("nesting past the limit must be rejected");
        assert!(err.to_string().contains("nesting too deep"), "unexpected error: {err}");
    }

    /// Pins the exact boundary `MAX_PROTO_GROUP_DEPTH`'s doc comment derives from the documented
    /// protobuf recursion limit: a total nesting depth of 10001 (this group plus 10000 nested
    /// `StartGroup` keys) is accepted, and the 10002nd level (10001 nested keys) is rejected.
    #[test]
    fn skip_proto_value_group_nesting_matches_the_documented_recursion_boundary() {
        assert_eq!(MAX_PROTO_GROUP_DEPTH, 10_001, "test below is written against this exact number");

        let mut accepted = vec![0x0b_u8; MAX_PROTO_GROUP_DEPTH - 1];
        accepted.extend(std::iter::repeat_n(0x0c_u8, MAX_PROTO_GROUP_DEPTH));
        let consumed = skip_proto_value(&accepted, 1, 3).expect("a total nesting depth of 10001 must be accepted");
        assert_eq!(consumed, accepted.len());

        let rejected = vec![0x0b_u8; MAX_PROTO_GROUP_DEPTH];
        let err = skip_proto_value(&rejected, 1, 3).expect_err("a total nesting depth of 10002 must be rejected");
        assert!(err.to_string().contains("nesting too deep"), "unexpected error: {err}");
    }
}
