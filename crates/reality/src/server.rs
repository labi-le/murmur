//! The REALITY server side: authentication, plus the fallback relay for a client whose handshake
//! does not authenticate.
//!
//! Scope cut, stated up front: the server mirrors the *exact* wire bytes of the real `dest`
//! server's handshake back to the client even on the authenticated path (dialing `dest`, reading
//! its genuine `ServerHello`/records, and only substituting the key share and certificate), so a
//! passive observer sees byte-identical framing to a real `dest` handshake. That requires reaching
//! into a forked TLS stack's internal handshake state machine at a level this crate's independent,
//! standards-based TLS 1.3 engine cannot replicate without becoming a full byte-for-byte
//! `dest`-camouflaging proxy of another TLS engine's internal state. This crate keeps the
//! *authentication protocol* faithful (`ClientHello` splice decode, `AuthKey` derivation, the
//! Ed25519-cert HMAC trick, the same handshake wire format) but generates its own self-consistent
//! `ServerHello`/handshake for an authenticated client instead of mirroring `dest`'s bytes -- a
//! real REALITY client does not care about that provenance, only about the derived keys and the
//! certificate HMAC, so wire interop is unaffected. The **unauthenticated/fallback path**, which
//! is what actually needs to look like a real `dest` handshake to a censor, is preserved: any
//! connection that doesn't decrypt as a valid REALITY `ClientHello` is relayed byte-for-byte to
//! `dest`, unparsed.

use std::collections::HashSet;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Result};
use rand::RngCore as _;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::cert;
use crate::handshake::{self, ClientHello, ServerHello};
use crate::record::RecordLayer;
use crate::stream::RealityStream;
use crate::suite::{hkdf_sha256_reality, CipherSuite, KeySchedule};

pub(crate) const MAX_SHORT_ID_LEN: usize = 8;

const OFFERED_SUITES: [CipherSuite; 3] =
    [CipherSuite::Aes128GcmSha256, CipherSuite::Aes256GcmSha384, CipherSuite::Chacha20Poly1305Sha256];

pub type BoxedStream = Box<dyn AsyncReadWriteUnpinSend>;
// Deliberate blanket impl (guideline section 7): the trait is a name for the boxed stream bound
// [`BoxedStream`] needs, so every conforming stream has to satisfy it automatically.
pub trait AsyncReadWriteUnpinSend: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> AsyncReadWriteUnpinSend for T {}

/// Dials the real `dest`, for the fallback relay. Boxed/dyn so callers can plug in their own
/// tunnel dialer without this crate depending on the dialer's types.
pub type DialDest = Arc<dyn Fn() -> Pin<Box<dyn Future<Output = io::Result<BoxedStream>> + Send>> + Send + Sync>;

pub struct RealityServerConfig {
    pub private_key: [u8; 32],
    pub server_names: HashSet<String>,
    pub short_ids: HashSet<[u8; MAX_SHORT_ID_LEN]>,
    pub max_time_diff: Option<Duration>,
    pub dial_dest: DialDest,
    pub limit_fallback_upload: FallbackLimit,
    pub limit_fallback_download: FallbackLimit,
    leaf_signing_key: ed25519_dalek::SigningKey,
}

impl RealityServerConfig {
    pub fn new(
        private_key: [u8; 32],
        server_names: HashSet<String>,
        short_ids: HashSet<[u8; MAX_SHORT_ID_LEN]>,
        max_time_diff: Option<Duration>,
        dial_dest: DialDest,
    ) -> Self {
        // One process-lifetime Ed25519 leaf keypair, reused across every connection -- only the
        // HMAC "signature" differs per connection, keyed by that connection's `AuthKey`.
        let mut seed = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rng(), &mut seed);
        let leaf_signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        Self {
            private_key,
            server_names,
            short_ids,
            max_time_diff,
            dial_dest,
            limit_fallback_upload: FallbackLimit::default(),
            limit_fallback_download: FallbackLimit::default(),
            leaf_signing_key,
        }
    }
}

/// Redacts the static private key and the leaf signing key; the short IDs are reported as a count.
impl core::fmt::Debug for RealityServerConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RealityServerConfig")
            .field("private_key", &"<redacted>")
            .field("server_names", &self.server_names)
            .field("short_ids", &self.short_ids.len())
            .field("max_time_diff", &self.max_time_diff)
            .field("limit_fallback_upload", &self.limit_fallback_upload)
            .field("limit_fallback_download", &self.limit_fallback_download)
            .finish_non_exhaustive()
    }
}

/// One raw TLS record's wire bytes, captured before any parsing so a failed/rejected
/// authentication attempt can still be replayed verbatim to `dest`.
async fn read_one_record_raw<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).await?;
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut raw = Vec::with_capacity(5 + len);
    raw.extend_from_slice(&header);
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await?;
    raw.extend_from_slice(&payload);
    Ok(raw)
}

/// The `limit-fallback-upload`/`limit-fallback-download` metering.
///
/// A connection that fails authentication is relayed to `dest`, and this meters that relay so a
/// scanner cannot use it as an amplifier. The first `after_bytes` are free, then a token bucket
/// refills at `bytes_per_sec` up to `burst_bytes_per_sec`; `bytes_per_sec == 0` means no limit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FallbackLimit {
    pub after_bytes: u64,
    pub bytes_per_sec: u64,
    pub burst_bytes_per_sec: u64,
}

impl FallbackLimit {
    fn is_enabled(self) -> bool {
        self.bytes_per_sec > 0
    }
}

/// A token bucket: full at `capacity` when created, refilled at `rate` per second. A request
/// larger than the burst drives the balance negative and is served once it refills.
pub(crate) struct TokenBucket {
    rate: u64,
    capacity: u64,
    available: i64,
    last: Instant,
}

impl TokenBucket {
    pub(crate) fn new(limit: FallbackLimit) -> Self {
        let capacity = limit.bytes_per_sec.max(limit.burst_bytes_per_sec);
        Self {
            rate: limit.bytes_per_sec,
            capacity,
            available: i64::try_from(capacity).unwrap_or(i64::MAX),
            last: Instant::now(),
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed_nanos = now.duration_since(self.last).as_nanos();
        let gained = u128::from(self.rate).saturating_mul(elapsed_nanos) / 1_000_000_000;
        let gained = i64::try_from(gained.min(u128::from(self.capacity))).unwrap_or(i64::MAX);
        self.available = self.available.saturating_add(gained).min(i64::try_from(self.capacity).unwrap_or(i64::MAX));
        self.last = now;
    }

    /// Charges `bytes` and returns how long the caller must hold them back, or `None` to go on.
    pub(crate) fn charge(&mut self, bytes: u64) -> Option<Duration> {
        if bytes == 0 {
            return None;
        }
        self.refill();
        self.available = self.available.saturating_sub(i64::try_from(bytes).unwrap_or(i64::MAX));
        if self.available >= 0 {
            return None;
        }
        let owed_nanos =
            u128::from(self.available.unsigned_abs()).saturating_mul(1_000_000_000) / u128::from(self.rate);
        let delay = Duration::from_nanos(u64::try_from(owed_nanos).unwrap_or(u64::MAX));
        if delay.is_zero() {
            return None;
        }
        self.last = Instant::now() + delay;
        Some(delay)
    }
}

/// Wraps one side of a fallback relay so the bytes read out of it are metered.
pub(crate) struct FallbackThrottle<T> {
    inner: T,
    free: u64,
    bucket: Option<TokenBucket>,
    delay: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<T> FallbackThrottle<T> {
    pub(crate) fn new(inner: T, limit: FallbackLimit) -> Self {
        let bucket = limit.is_enabled().then(|| TokenBucket::new(limit));
        Self { inner, free: limit.after_bytes, bucket, delay: None }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for FallbackThrottle<T> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if let Some(delay) = this.delay.as_mut() {
                match delay.as_mut().poll(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(()) => this.delay = None,
                }
            }
            let filled = buf.filled().len();
            let result = match Pin::new(&mut this.inner).poll_read(cx, buf) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => result,
            };
            let read = buf.filled().len() - filled;
            if let Err(err) = result {
                return Poll::Ready(Err(err));
            }
            if this.free > 0 {
                this.free = this.free.saturating_sub(u64::try_from(read).unwrap_or(u64::MAX));
                return Poll::Ready(Ok(()));
            }
            match this.bucket.as_mut().and_then(|bucket| bucket.charge(u64::try_from(read).unwrap_or(u64::MAX))) {
                Some(delay) => this.delay = Some(Box::pin(tokio::time::sleep(delay))),
                None => return Poll::Ready(Ok(())),
            }
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for FallbackThrottle<T> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Relays `stream` to `dest` byte-for-byte in both directions, first replaying `already_read`
/// (the bytes this function's caller already consumed from `stream` while probing for a REALITY
/// `ClientHello`) to `dest`, mirroring the fallback path: two copy loops, each over a connection
/// rate-limited by `limit_fallback_upload` and `limit_fallback_download`.
async fn relay_to_dest<S: AsyncRead + AsyncWrite + Unpin + Send>(
    stream: S,
    already_read: &[u8],
    cfg: &RealityServerConfig,
) -> Result<()> {
    let mut dest = (cfg.dial_dest)().await.map_err(|err| anyhow!("REALITY: failed to dial dest: {err}"))?;
    dest.write_all(already_read).await?;
    dest.flush().await?;
    let mut uplink = FallbackThrottle::new(stream, cfg.limit_fallback_upload);
    let mut downlink = FallbackThrottle::new(dest.as_mut(), cfg.limit_fallback_download);
    tokio::io::copy_bidirectional(&mut uplink, &mut downlink).await?;
    Ok(())
}

/// The listener's `accept`, narrowed to one connection.
///
/// On success, returns the decrypted proxy stream ready for the inbound listener's own protocol to
/// read/write. On anything else -- garbled/non-TLS input, wrong SNI, a failed `AuthKey` decrypt, an
/// unknown short ID, an out-of-window timestamp -- this relays the connection to `dest` to
/// completion (mirroring what a censor probing this crate would see from a real `dest`) and returns
/// `Err`; the caller should treat that as "no proxy connection, already handled" and move on to the
/// next `accept()`, not as a hard listener error.
pub async fn reality_server_accept<S>(mut stream: S, cfg: &RealityServerConfig) -> Result<RealityStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    let first_record =
        read_one_record_raw(&mut stream).await.map_err(|err| anyhow!("REALITY: failed to read ClientHello: {err}"))?;

    let Some((client_hello, auth_key)) = parse_authenticated_client_hello(&first_record, cfg) else {
        relay_to_dest(stream, &first_record, cfg).await?;
        return Err(anyhow!("REALITY: not an authenticated client, relayed to dest"));
    };

    match complete_authenticated_handshake(stream, client_hello, &auth_key, cfg).await {
        Ok(reality_stream) => Ok(reality_stream),
        Err((stream, err)) => {
            murmur_log::debugln!("REALITY: authenticated handshake failed after ClientHello: {err}");
            let _ = relay_to_dest(stream, &first_record, cfg).await;
            Err(err)
        }
    }
}

/// The server's inline handshake step: decode the `ClientHello`, derive `AuthKey` from the
/// server's static private key and the client's ephemeral X25519 share, and check the session-id
/// AEAD, protocol version window, and short ID all at once. `None` means "not us", i.e. relay to
/// `dest` unparsed.
fn parse_authenticated_client_hello(
    first_record_raw: &[u8],
    cfg: &RealityServerConfig,
) -> Option<(ClientHello, [u8; 32])> {
    if first_record_raw.first() != Some(&handshake::CONTENT_TYPE_HANDSHAKE) {
        return None;
    }
    let payload = first_record_raw.get(5..)?;
    let [record_type, len_hi, len_mid, len_lo, ..] = *payload else { return None };
    if record_type != handshake::HANDSHAKE_TYPE_CLIENT_HELLO {
        return None;
    }
    let declared = 4 + u32::from_be_bytes([0, len_hi, len_mid, len_lo]) as usize;
    if declared != payload.len() {
        return None; // ClientHello split across records: not handled by this simplified server.
    }
    let client_hello = ClientHello::parse(payload).ok()?;
    if !cfg.server_names.contains(&client_hello.server_name) {
        return None;
    }

    let client_public = client_hello.x25519_public?;
    // A non-contributory peer point (a low-order point, including all zeroes) is rejected here,
    // leaving no `AuthKey` so the auth block is skipped. The bare RFC 7748 `x25519` would instead
    // return the all-zero secret for such a point, and anyone can HKDF that into a valid
    // `SessionId`.
    let auth_key_shared =
        x25519_dalek::StaticSecret::from(cfg.private_key).diffie_hellman(&x25519_dalek::PublicKey::from(client_public));
    if !auth_key_shared.was_contributory() {
        return None;
    }
    let auth_key = hkdf_sha256_reality(auth_key_shared.as_bytes(), &client_hello.random[..20]);

    let aad = client_hello.raw_with_zero_session_id();
    let nonce: [u8; 12] = client_hello.random[20..32].try_into().ok()?;
    let plaintext = CipherSuite::Aes256GcmSha384.open(&auth_key, &nonce, &client_hello.session_id, &aad).ok()?;
    let Ok(plaintext) = <[u8; 16]>::try_from(plaintext) else {
        return None;
    };
    if plaintext[0] != 1 || plaintext[1] != 8 || plaintext[2] != 2 {
        return None;
    }
    let client_unix = u32::from_be_bytes([plaintext[4], plaintext[5], plaintext[6], plaintext[7]]);
    if let Some(max_diff) = cfg.max_time_diff {
        if !within_max_time_diff(client_unix, crate::clock::now(), max_diff) {
            return None;
        }
    }
    let mut short_id = [0u8; MAX_SHORT_ID_LEN];
    short_id.copy_from_slice(&plaintext[8..16]);
    if !cfg.short_ids.contains(&short_id) {
        return None;
    }

    Some((client_hello, auth_key))
}

/// The client's whole-second Unix stamp must be within `max_diff` of the server clock, where
/// `max_diff` carries microsecond precision. Truncating the window with `as_secs()` would collapse
/// any sub-second budget to "same Unix second", refusing clients that should be accepted.
pub(crate) fn within_max_time_diff(client_unix: u32, now: SystemTime, max_diff: Duration) -> bool {
    let now = now.duration_since(UNIX_EPOCH).unwrap_or_default();
    now.abs_diff(Duration::from_secs(u64::from(client_unix))) <= max_diff
}

/// On success, the returned [`RealityStream`] is ready for application data. On failure, the
/// original `stream` is handed back (not consumed by the failed attempt) so the caller can still
/// relay it to `dest`.
async fn complete_authenticated_handshake<S>(
    stream: S,
    client_hello: ClientHello,
    auth_key: &[u8; 32],
    cfg: &RealityServerConfig,
) -> std::result::Result<RealityStream<S>, (S, anyhow::Error)>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    let mut record_layer = RecordLayer::new(stream);
    let outcome = complete_authenticated_handshake_inner(&mut record_layer, &client_hello, auth_key, cfg).await;
    match outcome {
        Ok(()) => Ok(RealityStream::new(record_layer)),
        Err(err) => Err((record_layer.into_inner(), err)),
    }
}

async fn complete_authenticated_handshake_inner<S: AsyncRead + AsyncWrite + Unpin>(
    record_layer: &mut RecordLayer<S>,
    client_hello: &ClientHello,
    auth_key: &[u8; 32],
    cfg: &RealityServerConfig,
) -> Result<()> {
    let suite = OFFERED_SUITES
        .into_iter()
        .find(|s| client_hello.cipher_suites.contains(s))
        .ok_or_else(|| anyhow!("REALITY: no mutually supported cipher suite"))?;

    let (server_private, server_public) = crate::suite::generate_x25519_keypair();
    let mut server_random = [0u8; 32];
    rand::rng().fill_bytes(&mut server_random);
    let server_hello = ServerHello::build(server_random, &client_hello.session_id, suite, server_public);
    record_layer.write_plaintext_handshake(&server_hello.raw).await?;

    let tls_shared = x25519_dalek::x25519(
        server_private,
        client_hello.x25519_public.ok_or_else(|| anyhow!("REALITY: ClientHello without X25519 key share"))?,
    );
    let mut transcript = suite.transcript();
    transcript.update(&client_hello.raw);
    transcript.update(&server_hello.raw);
    let ch_sh_digest = transcript.digest();

    let schedule = KeySchedule::new(suite, &tls_shared, &ch_sh_digest);
    let (server_hs_key, server_hs_iv) = schedule.traffic_key_iv(&schedule.server_handshake_secret);
    let (client_hs_key, client_hs_iv) = schedule.traffic_key_iv(&schedule.client_handshake_secret);
    record_layer.set_write_keys(suite, server_hs_key, server_hs_iv);
    record_layer.set_read_keys(suite, client_hs_key, client_hs_iv);

    let ee_msg = handshake::build_encrypted_extensions();
    record_layer.write_encrypted(handshake::CONTENT_TYPE_HANDSHAKE, &ee_msg).await?;
    transcript.update(&ee_msg);

    let leaf_public = cfg.leaf_signing_key.verifying_key().to_bytes();
    let hmac_signature = cert::hmac_signature(auth_key, &leaf_public);
    let cert_der = cert::build_fake_leaf(&leaf_public, &hmac_signature);
    let cert_msg = handshake::build_certificate(&cert_der);
    record_layer.write_encrypted(handshake::CONTENT_TYPE_HANDSHAKE, &cert_msg).await?;
    transcript.update(&cert_msg);
    let pre_cv_digest = transcript.digest();

    let cv_msg = handshake::build_certificate_verify(&cfg.leaf_signing_key, &pre_cv_digest);
    record_layer.write_encrypted(handshake::CONTENT_TYPE_HANDSHAKE, &cv_msg).await?;
    transcript.update(&cv_msg);
    let pre_finished_digest = transcript.digest();

    let server_verify_data = schedule.finished_verify_data(&schedule.server_handshake_secret, &pre_finished_digest);
    let finished_msg = handshake::build_finished(&server_verify_data);
    record_layer.write_encrypted(handshake::CONTENT_TYPE_HANDSHAKE, &finished_msg).await?;
    transcript.update(&finished_msg);
    let through_server_finished = transcript.digest();

    let client_finished_msg = record_layer.read_handshake_message().await?;
    let client_verify_data = handshake::parse_finished(&client_finished_msg)?;
    let expected = schedule.finished_verify_data(&schedule.client_handshake_secret, &through_server_finished);
    if client_verify_data != expected {
        return Err(anyhow!("REALITY: client Finished does not verify"));
    }

    let (client_ap_secret, server_ap_secret) = schedule.application_secrets(&through_server_finished);
    let (client_ap_key, client_ap_iv) = schedule.traffic_key_iv(&client_ap_secret);
    let (server_ap_key, server_ap_iv) = schedule.traffic_key_iv(&server_ap_secret);
    record_layer.set_read_keys(suite, client_ap_key, client_ap_iv);
    record_layer.set_write_keys(suite, server_ap_key, server_ap_iv);

    Ok(())
}
