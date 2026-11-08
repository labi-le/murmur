//! Consumer-visible regressions for `alterId > 0` (the VMess legacy MD5/CFB handshake).
//!
//! The `alterId > 0, cipher = auto` nodes pin these legacy branches: the request header becomes
//! an HMAC-MD5 over the unix seconds, keyed by the alter-id uuid, followed by the ordinary
//! header CFB-encrypted under the command key, and the response header becomes four bytes
//! CFB-decrypted under the MD5 of the request key and the MD5 of the request nonce, which also
//! derive the response body keys. The body framing itself stays the configured AEAD mode.
//!
//! Every expected byte here is built from the raw primitives (AES-CFB, MD5, HMAC, SHAKE128,
//! AES-128-GCM), never from the crate's helpers, so a change in the production format cannot
//! rewrite the expectation.
// Test code is exempt from the production panic posture: the bans on `unwrap`,
// `expect`, `panic`, indexing and casts exist to keep a long-lived server process
// alive, and a failing test is supposed to abort. Style tiers are exempt for the
// same reason -- the scaffolding around an assertion is not product code.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::unreachable,
    clippy::todo,
    clippy::unimplemented,
    clippy::pedantic,
    clippy::nursery
)]

use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;
use std::task::{Context, Poll};

use aes::cipher::array::Array;
use aes::cipher::{InnerIvInit as _, KeyInit, KeyIvInit as _};
use aes::Aes128;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use cfb_mode::{BufDecryptor, Encryptor};
use chrono::{DateTime, TimeZone, Utc};
use hmac::{Hmac, Mac};
use md5::{Digest as _, Md5};
use murmur_sing::metadata::Socksaddr;
use murmur_std_compat::net::{Addr, Conn as NetConn, TcpAddr};
use murmur_transport_vmess::sing::client::Client;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Shake128, Shake128Reader};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use uuid::Uuid;

type HmacMd5 = Hmac<Md5>;

const UUID_STR: &str = "b831381d-6ec4-4d53-a4b6-b0e3a1b2c3d4";
const CMD_SALT: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";
const ALTER_SALT: &[u8] = b"16167dc8-16b6-4e6d-b8bb-65dd68113a81";
const TS_I64: i64 = 1_700_000_000;
const TS_U64: u64 = 1_700_000_000;

const OPTION_CHUNK_STREAM: u8 = 1;
const OPTION_CHUNK_MASKING: u8 = 4;
const SECURITY_AES128GCM: u8 = 3;
const SECURITY_NONE: u8 = 5;

fn uuid() -> Uuid {
    Uuid::parse_str(UUID_STR).expect("valid uuid")
}

fn fixed_time() -> DateTime<Utc> {
    Utc.timestamp_opt(TS_I64, 0).single().expect("valid timestamp")
}

fn md5_16(data: &[u8]) -> [u8; 16] {
    Md5::digest(data).into()
}

fn salted_md5(uuid: &Uuid, salt: &[u8]) -> [u8; 16] {
    let mut hash = Md5::new();
    md5::Digest::update(&mut hash, uuid.as_bytes());
    md5::Digest::update(&mut hash, salt);
    hash.finalize().into()
}

fn cmd_key() -> [u8; 16] {
    salted_md5(&uuid(), CMD_SALT)
}

fn alter_key() -> [u8; 16] {
    salted_md5(&uuid(), ALTER_SALT)
}

fn hmac_md5(key: &[u8], msg: &[u8]) -> [u8; 16] {
    let mut mac = HmacMd5::new_from_slice(key).expect("hmac key");
    Mac::update(&mut mac, msg);
    mac.finalize().into_bytes().into()
}

fn legacy_time_hash(ts: u64) -> [u8; 16] {
    let be = ts.to_be_bytes();
    let mut hash = Md5::new();
    for _ in 0..4 {
        md5::Digest::update(&mut hash, be);
    }
    hash.finalize().into()
}

fn cfb_encrypt(key: &[u8; 16], iv: &[u8; 16], data: &mut [u8]) {
    Encryptor::<Aes128>::new_from_slices(key, iv).expect("aes-128-cfb encrypter").encrypt(data);
}

fn cfb_decryptor(key: &[u8; 16], iv: &[u8; 16]) -> BufDecryptor<Aes128> {
    BufDecryptor::<Aes128>::inner_iv_init(Aes128::new(&Array::from(*key)), &Array::from(*iv))
}

fn fnv1a32(data: &[u8]) -> u32 {
    let mut hash: u32 = 2_166_136_261;
    for &byte in data {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(16_777_619);
    }
    hash
}

fn nonce_with_count(base: &[u8; 12], count: u16) -> [u8; 12] {
    let mut nonce = *base;
    nonce[..2].copy_from_slice(&count.to_be_bytes());
    nonce
}

fn gcm_seal(key: &[u8], nonce12: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes128Gcm::new_from_slice(key).expect("aes-128-gcm key");
    cipher
        .encrypt(<&Nonce<_>>::try_from(&nonce12[..]).expect("12-byte nonce"), Payload { msg: plaintext, aad: &[] })
        .expect("seal")
}

fn gcm_open(key: &[u8], nonce12: &[u8; 12], ciphertext: &[u8]) -> Vec<u8> {
    let cipher = Aes128Gcm::new_from_slice(key).expect("aes-128-gcm key");
    cipher
        .decrypt(<&Nonce<_>>::try_from(&nonce12[..]).expect("12-byte nonce"), Payload { msg: ciphertext, aad: &[] })
        .expect("open")
}

struct DuplexConn {
    inner: DuplexStream,
    max_read: usize,
}

impl DuplexConn {
    const fn new(inner: DuplexStream, max_read: usize) -> Self {
        Self { inner, max_read }
    }
}

impl AsyncRead for DuplexConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.max_read == 0 || buf.remaining() <= this.max_read {
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }
        let mut tmp = vec![0u8; this.max_read];
        let mut limited = ReadBuf::new(&mut tmp);
        match Pin::new(&mut this.inner).poll_read(cx, &mut limited) {
            Poll::Ready(Ok(())) => {
                buf.put_slice(limited.filled());
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for DuplexConn {
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

impl NetConn for DuplexConn {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        Ok(Box::new(TcpAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)))
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        Ok(Box::new(TcpAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)))
    }

    fn close(&self) -> io::Result<()> {
        Ok(())
    }
}

fn duplex_conn(io: DuplexStream, max_read: usize) -> Box<dyn NetConn> {
    Box::new(DuplexConn::new(io, max_read))
}

struct Request {
    auth: [u8; 16],
    version: u8,
    request_nonce: [u8; 16],
    request_key: [u8; 16],
    response_header: u8,
    option: u8,
    security: u8,
    padding_len: u8,
    command: u8,
    port: u16,
    addr: Vec<u8>,
    plain: Vec<u8>,
    checksum: u32,
}

impl Request {
    fn fnv_ok(&self) -> bool {
        fnv1a32(&self.plain[..self.plain.len() - 4]) == self.checksum
    }
}

async fn read_plain<R: AsyncRead + Unpin>(
    r: &mut R,
    dec: &mut BufDecryptor<Aes128>,
    plain: &mut Vec<u8>,
    n: usize,
) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf).await.expect("request bytes");
    dec.decrypt(&mut buf);
    plain.extend_from_slice(&buf);
    buf
}

async fn parse_request<R: AsyncRead + Unpin>(r: &mut R, key: &[u8; 16], iv: &[u8; 16]) -> Request {
    let mut auth = [0u8; 16];
    r.read_exact(&mut auth).await.expect("legacy auth id");

    let mut dec = cfb_decryptor(key, iv);
    let mut plain = Vec::new();
    let version = read_plain(r, &mut dec, &mut plain, 1).await[0];
    let request_nonce: [u8; 16] = read_plain(r, &mut dec, &mut plain, 16).await.try_into().expect("nonce");
    let request_key: [u8; 16] = read_plain(r, &mut dec, &mut plain, 16).await.try_into().expect("key");
    let response_header = read_plain(r, &mut dec, &mut plain, 1).await[0];
    let option = read_plain(r, &mut dec, &mut plain, 1).await[0];
    let padding_security = read_plain(r, &mut dec, &mut plain, 1).await[0];
    let _reversed = read_plain(r, &mut dec, &mut plain, 1).await[0];
    let command = read_plain(r, &mut dec, &mut plain, 1).await[0];
    let port = u16::from_be_bytes(read_plain(r, &mut dec, &mut plain, 2).await.try_into().expect("port"));
    let family = read_plain(r, &mut dec, &mut plain, 1).await[0];
    let addr = match family {
        1 => read_plain(r, &mut dec, &mut plain, 4).await,
        3 => read_plain(r, &mut dec, &mut plain, 16).await,
        2 => {
            let len = usize::from(read_plain(r, &mut dec, &mut plain, 1).await[0]);
            read_plain(r, &mut dec, &mut plain, len).await
        }
        other => panic!("unknown address family {other}"),
    };
    let padding_len = padding_security >> 4;
    let _padding = read_plain(r, &mut dec, &mut plain, usize::from(padding_len)).await;
    let checksum = u32::from_be_bytes(read_plain(r, &mut dec, &mut plain, 4).await.try_into().expect("checksum"));

    Request {
        auth,
        version,
        request_nonce,
        request_key,
        response_header,
        option,
        security: padding_security & 0x0f,
        padding_len,
        command,
        port,
        addr,
        plain,
        checksum,
    }
}

async fn read_one_frame<R: AsyncRead + Unpin>(r: &mut R, key: &[u8], nonce16: &[u8; 16]) -> Vec<u8> {
    let mut base = [0u8; 12];
    base.copy_from_slice(&nonce16[..12]);
    let mut shake = Shake128::default().chain(&nonce16[..]).finalize_xof();
    let mut len = [0u8; 2];
    r.read_exact(&mut len).await.expect("frame length");
    let mut mask = [0u8; 2];
    shake.read(&mut mask);
    let length = usize::from(u16::from_be_bytes(len) ^ u16::from_be_bytes(mask));
    let mut sealed = vec![0u8; length];
    r.read_exact(&mut sealed).await.expect("frame body");
    gcm_open(key, &nonce_with_count(&base, 0), &sealed)
}

struct ReferenceResponder {
    key: [u8; 16],
    iv: [u8; 16],
    base: [u8; 12],
    shake: Shake128Reader,
    count: u16,
    option: u8,
}

impl ReferenceResponder {
    fn new(request: &Request) -> Self {
        let key = md5_16(&request.request_key);
        let iv = md5_16(&request.request_nonce);
        let mut base = [0u8; 12];
        base.copy_from_slice(&iv[..12]);
        let shake = Shake128::default().chain(&iv[..]).finalize_xof();
        Self { key, iv, base, shake, count: 0, option: request.option }
    }

    fn header(&mut self, response_header: u8) -> Vec<u8> {
        let mut header = vec![response_header, self.option, 0, 0];
        cfb_encrypt(&self.key, &self.iv, &mut header);
        header
    }

    fn frame(&mut self, chunk: &[u8]) -> Vec<u8> {
        let sealed = gcm_seal(&self.key, &nonce_with_count(&self.base, self.count), chunk);
        self.count = self.count.wrapping_add(1);
        let mut out = Vec::with_capacity(2 + sealed.len());
        out.extend_from_slice(&masked_length(&mut self.shake, sealed.len()));
        out.extend_from_slice(&sealed);
        out
    }

    fn terminator(&mut self) -> Vec<u8> {
        masked_length(&mut self.shake, 0).to_vec()
    }
}

fn masked_length(shake: &mut Shake128Reader, len: usize) -> [u8; 2] {
    let mut mask = [0u8; 2];
    shake.read(&mut mask);
    (u16::try_from(len).expect("frame fits u16") ^ u16::from_be_bytes(mask)).to_be_bytes()
}

#[tokio::test]
async fn legacy_alter_id_request_matches_reference_and_keeps_aead_body() {
    let (client_io, mut server_io) = tokio::io::duplex(1 << 20);
    let client = Client::new(uuid(), "aes-128-gcm", 4, false, false, fixed_time).expect("client");
    let dest = Socksaddr::from_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 34)), 443);

    let mut conn = client
        .dial_conn(duplex_conn(client_io, 0), dest)
        .await
        .expect("alterId = 4 must dial with the legacy MD5/CFB handshake instead of being refused");
    let conn = &mut *conn;

    let request = parse_request(&mut server_io, &cmd_key(), &legacy_time_hash(TS_U64)).await;
    assert_eq!(request.version, 1);
    assert_eq!(request.command, 1);
    assert_eq!(request.option, OPTION_CHUNK_STREAM | OPTION_CHUNK_MASKING);
    assert_eq!(request.security, SECURITY_AES128GCM);
    assert!(request.padding_len < 16, "padding must stay below the 16-byte cap");
    assert_eq!(
        request.auth,
        hmac_md5(&alter_key(), &TS_U64.to_be_bytes()),
        "legacy auth must be HMAC-MD5 keyed by the alter-id uuid"
    );
    assert_ne!(
        request.auth,
        hmac_md5(uuid().as_bytes(), &TS_U64.to_be_bytes()),
        "legacy auth must not fall back to the raw uuid key"
    );
    assert!(request.fnv_ok(), "the header checksum must cover the plaintext header");
    assert_eq!(request.port, 443);
    assert_eq!(request.addr, vec![192, 0, 2, 34]);

    let payload: &[u8] = b"vmess legacy request body";
    conn.write_all(payload).await.expect("write payload");
    let body = read_one_frame(&mut server_io, &request.request_key, &request.request_nonce).await;
    assert_eq!(body, payload, "the request body must stay the configured AEAD mode");
}

#[tokio::test]
async fn legacy_alter_id_response_is_decoded_with_md5_derived_keys() {
    let (client_io, mut server_io) = tokio::io::duplex(1 << 20);
    let client = Client::new(uuid(), "aes-128-gcm", 4, false, false, fixed_time).expect("client");
    let dest = Socksaddr::from_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 34)), 443);

    let mut conn = client
        .dial_conn(duplex_conn(client_io, 0), dest)
        .await
        .expect("alterId = 4 must dial with the legacy MD5/CFB handshake instead of being refused");
    let conn = &mut *conn;
    let request = parse_request(&mut server_io, &cmd_key(), &legacy_time_hash(TS_U64)).await;

    let payload: &[u8] = b"vmess legacy response body";
    let mut responder = ReferenceResponder::new(&request);
    let mut wire = responder.header(request.response_header);
    wire.extend_from_slice(&responder.frame(payload));
    wire.extend_from_slice(&responder.terminator());
    server_io.write_all(&wire).await.expect("write response");

    let mut got = vec![0u8; payload.len()];
    conn.read_exact(&mut got)
        .await
        .expect("the legacy response header and AEAD body must decode under the md5-derived keys");
    assert_eq!(got, payload);

    let mut eof = [0u8; 8];
    assert_eq!(conn.read(&mut eof).await.expect("terminal read"), 0, "the terminal chunk ends the stream cleanly");
}

#[tokio::test]
async fn legacy_alter_id_partial_io_response_survives_one_byte_reads() {
    let (client_io, mut server_io) = tokio::io::duplex(1 << 20);
    let client = Client::new(uuid(), "aes-128-gcm", 4, false, false, fixed_time).expect("client");
    let dest = Socksaddr::from_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 34)), 443);

    let mut conn = client
        .dial_conn(duplex_conn(client_io, 1), dest)
        .await
        .expect("alterId = 4 must dial with the legacy MD5/CFB handshake instead of being refused");
    let conn = &mut *conn;
    let request = parse_request(&mut server_io, &cmd_key(), &legacy_time_hash(TS_U64)).await;

    let chunks: [&[u8]; 2] = [b"first-legacy-part-", b"second-legacy-part"];
    let mut responder = ReferenceResponder::new(&request);
    let mut wire = responder.header(request.response_header);
    for chunk in chunks {
        wire.extend_from_slice(&responder.frame(chunk));
    }
    wire.extend_from_slice(&responder.terminator());
    for byte in &wire {
        server_io.write_all(&[*byte]).await.expect("write response byte");
    }

    let expected: Vec<u8> = chunks.concat();
    let mut got = Vec::new();
    let mut small = [0u8; 5];
    while got.len() < expected.len() {
        let n = conn.read(&mut small).await.expect("read under one-byte upstream reads");
        assert!(n > 0, "a partial read must still make progress");
        got.extend_from_slice(&small[..n]);
    }
    assert_eq!(got, expected);
}

#[tokio::test]
async fn legacy_alter_id_mismatched_response_header_is_rejected() {
    let (client_io, mut server_io) = tokio::io::duplex(1 << 20);
    let client = Client::new(uuid(), "aes-128-gcm", 4, false, false, fixed_time).expect("client");
    let dest = Socksaddr::from_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 34)), 443);

    let mut conn = client
        .dial_conn(duplex_conn(client_io, 0), dest)
        .await
        .expect("alterId = 4 must dial with the legacy MD5/CFB handshake instead of being refused");
    let conn = &mut *conn;
    let request = parse_request(&mut server_io, &cmd_key(), &legacy_time_hash(TS_U64)).await;

    let mut responder = ReferenceResponder::new(&request);
    let mut wire = responder.header(request.response_header ^ 0x5a);
    wire.extend_from_slice(&responder.frame(b"data"));
    server_io.write_all(&wire).await.expect("write response");

    let mut buf = [0u8; 4];
    let _error =
        conn.read(&mut buf).await.expect_err("a response header byte that does not echo the request must be rejected");
}

#[tokio::test]
async fn legacy_alter_id_security_none_keeps_legacy_header_and_raw_body() {
    let (client_io, mut server_io) = tokio::io::duplex(1 << 20);
    let client = Client::new(uuid(), "none", 4, false, false, fixed_time).expect("client");
    let dest = Socksaddr::from_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 34)), 443);

    let mut conn = client
        .dial_conn(duplex_conn(client_io, 0), dest)
        .await
        .expect("alterId = 4 must dial with the legacy MD5/CFB handshake instead of being refused");
    let conn = &mut *conn;
    let request = parse_request(&mut server_io, &cmd_key(), &legacy_time_hash(TS_U64)).await;
    assert_eq!(request.option, 0, "security = none keeps the TCP option byte clear");
    assert_eq!(request.security, SECURITY_NONE);

    let mut header = vec![request.response_header, request.option, 0, 0];
    cfb_encrypt(&md5_16(&request.request_key), &md5_16(&request.request_nonce), &mut header);
    server_io.write_all(&header).await.expect("write response header");
    let payload: &[u8] = b"raw-body-with-legacy-header";
    server_io.write_all(payload).await.expect("write raw body");

    let mut got = vec![0u8; payload.len()];
    conn.read_exact(&mut got).await.expect("raw body after a legacy response header");
    assert_eq!(got, payload);
}

#[tokio::test]
async fn legacy_alter_id_response_command_bytes_are_consumed_before_the_body() {
    let (client_io, mut server_io) = tokio::io::duplex(1 << 20);
    let client = Client::new(uuid(), "aes-128-gcm", 4, false, false, fixed_time).expect("client");
    let dest = Socksaddr::from_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 34)), 443);

    let mut conn = client
        .dial_conn(duplex_conn(client_io, 0), dest)
        .await
        .expect("alterId = 4 must dial with the legacy MD5/CFB handshake instead of being refused");
    let conn = &mut *conn;
    let request = parse_request(&mut server_io, &cmd_key(), &legacy_time_hash(TS_U64)).await;

    let mut responder = ReferenceResponder::new(&request);
    let command: [u8; 3] = [0xaa, 0xbb, 0xcc];
    let mut header = vec![request.response_header, request.option, 0, u8::try_from(command.len()).expect("fits")];
    cfb_encrypt(&responder.key, &responder.iv, &mut header);
    let mut wire = header;
    wire.extend_from_slice(&command);
    wire.extend_from_slice(&responder.frame(b"after-command"));
    wire.extend_from_slice(&responder.terminator());
    server_io.write_all(&wire).await.expect("write response");

    let mut got = vec![0u8; 13];
    conn.read_exact(&mut got).await.expect("body decodes after the response command bytes");
    assert_eq!(got, b"after-command");
}
