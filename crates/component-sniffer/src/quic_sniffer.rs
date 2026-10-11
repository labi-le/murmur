//! RFC 9000 variable-length integers live in the `quicvarint` submodule below, scoped to this
//! file's synchronous byte-slice cursor rather than the stream-oriented `transport::masque` mirror.

use std::sync::Arc;
use std::time::Duration;

use aes::cipher::{BlockCipherEncrypt, KeyInit};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use hkdf::Hkdf;
use parking_lot::RwLock;
use sha2::Sha256;
use thiserror::Error;
use tokio_util::sync::CancellationToken;

use murmur_compat::sing_buf::{new_packet, Buffer};
use murmur_constant::adapters::{PacketAdapter, PacketSender};
use murmur_constant::metadata::{Metadata, NetWork};
use murmur_constant::sniffer::sniffer::{MultiPacketSniffer, ReplaceDomain, Sniffer};

use super::base_sniffer::{BaseSniffer, SnifferConfig};
use super::bitmap::Bitmap;
use super::tls_sniffer::{
    client_hello_size, read_client_hello, ClientHelloError, ErrNotClientHello, ErrNotTLS, TLS_HANDSHAKE_HEADER_LEN,
};

/// Timeout before the QUIC sniffer gives up on a connection.
const QUIC_WAIT_CONN: Duration = Duration::from_secs(3);

/// Bounds both the highest Initial CRYPTO stream offset and the payload retained by the sniffer.
const MAX_CRYPTO_STREAM_OFFSET: u64 = 64 * 1024;

/// RFC 9000 §19.
const FRAME_PADDING: u8 = 0x0;
const FRAME_PING: u8 = 0x1;
const FRAME_ACK: u8 = 0x2;
const FRAME_ACK_WITH_ECN: u8 = 0x3;
const FRAME_CRYPTO: u8 = 0x6;
const FRAME_CONNECTION_CLOSE: u8 = 0x1c;

#[derive(Debug, Error)]
#[error("not QUIC")]
pub(crate) struct ErrNotQUIC;

#[derive(Debug, Error)]
#[error("not QUIC initial packet")]
pub(crate) struct ErrNotQUICInitial;

#[derive(Debug, Error)]
#[error("QUIC decryption failed")]
pub(crate) struct ErrQUICDecryptionFailed;

/// QUIC v2 remaps long-header packet type bits, so Initial and Retry values are stored with the
/// other version-specific parameters.
pub(crate) struct QuicStructure {
    ver: u32,
    type_initial: u8,
    type_retry: u8,
    initial_salt: &'static [u8],
    label_prefix: &'static str,
}

static QUIC_DRAFT29: QuicStructure = QuicStructure {
    ver: 0xff00_001d,
    type_initial: 0b00,
    type_retry: 0b11,
    initial_salt: &[
        0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90,
        0xa8, 0x99,
    ],
    label_prefix: "quic",
};

/// RFC 9001 §5.2.
static QUIC_V1: QuicStructure = QuicStructure {
    ver: 0x1,
    type_initial: 0b00,
    type_retry: 0b11,
    initial_salt: &[
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb,
        0x7f, 0x0a,
    ],
    label_prefix: "quic",
};

/// RFC 9369 §3.2 – 3.3.
static QUIC_V2: QuicStructure = QuicStructure {
    ver: 0x6b33_43cf,
    type_initial: 0b01,
    type_retry: 0b00,
    initial_salt: &[
        0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd,
        0x2e, 0xd9,
    ],
    label_prefix: "quicv2",
};

static LIST_QUIC_VERSIONS: [&QuicStructure; 3] = [&QUIC_DRAFT29, &QUIC_V1, &QUIC_V2];

#[derive(Clone, Default)]
struct QuicLabels {
    hp: Vec<u8>,
    key: Vec<u8>,
    iv: Vec<u8>,
}

#[derive(Clone, Default)]
struct QuicInitialKey {
    dest_conn_id: Vec<u8>,
    labels: QuicLabels,
    largest_packet_number: i64,
}

#[derive(Debug)]
pub struct QUICSniffer {
    base: BaseSniffer,
}

impl QUICSniffer {
    pub fn new(sniffer_config: SnifferConfig) -> anyhow::Result<Self> {
        let mut ports = sniffer_config.ports;
        if ports.is_empty() {
            ports =
                murmur_common::utils::ranges::IntRanges::from(vec![murmur_common::utils::range::new_range(443, 443)]);
        }
        Ok(Self { base: BaseSniffer::new(ports, NetWork::UDP) })
    }
}

impl Sniffer for QUICSniffer {
    fn support_network(&self) -> NetWork {
        NetWork::UDP
    }

    fn as_multi_packet(&self) -> Option<&dyn MultiPacketSniffer> {
        Some(self)
    }

    fn sniff_data(&self, _b: &[u8]) -> anyhow::Result<String> {
        Err(super::dispatcher::ErrorUnsupportedSniffer.into())
    }

    fn protocol(&self) -> String {
        "quic".to_owned()
    }

    fn support_port(&self, port: u16) -> bool {
        self.base.support_port(port)
    }
}

impl MultiPacketSniffer for QUICSniffer {
    fn wrapper_sender(
        &self,
        packet_sender: Arc<dyn PacketSender>,
        replace_domain: ReplaceDomain,
    ) -> Arc<dyn PacketSender> {
        Arc::new(QuicPacketSender {
            inner: packet_sender,
            replace_domain,
            state: RwLock::new(QuicPacketSenderState::default()),
            done: CancellationToken::new(),
        })
    }
}

#[derive(Default)]
struct QuicPacketSenderState {
    structure: Option<&'static QuicStructure>,
    initial_keys: Vec<QuicInitialKey>,
    buffer: Vec<u8>,
    received_crypto_data: Bitmap,
    contiguous_crypto_end: u64,
    result: String,
    closed: bool,
}

pub(crate) struct QuicPacketSender {
    inner: Arc<dyn PacketSender>,
    replace_domain: ReplaceDomain,
    state: RwLock<QuicPacketSenderState>,
    done: CancellationToken,
}

#[async_trait::async_trait]
impl PacketSender for QuicPacketSender {
    /// `Send`: the wrapped sender is always invoked at the end, whether or not the packet parsed.
    // cancel-safe: every sniffer-side state change happens before the only await.
    async fn send(&self, current: Arc<dyn PacketAdapter>) {
        let closed = self.state.read().closed;
        if !closed && self.read_quic_data(current.data()).is_err() {
            self.close();
        }
        self.inner.send(current).await;
    }

    // cancel-safe: no state is touched; the call forwards to the wrapped sender.
    async fn process(
        &self,
        conn: Arc<dyn murmur_constant::adapters::PacketConn>,
        proxy: Arc<dyn murmur_constant::adapters::WriteBackProxy>,
    ) {
        self.inner.process(conn, proxy).await;
    }

    fn close(&self) {
        self.inner.close();
        self.close_sniffing();
    }

    // NOT cancel-safe: the replacement runs on the inner call after the select, so a future
    // dropped mid-await leaves the sniffed domain unapplied.
    async fn do_sniff(&self, metadata: &mut Metadata) -> anyhow::Result<()> {
        tokio::select! {
            () = self.done.cancelled() => {
                let result = self.state.read().result.clone();
                if !result.is_empty() {
                    (self.replace_domain)(metadata, &result);
                }
            }
            () = tokio::time::sleep(QUIC_WAIT_CONN) => {
                self.close_sniffing();
            }
        }

        self.inner.do_sniff(metadata).await
    }

    fn add_mapping(&self, origin_metadata: &Metadata, metadata: &Metadata) {
        self.inner.add_mapping(origin_metadata, metadata);
    }

    fn restore_read_from(&self, addr: std::net::IpAddr) -> std::net::IpAddr {
        self.inner.restore_read_from(addr)
    }
}

impl QuicPacketSender {
    /// the `close`; renamed to avoid clashing with the `PacketSender::close` trait method.
    fn close_sniffing(&self) {
        let mut state = self.state.write();
        if !state.closed {
            self.done.cancel();
            state.closed = true;
            let old_buffer = std::mem::take(&mut state.buffer);
            let _ = murmur_common_pool::put(old_buffer);
            state.received_crypto_data = Bitmap::default();
            state.contiguous_crypto_end = 0;
        }
    }

    /// A UDP datagram can contain multiple coalesced QUIC packets. Walk each packet boundary so
    /// every Initial packet contributes its CRYPTO data.
    fn read_quic_data(&self, mut b: &[u8]) -> anyhow::Result<()> {
        let mut first_packet = true;
        while !b.is_empty() {
            let packet_len = self.read_quic_packet(b, !first_packet)?;
            if packet_len == 0 {
                return Err(ErrNotQUIC.into());
            }
            let Some(rest) = b.get(packet_len..) else {
                return Err(ErrNotQUIC.into());
            };
            b = rest;
            first_packet = false;
        }

        let domain = self.try_assemble()?;
        if !domain.is_empty() {
            self.state.write().result = domain;
            self.close_sniffing();
        }

        Ok(())
    }

    /// Processes one packet and returns its length in the datagram. Long-header packets carry an
    /// explicit length. A short-header packet is accepted only after one of them and consumes the
    /// remainder because it has no length field.
    fn read_quic_packet(&self, b: &[u8], coalesced: bool) -> anyhow::Result<usize> {
        let mut cursor = ByteCursor::new(b);

        let type_byte = cursor.read_byte().map_err(|_| ErrNotQUIC)?;

        if type_byte & 0x80 == 0 {
            if coalesced {
                return Ok(b.len());
            }
            return Err(ErrNotQUICInitial.into());
        }
        if type_byte & 0x40 == 0 {
            return Err(ErrNotQUICInitial.into());
        }

        let vb = cursor.read_bytes(4).map_err(|_| ErrNotQUIC)?.to_vec();

        let s = self.get_quic_structure(&vb)?;

        let conn_id_len = cursor.read_byte().map_err(|_| ErrNotQUIC)?;
        if conn_id_len == 0 {
            return Err(ErrNotQUIC.into());
        }
        let dest_conn_id = cursor.read_bytes(conn_id_len as usize).map_err(|_| ErrNotQUIC)?.to_vec();

        let src_conn_id_len = cursor.read_byte().map_err(|_| ErrNotQUIC)?;
        cursor.read_bytes(src_conn_id_len as usize).map_err(|_| ErrNotQUIC)?;

        let packet_type = (type_byte & 0x30) >> 4;
        if packet_type == s.type_retry {
            return Ok(b.len());
        }

        if packet_type == s.type_initial {
            let token_len = quicvarint::read(&mut cursor).map_err(|_| ErrNotQUIC)?;
            let Ok(token_len) = usize::try_from(token_len) else {
                return Err(ErrNotQUIC.into());
            };
            if token_len > cursor.remaining() {
                return Err(ErrNotQUIC.into());
            }
            cursor.read_bytes(token_len).map_err(|_| ErrNotQUIC)?;
        }

        let packet_len = quicvarint::read(&mut cursor).map_err(|_| ErrNotQUIC)?;

        let hdr_len = b.len() - cursor.remaining();
        let Ok(packet_len) = usize::try_from(packet_len) else {
            return Err(ErrNotQUIC.into());
        };
        if packet_len > b.len() - hdr_len {
            return Err(ErrNotQUIC.into());
        }
        let packet_end = hdr_len + packet_len;
        if packet_type != s.type_initial {
            return Ok(packet_end);
        }

        let mut cache = new_packet();
        let decrypted = match self.decrypt_quic_initial_packet(b, hdr_len, packet_end, &dest_conn_id, s, &mut cache) {
            Ok(decrypted) => decrypted,
            Err(err) => {
                cache.release();
                if err.is::<ErrQUICDecryptionFailed>() {
                    return Ok(packet_end);
                }
                return Err(err);
            }
        };
        cache.release();

        self.read_quic_frames(&decrypted)?;

        Ok(packet_end)
    }

    /// Tries the Initial key epochs retained for the connection. Retry changes the Initial keys
    /// without resetting packet numbers. Per-key decoder state also lets delayed pre-Retry
    /// packets be authenticated, while later header DCID changes continue using the same
    /// retained keys.
    fn decrypt_quic_initial_packet(
        &self,
        b: &[u8],
        hdr_len: usize,
        packet_end: usize,
        dest_conn_id: &[u8],
        s: &'static QuicStructure,
        cache: &mut Buffer,
    ) -> anyhow::Result<Vec<u8>> {
        let mut state = self.state.write();

        if state.initial_keys.is_empty() {
            let key = new_quic_initial_key(dest_conn_id, s)?;
            state.initial_keys.push(key);
        }

        let mut decrypt_err: Option<anyhow::Error> = None;
        let mut has_current_dest_conn_id = false;
        let mut largest_packet_number = -1i64;
        for key in &mut state.initial_keys {
            has_current_dest_conn_id = has_current_dest_conn_id || dest_conn_id == key.dest_conn_id.as_slice();
            if key.largest_packet_number > largest_packet_number {
                largest_packet_number = key.largest_packet_number;
            }
            match decrypt_quic_initial_packet(b, hdr_len, packet_end, &key.labels, key.largest_packet_number, cache) {
                Ok((decrypted, packet_number)) => {
                    if packet_number > key.largest_packet_number {
                        key.largest_packet_number = packet_number;
                    }
                    return Ok(decrypted);
                }
                Err(err) => decrypt_err = Some(err),
            }
        }
        if has_current_dest_conn_id {
            return Err(decrypt_err.unwrap_or_else(|| ErrQUICDecryptionFailed.into()));
        }

        // A Retry changes the DCID used to derive Initial keys without resetting the packet
        // number space, so the new epoch inherits the largest authenticated packet number. Add it
        // only after authentication, preventing a corrupt packet from replacing working keys.
        // QUIC permits at most one accepted Retry, keeping two epochs sufficient for a connection.
        let mut candidate = new_quic_initial_key(dest_conn_id, s)?;
        candidate.largest_packet_number = largest_packet_number;
        let (decrypted, packet_number) = decrypt_quic_initial_packet(
            b,
            hdr_len,
            packet_end,
            &candidate.labels,
            candidate.largest_packet_number,
            cache,
        )?;
        candidate.largest_packet_number = packet_number;
        if state.initial_keys.len() == 1 {
            state.initial_keys.push(candidate);
        } else if let Some(retry_keys) = state.initial_keys.get_mut(1) {
            *retry_keys = candidate;
        }
        drop(state);
        Ok(decrypted)
    }

    /// Validates the frames allowed in an Initial packet and retains CRYPTO frame data for
    /// `ClientHello` reassembly.
    fn read_quic_frames(&self, data: &[u8]) -> anyhow::Result<()> {
        let mut cursor = ByteCursor::new(data);
        while !cursor.is_empty() {
            if self.state.read().closed {
                return Ok(());
            }

            let mut frame_type = FRAME_PADDING;
            while frame_type == FRAME_PADDING && !cursor.is_empty() {
                frame_type = cursor.read_byte().unwrap_or(FRAME_PADDING);
            }
            match frame_type {
                FRAME_PADDING | FRAME_PING => {}
                FRAME_ACK | FRAME_ACK_WITH_ECN => {
                    quicvarint::read(&mut cursor)?;
                    quicvarint::read(&mut cursor)?;
                    let ack_range_count = quicvarint::read(&mut cursor)?;
                    quicvarint::read(&mut cursor)?;
                    for _ in 0..ack_range_count {
                        quicvarint::read(&mut cursor)?;
                        quicvarint::read(&mut cursor)?;
                    }
                    if frame_type == FRAME_ACK_WITH_ECN {
                        quicvarint::read(&mut cursor)?;
                        quicvarint::read(&mut cursor)?;
                        quicvarint::read(&mut cursor)?;
                    }
                }
                FRAME_CRYPTO => {
                    let offset = quicvarint::read(&mut cursor)?;
                    let length = quicvarint::read(&mut cursor)?;
                    let Ok(length) = usize::try_from(length) else {
                        anyhow::bail!(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
                    };
                    if length > cursor.remaining() {
                        anyhow::bail!(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
                    }
                    let data = cursor.read_bytes(length)?.to_vec();
                    self.add_crypto_data(offset, &data)?;
                }
                FRAME_CONNECTION_CLOSE => {
                    quicvarint::read(&mut cursor)?;
                    quicvarint::read(&mut cursor)?;
                    let length = quicvarint::read(&mut cursor)?;
                    let Ok(length) = usize::try_from(length) else {
                        anyhow::bail!(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
                    };
                    if length > cursor.remaining() {
                        anyhow::bail!(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
                    }
                    cursor.read_bytes(length)?;
                }
                _ => return Err(ErrNotQUICInitial.into()),
            }
        }
        Ok(())
    }

    /// Stores a bounded CRYPTO fragment, growing the buffer only as needed and tracking exact
    /// byte coverage across out-of-order, overlapping, or retransmitted frames.
    fn add_crypto_data(&self, offset: u64, data: &[u8]) -> anyhow::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let length = data.len() as u64;
        if offset > MAX_CRYPTO_STREAM_OFFSET || length > MAX_CRYPTO_STREAM_OFFSET - offset {
            anyhow::bail!(std::io::Error::from(std::io::ErrorKind::WriteZero));
        }
        let start = usize::try_from(offset).map_err(|_| std::io::Error::from(std::io::ErrorKind::WriteZero))?;
        let end = usize::try_from(offset + length).map_err(|_| std::io::Error::from(std::io::ErrorKind::WriteZero))?;

        let mut state = self.state.write();
        if state.closed {
            return Ok(());
        }

        if end > state.buffer.capacity() {
            let mut new_buffer = murmur_common_pool::get(end);
            let old_len = state.buffer.len();
            let Some(head) = new_buffer.get_mut(..old_len) else {
                anyhow::bail!(std::io::Error::from(std::io::ErrorKind::WriteZero));
            };
            head.copy_from_slice(&state.buffer);
            let old_buffer = std::mem::replace(&mut state.buffer, new_buffer);
            let _ = murmur_common_pool::put(old_buffer);
        } else if end > state.buffer.len() {
            state.buffer.resize(end, 0);
        }
        let Some(dst) = state.buffer.get_mut(start..end) else {
            anyhow::bail!(std::io::Error::from(std::io::ErrorKind::WriteZero));
        };
        dst.copy_from_slice(data);

        state.received_crypto_data.set_range(start.cast_signed(), end.cast_signed());

        // The contiguous prefix only moves forward, allowing the bitmap to skip complete words
        // without rescanning the assembled prefix.
        let contiguous_end = state.contiguous_crypto_end;
        if offset <= contiguous_end && offset + length > contiguous_end {
            let buffer_len = state.buffer.len().cast_signed();
            let from =
                isize::try_from(contiguous_end).map_err(|_| std::io::Error::from(std::io::ErrorKind::WriteZero))?;
            let next_end = state.received_crypto_data.first_unset(from, buffer_len);
            state.contiguous_crypto_end =
                u64::try_from(next_end).map_err(|_| std::io::Error::from(std::io::ErrorKind::WriteZero))?;
        }
        drop(state);
        Ok(())
    }

    #[expect(
        clippy::significant_drop_tightening,
        reason = "the read guard is the accessor for the buffered crypto stream; cloning it out to shorten the guard would allocate on every sniff"
    )]
    fn try_assemble(&self) -> anyhow::Result<String> {
        let state = self.state.read();

        if state.closed || state.contiguous_crypto_end == 0 {
            return Ok(String::new());
        }
        let contiguous_end = usize::try_from(state.contiguous_crypto_end)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::WriteZero))?;

        if state.contiguous_crypto_end >= TLS_HANDSHAKE_HEADER_LEN as u64 {
            let Some(header) = state.buffer.get(..TLS_HANDSHAKE_HEADER_LEN) else {
                anyhow::bail!(std::io::Error::from(std::io::ErrorKind::WriteZero));
            };
            let hello_size = client_hello_size(header)?;
            if hello_size as u64 > MAX_CRYPTO_STREAM_OFFSET {
                anyhow::bail!(std::io::Error::from(std::io::ErrorKind::WriteZero));
            }
        }

        let Some(crypto_data) = state.buffer.get(..contiguous_end) else {
            anyhow::bail!(std::io::Error::from(std::io::ErrorKind::WriteZero));
        };
        match read_client_hello(crypto_data) {
            Ok(domain) => Ok(domain),
            Err(ClientHelloError::NeedMoreData(length)) => {
                if length as u64 > MAX_CRYPTO_STREAM_OFFSET {
                    anyhow::bail!(std::io::Error::from(std::io::ErrorKind::WriteZero));
                }
                Ok(String::new())
            }
            Err(ClientHelloError::NotClientHello) => Err(ErrNotClientHello.into()),
            Err(ClientHelloError::NotTLS) => Err(ErrNotTLS.into()),
            Err(ClientHelloError::Other(err)) => Err(err),
        }
    }

    fn get_quic_structure(&self, vb: &[u8]) -> anyhow::Result<&'static QuicStructure> {
        let mut state = self.state.write();
        if let Some(structure) = state.structure {
            return Ok(structure);
        }

        let Ok(version) = <[u8; 4]>::try_from(vb) else {
            return Err(ErrNotQUIC.into());
        };
        let n = u32::from_be_bytes(version);
        for v in LIST_QUIC_VERSIONS {
            if v.ver == n {
                state.structure = Some(v);
                drop(state);
                return Ok(v);
            }
        }

        Err(ErrNotQUIC.into())
    }
}

/// Removes header protection and decrypts one Initial packet with the supplied key set.
fn decrypt_quic_initial_packet(
    b: &[u8],
    hdr_len: usize,
    packet_end: usize,
    labels: &QuicLabels,
    largest_packet_number: i64,
    cache: &mut Buffer,
) -> anyhow::Result<(Vec<u8>, i64)> {
    // Failed key epochs leave scratch data behind. Reset it before every attempt so trying
    // retained Retry keys does not consume the buffer cumulatively.
    cache.reset();

    let hp_key: [u8; 16] = labels.hp.as_slice().try_into().map_err(|_| ErrNotQUIC)?;
    let hp_cipher = aes::Aes128::new_from_slice(&hp_key).map_err(|_| ErrNotQUIC)?;

    if hdr_len + 4 + 16 > packet_end {
        return Err(ErrNotQUIC.into());
    }

    let Some(sample) = b.get(hdr_len + 4..hdr_len + 4 + 16) else {
        return Err(ErrNotQUIC.into());
    };
    let sample: [u8; 16] = sample.try_into().map_err(|_| ErrNotQUIC)?;
    let mut mask_block = cipher::Array::from(sample);
    hp_cipher.encrypt_block(&mut mask_block);
    let mask: [u8; 16] = mask_block.into();
    let Some(&encrypted_first_byte) = b.first() else {
        return Err(ErrNotQUIC.into());
    };
    // Long headers have their low four bits protected.
    let first_byte = encrypted_first_byte ^ (mask[0] & 0x0f);
    let packet_number_length = usize::from((first_byte & 0x3) + 1);
    let ext_hdr_len = hdr_len + packet_number_length;

    let Some(plain_header) = b.get(..ext_hdr_len) else {
        return Err(ErrNotQUIC.into());
    };
    let ext_hdr = cache.extend(ext_hdr_len);
    ext_hdr.copy_from_slice(plain_header);
    let Some(protected_first_byte) = ext_hdr.first_mut() else {
        return Err(ErrNotQUIC.into());
    };
    *protected_first_byte = first_byte;

    let Some(protected) = ext_hdr.get_mut(hdr_len..) else {
        return Err(ErrNotQUIC.into());
    };
    for (byte, mask_byte) in protected.iter_mut().zip(mask.iter().skip(1)) {
        *byte ^= *mask_byte;
    }

    if ext_hdr_len > packet_end {
        return Err(ErrNotQUIC.into());
    }
    let mut truncated_packet_number: i64 = 0;
    let Some(protected) = ext_hdr.get(hdr_len..) else {
        return Err(ErrNotQUIC.into());
    };
    for &byte in protected {
        truncated_packet_number = (truncated_packet_number << 8) | i64::from(byte);
    }
    let decoded_packet_number =
        decode_quic_packet_number(packet_number_length, largest_packet_number, truncated_packet_number);

    let ext_hdr = ext_hdr.to_vec();
    let Some(data) = b.get(ext_hdr_len..packet_end) else {
        return Err(ErrNotQUIC.into());
    };

    let key: [u8; 16] = labels.key.as_slice().try_into().map_err(|_| ErrNotQUIC)?;
    let aead = Aes128Gcm::new_from_slice(&key).map_err(|_| ErrNotQUIC)?;

    // We only decrypt once, so we do not need to XOR it back.
    let mut iv = labels.iv.clone();
    for (byte, pn_byte) in
        iv.iter_mut().rev().take(8).zip(decoded_packet_number.cast_unsigned().to_be_bytes().iter().rev())
    {
        *byte ^= *pn_byte;
    }
    let nonce = <&Nonce<_>>::try_from(iv.as_slice()).map_err(|_| ErrNotQUIC)?;
    let decrypted = aead.decrypt(nonce, Payload { msg: data, aad: &ext_hdr }).map_err(|_| ErrQUICDecryptionFailed)?;

    Ok((decrypted, decoded_packet_number))
}

/// Reconstructs a packet number from its truncated wire representation using the window from
/// RFC 9000 Appendix A.3.
const fn decode_quic_packet_number(length: usize, largest: i64, truncated: i64) -> i64 {
    let expected = largest + 1;
    let window = 1i64 << (length * 8);
    let half_window = window / 2;
    let mask = window - 1;
    let candidate = (expected & !mask) | truncated;
    if candidate <= expected - half_window && candidate < (1i64 << 62) - window {
        candidate + window
    } else if candidate > expected + half_window && candidate >= window {
        candidate - window
    } else {
        candidate
    }
}

fn new_quic_initial_key(dest_conn_id: &[u8], s: &'static QuicStructure) -> anyhow::Result<QuicInitialKey> {
    Ok(QuicInitialKey {
        dest_conn_id: dest_conn_id.to_vec(),
        labels: expand_labels(dest_conn_id, s)?,
        largest_packet_number: -1,
    })
}

fn expand_labels(dest_conn_id: &[u8], s: &QuicStructure) -> anyhow::Result<QuicLabels> {
    let (initial_secret, _hk) = Hkdf::<Sha256>::extract(Some(s.initial_salt), dest_conn_id);
    let secret = hkdf_expand_label(&initial_secret, "client in", 32)?;

    let lp = s.label_prefix;
    Ok(QuicLabels {
        hp: hkdf_expand_label(&secret, &format!("{lp} hp"), 16)?,
        key: hkdf_expand_label(&secret, &format!("{lp} key"), 16)?,
        iv: hkdf_expand_label(&secret, &format!("{lp} iv"), 12)?,
    })
}

fn hkdf_expand_label(secret: &[u8], label: &str, length: usize) -> anyhow::Result<Vec<u8>> {
    let label_len = u8::try_from(6 + label.len()).map_err(|_| ErrNotQUIC)?;
    let mut info = Vec::with_capacity(2 + 1 + 6 + label.len() + 1);
    info.extend_from_slice(&u16::try_from(length).map_err(|_| ErrNotQUIC)?.to_be_bytes());
    info.push(label_len);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label.as_bytes());
    info.push(0);

    let hkdf = Hkdf::<Sha256>::from_prk(secret).map_err(|_| ErrNotQUIC)?;
    let mut out = vec![0u8; length];
    hkdf.expand(&info, &mut out).map_err(|_| ErrNotQUIC)?;
    Ok(out)
}

/// A read-only cursor over a byte slice: the
/// datagram bytes are only walked sequentially, never mutated, so a borrowing cursor avoids the
/// copy that wrapping them in a `common::buf::Buffer` (an owned type) would require.
struct ByteCursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ByteCursor<'a> {
    const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    const fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    const fn is_empty(&self) -> bool {
        self.pos >= self.data.len()
    }

    fn read_byte(&mut self) -> anyhow::Result<u8> {
        let b = *self.data.get(self.pos).ok_or_else(|| anyhow::anyhow!("EOF"))?;
        self.pos += 1;
        Ok(b)
    }

    fn read_bytes(&mut self, n: usize) -> anyhow::Result<&'a [u8]> {
        if self.remaining() < n {
            anyhow::bail!("EOF");
        }
        let data: &'a [u8] = self.data;
        let out = data.get(self.pos..self.pos + n).ok_or_else(|| anyhow::anyhow!("EOF"))?;
        self.pos += n;
        Ok(out)
    }
}

/// RFC 9000 §16 variable-length integers over the synchronous [`ByteCursor`] this file reads with.
mod quicvarint {
    use super::ByteCursor;

    #[cfg(test)]
    pub(super) const MAX: u64 = (1 << 62) - 1;

    pub(super) fn read(cursor: &mut ByteCursor<'_>) -> anyhow::Result<u64> {
        let first = cursor.read_byte()?;
        let length = 1usize << (first >> 6);
        let mut value = u64::from(first & 0x3f);
        for _ in 1..length {
            value = (value << 8) | u64::from(cursor.read_byte()?);
        }
        Ok(value)
    }

    #[cfg(test)]
    pub(super) fn append(buf: &mut Vec<u8>, value: u64) {
        append_with_len(buf, value, varint_len(value));
    }

    #[cfg(test)]
    pub(super) fn append_with_len(buf: &mut Vec<u8>, value: u64, byte_len: usize) {
        let len_bits = match byte_len {
            1 => 0u8,
            2 => 1,
            4 => 2,
            8 => 3,
            _ => panic!("invalid varint length"),
        };
        let mut bytes = value.to_be_bytes()[8 - byte_len..].to_vec();
        bytes[0] |= len_bits << 6;
        buf.extend_from_slice(&bytes);
    }

    #[cfg(test)]
    fn varint_len(value: u64) -> usize {
        if value < 1 << 6 {
            1
        } else if value < 1 << 14 {
            2
        } else if value < 1 << 30 {
            4
        } else if value < 1 << 62 {
            8
        } else {
            panic!("value too large for varint")
        }
    }
}

#[cfg(test)]
mod tests {
    use byteorder::{BigEndian, ByteOrder};

    use super::quicvarint;
    use super::*;

    struct NoopSender;

    #[async_trait::async_trait]
    impl PacketSender for NoopSender {
        async fn send(&self, _packet: Arc<dyn PacketAdapter>) {}

        async fn process(
            &self,
            _conn: Arc<dyn murmur_constant::adapters::PacketConn>,
            _proxy: Arc<dyn murmur_constant::adapters::WriteBackProxy>,
        ) {
        }

        fn close(&self) {}

        async fn do_sniff(&self, _metadata: &mut Metadata) -> anyhow::Result<()> {
            Ok(())
        }

        fn add_mapping(&self, _origin_metadata: &Metadata, _metadata: &Metadata) {}

        fn restore_read_from(&self, addr: std::net::IpAddr) -> std::net::IpAddr {
            addr
        }
    }

    fn new_test_sender() -> QuicPacketSender {
        QuicPacketSender {
            inner: Arc::new(NoopSender),
            replace_domain: Arc::new(|_, _| {}),
            state: RwLock::new(QuicPacketSenderState::default()),
            done: CancellationToken::new(),
        }
    }

    fn make_test_client_hello(host: &str, padding_len: usize) -> Vec<u8> {
        let mut extensions = Vec::new();
        if !host.is_empty() {
            let server_name = host.as_bytes();
            let server_name_list_len = 1 + 2 + server_name.len();
            let extension_data_len = 2 + server_name_list_len;
            extensions = vec![0u8; 4 + extension_data_len];
            BigEndian::write_u16(&mut extensions[2..4], extension_data_len as u16);
            BigEndian::write_u16(&mut extensions[4..6], server_name_list_len as u16);
            BigEndian::write_u16(&mut extensions[7..9], server_name.len() as u16);
            extensions[9..].copy_from_slice(server_name);
        }
        if padding_len > 0 {
            let mut padding = vec![0u8; 4 + padding_len];
            BigEndian::write_u16(&mut padding[0..2], 0x15);
            BigEndian::write_u16(&mut padding[2..4], padding_len as u16);
            extensions.extend_from_slice(&padding);
        }

        let mut body = Vec::with_capacity(64 + host.len());
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0);
        body.extend_from_slice(&[0, 2, 0x13, 0x01]);
        body.extend_from_slice(&[1, 0]);
        let mut ext_len = [0u8; 2];
        BigEndian::write_u16(&mut ext_len, extensions.len() as u16);
        body.extend_from_slice(&ext_len);
        body.extend_from_slice(&extensions);

        let mut hello = vec![0x01, (body.len() >> 16) as u8, (body.len() >> 8) as u8, body.len() as u8];
        hello.extend_from_slice(&body);
        hello
    }

    fn make_protected_quic_initial_packet(
        dest_conn_id: &[u8],
        labels: &QuicLabels,
        packet_number: i64,
        packet_number_length: usize,
        plaintext: &[u8],
    ) -> (Vec<u8>, usize) {
        let mut header = vec![0xc0 | (packet_number_length - 1) as u8, 0, 0, 0, 1, dest_conn_id.len() as u8];
        header.extend_from_slice(dest_conn_id);
        header.extend_from_slice(&[0, 0]);
        quicvarint::append(&mut header, (packet_number_length + plaintext.len() + 16) as u64);
        let packet_number_offset = header.len();
        for i in 0..packet_number_length {
            let shift = (packet_number_length - 1 - i) * 8;
            header.push((packet_number as u64 >> shift) as u8);
        }

        let key: [u8; 16] = labels.key.as_slice().try_into().expect("128-bit key");
        let aead = Aes128Gcm::new_from_slice(&key).expect("valid key");
        let mut nonce_bytes = labels.iv.clone();
        for i in 0..8 {
            let len = nonce_bytes.len();
            nonce_bytes[len - 1 - i] ^= (packet_number as u64 >> (8 * i)) as u8;
        }
        let nonce = <&Nonce<_>>::try_from(nonce_bytes.as_slice()).expect("12-byte GCM nonce");
        let ciphertext = aead.encrypt(nonce, Payload { msg: plaintext, aad: &header }).expect("encrypts");
        let mut packet = header.clone();
        packet.extend_from_slice(&ciphertext);

        let hp_key: [u8; 16] = labels.hp.as_slice().try_into().expect("128-bit hp key");
        let hp_cipher = aes::Aes128::new_from_slice(&hp_key).expect("valid hp key");
        let sample: [u8; 16] =
            packet[packet_number_offset + 4..packet_number_offset + 4 + 16].try_into().expect("sample is 16 bytes");
        let mut mask_block = cipher::Array::from(sample);
        hp_cipher.encrypt_block(&mut mask_block);
        let mask: [u8; 16] = mask_block.into();
        packet[0] ^= mask[0] & 0x0f;
        for i in 0..packet_number_length {
            packet[packet_number_offset + i] ^= mask[1 + i];
        }

        (packet, packet_number_offset)
    }

    #[test]
    fn decode_quic_packet_number_table() {
        let cases: &[(&str, i64, usize, i64, i64)] = &[
            ("first packet", -1, 1, 0, 0),
            ("next window", 127, 1, 0, 256),
            ("previous window", 382, 1, 0, 256),
            ("following window", 383, 1, 0, 512),
            ("rfc 9000 appendix a.3", 0xa82f_30ea, 2, 0x9b32, 0xa82f_9b32),
        ];
        for (name, largest, length, truncated, expected) in cases {
            assert_eq!(decode_quic_packet_number(*length, *largest, *truncated), *expected, "{name}");
        }
    }

    #[test]
    fn reconstructed_packet_number_in_nonce() {
        let dest_conn_id = b"initial dcid".to_vec();
        let labels = expand_labels(&dest_conn_id, &QUIC_V1).expect("labels expand");
        let plaintext = b"initial payload".to_vec();
        let (packet, packet_number_offset) =
            make_protected_quic_initial_packet(&dest_conn_id, &labels, 256, 1, &plaintext);

        let mut cache = new_packet();
        let packet_len = packet.len();
        let (decrypted, packet_number) =
            decrypt_quic_initial_packet(&packet, packet_number_offset, packet_len, &labels, 127, &mut cache)
                .expect("packet decrypts");
        cache.release();
        assert_eq!(packet_number, 256);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn retains_retry_epoch_across_header_dcid_changes() {
        let original_dest_conn_id = b"original dcid".to_vec();
        let retry_dest_conn_id = b"retry dcid".to_vec();
        let retry_key = new_quic_initial_key(&retry_dest_conn_id, &QUIC_V1).expect("retry key derives");
        let mut original_key = new_quic_initial_key(&original_dest_conn_id, &QUIC_V1).expect("initial key derives");
        original_key.largest_packet_number = 200;

        let packet_sender = new_test_sender();
        packet_sender.state.write().initial_keys = vec![original_key];

        let mut cache = new_packet();
        let plaintext = b"retry payload".to_vec();
        let (packet, packet_number_offset) =
            make_protected_quic_initial_packet(&retry_dest_conn_id, &retry_key.labels, 256, 1, &plaintext);
        let decrypted = packet_sender
            .decrypt_quic_initial_packet(
                &packet,
                packet_number_offset,
                packet.len(),
                &retry_dest_conn_id,
                &QUIC_V1,
                &mut cache,
            )
            .expect("packet decrypts");
        assert_eq!(decrypted, plaintext);
        assert_eq!(packet_sender.state.read().initial_keys.len(), 2);
        assert_eq!(packet_sender.state.read().initial_keys[1].largest_packet_number, 256);

        let plaintext = b"changed dcid payload".to_vec();
        let (packet, packet_number_offset) =
            make_protected_quic_initial_packet(&original_dest_conn_id, &retry_key.labels, 257, 1, &plaintext);
        let decrypted = packet_sender
            .decrypt_quic_initial_packet(
                &packet,
                packet_number_offset,
                packet.len(),
                &original_dest_conn_id,
                &QUIC_V1,
                &mut cache,
            )
            .expect("packet decrypts");
        assert_eq!(decrypted, plaintext);
        assert_eq!(packet_sender.state.read().initial_keys[1].largest_packet_number, 257);
        cache.release();
    }

    #[test]
    fn continues_after_delayed_packet_outside_reconstruction_window() {
        let dest_conn_id = b"initial dcid".to_vec();
        let mut initial_key = new_quic_initial_key(&dest_conn_id, &QUIC_V1).expect("initial key derives");
        initial_key.largest_packet_number = 200;

        let packet_sender = new_test_sender();
        packet_sender.state.write().initial_keys = vec![initial_key.clone()];

        let (delayed, _) = make_protected_quic_initial_packet(
            &dest_conn_id,
            &initial_key.labels,
            0,
            1,
            &[FRAME_PING, FRAME_PADDING, FRAME_PADDING],
        );
        packet_sender.read_quic_data(&delayed).expect("delayed packet parses");
        assert!(!packet_sender.state.read().closed);

        let client_hello = make_test_client_hello("example.com", 0);
        let mut crypto_frame = vec![FRAME_CRYPTO];
        quicvarint::append(&mut crypto_frame, 0);
        quicvarint::append(&mut crypto_frame, client_hello.len() as u64);
        crypto_frame.extend_from_slice(&client_hello);
        let (next, _) = make_protected_quic_initial_packet(&dest_conn_id, &initial_key.labels, 201, 1, &crypto_frame);
        packet_sender.read_quic_data(&next).expect("next packet parses");
        assert_eq!(packet_sender.state.read().result, "example.com");

        packet_sender.close_sniffing();
    }

    #[test]
    fn rejects_reason_length_larger_than_remaining_data() {
        let mut data = vec![FRAME_CONNECTION_CLOSE, 0, 0];
        quicvarint::append_with_len(&mut data, quicvarint::MAX, 8);
        let err = new_test_sender().read_quic_frames(&data).unwrap_err();
        assert_eq!(
            err.downcast_ref::<std::io::Error>().map(std::io::Error::kind),
            Some(std::io::ErrorKind::UnexpectedEof)
        );
    }

    #[test]
    fn client_hello_followed_by_crypto_data() {
        let client_hello = make_test_client_hello("example.com", 0);
        let mut crypto_data = client_hello;
        crypto_data.extend_from_slice(&[0x02, 0, 0, 0]);
        let sender = new_test_sender();
        sender.add_crypto_data(0, &crypto_data).expect("crypto data stored");

        let domain = sender.try_assemble().expect("assembles");
        assert_eq!(domain, "example.com");
        sender.close_sniffing();
    }

    #[test]
    fn one_byte_gap_remains_incomplete() {
        let client_hello = make_test_client_hello("example.com", 0);
        let sender = new_test_sender();

        sender.add_crypto_data(0, &client_hello[..1]).expect("stored");
        sender.add_crypto_data(2, &client_hello[2..]).expect("stored");
        let domain = sender.try_assemble().expect("assembles");
        assert!(domain.is_empty());
        assert_eq!(sender.state.read().contiguous_crypto_end, 1);

        sender.add_crypto_data(1, &client_hello[1..2]).expect("stored");
        let domain = sender.try_assemble().expect("assembles");
        assert_eq!(domain, "example.com");
        sender.close_sniffing();
    }

    #[test]
    fn many_sparse_fragments() {
        let client_hello = make_test_client_hello("example.com", 4 * 1024);
        let sender = new_test_sender();

        let mut i = 0;
        while i < client_hello.len() {
            sender.add_crypto_data(i as u64, &client_hello[i..i + 1]).expect("stored");
            i += 2;
        }
        assert_eq!(sender.state.read().contiguous_crypto_end, 1);

        let mut i = 1;
        while i < client_hello.len() {
            sender.add_crypto_data(i as u64, &client_hello[i..i + 1]).expect("stored");
            i += 2;
        }

        let domain = sender.try_assemble().expect("assembles");
        assert_eq!(domain, "example.com");
        sender.close_sniffing();
    }

    #[test]
    fn client_hello_larger_than_16_kib() {
        let client_hello = make_test_client_hello("example.com", 20 * 1024);
        let sender = new_test_sender();

        const FIRST_FRAGMENT_LEN: usize = 4 * 1024;
        sender.add_crypto_data(0, &client_hello[..FIRST_FRAGMENT_LEN]).expect("stored");
        let initial_capacity = sender.state.read().buffer.capacity();
        sender.add_crypto_data(FIRST_FRAGMENT_LEN as u64, &client_hello[FIRST_FRAGMENT_LEN..]).expect("stored");
        assert!(client_hello.len() > 16 * 1024);
        assert!(sender.state.read().buffer.capacity() > initial_capacity);

        let domain = sender.try_assemble().expect("assembles");
        assert_eq!(domain, "example.com");
        sender.close_sniffing();
    }

    #[test]
    fn server_name_before_client_hello_padding() {
        const PADDING_LEN: usize = 20 * 1024;
        let client_hello = make_test_client_hello("example.com", PADDING_LEN);
        let prefix_len = client_hello.len() - (4 + PADDING_LEN);
        let sender = new_test_sender();

        sender.add_crypto_data(0, &client_hello[..prefix_len]).expect("stored");
        assert!(sender.state.read().contiguous_crypto_end < client_hello.len() as u64);

        let domain = sender.try_assemble().expect("assembles");
        assert_eq!(domain, "example.com");
        sender.close_sniffing();
    }
}
