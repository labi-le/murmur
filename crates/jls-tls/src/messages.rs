//! TLS 1.3 handshake message bodies (RFC 8446 §4), fixed to exactly:
//! `TLS_AES_128_GCM_SHA256`, X25519, `ecdsa_secp256r1_sha256`.

use crate::cursor::{build_handshake_message, Reader, Writer};
use crate::error::{Result, TlsError};

pub(crate) const MSG_CLIENT_HELLO: u8 = 1;
pub(crate) const MSG_SERVER_HELLO: u8 = 2;
pub(crate) const MSG_NEW_SESSION_TICKET: u8 = 4;
pub(crate) const MSG_ENCRYPTED_EXTENSIONS: u8 = 8;
pub(crate) const MSG_CERTIFICATE: u8 = 11;
pub(crate) const MSG_CERTIFICATE_VERIFY: u8 = 15;
pub(crate) const MSG_FINISHED: u8 = 20;

const EXT_SERVER_NAME: u16 = 0;
const EXT_SUPPORTED_GROUPS: u16 = 10;
const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
const EXT_ALPN: u16 = 16;
const EXT_PRE_SHARED_KEY: u16 = 41;
const EXT_EARLY_DATA: u16 = 42;
const EXT_SUPPORTED_VERSIONS: u16 = 43;
const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 45;
const EXT_KEY_SHARE: u16 = 51;
const EXT_QUIC_TRANSPORT_PARAMETERS: u16 = 57;

/// RFC 8446 §4.2.9 `psk_dhe_ke(1)`: the PSK is combined with an (EC)DHE share,
/// which is the only mode this engine offers.
pub(crate) const PSK_MODE_PSK_DHE_KE: u8 = 1;

/// RFC 8446 §4.2.10 / RFC 9001 §4.6.1: the `max_early_data_size` a QUIC server
/// uses to say "0-RTT accepted"; the extension is omitted to say it is not.
pub const MAX_EARLY_DATA_SIZE_QUIC: u32 = 0xffff_ffff;

/// RFC 8446 §4.6.1: servers MUST NOT use a lifetime greater than seven days.
pub const MAX_SESSION_TICKET_LIFETIME_SECS: u32 = 604_800;

const CIPHER_SUITE_TLS13_AES128_GCM_SHA256: u16 = 0x1301;
const GROUP_X25519: u16 = 0x001d;
const SIG_SCHEME_ECDSA_SECP256R1_SHA256: u16 = 0x0403;
const TLS_1_3: u16 = 0x0304;

/// Advertised in `ClientHello.signature_algorithms` for broad interop with
/// peers doing scheme selection; this engine only ever produces or verifies
/// [`SIG_SCHEME_ECDSA_SECP256R1_SHA256`] signatures itself.
const OFFERED_SIGNATURE_ALGORITHMS: [u16; 6] = [0x0403, 0x0804, 0x0805, 0x0806, 0x0807, 0x0401];

struct ExtWriter {
    buf: Vec<u8>,
}

impl ExtWriter {
    fn new() -> Self {
        Self { buf: Vec::new() }
    }

    fn push(&mut self, ext_type: u16, data: &[u8]) -> Result<()> {
        let len: u16 = data.len().try_into().map_err(|_| TlsError::protocol("messages: extension too long"))?;
        self.buf.extend_from_slice(&ext_type.to_be_bytes());
        self.buf.extend_from_slice(&len.to_be_bytes());
        self.buf.extend_from_slice(data);
        Ok(())
    }
}

fn build_alpn_extension(protocols: &[String]) -> Result<Vec<u8>> {
    let mut list = Writer::new();
    for proto in protocols {
        list.vec8(proto.as_bytes())?;
    }
    let mut w = Writer::new();
    w.vec16(&list.buf)?;
    Ok(w.buf)
}

fn parse_alpn_extension(data: &[u8]) -> Result<Vec<String>> {
    let mut r = Reader::new(data);
    let list = r.vec16()?;
    let mut inner = Reader::new(list);
    let mut out = Vec::new();
    while !inner.is_empty() {
        let proto = inner.vec8()?;
        out.push(
            String::from_utf8(proto.to_vec()).map_err(|_| TlsError::protocol("messages: alpn protocol not utf-8"))?,
        );
    }
    Ok(out)
}

#[derive(Clone, Copy)]
pub(crate) struct ClientHelloPsk<'a> {
    /// The `NewSessionTicket`'s `ticket` field, echoed verbatim.
    pub identity: &'a [u8],
    /// `ticket_age_ms + ticket_age_add mod 2^32` (RFC 8446 §4.2.11.1).
    pub obfuscated_ticket_age: u32,
    /// The binder over the truncated ClientHello; a zeroed placeholder while
    /// the transcript it covers is being built.
    pub binder: &'a [u8; 32],
}

#[derive(Clone, Copy)]
pub(crate) struct ClientHelloParams<'a> {
    pub legacy_session_id: &'a [u8; 32],
    pub random: &'a [u8; 32],
    pub server_name: &'a str,
    pub alpn: &'a [String],
    pub x25519_public: &'a [u8; 32],
    /// RFC 9001 §8.2: QUIC requires the extension on both sides, so it is
    /// `Some` in the QUIC handshake and `None` over TCP, where it is rejected.
    pub quic_transport_parameters: Option<&'a [u8]>,
    /// `Some` to offer a resumption PSK.
    pub psk: Option<ClientHelloPsk<'a>>,
    /// RFC 8446 §4.2.10: only meaningful together with a 0-RTT-capable PSK,
    /// whose first identity protects the early data.
    pub early_data: bool,
}

/// Builds a `ClientHello` message (handshake header included). The random field
/// is written verbatim, so callers must pass the real (JLS `FakeRandom`)
/// bytes that will actually go out on the wire.
pub(crate) fn build_client_hello(params: &ClientHelloParams<'_>) -> Result<Vec<u8>> {
    let mut w = Writer::new();
    w.u16(0x0303);
    w.bytes(params.random);
    w.vec8(params.legacy_session_id)?;
    w.vec16(&CIPHER_SUITE_TLS13_AES128_GCM_SHA256.to_be_bytes())?;
    w.vec8(&[0x00])?;

    let mut ext = ExtWriter::new();

    let mut sni = Writer::new();
    let mut sni_list = Writer::new();
    sni_list.u8(0);
    sni_list.vec16(params.server_name.as_bytes())?;
    sni.vec16(&sni_list.buf)?;
    ext.push(EXT_SERVER_NAME, &sni.buf)?;

    let mut groups = Writer::new();
    groups.vec16(&GROUP_X25519.to_be_bytes())?;
    ext.push(EXT_SUPPORTED_GROUPS, &groups.buf)?;

    let mut sig_algs = Writer::new();
    let mut sig_list = Writer::new();
    for scheme in OFFERED_SIGNATURE_ALGORITHMS {
        sig_list.u16(scheme);
    }
    sig_algs.vec16(&sig_list.buf)?;
    ext.push(EXT_SIGNATURE_ALGORITHMS, &sig_algs.buf)?;

    if !params.alpn.is_empty() {
        ext.push(EXT_ALPN, &build_alpn_extension(params.alpn)?)?;
    }

    let mut versions = Writer::new();
    versions.vec8(&TLS_1_3.to_be_bytes())?;
    ext.push(EXT_SUPPORTED_VERSIONS, &versions.buf)?;

    let mut key_share = Writer::new();
    let mut entry = Writer::new();
    entry.u16(GROUP_X25519);
    entry.vec16(params.x25519_public)?;
    key_share.vec16(&entry.buf)?;
    ext.push(EXT_KEY_SHARE, &key_share.buf)?;

    if params.early_data {
        ext.push(EXT_EARLY_DATA, &[])?;
    }

    if let Some(quic_params) = params.quic_transport_parameters {
        ext.push(EXT_QUIC_TRANSPORT_PARAMETERS, quic_params)?;
    }

    if params.psk.is_some() {
        ext.push(EXT_PSK_KEY_EXCHANGE_MODES, &[1, PSK_MODE_PSK_DHE_KE])?;
    }

    if let Some(psk) = &params.psk {
        ext.push(EXT_PRE_SHARED_KEY, &build_pre_shared_key_extension(psk)?)?;
    }

    w.vec16(&ext.buf)?;
    build_handshake_message(MSG_CLIENT_HELLO, &w.buf)
}

/// RFC 8446 §4.2.11: the `OfferedPsks` structure, whose identity list runs
/// `<7..2^16-1>` and whose binder list runs `<33..2^16-1>`.
fn build_pre_shared_key_extension(psk: &ClientHelloPsk<'_>) -> Result<Vec<u8>> {
    let mut identity = Writer::new();
    identity.vec16(psk.identity)?;
    identity.u32(psk.obfuscated_ticket_age);

    let mut identities = Writer::new();
    identities.vec16(&identity.buf)?;

    let mut entries = Writer::new();
    entries.vec8(psk.binder)?;

    let mut binders = Writer::new();
    binders.vec16(&entries.buf)?;

    let mut w = Writer::new();
    w.bytes(&identities.buf);
    w.bytes(&binders.buf);
    Ok(w.buf)
}

pub(crate) struct ParsedClientHello {
    pub random: [u8; 32],
    pub legacy_session_id: Vec<u8>,
    pub server_name: Option<String>,
    pub alpn: Vec<String>,
    pub x25519_public: Option<[u8; 32]>,
    pub offers_tls13_aes128_gcm: bool,
    pub offers_x25519: bool,
    pub supported_versions: Vec<u16>,
    pub quic_transport_parameters: Option<Vec<u8>>,
    /// RFC 8446 §4.2.10: the client offered to send early data.
    pub early_data: bool,
    pub psk_identities: Vec<Vec<u8>>,
    pub psk_obfuscated_ticket_ages: Vec<u32>,
    pub psk_binders: Vec<Vec<u8>>,
    pub psk_modes: Vec<u8>,
    /// Length of the `binders` list including its two length bytes, for
    /// [`truncate_client_hello_binders`].
    psk_binders_list_len: usize,
}

/// RFC 8446 §4.2.11.2: the transcript input for a `PskBinderEntry` is the
/// `ClientHello` truncated after the `pre_shared_key` extension's `identities`
/// field, with every length field left as if the binders were present.
pub(crate) fn truncate_client_hello_binders(raw: &[u8], parsed: &ParsedClientHello) -> Option<Vec<u8>> {
    if parsed.psk_binders.is_empty() || parsed.psk_binders_list_len > raw.len() {
        return None;
    }
    let end = raw.len() - parsed.psk_binders_list_len;
    Some(raw.get(..end)?.to_vec())
}

/// The server's TLS 1.3 check. A `ClientHello` with no
/// `supported_versions` extension offers nothing but its `legacy_version`
/// field, which is never 1.3, so an empty list must not pass.
pub(crate) fn offers_tls13(supported_versions: &[u16]) -> bool {
    supported_versions.contains(&TLS_1_3)
}

/// Parses a `ClientHello` body (the handshake header must already have been
/// stripped off by the caller). Unknown extensions are skipped; only the
/// extensions this engine understands are extracted.
pub(crate) fn parse_client_hello(body: &[u8]) -> Result<ParsedClientHello> {
    let mut r = Reader::new(body);
    let _legacy_version = r.u16()?;
    let random: [u8; 32] = r.take_array()?;
    let legacy_session_id = r.vec8()?.to_vec();

    let cipher_suites = r.vec16()?;
    let offers_tls13_aes128_gcm = cipher_suites
        .chunks_exact(2)
        .any(|suite| u16::from_be_bytes(suite.try_into().unwrap_or_default()) == CIPHER_SUITE_TLS13_AES128_GCM_SHA256);

    let _compression_methods = r.vec8()?;

    let mut server_name = None;
    let mut alpn = Vec::new();
    let mut x25519_public = None;
    let mut offers_x25519 = false;
    let mut supported_versions = Vec::new();
    let mut quic_transport_parameters = None;
    let mut early_data = false;
    let mut psk_identities = Vec::new();
    let mut psk_obfuscated_ticket_ages = Vec::new();
    let mut psk_binders = Vec::new();
    let mut psk_modes = Vec::new();
    let mut psk_binders_list_len = 0;

    if !r.is_empty() {
        let ext_list = r.vec16()?;
        let mut er = Reader::new(ext_list);
        while !er.is_empty() {
            let ext_type = er.u16()?;
            let ext_data = er.vec16()?;
            match ext_type {
                EXT_SERVER_NAME => server_name = parse_server_name_extension(ext_data)?,
                EXT_ALPN => alpn = parse_alpn_extension(ext_data)?,
                EXT_SUPPORTED_GROUPS => offers_x25519 = offers_x25519_group(ext_data)?,
                EXT_KEY_SHARE => x25519_public = parse_x25519_key_share(ext_data)?,
                EXT_SUPPORTED_VERSIONS => {
                    let mut vr = Reader::new(ext_data);
                    let list = vr.vec8()?;
                    let mut lr = Reader::new(list);
                    while !lr.is_empty() {
                        supported_versions.push(u16::from_be_bytes(lr.take_array()?));
                    }
                }
                EXT_QUIC_TRANSPORT_PARAMETERS => quic_transport_parameters = Some(ext_data.to_vec()),
                EXT_EARLY_DATA => early_data = true,
                EXT_PSK_KEY_EXCHANGE_MODES => {
                    let mut mr = Reader::new(ext_data);
                    psk_modes = mr.vec8()?.to_vec();
                }
                EXT_PRE_SHARED_KEY => {
                    if !er.is_empty() {
                        return Err(TlsError::protocol("messages: pre_shared_key is not the last extension"));
                    }
                    let offer = parse_pre_shared_key_extension(ext_data)?;
                    psk_identities = offer.identities;
                    psk_obfuscated_ticket_ages = offer.obfuscated_ticket_ages;
                    psk_binders = offer.binders;
                    psk_binders_list_len = offer.binders_list_len;
                }
                _ => {}
            }
        }
    }

    Ok(ParsedClientHello {
        random,
        legacy_session_id,
        server_name,
        alpn,
        x25519_public,
        offers_tls13_aes128_gcm,
        offers_x25519,
        supported_versions,
        quic_transport_parameters,
        early_data,
        psk_identities,
        psk_obfuscated_ticket_ages,
        psk_binders,
        psk_modes,
        psk_binders_list_len,
    })
}

/// Parses the `server_name` extension down to its `host_name` entry.
fn parse_server_name_extension(ext_data: &[u8]) -> Result<Option<String>> {
    let mut sr = Reader::new(ext_data);
    let list = sr.vec16()?;
    let mut lr = Reader::new(list);
    if lr.is_empty() {
        return Ok(None);
    }
    let name_type = lr.u8()?;
    let name = lr.vec16()?;
    if name_type != 0 {
        return Ok(None);
    }
    Ok(Some(String::from_utf8(name.to_vec()).map_err(|_| TlsError::protocol("messages: server_name not utf-8"))?))
}

/// Whether a `supported_groups` extension advertises X25519.
fn offers_x25519_group(ext_data: &[u8]) -> Result<bool> {
    let mut gr = Reader::new(ext_data);
    let groups = gr.vec16()?;
    Ok(groups.chunks_exact(2).any(|group| u16::from_be_bytes(group.try_into().unwrap_or_default()) == GROUP_X25519))
}

/// The X25519 `key_exchange` of a `key_share` extension, if it carries one.
fn parse_x25519_key_share(ext_data: &[u8]) -> Result<Option<[u8; 32]>> {
    let mut kr = Reader::new(ext_data);
    let entries = kr.vec16()?;
    let mut ler = Reader::new(entries);
    let mut key: Option<[u8; 32]> = None;
    while !ler.is_empty() {
        let group = ler.u16()?;
        let key_exchange = ler.vec16()?;
        if group == GROUP_X25519 {
            key =
                Some(key_exchange.try_into().map_err(|_| TlsError::protocol("messages: bad x25519 key_share length"))?);
        }
    }
    Ok(key)
}

/// The `pre_shared_key` extension's offers: one identity and obfuscated ticket
/// age per entry, plus the binders that follow the identity list.
struct PskOffer {
    identities: Vec<Vec<u8>>,
    obfuscated_ticket_ages: Vec<u32>,
    binders: Vec<Vec<u8>>,
    binders_list_len: usize,
}

fn parse_pre_shared_key_extension(ext_data: &[u8]) -> Result<PskOffer> {
    let mut pr = Reader::new(ext_data);
    let identities = pr.vec16()?;
    let mut ir = Reader::new(identities);
    let mut offered = Vec::new();
    let mut obfuscated_ticket_ages = Vec::new();
    while !ir.is_empty() {
        offered.push(ir.vec16()?.to_vec());
        obfuscated_ticket_ages.push(u32::from_be_bytes(ir.take_array()?));
    }
    let binders = pr.vec16()?;
    let binders_list_len = 2 + binders.len();
    let mut br = Reader::new(binders);
    let mut psk_binders = Vec::new();
    while !br.is_empty() {
        psk_binders.push(br.vec8()?.to_vec());
    }
    Ok(PskOffer { identities: offered, obfuscated_ticket_ages, binders: psk_binders, binders_list_len })
}

/// Builds a `ServerHello` message (handshake header included).
pub(crate) fn build_server_hello(
    session_id_echo: &[u8],
    random: &[u8; 32],
    x25519_public: &[u8; 32],
    selected_identity: Option<u16>,
) -> Result<Vec<u8>> {
    let mut w = Writer::new();
    w.u16(0x0303);
    w.bytes(random);
    w.vec8(session_id_echo)?;
    w.bytes(&CIPHER_SUITE_TLS13_AES128_GCM_SHA256.to_be_bytes());
    w.u8(0x00);

    let mut ext = ExtWriter::new();
    ext.push(EXT_SUPPORTED_VERSIONS, &TLS_1_3.to_be_bytes())?;
    let mut key_share = Writer::new();
    key_share.u16(GROUP_X25519);
    key_share.vec16(x25519_public)?;
    ext.push(EXT_KEY_SHARE, &key_share.buf)?;

    if let Some(index) = selected_identity {
        ext.push(EXT_PRE_SHARED_KEY, &index.to_be_bytes())?;
    }

    w.vec16(&ext.buf)?;
    build_handshake_message(MSG_SERVER_HELLO, &w.buf)
}

pub(crate) struct ParsedServerHello {
    pub random: [u8; 32],
    pub legacy_session_id_echo: Vec<u8>,
    pub x25519_public: [u8; 32],
    /// RFC 8446 §4.2.11: the PSK the server accepted, as an index into the
    /// client's `pre_shared_key` identities.
    pub selected_identity: Option<u16>,
}

/// Parses a `ServerHello` body (handshake header already stripped).
pub(crate) fn parse_server_hello(body: &[u8]) -> Result<ParsedServerHello> {
    let mut r = Reader::new(body);
    let _legacy_version = r.u16()?;
    let random: [u8; 32] = r.take_array()?;
    let legacy_session_id_echo = r.vec8()?.to_vec();
    let cipher_suite = u16::from_be_bytes(r.take_array()?);
    if cipher_suite != CIPHER_SUITE_TLS13_AES128_GCM_SHA256 {
        return Err(TlsError::protocol("messages: server negotiated an unsupported cipher suite"));
    }
    let _compression_method = r.u8()?;

    let mut x25519_public = None;
    let mut selected_identity = None;
    if !r.is_empty() {
        let ext_list = r.vec16()?;
        let mut er = Reader::new(ext_list);
        while !er.is_empty() {
            let ext_type = er.u16()?;
            let ext_data = er.vec16()?;
            if ext_type == EXT_KEY_SHARE {
                let mut kr = Reader::new(ext_data);
                let group = kr.u16()?;
                if group != GROUP_X25519 {
                    return Err(TlsError::protocol("messages: server negotiated an unsupported group"));
                }
                let key_exchange = kr.vec16()?;
                x25519_public = Some(
                    key_exchange.try_into().map_err(|_| TlsError::protocol("messages: bad x25519 key_share length"))?,
                );
            } else if ext_type == EXT_SUPPORTED_VERSIONS {
                let version = u16::from_be_bytes(
                    ext_data.try_into().map_err(|_| TlsError::protocol("messages: bad supported_versions"))?,
                );
                if version != TLS_1_3 {
                    return Err(TlsError::protocol("messages: server did not negotiate TLS 1.3"));
                }
            } else if ext_type == EXT_PRE_SHARED_KEY {
                selected_identity = Some(u16::from_be_bytes(
                    ext_data.try_into().map_err(|_| TlsError::protocol("messages: bad selected_identity"))?,
                ));
            }
        }
    }
    let x25519_public = x25519_public.ok_or_else(|| TlsError::protocol("messages: server hello missing key_share"))?;

    Ok(ParsedServerHello { random, legacy_session_id_echo, x25519_public, selected_identity })
}

/// The parts of `EncryptedExtensions` this engine consumes.
pub(crate) struct ParsedEncryptedExtensions {
    pub alpn: Option<String>,
    pub quic_transport_parameters: Option<Vec<u8>>,
    /// RFC 8446 §4.2.10: the server will process the client's 0-RTT data.
    pub early_data: bool,
}

/// Builds an `EncryptedExtensions` message. `alpn` is the single negotiated
/// protocol, if any.
pub(crate) fn build_encrypted_extensions(
    alpn: Option<&str>,
    quic_transport_parameters: Option<&[u8]>,
    early_data: bool,
) -> Result<Vec<u8>> {
    let mut ext = ExtWriter::new();
    if let Some(proto) = alpn {
        let protocols = [proto.to_owned()];
        ext.push(EXT_ALPN, &build_alpn_extension(&protocols)?)?;
    }
    if let Some(quic_params) = quic_transport_parameters {
        ext.push(EXT_QUIC_TRANSPORT_PARAMETERS, quic_params)?;
    }
    if early_data {
        ext.push(EXT_EARLY_DATA, &[])?;
    }
    let mut w = Writer::new();
    w.vec16(&ext.buf)?;
    build_handshake_message(MSG_ENCRYPTED_EXTENSIONS, &w.buf)
}

pub(crate) fn parse_encrypted_extensions(body: &[u8]) -> Result<ParsedEncryptedExtensions> {
    let mut r = Reader::new(body);
    let ext_list = r.vec16()?;
    let mut er = Reader::new(ext_list);
    let mut alpn = None;
    let mut quic_transport_parameters = None;
    let mut early_data = false;
    while !er.is_empty() {
        let ext_type = er.u16()?;
        let ext_data = er.vec16()?;
        match ext_type {
            EXT_ALPN => alpn = parse_alpn_extension(ext_data)?.into_iter().next(),
            EXT_QUIC_TRANSPORT_PARAMETERS => quic_transport_parameters = Some(ext_data.to_vec()),
            EXT_EARLY_DATA => early_data = true,
            _ => {}
        }
    }
    Ok(ParsedEncryptedExtensions { alpn, quic_transport_parameters, early_data })
}

/// Builds a `NewSessionTicket` message (RFC 8446 §4.6.1). `max_early_data`
/// `0` omits the `early_data` extension, which is how a QUIC server says it
/// will not accept 0-RTT (RFC 9001 §4.6.1).
pub(crate) fn build_new_session_ticket(
    lifetime: u32,
    age_add: u32,
    nonce: &[u8],
    ticket: &[u8],
    max_early_data: u32,
) -> Result<Vec<u8>> {
    let mut ext = ExtWriter::new();
    if max_early_data > 0 {
        ext.push(EXT_EARLY_DATA, &max_early_data.to_be_bytes())?;
    }

    let mut w = Writer::new();
    w.u32(lifetime);
    w.u32(age_add);
    w.vec8(nonce)?;
    w.vec16(ticket)?;
    w.vec16(&ext.buf)?;
    build_handshake_message(MSG_NEW_SESSION_TICKET, &w.buf)
}

pub(crate) struct ParsedNewSessionTicket {
    pub lifetime: u32,
    pub age_add: u32,
    pub nonce: Vec<u8>,
    pub ticket: Vec<u8>,
    pub max_early_data: u32,
}

pub(crate) fn parse_new_session_ticket(body: &[u8]) -> Result<ParsedNewSessionTicket> {
    let mut r = Reader::new(body);
    let lifetime = u32::from_be_bytes(r.take_array()?);
    let age_add = u32::from_be_bytes(r.take_array()?);
    let nonce = r.vec8()?.to_vec();
    let ticket = r.vec16()?.to_vec();
    let ext_list = r.vec16()?;
    let mut er = Reader::new(ext_list);
    let mut max_early_data = 0;
    while !er.is_empty() {
        let ext_type = er.u16()?;
        let ext_data = er.vec16()?;
        if ext_type == EXT_EARLY_DATA {
            max_early_data = u32::from_be_bytes(
                ext_data.try_into().map_err(|_| TlsError::protocol("messages: bad max_early_data_size"))?,
            );
        }
    }
    Ok(ParsedNewSessionTicket { lifetime, age_add, nonce, ticket, max_early_data })
}

/// Builds a `Certificate` message (TLS 1.3 shape) carrying exactly one
/// self-signed leaf, no chain.
pub(crate) fn build_certificate(cert_der: &[u8]) -> Result<Vec<u8>> {
    let mut w = Writer::new();
    w.vec8(&[])?;

    let mut entry = Writer::new();
    entry.vec24(cert_der)?;
    entry.u16(0);

    let mut list = Writer::new();
    list.bytes(&entry.buf);
    w.vec24(&list.buf)?;

    build_handshake_message(MSG_CERTIFICATE, &w.buf)
}

/// Parses a `Certificate` body, returning each entry's DER bytes in the order
/// the peer sent them: the leaf first, then the intermediates.
pub(crate) fn parse_certificate_chain(body: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut r = Reader::new(body);
    let _context = r.vec8()?;
    let list = r.vec24()?;
    let mut lr = Reader::new(list);
    let mut chain = Vec::new();
    while !lr.is_empty() {
        chain.push(lr.vec24()?.to_vec());
        let _extensions = lr.vec16()?;
    }
    if chain.is_empty() {
        return Err(TlsError::protocol("messages: empty certificate list"));
    }
    Ok(chain)
}

/// Builds a `CertificateVerify` message, fixed to `ecdsa_secp256r1_sha256`.
pub(crate) fn build_certificate_verify(signature_der: &[u8]) -> Result<Vec<u8>> {
    let mut w = Writer::new();
    w.u16(SIG_SCHEME_ECDSA_SECP256R1_SHA256);
    w.vec16(signature_der)?;
    build_handshake_message(MSG_CERTIFICATE_VERIFY, &w.buf)
}

/// Parses a `CertificateVerify` body, returning the DER signature bytes.
/// Rejects any signature scheme other than `ecdsa_secp256r1_sha256`, the only
/// one this engine ever verifies.
pub(crate) fn parse_certificate_verify(body: &[u8]) -> Result<Vec<u8>> {
    let mut r = Reader::new(body);
    let scheme = r.u16()?;
    if scheme != SIG_SCHEME_ECDSA_SECP256R1_SHA256 {
        return Err(TlsError::protocol("messages: unsupported CertificateVerify signature scheme"));
    }
    Ok(r.vec16()?.to_vec())
}

/// RFC 8446 §4.4.3: the content signed by `CertificateVerify` is 64 bytes of
/// `0x20`, then `"TLS 1.3, server CertificateVerify"`, then a single `0x00`
/// byte, then the transcript hash up to and including `Certificate`.
pub(crate) fn certificate_verify_signed_content(transcript_hash_through_certificate: &[u8; 32]) -> Vec<u8> {
    let mut content = vec![0x20u8; 64];
    content.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    content.push(0x00);
    content.extend_from_slice(transcript_hash_through_certificate);
    content
}

/// Builds a `Finished` message.
pub(crate) fn build_finished(verify_data: &[u8; 32]) -> Result<Vec<u8>> {
    build_handshake_message(MSG_FINISHED, verify_data)
}

/// Parses a `Finished` body, returning its `verify_data`.
pub(crate) fn parse_finished(body: &[u8]) -> Result<[u8; 32]> {
    body.try_into().map_err(|_| TlsError::protocol("messages: malformed Finished (verify_data must be 32 bytes)"))
}
