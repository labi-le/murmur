//! Minimal TLS 1.3 handshake message wire format: only the fields a Restls client/relay ever
//! needs to build or inspect (RFC 8446 §4).

use anyhow::{anyhow, bail, Result};

use crate::consts::{
    EXT_ALPN, EXT_KEY_SHARE, EXT_PRE_SHARED_KEY, EXT_PSK_KEY_EXCHANGE_MODES, EXT_SERVER_NAME, EXT_SIGNATURE_ALGORITHMS,
    EXT_SUPPORTED_GROUPS, EXT_SUPPORTED_VERSIONS, HANDSHAKE_TYPE_CLIENT_HELLO, HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE,
    HANDSHAKE_TYPE_FINISHED, PSK_KE_MODE_DHE, VERSION_TLS12, VERSION_TLS13,
};

fn put_u16_len_prefixed(out: &mut Vec<u8>, body: impl FnOnce(&mut Vec<u8>)) {
    let start = out.len();
    out.extend_from_slice(&[0, 0]);
    body(out);
    #[expect(clippy::cast_possible_truncation, reason = "the extension length field is 16 bits by definition")]
    let len = (out.len() - start - 2) as u16;
    if let Some(slot) = out.get_mut(start..start + 2) {
        slot.copy_from_slice(&len.to_be_bytes());
    }
}

#[derive(Debug)]
pub struct KeyShareEntry {
    pub group: u16,
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub struct PskIdentity {
    pub label: Vec<u8>,
    pub obfuscated_ticket_age: u32,
}

/// Everything a Restls client needs to build the wire bytes of one ClientHello.
#[derive(Debug)]
pub struct ClientHelloBuilder {
    pub random: [u8; 32],
    pub session_id: [u8; 32],
    pub cipher_suites: Vec<u16>,
    pub server_name: String,
    pub supported_groups: Vec<u16>,
    /// Advertised as ALPN (RFC 7301) between `supported_groups` and
    /// `signature_algorithms`, where Chrome's own ClientHello carries it.
    pub next_protos: Vec<String>,
    pub key_shares: Vec<KeyShareEntry>,
    pub signature_algorithms: Vec<u16>,
    pub psk_identities: Vec<PskIdentity>,
    /// One binder per `psk_identities` entry, filled in once the real PSK binder HMAC is known.
    /// Restls only ever offers the previous session's opaque ticket for session-id-auth-token
    /// purposes and never actually resumes, so this stays empty in this crate; see `client.rs`.
    pub psk_binders: Vec<[u8; 32]>,
    /// When set, omits the TLS 1.3-only `key_share`/`supported_versions`/
    /// `psk_key_exchange_modes`/`pre_shared_key` extensions: a TLS 1.2 ClientHello negotiates its
    /// ECDHE key exchange via `ServerKeyExchange`/`ClientKeyExchange` messages, not extensions.
    pub tls12_mode: bool,
}

impl ClientHelloBuilder {
    /// Marshals the full `ClientHello` handshake message (msg_type + 3-byte length + body).
    /// Returns `(bytes, offset_of_extensions_body_start)` so the caller can locate where the
    /// (currently absent) PSK binder would need patching back in for real resumption support.
    #[must_use]
    pub fn marshal(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(256);
        body.extend_from_slice(&VERSION_TLS12.to_be_bytes());
        body.extend_from_slice(&self.random);
        body.push(32);
        body.extend_from_slice(&self.session_id);
        put_u16_len_prefixed(&mut body, |out| {
            for cs in &self.cipher_suites {
                out.extend_from_slice(&cs.to_be_bytes());
            }
        });
        body.push(1);
        body.push(0);
        put_u16_len_prefixed(&mut body, |out| self.marshal_extensions(out));

        let mut msg = Vec::with_capacity(4 + body.len());
        msg.push(HANDSHAKE_TYPE_CLIENT_HELLO);
        #[expect(clippy::cast_possible_truncation, reason = "the handshake body length field is 24 bits by definition")]
        let len = body.len() as u32;
        msg.extend_from_slice(&len.to_be_bytes()[1..]);
        msg.extend_from_slice(&body);
        msg
    }

    fn marshal_extensions(&self, out: &mut Vec<u8>) {
        if !self.server_name.is_empty() {
            write_ext(out, EXT_SERVER_NAME, |out| {
                put_u16_len_prefixed(out, |out| {
                    out.push(0);
                    put_u16_len_prefixed(out, |out| out.extend_from_slice(self.server_name.as_bytes()));
                });
            });
        }
        write_ext(out, EXT_SUPPORTED_GROUPS, |out| {
            put_u16_len_prefixed(out, |out| {
                for g in &self.supported_groups {
                    out.extend_from_slice(&g.to_be_bytes());
                }
            });
        });
        if !self.next_protos.is_empty() {
            write_ext(out, EXT_ALPN, |out| {
                put_u16_len_prefixed(out, |out| {
                    for proto in &self.next_protos {
                        #[expect(clippy::cast_possible_truncation, reason = "RFC 7301 caps ALPN names at 255 bytes")]
                        out.push(proto.len() as u8);
                        out.extend_from_slice(proto.as_bytes());
                    }
                });
            });
        }
        write_ext(out, EXT_SIGNATURE_ALGORITHMS, |out| {
            put_u16_len_prefixed(out, |out| {
                for s in &self.signature_algorithms {
                    out.extend_from_slice(&s.to_be_bytes());
                }
            });
        });
        if !self.tls12_mode {
            write_ext(out, EXT_KEY_SHARE, |out| {
                put_u16_len_prefixed(out, |out| {
                    for ks in &self.key_shares {
                        out.extend_from_slice(&ks.group.to_be_bytes());
                        put_u16_len_prefixed(out, |out| out.extend_from_slice(&ks.data));
                    }
                });
            });
            write_ext(out, EXT_SUPPORTED_VERSIONS, |out| {
                out.push(2);
                out.extend_from_slice(&VERSION_TLS13.to_be_bytes());
            });
            if !self.psk_identities.is_empty() {
                write_ext(out, EXT_PSK_KEY_EXCHANGE_MODES, |out| {
                    out.push(1);
                    out.push(PSK_KE_MODE_DHE);
                });
            }
        }
        if !self.psk_identities.is_empty() {
            write_ext(out, EXT_PRE_SHARED_KEY, |out| {
                put_u16_len_prefixed(out, |out| {
                    for psk in &self.psk_identities {
                        put_u16_len_prefixed(out, |out| out.extend_from_slice(&psk.label));
                        out.extend_from_slice(&psk.obfuscated_ticket_age.to_be_bytes());
                    }
                });
                put_u16_len_prefixed(out, |out| {
                    for binder in &self.psk_binders {
                        #[expect(clippy::cast_possible_truncation, reason = "a PSK binder is exactly 32 bytes")]
                        out.push(binder.len() as u8);
                        out.extend_from_slice(binder);
                    }
                });
            });
        }
    }
}

fn write_ext(out: &mut Vec<u8>, id: u16, body: impl FnOnce(&mut Vec<u8>)) {
    out.extend_from_slice(&id.to_be_bytes());
    put_u16_len_prefixed(out, body);
}

#[derive(Debug)]
pub struct ParsedServerHello {
    pub random: [u8; 32],
    pub cipher_suite: u16,
    pub supported_version: u16,
    pub key_share: Option<KeyShareEntry>,
    pub selected_identity_present: bool,
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let Some(out) = self.buf.get(self.pos..self.pos + n) else {
            bail!("restls: short handshake message");
        };
        self.pos += n;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8> {
        let [byte] = self.take(1)? else {
            bail!("restls: short handshake message");
        };
        Ok(*byte)
    }

    fn u16(&mut self) -> Result<u16> {
        let [hi, lo] = self.take(2)? else {
            bail!("restls: short handshake message");
        };
        Ok(u16::from_be_bytes([*hi, *lo]))
    }

    fn u24(&mut self) -> Result<u32> {
        let [b0, b1, b2] = self.take(3)? else {
            bail!("restls: short handshake message");
        };
        Ok(u32::from(*b0) << 16 | u32::from(*b1) << 8 | u32::from(*b2))
    }

    fn u8_len_prefixed(&mut self) -> Result<&'a [u8]> {
        let n = self.u8()? as usize;
        self.take(n)
    }

    fn u16_len_prefixed(&mut self) -> Result<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }

    fn remaining(&self) -> &'a [u8] {
        self.buf.get(self.pos..).unwrap_or_default()
    }
}

/// Parses a `ServerHello` handshake message body (without the 4-byte msg_type+length header).
pub fn parse_server_hello(body: &[u8]) -> Result<ParsedServerHello> {
    let mut r = Reader::new(body);
    let _legacy_version = r.u16()?;
    let random: [u8; 32] = r.take(32)?.try_into().map_err(|_| anyhow!("restls: short handshake message"))?;
    let _session_id_echo = r.u8_len_prefixed()?;
    let cipher_suite = r.u16()?;
    let _compression = r.u8()?;
    let ext_block = if r.remaining().is_empty() { &[][..] } else { r.u16_len_prefixed()? };

    let mut supported_version = VERSION_TLS12;
    let mut key_share = None;
    let mut selected_identity_present = false;
    let mut er = Reader::new(ext_block);
    while er.pos < er.buf.len() {
        let id = er.u16()?;
        let data = er.u16_len_prefixed()?;
        match id {
            EXT_SUPPORTED_VERSIONS => {
                let mut dr = Reader::new(data);
                supported_version = dr.u16()?;
            }
            EXT_KEY_SHARE => {
                let mut dr = Reader::new(data);
                let group = dr.u16()?;
                let ks_data = dr.u16_len_prefixed()?.to_vec();
                key_share = Some(KeyShareEntry { group, data: ks_data });
            }
            EXT_PRE_SHARED_KEY => {
                selected_identity_present = true;
            }
            _ => {}
        }
    }

    Ok(ParsedServerHello { random, cipher_suite, supported_version, key_share, selected_identity_present })
}

/// Extracts the first complete handshake message (`msg_type||u24 len||body`) from a record's
/// payload, returning it (including the 4-byte header) and its byte length.
pub fn first_handshake_message(payload: &[u8]) -> Result<&[u8]> {
    let mut r = Reader::new(payload);
    let _msg_type = r.u8()?;
    let len = r.u24()? as usize;
    let total = 4 + len;
    payload.get(..total).ok_or_else(|| anyhow!("restls: fragmented handshake message"))
}

#[derive(Debug)]
pub struct ParsedCertificateEntry {
    pub cert_data: Vec<u8>,
}

#[derive(Debug)]
pub struct ParsedCertificateMsg {
    pub entries: Vec<ParsedCertificateEntry>,
}

/// Parses a `Certificate` handshake message body (RFC 8446 §4.4.2).
pub fn parse_certificate(body: &[u8]) -> Result<ParsedCertificateMsg> {
    let mut r = Reader::new(body);
    let _context = r.u8_len_prefixed()?;
    let list = r.u24()? as usize;
    let Some(list_bytes) = r.remaining().get(..list) else {
        bail!("restls: short Certificate list");
    };
    let mut lr = Reader::new(list_bytes);
    let mut entries = Vec::new();
    while lr.pos < lr.buf.len() {
        let cert_len = lr.u24()? as usize;
        let cert_data = lr.take(cert_len)?.to_vec();
        let _extensions = lr.u16_len_prefixed()?;
        entries.push(ParsedCertificateEntry { cert_data });
    }
    Ok(ParsedCertificateMsg { entries })
}

#[derive(Debug)]
pub struct ParsedCertificateVerify {
    pub scheme: u16,
    pub signature: Vec<u8>,
}

/// Parses a `CertificateVerify` handshake message body (RFC 8446 §4.4.3).
pub fn parse_certificate_verify(body: &[u8]) -> Result<ParsedCertificateVerify> {
    let mut r = Reader::new(body);
    let scheme = r.u16()?;
    let signature = r.u16_len_prefixed()?.to_vec();
    Ok(ParsedCertificateVerify { scheme, signature })
}

/// Marshals a `Finished` handshake message (RFC 8446 §4.4.4): just the msg_type+length header
/// wrapped around `verify_data`.
#[must_use]
pub fn marshal_finished(verify_data: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(4 + 32);
    msg.push(HANDSHAKE_TYPE_FINISHED);
    msg.extend_from_slice(&[0, 0, 32]);
    msg.extend_from_slice(verify_data);
    msg
}

/// Extracts `verify_data` out of a parsed `Finished` handshake message (with its 4-byte header).
pub fn parse_finished(msg: &[u8]) -> Result<[u8; 32]> {
    if msg.len() != 4 + 32 || msg.first() != Some(&HANDSHAKE_TYPE_FINISHED) {
        return Err(anyhow!("restls: malformed Finished message"));
    }
    let body = msg.get(4..36).ok_or_else(|| anyhow!("restls: malformed Finished message"))?;
    body.try_into().map_err(|_| anyhow!("restls: malformed Finished message"))
}
/// A parsed `ServerKeyExchange` handshake message body for the ECDHE key exchange restls uses.
///
/// It carries RFC 4492 §5.4 `ServerECDHParams` + RFC 8446-style 2-byte `SignatureScheme`, since
/// Restls only negotiates TLS 1.2 with `signature_algorithms`-bearing peers.
#[derive(Debug)]
pub struct ParsedServerKeyExchange {
    pub curve: u16,
    pub public_key: Vec<u8>,
    /// The raw `ServerECDHParams` bytes (`curve_type(1)||curve(2)||pubkey_len(1)||pubkey`), the
    /// exact slice the server's signature covers, the RFC 4492 §5.4 hash input.
    pub params: Vec<u8>,
    pub signature_scheme: u16,
    pub signature: Vec<u8>,
}

/// Parses a `ServerKeyExchange` handshake message body (without the 4-byte header).
pub fn parse_server_key_exchange(body: &[u8]) -> Result<ParsedServerKeyExchange> {
    let mut r = Reader::new(body);
    let curve_type = r.u8()?;
    if curve_type != 3 {
        bail!("restls: server selected unsupported (non-named-curve) ECDHE curve type");
    }
    let curve = r.u16()?;
    let public_key = r.u8_len_prefixed()?.to_vec();
    let params_len = 1 + 2 + 1 + public_key.len();
    let Some(params) = body.get(..params_len) else {
        bail!("restls: short ServerKeyExchange");
    };
    let params = params.to_vec();
    let signature_scheme = r.u16()?;
    let signature = r.u16_len_prefixed()?.to_vec();
    Ok(ParsedServerKeyExchange { curve, public_key, params, signature_scheme, signature })
}

/// Marshals a `ClientKeyExchange` handshake message for the ECDHE case: `pubkey_len(1) ||
/// pubkey`.
#[must_use]
pub fn marshal_client_key_exchange(public_key: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(4 + 1 + public_key.len());
    msg.push(HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE);
    #[expect(clippy::cast_possible_truncation, reason = "the handshake body length field is 24 bits by definition")]
    let body_len = (1 + public_key.len()) as u32;
    msg.extend_from_slice(&body_len.to_be_bytes()[1..]);
    #[expect(clippy::cast_possible_truncation, reason = "RFC 4492 caps an ECDHE public key at 255 bytes")]
    msg.push(public_key.len() as u8);
    msg.extend_from_slice(public_key);
    msg
}

/// Marshals a TLS 1.2 `Finished` handshake message: 12-byte `verify_data` (RFC 5246 §7.4.9),
/// unlike TLS 1.3's 32-byte one (see [`marshal_finished`]).
#[must_use]
pub fn marshal_finished12(verify_data: &[u8; 12]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(4 + 12);
    msg.push(HANDSHAKE_TYPE_FINISHED);
    msg.extend_from_slice(&[0, 0, 12]);
    msg.extend_from_slice(verify_data);
    msg
}

/// Extracts `verify_data` out of a parsed TLS 1.2 `Finished` handshake message (with header).
pub fn parse_finished12(msg: &[u8]) -> Result<[u8; 12]> {
    if msg.len() != 4 + 12 || msg.first() != Some(&HANDSHAKE_TYPE_FINISHED) {
        return Err(anyhow!("restls: malformed TLS 1.2 Finished message"));
    }
    let body = msg.get(4..16).ok_or_else(|| anyhow!("restls: malformed TLS 1.2 Finished message"))?;
    body.try_into().map_err(|_| anyhow!("restls: malformed TLS 1.2 Finished message"))
}

#[cfg(test)]
mod tls12_message_tests {
    use super::*;

    #[test]
    fn server_key_exchange_round_trips_through_hand_built_bytes() {
        let mut body = vec![3u8, 0x00, 0x1d, 32];
        body.extend_from_slice(&[0xAAu8; 32]);
        body.extend_from_slice(&[0x04, 0x03]);
        body.extend_from_slice(&[0, 4]);
        body.extend_from_slice(&[0xBBu8; 4]);

        let parsed = parse_server_key_exchange(&body).expect("parses");
        assert_eq!(parsed.curve, 0x001d);
        assert_eq!(parsed.public_key, vec![0xAAu8; 32]);
        assert_eq!(parsed.signature_scheme, 0x0403);
        assert_eq!(parsed.signature, vec![0xBBu8; 4]);
        assert_eq!(parsed.params, &body[..4 + 32]);
    }

    #[test]
    fn client_key_exchange_marshals_length_prefixed_point() {
        let msg = marshal_client_key_exchange(&[1, 2, 3]);
        assert_eq!(msg[0], HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE);
        assert_eq!(&msg[1..4], &[0, 0, 4]);
        assert_eq!(msg[4], 3);
        assert_eq!(&msg[5..8], &[1, 2, 3]);
    }

    #[test]
    fn finished12_round_trips() {
        let verify_data = [7u8; 12];
        let msg = marshal_finished12(&verify_data);
        assert_eq!(parse_finished12(&msg).expect("parses"), verify_data);
    }
}

#[cfg(test)]
mod client_hello_extension_tests {
    use super::*;
    use crate::consts::{CIPHER_SUITE_AES_128_GCM_SHA256, GROUP_X25519, SIG_ECDSA_SECP256R1_SHA256};

    fn client_hello(next_protos: Vec<String>, tls12_mode: bool) -> Vec<u8> {
        ClientHelloBuilder {
            random: [0; 32],
            session_id: [1; 32],
            cipher_suites: vec![CIPHER_SUITE_AES_128_GCM_SHA256],
            server_name: "restls-interop-target".to_owned(),
            supported_groups: vec![GROUP_X25519],
            next_protos,
            key_shares: vec![KeyShareEntry { group: GROUP_X25519, data: vec![2; 32] }],
            signature_algorithms: vec![SIG_ECDSA_SECP256R1_SHA256],
            psk_identities: vec![],
            psk_binders: vec![],
            tls12_mode,
        }
        .marshal()
    }

    fn extension_windows(hello: &[u8]) -> Vec<(u16, Vec<u8>)> {
        // msg_type + u24 length + legacy_version + random + session_id length + session_id
        let mut pos = 4 + 2 + 32 + 1 + 32;
        let cipher_len = usize::from(hello[pos]) << 8 | usize::from(hello[pos + 1]);
        pos += 2 + cipher_len;
        pos += 1 + usize::from(hello[pos]);
        let ext_len = usize::from(hello[pos]) << 8 | usize::from(hello[pos + 1]);
        pos += 2;
        let end = pos + ext_len;
        let mut extensions = Vec::new();
        while pos < end {
            let id = u16::from_be_bytes([hello[pos], hello[pos + 1]]);
            let len = usize::from(hello[pos + 2]) << 8 | usize::from(hello[pos + 3]);
            extensions.push((id, hello[pos + 4..pos + 4 + len].to_vec()));
            pos += 4 + len;
        }
        extensions
    }

    #[test]
    fn alpn_lists_every_protocol_between_groups_and_signature_algorithms() {
        let hello = client_hello(vec!["h2".to_owned(), "http/1.1".to_owned()], false);
        let extensions = extension_windows(&hello);
        let ids: Vec<u16> = extensions.iter().map(|(id, _)| *id).collect();
        let alpn_at = ids.iter().position(|id| *id == EXT_ALPN).expect("ALPN extension present");
        assert_eq!(ids[alpn_at - 1], EXT_SUPPORTED_GROUPS);
        assert_eq!(ids[alpn_at + 1], EXT_SIGNATURE_ALGORITHMS);
        assert_eq!(
            extensions[alpn_at].1,
            vec![0, 12, 2, b'h', b'2', 8, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1']
        );
    }

    #[test]
    fn tls12_client_hello_also_offers_alpn() {
        let hello = client_hello(vec!["h2".to_owned()], true);
        let extensions = extension_windows(&hello);
        assert!(extensions.iter().any(|(id, body)| *id == EXT_ALPN && body == &[0, 3, 2, b'h', b'2']));
        assert!(!extensions.iter().any(|(id, _)| *id == EXT_KEY_SHARE));
    }

    #[test]
    fn no_alpn_extension_without_configured_protocols() {
        let hello = client_hello(Vec::new(), false);
        assert!(!extension_windows(&hello).iter().any(|(id, _)| *id == EXT_ALPN));
    }
}
