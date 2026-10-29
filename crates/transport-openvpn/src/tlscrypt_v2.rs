//! The `tls-crypt-v2` control-channel wrapper: a per-client key that carries the `tls-crypt`
//! key.

use std::fmt;

use anyhow::{bail, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

use super::packet::ControlCryptor;
use super::tlscrypt::{clone_bytes, new_tls_crypt, TLSCrypt};

pub const TLS_CRYPT_V2_CLIENT_PEM_TYPE: &str = "OpenVPN tls-crypt-v2 client key";
pub(crate) const TLS_CRYPT_V2_CLIENT_KEY_DATA_LENGTH: usize = 256;

/// Client-side tls-crypt-v2 protection state.
///
/// Control packet encryption uses the first 256 bytes exactly like tls-crypt v1
/// with inverse/client direction. The remainder of the client PEM is the wrapped
/// client key that must be appended to the initial V3 hard-reset packet.
pub struct TLSCryptV2 {
    tls_crypt: TLSCrypt,
    wrapped_client_key: Vec<u8>,
}

impl fmt::Debug for TLSCryptV2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TLSCryptV2").finish_non_exhaustive()
    }
}

impl ControlCryptor for TLSCryptV2 {
    fn wrap(&self, header: &[u8], packet_id: u32, unix_time: u32, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.tls_crypt.wrap(header, packet_id, unix_time, plaintext)
    }

    fn unwrap(&self, packet: &[u8]) -> Result<(Vec<u8>, u32, u32, Vec<u8>)> {
        self.tls_crypt.unwrap(packet)
    }

    fn wrapped_client_key(&self) -> Option<Vec<u8>> {
        Some(clone_bytes(&self.wrapped_client_key))
    }
}

pub fn new_tls_crypt_v2(key_material: &[u8], wrapped_client_key: &[u8]) -> Result<TLSCryptV2> {
    if key_material.len() != TLS_CRYPT_V2_CLIENT_KEY_DATA_LENGTH {
        bail!(
            "invalid tls-crypt-v2 key material length {}, expected {}",
            key_material.len(),
            TLS_CRYPT_V2_CLIENT_KEY_DATA_LENGTH
        );
    }
    if wrapped_client_key.is_empty() {
        bail!("missing wrapped tls-crypt-v2 client key");
    }
    let tls_crypt = new_tls_crypt(key_material, true)?;
    Ok(TLSCryptV2 { tls_crypt, wrapped_client_key: clone_bytes(wrapped_client_key) })
}

/// Parses the standard `OpenVPN` client PEM. The PEM body is base64, not the
/// hex-body format used by "`OpenVPN` Static key V1".
pub fn decode_tls_crypt_v2_client_key(input: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let Some((pem_type, bytes)) = pem_decode(input) else {
        bail!("invalid tls-crypt-v2 client PEM");
    };
    if pem_type != TLS_CRYPT_V2_CLIENT_PEM_TYPE {
        bail!("invalid tls-crypt-v2 client PEM");
    }
    if bytes.len() <= TLS_CRYPT_V2_CLIENT_KEY_DATA_LENGTH {
        bail!("tls-crypt-v2 client PEM missing wrapped key");
    }
    let (key_material, wrapped_client_key) = bytes.split_at(TLS_CRYPT_V2_CLIENT_KEY_DATA_LENGTH);
    Ok((clone_bytes(key_material), clone_bytes(wrapped_client_key)))
}

/// The PEM surface this crate needs: the first block whose body
/// base64-decodes, as its type label plus body bytes. `None` means no block.
/// Lines lose their trailing `" \t"` and `"\r"`, and leading `Key: Value` header lines are
/// skipped.
pub(crate) fn pem_decode(input: &[u8]) -> Option<(String, Vec<u8>)> {
    let text = String::from_utf8_lossy(input);
    let lines: Vec<&str> = text
        .split('\n')
        .map(|line| line.strip_suffix('\r').map_or(line, |line| line).trim_end_matches([' ', '\t']))
        .collect();

    // Finds the END line first and then takes the last BEGIN
    // line before it, so a document holding several blocks resolves the same way.
    let mut search_from = 0;
    while search_from < lines.len() {
        let end_index = lines
            .iter()
            .enumerate()
            .skip(search_from)
            .find(|(_, line)| line.starts_with("-----END "))
            .map(|(index, _)| index)?;
        search_from = end_index + 1;
        let Some(begin_index) = lines
            .iter()
            .enumerate()
            .take(end_index)
            .rev()
            .find(|(_, line)| line.starts_with("-----BEGIN "))
            .map(|(index, _)| index)
        else {
            continue;
        };
        let Some(label) = lines
            .get(begin_index)
            .and_then(|line| line.strip_prefix("-----BEGIN "))
            .and_then(|rest| rest.strip_suffix("-----"))
        else {
            continue;
        };
        let label = label.to_owned();
        let end_marker = format!("-----END {label}-----");
        if lines.get(end_index).is_none_or(|line| *line != end_marker) {
            continue;
        }

        // Every leading `Key: Value` line is parsed as a header and excluded from
        // the body; a header block must be separated from the END line by at least
        // one line, or the block is skipped.
        let body_lines = lines.get(begin_index + 1..end_index).unwrap_or_default();
        let header_lines = body_lines.iter().take_while(|line| line.contains(':')).count();
        if header_lines > 0 && begin_index + 1 + header_lines == end_index {
            continue;
        }

        // Every space and tab is removed from the body region before base64-decoding
        // it, so interior whitespace is dropped as well.
        let body: String = body_lines
            .get(header_lines..)
            .unwrap_or_default()
            .concat()
            .chars()
            .filter(|c| !matches!(c, ' ' | '\t'))
            .collect();
        if let Ok(bytes) = STANDARD.decode(body) {
            return Some((label, bytes));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use async_trait::async_trait;
    use tokio::sync::{mpsc, Mutex as AsyncMutex};

    use super::*;
    use crate::control::{CancelContext, ControlChannel, ControlIO};
    use crate::packet::{self, decode_control_packet, Opcode, SessionID, OPCODE_SHIFT, P_CONTROL_HARD_RESET_CLIENT_V3};
    use crate::tlscrypt::new_tls_crypt;

    fn test_static_key() -> Vec<u8> {
        (0..=255u8).collect()
    }

    fn test_tls_crypt_v2_client_pem() -> Vec<u8> {
        let mut key = test_static_key();
        key.extend_from_slice(b"wrapped-client-key-fixture");
        let encoded = STANDARD.encode(key.as_slice());
        let mut pem = String::from("-----BEGIN OpenVPN tls-crypt-v2 client key-----\n");
        for chunk in encoded.as_bytes().chunks(64) {
            pem.push_str(&String::from_utf8_lossy(chunk));
            pem.push('\n');
        }
        pem.push_str("-----END OpenVPN tls-crypt-v2 client key-----\n");
        pem.into_bytes()
    }

    #[test]
    fn decode_tls_crypt_v2_client_key_works() {
        let (key, wrapped) = decode_tls_crypt_v2_client_key(&test_tls_crypt_v2_client_pem()).expect("decode");
        assert_eq!(key.len(), 256, "decoded key len={}", key.len());
        assert_eq!(wrapped, b"wrapped-client-key-fixture");
    }

    #[test]
    fn decode_tls_crypt_v2_rejects_hex_static_key_style() {
        let hex_style = concat!(
            "-----BEGIN OpenVPN tls-crypt-v2 client key-----\n",
            "aaaaaaaa\n-----END OpenVPN tls-crypt-v2 client key-----\n"
        );
        assert!(decode_tls_crypt_v2_client_key(hex_style.as_bytes()).is_err(), "expected invalid PEM/base64 rejection");
    }

    #[test]
    fn tls_crypt_v2_uses_client_material_for_control_protection() {
        let (key, wrapped) = decode_tls_crypt_v2_client_key(&test_tls_crypt_v2_client_pem()).expect("decode");
        let client = new_tls_crypt_v2(&key, &wrapped).expect("new v2 client");
        let server = new_tls_crypt(&key, false).expect("new server");

        let header = vec![packet::opcode_key_id(P_CONTROL_HARD_RESET_CLIENT_V3, 0), 1, 2, 3, 4, 5, 6, 7, 8];
        let plain = b"control payload".to_vec();
        let encoded = client.wrap(&header, 0x0f00_0001, 1_714_567_890, &plain).expect("wrap");
        assert_eq!(
            hex::encode(&encoded),
            "5001020304050607080f00000166323ad2f148814e8fef8962eab0374cf730f81f1f33c4503d7d2a4815f56ca\
9c22f410b37db199e2bdcb4cc74bdb5671f3a1b",
        );

        let (_header, _packet_id, _unix_time, decoded) = server.unwrap(&encoded).expect("unwrap");
        assert_eq!(decoded, plain);
    }

    struct MemoryPacketIO {
        incoming: AsyncMutex<mpsc::Receiver<Vec<u8>>>,
        outgoing: mpsc::Sender<Vec<u8>>,
    }

    impl MemoryPacketIO {
        fn pair() -> (Arc<Self>, Arc<Self>) {
            let (a_to_b_tx, a_to_b_rx) = mpsc::channel(16);
            let (b_to_a_tx, b_to_a_rx) = mpsc::channel(16);
            let a = Arc::new(Self { incoming: AsyncMutex::new(b_to_a_rx), outgoing: a_to_b_tx });
            let b = Arc::new(Self { incoming: AsyncMutex::new(a_to_b_rx), outgoing: b_to_a_tx });
            (a, b)
        }
    }

    #[async_trait]
    impl ControlIO for MemoryPacketIO {
        async fn read_packet(&self, _ctx: &CancelContext) -> Result<Vec<u8>> {
            let mut incoming = self.incoming.lock().await;
            incoming.recv().await.ok_or_else(|| anyhow::anyhow!("memory packet io closed"))
        }

        async fn write_packet(&self, _ctx: &CancelContext, packet: &[u8]) -> Result<()> {
            self.outgoing.send(packet.to_vec()).await.map_err(|_| anyhow::anyhow!("memory packet io closed"))
        }

        async fn write_packet_allow_active_stop(&self, ctx: &CancelContext, packet: &[u8]) -> Result<()> {
            self.write_packet(ctx, packet).await
        }

        async fn close(&self) -> Result<()> {
            Ok(())
        }

        fn local_addr(&self) -> Option<SocketAddr> {
            None
        }

        fn remote_addr(&self) -> Option<SocketAddr> {
            None
        }
    }

    #[tokio::test]
    async fn tls_crypt_v2_send_reset_uses_v3_and_appends_wrapped_key() {
        let (key, wrapped) = decode_tls_crypt_v2_client_key(&test_tls_crypt_v2_client_pem()).expect("decode");
        let crypt = new_tls_crypt_v2(&key, &wrapped).expect("new v2 client");

        let (client_io, server_io) = MemoryPacketIO::pair();
        let session = SessionID(*b"client01");
        let channel = ControlChannel::new(client_io, Some(Arc::new(crypt)), session);
        let ctx = CancelContext::background();
        channel.send_reset(&ctx).await.expect("send reset");

        let raw = server_io.read_packet(&ctx).await.expect("read raw packet");
        let opcode = raw[0] >> OPCODE_SHIFT;
        assert_eq!(Opcode(opcode), P_CONTROL_HARD_RESET_CLIENT_V3, "expected V3 opcode, got {opcode}");
        assert!(raw.ends_with(&wrapped), "initial V3 reset missing wrapped client key");

        let protected = &raw[..raw.len() - wrapped.len()];
        let server_crypt = new_tls_crypt(&key, false).expect("new server crypt");
        let (decoded, _packet_id, _unix_time) =
            decode_control_packet(Some(&server_crypt), protected).expect("decode control packet");
        assert!(
            decoded.opcode == P_CONTROL_HARD_RESET_CLIENT_V3 && decoded.message_id == 0,
            "unexpected packet: {}/{}",
            decoded.opcode,
            decoded.message_id
        );
    }
}
