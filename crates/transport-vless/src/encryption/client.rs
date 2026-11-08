use std::sync::{Arc, LazyLock};

use anyhow::{anyhow, Result};
use chrono::{DateTime, TimeDelta, Utc};
use parking_lot::RwLock;
use rand::rngs::OsRng;
use rand::TryRngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::sleep;

use murmur_common::time::duration_from_nanos;
use murmur_common_net::io::Stream;

use super::common::{
    copy_prefix, creat_padding, decode_length, encode_length, parse_padding, x25519_diffie_hellman, CommonConn, AEAD,
    MAX_NONCE,
};
use super::key::mlkem;
use super::xor::AesCtrStream;
use x25519_dalek::{PublicKey, StaticSecret};

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn has_gcm_asm_amd64() -> bool {
    // The CPU features AES-GCM hardware support requires on this architecture.
    std::arch::is_x86_feature_detected!("aes")
        && std::arch::is_x86_feature_detected!("pclmulqdq")
        && std::arch::is_x86_feature_detected!("sse4.1")
        && std::arch::is_x86_feature_detected!("ssse3")
}

#[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
fn has_gcm_asm_amd64() -> bool {
    false
}

#[cfg(target_arch = "aarch64")]
fn has_gcm_asm_arm64() -> bool {
    std::arch::is_aarch64_feature_detected!("aes") && std::arch::is_aarch64_feature_detected!("pmull")
}

#[cfg(not(target_arch = "aarch64"))]
const fn has_gcm_asm_arm64() -> bool {
    false
}

/// Whether s390x hardware acceleration is available. No stable runtime check exists, so
/// hardware support is never reported.
const fn has_gcm_asm_s390x() -> bool {
    false
}

const fn has_gcm_asm_ppc64() -> bool {
    cfg!(target_arch = "powerpc64")
}

static HAS_GCM_ASM_AMD64: LazyLock<bool> = LazyLock::new(has_gcm_asm_amd64);
static HAS_GCM_ASM_ARM64: LazyLock<bool> = LazyLock::new(has_gcm_asm_arm64);
static HAS_GCM_ASM_S390X: LazyLock<bool> = LazyLock::new(has_gcm_asm_s390x);
static HAS_GCM_ASM_PPC64: LazyLock<bool> = LazyLock::new(has_gcm_asm_ppc64);

pub static HAS_AESGCM_HARDWARE_SUPPORT: LazyLock<bool> =
    LazyLock::new(|| *HAS_GCM_ASM_AMD64 || *HAS_GCM_ASM_ARM64 || *HAS_GCM_ASM_S390X || *HAS_GCM_ASM_PPC64);

/// The client's NFS key, either X25519 or ML-KEM-768.
#[derive(Clone, Debug)]
pub enum NfsPKey {
    X25519(PublicKey),
    MlKem768(mlkem::EncapsulationKey768),
}

/// The lock-guarded expiry, PFS key and ticket.
#[derive(Clone, Debug, Default)]
pub struct ClientState {
    pub expire: Option<DateTime<Utc>>,
    pub pfs_key: Vec<u8>,
    pub ticket: Vec<u8>,
}

#[derive(Default)]
pub struct ClientInstance {
    pub nfs_p_keys: Vec<NfsPKey>,
    pub nfs_p_keys_bytes: Vec<Vec<u8>>,
    pub hash32s: Vec<[u8; 32]>,
    pub relays_length: i64,
    pub xor_mode: u32,
    pub seconds: u32,
    pub padding_lens: Vec<[i64; 3]>,
    pub padding_gaps: Vec<[i64; 3]>,
    pub rw_lock: RwLock<ClientState>,
}

/// Redacts the NFS key material; only the lengths of the key-derived vectors are shown.
impl core::fmt::Debug for ClientInstance {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClientInstance")
            .field("nfs_p_keys", &self.nfs_p_keys.len())
            .field("nfs_p_keys_bytes", &self.nfs_p_keys_bytes.len())
            .field("hash32s", &self.hash32s.len())
            .field("relays_length", &self.relays_length)
            .field("xor_mode", &self.xor_mode)
            .field("seconds", &self.seconds)
            .field("padding_lens", &self.padding_lens)
            .field("padding_gaps", &self.padding_gaps)
            .finish_non_exhaustive()
    }
}

/// The config structs keep every length as `i64` (`int`), but they index `usize`-sized buffers.
fn len_usize(value: i64) -> Result<usize> {
    usize::try_from(value).map_err(|_| anyhow!("length {value} does not fit a usize"))
}

fn len_i64(value: usize) -> Result<i64> {
    i64::try_from(value).map_err(|_| anyhow!("length {value} does not fit an i64"))
}

impl ClientInstance {
    pub fn init(&mut self, nfs_p_keys_bytes: Vec<Vec<u8>>, xor_mode: u32, seconds: u32, padding: &str) -> Result<()> {
        if !self.nfs_p_keys.is_empty() {
            return Err(anyhow!("already initialized"));
        }
        let l = nfs_p_keys_bytes.len();
        if l == 0 {
            return Err(anyhow!("empty nfsPKeysBytes"));
        }
        let mut nfs_p_keys = Vec::with_capacity(l);
        let mut hash32s = Vec::with_capacity(l);
        let mut relays_length = 0;
        for k in &nfs_p_keys_bytes {
            if k.len() == 32 {
                let key: [u8; 32] = k.as_slice().try_into().map_err(|_| anyhow!("nfs p key must be 32 bytes"))?;
                nfs_p_keys.push(NfsPKey::X25519(PublicKey::from(key)));
                relays_length += 32 + 32;
            } else {
                nfs_p_keys.push(NfsPKey::MlKem768(mlkem::new_encapsulation_key_768(k)?));
                relays_length += 1088 + 32;
            }
            hash32s.push(*blake3::hash(k).as_bytes());
        }
        relays_length -= 32;
        self.nfs_p_keys = nfs_p_keys;
        self.nfs_p_keys_bytes = nfs_p_keys_bytes;
        self.hash32s = hash32s;
        self.relays_length = relays_length;
        self.xor_mode = xor_mode;
        self.seconds = seconds;
        parse_padding(padding, &mut self.padding_lens, &mut self.padding_gaps)
    }

    /// One block per relay: its public key or ML-KEM-768 ciphertext, then 32 bytes binding it to
    /// the next relay's hash.
    fn write_relay_preamble(&self, client_hello: &mut [u8], iv: &[u8; 16], relays_end: usize) -> Result<Vec<u8>> {
        let (iv_dst, relays) = client_hello.split_at_mut(16);
        copy_prefix(iv_dst, iv);
        let relays =
            relays.get_mut(..relays_end - 16).ok_or_else(|| anyhow!("client hello is shorter than the relay block"))?;

        let mut nfs_key: Vec<u8> = Vec::new();
        let mut last_ctr: Option<AesCtrStream> = None;
        let mut relays_off = 0;
        for (j, (k, key_bytes)) in self.nfs_p_keys.iter().zip(self.nfs_p_keys_bytes.iter()).enumerate() {
            let index = if matches!(k, NfsPKey::MlKem768(_)) { 1088 } else { 32 };
            let Some(key_dst) = relays.get_mut(relays_off..relays_off + index) else {
                return Err(anyhow!("relay key exceeds the client hello"));
            };
            match k {
                NfsPKey::X25519(k) => {
                    let mut private_bytes = [0u8; 32];
                    OsRng.try_fill_bytes(&mut private_bytes)?;
                    let private_key = StaticSecret::from(private_bytes);
                    copy_prefix(key_dst, PublicKey::from(&private_key).as_bytes());
                    nfs_key = x25519_diffie_hellman(&private_key, k)?;
                }
                NfsPKey::MlKem768(k) => {
                    let (key, ciphertext) = k.encapsulate()?;
                    nfs_key = key;
                    copy_prefix(key_dst, &ciphertext);
                }
            }
            if self.xor_mode > 0 {
                // this xor can (others can't) be recovered by client's config, revealing an X25519
                // public key / ML-KEM-768 ciphertext, that's why "native" values
                let mut ctr = AesCtrStream::new(key_bytes, iv);
                ctr.xor_key_stream(key_dst);
            }
            if let Some(last_ctr) = last_ctr.as_mut() {
                let (head, _) = key_dst.split_at_mut(32);
                last_ctr.xor_key_stream(head);
                // make this relay irreplaceable
            }
            if j == self.nfs_p_keys.len() - 1 {
                break;
            }
            let Some(hash) = self.hash32s.get(j + 1) else {
                return Err(anyhow!("relay hash is missing"));
            };
            let Some(trail) = relays.get_mut(relays_off + index..relays_off + index + 32) else {
                return Err(anyhow!("relay trailer exceeds the client hello"));
            };
            let mut ctr = AesCtrStream::new(&nfs_key, iv);
            ctr.xor_key_stream_b2b(hash, trail);
            last_ctr = Some(ctr);
            relays_off += index + 32;
        }
        Ok(nfs_key)
    }

    /// 0-RTT: replays the cached ticket instead of exchanging keys. The flag reports whether the
    /// connection now carries the resumed hello and must be returned to the caller untouched.
    fn try_resume(
        self: &Arc<Self>,
        mut c: CommonConn,
        client_hello: &mut [u8],
        iv: &[u8; 16],
        nfs_key: &[u8],
        iv_and_realys_length: usize,
        nfs_aead: &mut AEAD,
    ) -> Result<(CommonConn, bool)> {
        if self.seconds == 0 {
            return Ok((c, false));
        }
        let state = self.rw_lock.read();
        if state.expire.is_none_or(|expire| Utc::now() >= expire) {
            return Ok((c, false));
        }

        let (pre_write, _) = client_hello.split_at_mut(iv_and_realys_length + 18 + 32);
        let (_, fields) = pre_write.split_at_mut(iv_and_realys_length);
        let (length_field, fields) = fields.split_at_mut(18);
        let (ticket_field, _) = fields.split_at_mut(32);

        c.client = Some(Arc::clone(self));
        let mut united_key = state.pfs_key.clone();
        united_key.extend_from_slice(nfs_key); // different unitedKey for each connection
        c.united_key = united_key;
        nfs_aead.seal(length_field, None, &encode_length(32), &[])?;
        nfs_aead.seal(ticket_field, None, &state.ticket, &[])?;
        drop(state);

        let aead = AEAD::new(ticket_field, &c.united_key, c.use_aes);
        c.pre_write = Some(pre_write.to_vec());
        c.aead = Some(aead);
        if self.xor_mode == 2 {
            let out_skip = c.pre_write.as_ref().map_or(0, Vec::len);
            let ctr = AesCtrStream::new(&c.united_key, iv);
            c = c.with_xor(ctr, None, out_skip, 16);
        }
        Ok((c, true))
    }

    // NOT cancel-safe: the handshake writes its preamble and messages to the socket before it completes, so a dropped call leaves the connection mid-exchange; the arms that await it drop it only when the connection is being torn down.
    pub async fn handshake(self: &Arc<Self>, conn: Box<dyn Stream>) -> Result<CommonConn> {
        if self.nfs_p_keys.is_empty() {
            return Err(anyhow!("uninitialized"));
        }
        let c = CommonConn::new(conn, *HAS_AESGCM_HARDWARE_SUPPORT);

        let iv_and_realys_length = 16 + len_usize(self.relays_length)?;
        let pfs_key_exchange_length = 18 + 1184 + 32 + 16;
        let (padding_length, mut padding_lens, padding_gaps) = creat_padding(&self.padding_lens, &self.padding_gaps);
        let padding_length = len_usize(padding_length)?;
        let mut client_hello = vec![0u8; iv_and_realys_length + pfs_key_exchange_length + padding_length];

        let mut iv = [0u8; 16];
        OsRng.try_fill_bytes(&mut iv)?;
        let nfs_key = self.write_relay_preamble(&mut client_hello, &iv, iv_and_realys_length)?;
        let mut nfs_aead = AEAD::new(&iv, &nfs_key, c.use_aes);

        let (mut c, resumed) =
            self.try_resume(c, &mut client_hello, &iv, &nfs_key, iv_and_realys_length, &mut nfs_aead)?;
        if resumed {
            return Ok(c);
        }

        let (_, hello) = client_hello.split_at_mut(iv_and_realys_length);
        let (pfs_section, padding_section) = hello.split_at_mut(pfs_key_exchange_length);
        let (pfs_length_field, pfs_key_dst) = pfs_section.split_at_mut(18);
        nfs_aead.seal(pfs_length_field, None, &encode_length(pfs_key_exchange_length - 18), &[])?;

        let mlkem768_d_key = mlkem::generate_key_768()?;
        let mut x25519_s_bytes = [0u8; 32];
        OsRng.try_fill_bytes(&mut x25519_s_bytes)?;
        let x25519_s_key = StaticSecret::from(x25519_s_bytes);
        let mut pfs_public_key = mlkem768_d_key.encapsulation_key()?.bytes();
        pfs_public_key.extend_from_slice(PublicKey::from(&x25519_s_key).as_bytes());
        nfs_aead.seal(pfs_key_dst, None, &pfs_public_key, &[])?;

        let (padding_length_field, padding_dst) = padding_section.split_at_mut(18);
        nfs_aead.seal(padding_length_field, None, &encode_length(padding_length - 18), &[])?;
        nfs_aead.seal_in_place(padding_dst, None, padding_length - 18 - 16, &[])?;

        let Some(first_len) = padding_lens.first_mut() else {
            return Err(anyhow!("padding lengths are empty"));
        };
        *first_len += len_i64(iv_and_realys_length + pfs_key_exchange_length)?;
        // sends padding in a fragmented way, to create variable traffic pattern, before inner VLESS
        // flow takes control
        send_padded_hello(&mut c, &client_hello, &padding_lens, &padding_gaps).await?;

        let pfs_key =
            complete_key_exchange(&mut c, &mut nfs_aead, &mlkem768_d_key, &x25519_s_key, &pfs_public_key, &nfs_key)
                .await?;

        let mut encrypted_ticket = vec![0u8; 32];
        c.conn.read_exact(&mut encrypted_ticket).await?;
        c.peer_aead.as_mut().ok_or_else(|| anyhow!("peer AEAD is set by this handshake"))?.open_in_place(
            &mut encrypted_ticket,
            None,
            32,
            &[],
        )?;
        let seconds = decode_length(&encrypted_ticket);

        if self.seconds > 0 && seconds > 0 {
            let mut state = self.rw_lock.write();
            state.expire = Some(Utc::now() + TimeDelta::seconds(len_i64(seconds)?));
            state.pfs_key = pfs_key;
            let (ticket, _) = encrypted_ticket.split_at(16);
            state.ticket = ticket.to_vec();
        }

        let mut encrypted_length = vec![0u8; 18];
        c.conn.read_exact(&mut encrypted_length).await?;
        c.peer_aead.as_mut().ok_or_else(|| anyhow!("peer AEAD is set by this handshake"))?.open_in_place(
            &mut encrypted_length,
            None,
            18,
            &[],
        )?;
        let (length_field, _) = encrypted_length.split_at(2);
        let length = decode_length(length_field);
        // important: allows server sends padding slowly, eliminating 1-RTT's traffic pattern
        c.peer_padding = Some(vec![0u8; length]);

        if self.xor_mode == 2 {
            let (ticket, _) = encrypted_ticket.split_at(16);
            let out_ctr = AesCtrStream::new(&c.united_key, &iv);
            let in_ctr = AesCtrStream::new(&c.united_key, ticket);
            c = c.with_xor(out_ctr, Some(in_ctr), 0, length);
        }
        Ok(c)
    }
}

async fn send_padded_hello(
    conn: &mut CommonConn,
    hello: &[u8],
    padding_lens: &[i64],
    padding_gaps: &[i64],
) -> Result<()> {
    let mut written = 0;
    for (i, l) in padding_lens.iter().enumerate() {
        if *l > 0 {
            let chunk_len = len_usize(*l)?;
            let chunk =
                hello.get(written..written + chunk_len).ok_or_else(|| anyhow!("padding exceeds the client hello"))?;
            conn.conn.write_all(chunk).await?;
            conn.conn.flush().await?;
            written += chunk_len;
        }
        if let Some(gap) = padding_gaps.get(i) {
            sleep(duration_from_nanos(*gap)).await;
        }
    }
    Ok(())
}

async fn complete_key_exchange(
    c: &mut CommonConn,
    nfs_aead: &mut AEAD,
    mlkem768_d_key: &mlkem::DecapsulationKey768,
    x25519_s_key: &StaticSecret,
    pfs_public_key: &[u8],
    nfs_key: &[u8],
) -> Result<Vec<u8>> {
    let mut encrypted_pfs_public_key = vec![0u8; 1088 + 32 + 16];
    c.conn.read_exact(&mut encrypted_pfs_public_key).await?;
    let encrypted_pfs_public_key_len = encrypted_pfs_public_key.len();
    nfs_aead.open_in_place(&mut encrypted_pfs_public_key, Some(&MAX_NONCE), encrypted_pfs_public_key_len, &[])?;
    let (peer_pfs_public_key, _) = encrypted_pfs_public_key.split_at(1088 + 32);
    let (mlkem768_part, x25519_part) = peer_pfs_public_key.split_at(1088);
    let mlkem768_key = mlkem768_d_key.decapsulate(mlkem768_part)?;
    let peer_x25519_p_key_bytes: [u8; 32] = x25519_part.try_into().map_err(|_| anyhow!("checked 32-byte slice"))?;
    let x25519_key = x25519_diffie_hellman(x25519_s_key, &PublicKey::from(peer_x25519_p_key_bytes))?;
    // the UnitedKey append must leave pfsKey itself at 64 bytes
    let mut pfs_key = Vec::with_capacity(32 + 32);
    pfs_key.extend_from_slice(&mlkem768_key);
    pfs_key.extend_from_slice(&x25519_key);
    let mut united_key = Vec::with_capacity(pfs_key.len() + nfs_key.len());
    united_key.extend_from_slice(&pfs_key);
    united_key.extend_from_slice(nfs_key);
    c.united_key = united_key;
    c.aead = Some(AEAD::new(pfs_public_key, &c.united_key, c.use_aes));
    c.peer_aead = Some(AEAD::new(peer_pfs_public_key, &c.united_key, c.use_aes));
    Ok(pfs_key)
}

#[cfg(test)]
mod tests {
    use super::HAS_AESGCM_HARDWARE_SUPPORT;

    #[test]
    fn test_has_aesgcm_hardware_support() {
        if cfg!(all(target_arch = "aarch64", target_os = "macos")) {
            assert!(*HAS_AESGCM_HARDWARE_SUPPORT);
        }
    }
}
