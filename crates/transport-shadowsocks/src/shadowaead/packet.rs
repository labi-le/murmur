use std::fmt;
use std::io;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use rand::rngs::OsRng;
use rand::TryRngCore;

use murmur_common_net::{EnhancePacketConn, WaitReadFrom};
use murmur_common_pool as pool;
use murmur_std_compat::net::{Addr, PacketConn as NetPacketConn};

use super::cipher::Cipher;

/// `ErrShortPacket`, recognisable across the `io::Error` boundary with a downcast:
/// `err.get_ref().and_then(|err| err.downcast_ref::<ErrShortPacket>())`.
#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
#[error("short packet")]
pub struct ErrShortPacket;

#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
#[error("short buffer")]
pub struct ErrShortBuffer;

const MAX_PACKET_SIZE: usize = 64 * 1024;

/// The zero nonce, read-only. 128 bytes is more than enough.
const ZERONONCE: [u8; 128] = [0u8; 128];

/// The zero nonce, shortened to the nonce size the cipher advertises.
fn zerononce(nonce_size: usize) -> Result<&'static [u8]> {
    ZERONONCE.get(..nonce_size).ok_or_else(|| ErrShortBuffer.into())
}

/// `to_io_error`: the packet sentinels keep their identity across an `io::Error` boundary.
fn to_io_error(err: anyhow::Error) -> io::Error {
    if err.is::<ErrShortPacket>() {
        return io::Error::other(ErrShortPacket);
    }
    if err.is::<ErrShortBuffer>() {
        return io::Error::other(ErrShortBuffer);
    }
    io::Error::other(err)
}

/// Encrypts `plaintext` under a random salt prepended to `dst`, which must hold
/// `salt_size + plaintext.len() + AEAD overhead` bytes.
pub fn pack(dst: &mut Vec<u8>, plaintext: &[u8], ciph: &dyn Cipher) -> Result<()> {
    let salt_size = ciph.salt_size();
    if dst.len() < salt_size {
        dst.resize(salt_size, 0);
    }
    let (salt, _) = dst.split_at_mut(salt_size);
    OsRng.try_fill_bytes(salt)?;
    let aead = ciph.encrypter(salt)?;
    if dst.len() < salt_size + plaintext.len() + aead.overhead() {
        return Err(ErrShortBuffer.into());
    }
    dst.truncate(salt_size);
    let nonce_size = aead.nonce_size();
    aead.seal(dst, zerononce(nonce_size)?, plaintext, &[])?;
    Ok(())
}

/// Decrypts `pkt`. `dst_len` is the length of the output area; only the length is needed, for the
/// `ErrShortBuffer` bound check.
///
/// Decrypts `pkt` in place and returns the plaintext prefix, so the caller never needs a separate
/// allocation for the payload.
pub fn unpack<'a>(dst_len: usize, pkt: &'a mut [u8], ciph: &dyn Cipher) -> Result<&'a mut [u8]> {
    let salt_size = ciph.salt_size();
    if pkt.len() < salt_size {
        return Err(ErrShortPacket.into());
    }
    let aead = ciph.decrypter(pkt.get(..salt_size).ok_or(ErrShortPacket)?)?;
    if pkt.len() < salt_size + aead.overhead() {
        return Err(ErrShortPacket.into());
    }
    if salt_size + dst_len + aead.overhead() < pkt.len() {
        return Err(ErrShortBuffer.into());
    }
    let payload = pkt.get_mut(salt_size..).ok_or(ErrShortPacket)?;
    aead.open_in_place(zerononce(aead.nonce_size())?, payload, &[])
}

pub struct PacketConn {
    conn: Arc<dyn EnhancePacketConn>,
    cipher: Box<dyn Cipher>,
}

impl fmt::Debug for PacketConn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketConn").finish_non_exhaustive()
    }
}

impl PacketConn {
    /// The wrapped `EnhancePacketConn`.
    #[must_use]
    pub fn enhance_packet_conn(&self) -> &Arc<dyn EnhancePacketConn> {
        &self.conn
    }

    /// The packet cipher.
    #[must_use]
    pub fn cipher(&self) -> &dyn Cipher {
        &*self.cipher
    }
}

pub fn new_packet_conn(c: Arc<dyn EnhancePacketConn>, ciph: Box<dyn Cipher>) -> PacketConn {
    PacketConn { conn: c, cipher: ciph }
}

#[async_trait]
impl NetPacketConn for PacketConn {
    async fn read_from(&self, b: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        let (n, addr) = self.conn.as_packet_conn().read_from(b).await?;
        let salt_size = self.cipher.salt_size();
        // Slicing past the salt would panic on a packet shorter than the salt; report
        // `ErrShortPacket` instead.
        let dst_len = b.len().saturating_sub(salt_size);
        let Some(pkt) = b.get_mut(..n) else {
            return Err(to_io_error(ErrShortPacket.into()));
        };
        let payload_len = unpack(dst_len, pkt, &*self.cipher).map_err(to_io_error)?.len();
        b.copy_within(salt_size..salt_size + payload_len, 0);
        Ok((payload_len, addr))
    }

    async fn write_to(&self, b: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        let mut buf = pool::get(MAX_PACKET_SIZE);
        let result = match pack(&mut buf, b, &*self.cipher) {
            Ok(()) => self.conn.as_packet_conn().write_to(&buf, addr).await.map(|_| b.len()),
            Err(err) => Err(to_io_error(err)),
        };
        let _ = pool::put(buf);
        result
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.conn.local_addr()
    }

    fn close(&self) -> io::Result<()> {
        self.conn.close()
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.conn.set_deadline(deadline)
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.conn.set_read_deadline(deadline)
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.conn.set_write_deadline(deadline)
    }
}

#[async_trait]
impl WaitReadFrom for PacketConn {
    // NOT cancel-safe: a dropped call has already consumed datagram framing from the socket, so a later read would start mid-frame; every `select!` arm that awaits it drops it only while the connection is being torn down.
    async fn wait_read_from(
        &self,
    ) -> (Vec<u8>, Option<Box<dyn FnOnce() + Send>>, Option<Box<dyn Addr>>, io::Result<()>) {
        let (mut data, put, addr, err) = self.conn.wait_read_from().await;
        if let Err(err) = err {
            return (data, put, addr, Err(err));
        }
        let salt_size = self.cipher.salt_size();
        let dst_len = data.len().saturating_sub(salt_size);
        match unpack(dst_len, &mut data, &*self.cipher) {
            Ok(payload) => {
                let payload = payload.to_vec();
                if put.is_none() {
                    let _ = pool::put(data);
                }
                (payload, put, addr, Ok(()))
            }
            Err(err) => {
                if let Some(put) = put {
                    put();
                } else {
                    let _ = pool::put(data);
                }
                (Vec::new(), None, addr, Err(to_io_error(err)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shadowaead::cipher::{aesgcm, chacha20poly1305};

    /// Pins `unpack` decoding a packet produced by `pack`: the salt prepended to a
    /// `zerononce`-sealed ciphertext, for a fixed psk/salt and the plaintext `"udp packet
    /// payload"`.
    fn assert_unpack_decodes_reference_packet(cipher: Box<dyn Cipher>, packet_hex: &str, want_plaintext_hex: &str) {
        let mut packet = hex::decode(packet_hex).expect("valid hex vector");
        let want = hex::decode(want_plaintext_hex).expect("valid hex vector");
        let got = unpack(want.len(), &mut packet, &*cipher).expect("unpack reference packet");
        assert_eq!(got, want, "unpack diverges from the shadowaead.Unpack");
    }

    #[test]
    fn unpack_decodes_reference_packet_aes_128_gcm() {
        let psk = [0x11u8; 16];
        assert_unpack_decodes_reference_packet(
            aesgcm(&psk).expect("aes-128-gcm cipher"),
            "22222222222222222222222222222222c481a25e0af7eec50bce95c55b09f7b1ea140640a58df7d097707964495cce8667ee",
            "756470207061636b6574207061796c6f6164",
        );
    }

    #[test]
    fn unpack_decodes_reference_packet_aes_256_gcm() {
        let psk = [0x11u8; 32];
        assert_unpack_decodes_reference_packet(
            aesgcm(&psk).expect("aes-256-gcm cipher"),
            "22222222222222222222222222222222222222222222222222222222222222227843eda8b2182d8220e4c05eb6edb2440ee0f1533546f2978e2a9a1339c8ef3543bd",
            "756470207061636b6574207061796c6f6164",
        );
    }

    #[test]
    fn unpack_decodes_reference_packet_chacha20_ietf_poly1305() {
        let psk = [0x11u8; 32];
        assert_unpack_decodes_reference_packet(
            chacha20poly1305(&psk).expect("chacha20-ietf-poly1305 cipher"),
            "2222222222222222222222222222222222222222222222222222222222222222f871ec21fbef3dbd62c3b8075cc96acc02adbc945a144e91fed4bf1af00b9338fe46",
            "756470207061636b6574207061796c6f6164",
        );
    }
}
