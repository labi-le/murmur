use std::fmt;
use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use rand::rngs::OsRng;
use rand::TryRngCore as _;

use murmur_common_net::{EnhancePacketConn, WaitReadFrom};
use murmur_common_pool as pool;
use murmur_std_compat::net::{Addr, PacketConn as NetPacketConn};

use super::cipher::Cipher;

pub const MAX_PACKET_SIZE: usize = 64 * 1024;

/// `ErrShortPacket`: the packet is too short to be a valid encrypted packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("short packet")]
pub struct ErrShortPacket;

/// The `ErrShortPacket` sentinel, callable in a `const` context.
#[must_use]
pub const fn err_short_packet() -> ErrShortPacket {
    ErrShortPacket
}

impl From<ErrShortPacket> for io::Error {
    fn from(err: ErrShortPacket) -> Self {
        Self::new(io::ErrorKind::UnexpectedEof, err)
    }
}

fn err_short_buffer() -> io::Error {
    io::Error::new(io::ErrorKind::WriteZero, "short buffer")
}

/// A random IV followed by the ciphertext, written into `dst`.
pub fn pack<'a>(dst: &'a mut [u8], plaintext: &[u8], s: &dyn Cipher) -> io::Result<&'a [u8]> {
    let iv_size = s.iv_size();
    let n = iv_size + plaintext.len();
    if dst.len() < n {
        return Err(err_short_buffer());
    }
    let (out, _) = dst.split_at_mut(n);
    let (iv, payload) = out.split_at_mut(iv_size);
    OsRng.try_fill_bytes(iv).map_err(io::Error::other)?;
    let mut stream = s.encrypter(iv);
    payload.copy_from_slice(plaintext);
    stream.apply_keystream(payload);
    Ok(&*out)
}

/// Decrypts `pkt` in place and returns its plaintext tail.
pub fn unpack_inplace<'a>(pkt: &'a mut [u8], s: &dyn Cipher) -> io::Result<&'a mut [u8]> {
    let iv_size = s.iv_size();
    if pkt.len() < iv_size {
        return Err(err_short_packet().into());
    }
    let (iv, payload) = pkt.split_at_mut(iv_size);
    let mut stream = s.decrypter(iv);
    stream.apply_keystream(payload);
    Ok(payload)
}

/// Decrypts `pkt` into the front of `dst`.
pub fn unpack<'a>(dst: &'a mut [u8], pkt: &[u8], s: &dyn Cipher) -> io::Result<&'a [u8]> {
    let iv_size = s.iv_size();
    if pkt.len() < iv_size {
        return Err(err_short_packet().into());
    }
    let n = pkt.len() - iv_size;
    if dst.len() < n {
        return Err(err_short_buffer());
    }
    let (iv, ciphertext) = pkt.split_at(iv_size);
    let mut stream = s.decrypter(iv);
    let (plain, _) = dst.split_at_mut(n);
    plain.copy_from_slice(ciphertext);
    stream.apply_keystream(plain);
    Ok(&*plain)
}

pub struct PacketConn {
    enhance_packet_conn: Arc<dyn EnhancePacketConn>,
    cipher: Box<dyn Cipher>,
}

impl fmt::Debug for PacketConn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketConn").finish_non_exhaustive()
    }
}

pub fn new_packet_conn(c: Arc<dyn EnhancePacketConn>, ciph: Box<dyn Cipher>) -> PacketConn {
    PacketConn { enhance_packet_conn: c, cipher: ciph }
}

#[async_trait]
impl NetPacketConn for PacketConn {
    async fn read_from(&self, b: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        let (n, addr) = self.enhance_packet_conn.read_from(b).await?;
        let plain_len = unpack_inplace(b.get_mut(..n).ok_or_else(err_short_packet)?, &*self.cipher)?.len();
        // the `copy_within` drops the IV off the front.
        b.copy_within(self.cipher.iv_size()..n, 0);
        Ok((plain_len, addr))
    }

    async fn write_to(&self, b: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        let mut buf = pool::get(MAX_PACKET_SIZE);
        let result = async {
            let packed = pack(&mut buf, b, &*self.cipher)?;
            self.enhance_packet_conn.write_to(packed, addr).await
        }
        .await;
        // the pooled block is returned whether or not the pack succeeded.
        let _ = pool::put(buf);
        result.map(|_| b.len())
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.enhance_packet_conn.local_addr()
    }

    fn close(&self) -> io::Result<()> {
        self.enhance_packet_conn.close()
    }
}

#[async_trait]
impl WaitReadFrom for PacketConn {
    // NOT cancel-safe: a dropped call has already consumed datagram framing from the socket, so a later read would start mid-frame; every `select!` arm that awaits it drops it only while the connection is being torn down.
    async fn wait_read_from(
        &self,
    ) -> (Vec<u8>, Option<Box<dyn FnOnce() + Send>>, Option<Box<dyn Addr>>, io::Result<()>) {
        let (mut data, put, addr, err) = self.enhance_packet_conn.wait_read_from().await;
        if err.is_err() {
            return (data, put, addr, err);
        }
        match unpack_inplace(&mut data, &*self.cipher) {
            Ok(plain) => {
                // The plaintext is a slice of the pooled block, so copy it out and let the caller
                // keep the `put` that returns the block.
                let plaintext = plain.to_vec();
                if put.is_none() {
                    let _ = pool::put(data);
                }
                (plaintext, put, addr, Ok(()))
            }
            Err(err) => {
                if let Some(put) = put {
                    put();
                } else {
                    let _ = pool::put(data);
                }
                (Vec::new(), None, addr, Err(err))
            }
        }
    }
}
