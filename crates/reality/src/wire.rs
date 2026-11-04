//! Minimal big-endian TLS wire encoding/decoding helpers (RFC 8446 §3), just the subset REALITY's
//! handshake trick touches: fixed-width integers and length-prefixed vectors.

use anyhow::{anyhow, Result};

pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub(crate) fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub(crate) fn u8(&mut self) -> Result<u8> {
        let b = *self.buf.get(self.pos).ok_or_else(|| anyhow!("wire: truncated u8"))?;
        self.pos += 1;
        Ok(b)
    }

    pub(crate) fn u16(&mut self) -> Result<u16> {
        let [hi, lo] = self.bytes(2)? else { return Err(anyhow!("wire: truncated u16")) };
        Ok(u16::from_be_bytes([*hi, *lo]))
    }

    pub(crate) fn u24(&mut self) -> Result<u32> {
        let [b0, b1, b2] = self.bytes(3)? else { return Err(anyhow!("wire: truncated u24")) };
        Ok(u32::from_be_bytes([0, *b0, *b1, *b2]))
    }

    pub(crate) fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        let remaining = self.buf.get(self.pos..).unwrap_or_default();
        let Some(out) = remaining.get(..n) else {
            return Err(anyhow!("wire: truncated field, wanted {n} have {}", remaining.len()));
        };
        self.pos += n;
        Ok(out)
    }

    /// A `<0..255>`-style vector: one length byte, then that many bytes.
    pub(crate) fn vec_u8(&mut self) -> Result<&'a [u8]> {
        let n = self.u8()? as usize;
        self.bytes(n)
    }

    /// A `<0..65535>`-style vector: two length bytes, then that many bytes.
    pub(crate) fn vec_u16(&mut self) -> Result<&'a [u8]> {
        let n = self.u16()? as usize;
        self.bytes(n)
    }

    /// A `<0..2^24-1>`-style vector: three length bytes, then that many bytes.
    pub(crate) fn vec_u24(&mut self) -> Result<&'a [u8]> {
        let n = self.u24()? as usize;
        self.bytes(n)
    }
}

#[derive(Default)]
pub(crate) struct Writer {
    pub buf: Vec<u8>,
}

impl Writer {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    pub(crate) fn u16(&mut self, v: u16) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub(crate) fn u24(&mut self, v: u32) -> &mut Self {
        let b = v.to_be_bytes();
        self.buf.extend_from_slice(&b[1..4]);
        self
    }

    pub(crate) fn bytes(&mut self, v: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(v);
        self
    }

    /// Writes `body` prefixed by its own one-byte length; panics (caller bug, not wire error) if
    /// it does not fit.
    pub(crate) fn vec_u8(&mut self, body: &[u8]) -> &mut Self {
        assert!(u8::try_from(body.len()).is_ok(), "vec_u8 body too long");
        #[expect(clippy::cast_possible_truncation, reason = "the assert above bounds the body to one length byte")]
        self.u8(body.len() as u8);
        self.bytes(body)
    }

    pub(crate) fn vec_u16(&mut self, body: &[u8]) -> &mut Self {
        assert!(u16::try_from(body.len()).is_ok(), "vec_u16 body too long");
        #[expect(clippy::cast_possible_truncation, reason = "the assert above bounds the body to two length bytes")]
        self.u16(body.len() as u16);
        self.bytes(body)
    }

    pub(crate) fn vec_u24(&mut self, body: &[u8]) -> &mut Self {
        assert!(body.len() <= 0x00FF_FFFF, "vec_u24 body too long");
        #[expect(clippy::cast_possible_truncation, reason = "the assert above bounds the body to three length bytes")]
        self.u24(body.len() as u32);
        self.bytes(body)
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

/// Wraps `body` as a handshake message: one type byte, a `u24` length, then `body` itself.
pub(crate) fn handshake_message(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(msg_type);
    #[expect(
        clippy::cast_possible_truncation,
        reason = "every caller builds a handshake message of a few hundred bytes, far below this 24-bit field"
    )]
    w.u24(body.len() as u32);
    w.bytes(body);
    w.into_bytes()
}
