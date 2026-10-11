//! Bounds-checked big-endian byte cursor used by [`crate::messages`] to parse
//! and build TLS 1.3 handshake message bodies.

use crate::error::{Result, TlsError};

pub(crate) struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

fn truncated() -> TlsError {
    TlsError::protocol("wire: truncated message")
}

impl<'a> Reader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub(crate) fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    pub(crate) fn u8(&mut self) -> Result<u8> {
        let &b = self.data.get(self.pos).ok_or_else(truncated)?;
        self.pos += 1;
        Ok(b)
    }

    pub(crate) fn u16(&mut self) -> Result<u16> {
        let bytes: [u8; 2] = self.take(2)?.try_into().map_err(|_| truncated())?;
        Ok(u16::from_be_bytes(bytes))
    }

    pub(crate) fn u24(&mut self) -> Result<u32> {
        let bytes: [u8; 3] = self.take_array()?;
        let [b0, b1, b2] = bytes;
        Ok(u32::from(b0) << 16 | u32::from(b1) << 8 | u32::from(b2))
    }

    pub(crate) fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take_array()?))
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let slice = self.data.get(self.pos..self.pos + n).ok_or_else(truncated)?;
        self.pos += n;
        Ok(slice)
    }

    pub(crate) fn take_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| truncated())
    }

    /// Reads a `<1-byte len><bytes>` vector.
    pub(crate) fn vec8(&mut self) -> Result<&'a [u8]> {
        let len = usize::from(self.u8()?);
        self.take(len)
    }

    /// Reads a `<2-byte len><bytes>` vector.
    pub(crate) fn vec16(&mut self) -> Result<&'a [u8]> {
        let len = usize::from(self.u16()?);
        self.take(len)
    }

    /// Reads a `<3-byte len><bytes>` vector.
    pub(crate) fn vec24(&mut self) -> Result<&'a [u8]> {
        let len = self.u24()? as usize;
        self.take(len)
    }
}

pub(crate) struct Writer {
    pub buf: Vec<u8>,
}

impl Writer {
    pub(crate) fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub(crate) fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub(crate) fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub(crate) fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub(crate) fn u24(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes()[1..]);
    }

    pub(crate) fn bytes(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Writes `<1-byte len><bytes>`; returns an error if `data` is too long.
    pub(crate) fn vec8(&mut self, data: &[u8]) -> Result<()> {
        let len: u8 = data.len().try_into().map_err(|_| TlsError::protocol("wire: vec8 too long"))?;
        self.u8(len);
        self.bytes(data);
        Ok(())
    }

    /// Writes `<2-byte len><bytes>`; returns an error if `data` is too long.
    pub(crate) fn vec16(&mut self, data: &[u8]) -> Result<()> {
        let len: u16 = data.len().try_into().map_err(|_| TlsError::protocol("wire: vec16 too long"))?;
        self.u16(len);
        self.bytes(data);
        Ok(())
    }

    /// Writes `<3-byte len><bytes>`; returns an error if `data` is too long.
    pub(crate) fn vec24(&mut self, data: &[u8]) -> Result<()> {
        let len: u32 = data.len().try_into().map_err(|_| TlsError::protocol("wire: vec24 too long"))?;
        if len > 0x00ff_ffff {
            return Err(TlsError::protocol("wire: vec24 too long"));
        }
        self.u24(len);
        self.bytes(data);
        Ok(())
    }
}

impl Default for Writer {
    fn default() -> Self {
        Self::new()
    }
}

/// Wraps `body` in a handshake message header: `msg_type(1) || len(3, BE)`.
pub(crate) fn build_handshake_message(msg_type: u8, body: &[u8]) -> Result<Vec<u8>> {
    let mut w = Writer::new();
    w.u8(msg_type);
    w.vec24(body)?;
    Ok(w.buf)
}

/// If `buf` contains at least one complete `[type(1) || len(3) || body]`
/// handshake message, drains and returns it; otherwise returns `None`. Used
/// for reassembling handshake messages that may be fragmented across, or
/// coalesced within, TLS records.
pub(crate) fn take_handshake_message(buf: &mut Vec<u8>) -> Option<Vec<u8>> {
    let header: [u8; 4] = buf.get(..4)?.try_into().ok()?;
    let [_, b1, b2, b3] = header;
    let body_len = (u32::from(b1) << 16 | u32::from(b2) << 8 | u32::from(b3)) as usize;
    let total = 4 + body_len;
    if buf.len() < total {
        return None;
    }
    Some(buf.drain(..total).collect())
}

/// Splits a complete raw handshake message (as returned by
/// [`take_handshake_message`]) into `(msg_type, body)`.
pub(crate) fn split_handshake_message(raw: &[u8]) -> Result<(u8, &[u8])> {
    let &msg_type = raw.first().ok_or_else(truncated)?;
    let body = raw.get(4..).ok_or_else(truncated)?;
    Ok((msg_type, body))
}
