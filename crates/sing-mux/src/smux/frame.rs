//! Only the version-1 frame shape is implemented: an 8-byte header
//! (version, command, little-endian u16 length, little-endian u32 stream id) followed by
//! `length` bytes of payload. Version 2's window-update frame and per-stream sliding window is never
//! negotiated here, so it is intentionally not implemented.

use bytes::Bytes;

pub(super) const HEADER_SIZE: usize = 8;
pub(super) const VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Cmd {
    Syn,
    Fin,
    Psh,
    Nop,
}

impl Cmd {
    fn to_byte(self) -> u8 {
        match self {
            Self::Syn => 0,
            Self::Fin => 1,
            Self::Psh => 2,
            Self::Nop => 3,
        }
    }

    fn from_byte(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Syn),
            1 => Some(Self::Fin),
            2 => Some(Self::Psh),
            3 => Some(Self::Nop),
            _ => None,
        }
    }
}

pub(super) struct Frame {
    pub(super) cmd: Cmd,
    pub(super) sid: u32,
    pub(super) data: Bytes,
}

impl Frame {
    pub(super) fn syn(sid: u32) -> Self {
        Self { cmd: Cmd::Syn, sid, data: Bytes::new() }
    }

    pub(super) fn fin(sid: u32) -> Self {
        Self { cmd: Cmd::Fin, sid, data: Bytes::new() }
    }

    pub(super) fn psh(sid: u32, data: Bytes) -> Self {
        Self { cmd: Cmd::Psh, sid, data }
    }
}

pub(super) fn encode_header(buf: &mut [u8; HEADER_SIZE], cmd: Cmd, sid: u32, len: u16) {
    buf[0] = VERSION;
    buf[1] = cmd.to_byte();
    buf[2..4].copy_from_slice(&len.to_le_bytes());
    buf[4..8].copy_from_slice(&sid.to_le_bytes());
}

pub(super) fn decode_header(buf: [u8; HEADER_SIZE]) -> Option<(Cmd, u32, u16)> {
    if buf[0] != VERSION {
        return None;
    }
    let cmd = Cmd::from_byte(buf[1])?;
    let len = u16::from_le_bytes([buf[2], buf[3]]);
    let sid = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
    Some((cmd, sid, len))
}
