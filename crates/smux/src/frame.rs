pub(crate) const CMD_SYN: u8 = 0;
pub(crate) const CMD_FIN: u8 = 1;
pub(crate) const CMD_PSH: u8 = 2;
pub(crate) const CMD_NOP: u8 = 3;
pub(crate) const CMD_UPD: u8 = 4;

pub(crate) const SIZE_OF_UPD: usize = 8;

/// The initial peer window.
pub(crate) const INITIAL_PEER_WINDOW: u32 = 262_144;

pub(crate) const HEADER_SIZE: usize = 1 + 1 + 2 + 4;

/// `verify_config` accepts only 1 or 2 and runs before any session exists, so the version
/// always fits in the single header byte.
#[expect(clippy::cast_possible_truncation, reason = "the version is validated to 1 or 2, so one byte holds it")]
#[expect(clippy::cast_sign_loss, reason = "the version is validated to 1 or 2, so the sign is never lost")]
pub(crate) fn version_byte(version: i32) -> u8 {
    version as u8
}

#[derive(Debug, Clone)]
pub(crate) struct Frame {
    pub ver: u8,
    pub cmd: u8,
    pub sid: u32,
    pub data: Vec<u8>,
}

impl Frame {
    pub(crate) fn new(ver: u8, cmd: u8, sid: u32) -> Self {
        Self { ver, cmd, sid, data: Vec::new() }
    }

    pub(crate) fn with_data(ver: u8, cmd: u8, sid: u32, data: Vec<u8>) -> Self {
        Self { ver, cmd, sid, data }
    }
}

pub(crate) fn encode_header(f: &Frame) -> [u8; HEADER_SIZE] {
    let mut h = [0u8; HEADER_SIZE];
    h[0] = f.ver;
    h[1] = f.cmd;
    #[expect(clippy::cast_possible_truncation, reason = "the header length field is 16 bits by definition")]
    let len = f.data.len() as u16;
    h[2..4].copy_from_slice(&len.to_le_bytes());
    h[4..8].copy_from_slice(&f.sid.to_le_bytes());
    h
}

pub(crate) struct RawHeader(pub [u8; HEADER_SIZE]);

impl RawHeader {
    pub(crate) fn version(&self) -> u8 {
        self.0[0]
    }

    pub(crate) fn cmd(&self) -> u8 {
        self.0[1]
    }

    pub(crate) fn length(&self) -> u16 {
        u16::from_le_bytes([self.0[2], self.0[3]])
    }

    pub(crate) fn stream_id(&self) -> u32 {
        u32::from_le_bytes([self.0[4], self.0[5], self.0[6], self.0[7]])
    }
}

pub(crate) struct UpdHeader(pub [u8; SIZE_OF_UPD]);

impl UpdHeader {
    pub(crate) fn encode(consumed: u32, window: u32) -> Self {
        let mut b = [0u8; SIZE_OF_UPD];
        b[0..4].copy_from_slice(&consumed.to_le_bytes());
        b[4..8].copy_from_slice(&window.to_le_bytes());
        Self(b)
    }

    pub(crate) fn consumed(&self) -> u32 {
        u32::from_le_bytes([self.0[0], self.0[1], self.0[2], self.0[3]])
    }

    pub(crate) fn window(&self) -> u32 {
        u32::from_le_bytes([self.0[4], self.0[5], self.0[6], self.0[7]])
    }
}
