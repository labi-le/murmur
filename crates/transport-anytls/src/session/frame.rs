#![expect(
    clippy::trivially_copy_pass_by_ref,
    reason = "callers borrow the header out of the receive buffer, and taking it by value would copy it per field"
)]

pub(crate) const CMD_WASTE: u8 = 0;
pub(crate) const CMD_SYN: u8 = 1;
pub(crate) const CMD_PSH: u8 = 2;
pub(crate) const CMD_FIN: u8 = 3;
pub(crate) const CMD_SETTINGS: u8 = 4;
pub(crate) const CMD_ALERT: u8 = 5;
pub(crate) const CMD_UPDATE_PADDING_SCHEME: u8 = 6;
pub(crate) const CMD_SYNACK: u8 = 7;
pub(crate) const CMD_HEART_REQUEST: u8 = 8;
pub(crate) const CMD_HEART_RESPONSE: u8 = 9;
pub(crate) const CMD_SERVER_SETTINGS: u8 = 10;

pub(crate) const HEADER_OVER_HEAD_SIZE: usize = 1 + 4 + 2;

/// `frame`, a packet to multiplex into a single connection.
#[derive(Debug, Default, Clone)]
pub(crate) struct Frame {
    pub cmd: u8,
    pub sid: u32,
    pub data: Vec<u8>,
}

pub(crate) const fn new_frame(cmd: u8, sid: u32) -> Frame {
    Frame { cmd, sid, data: Vec::new() }
}

pub(crate) type RawHeader = [u8; HEADER_OVER_HEAD_SIZE];

pub(crate) const fn header_cmd(header: &RawHeader) -> u8 {
    header[0]
}

pub(crate) const fn header_stream_id(header: &RawHeader) -> u32 {
    u32::from_be_bytes([header[1], header[2], header[3], header[4]])
}

pub(crate) const fn header_length(header: &RawHeader) -> u16 {
    u16::from_be_bytes([header[5], header[6]])
}
