use std::io;

use crate::error::{err_invalid_msg_type, err_invalid_version};

pub(crate) const PROTO_VERSION: u8 = 0;

pub(crate) const TYPE_DATA: u8 = 0;
pub(crate) const TYPE_WINDOW_UPDATE: u8 = 1;
pub(crate) const TYPE_PING: u8 = 2;
pub(crate) const TYPE_GO_AWAY: u8 = 3;

pub(crate) const FLAG_SYN: u16 = 1;
pub(crate) const FLAG_ACK: u16 = 2;
pub(crate) const FLAG_FIN: u16 = 4;
pub(crate) const FLAG_RST: u16 = 8;

pub(crate) const INITIAL_STREAM_WINDOW: u32 = 256 * 1024;
pub(crate) const MAX_STREAM_WINDOW: u32 = 16 * 1024 * 1024;

pub(crate) const GO_AWAY_NORMAL: u32 = 0;
pub(crate) const GO_AWAY_PROTO_ERR: u32 = 1;
#[allow(dead_code)]
pub(crate) const GO_AWAY_INTERNAL_ERR: u32 = 2;

pub(crate) const HEADER_SIZE: usize = 12;

#[derive(Clone, Copy, Debug)]
pub struct Header {
    pub msg_type: u8,
    pub flags: u16,
    pub stream_id: u32,
    pub length: u32,
}

impl Header {
    pub fn encode(msg_type: u8, flags: u16, stream_id: u32, length: u32) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf[0] = PROTO_VERSION;
        buf[1] = msg_type;
        buf[2..4].copy_from_slice(&flags.to_be_bytes());
        buf[4..8].copy_from_slice(&stream_id.to_be_bytes());
        buf[8..12].copy_from_slice(&length.to_be_bytes());
        buf
    }

    pub fn decode(buf: &[u8; HEADER_SIZE]) -> io::Result<Self> {
        if buf[0] != PROTO_VERSION {
            return Err(err_invalid_version());
        }
        let msg_type = buf[1];
        if msg_type > TYPE_GO_AWAY {
            return Err(err_invalid_msg_type());
        }
        Ok(Self {
            msg_type,
            flags: u16::from_be_bytes([buf[2], buf[3]]),
            stream_id: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
            length: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
        })
    }
}
