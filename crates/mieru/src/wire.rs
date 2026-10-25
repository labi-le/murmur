use std::time::{SystemTime, UNIX_EPOCH};

pub const METADATA_LENGTH: usize = 32;
pub const MAX_SESSION_OPEN_PAYLOAD: usize = 1024;
pub const MAX_PDU: usize = 32768;

#[derive(thiserror::Error, Debug)]
pub enum WireError {
    #[error("metadata is too short: got {0}, want {METADATA_LENGTH}")]
    TooShort(usize),
    #[error("unknown protocol type byte {0}")]
    UnknownProtocol(u8),
    #[error("low-entropy protocol variants are never received on this deployment")]
    LowEntropyUnsupported,
    #[error("timestamp {0} is outside the accepted window around {1}")]
    TimestampOutOfRange(u32, u32),
}

type Result<T, E = WireError> = std::result::Result<T, E>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ProtocolType {
    CloseConnRequest = 0,
    CloseConnResponse = 1,
    OpenSessionRequest = 2,
    OpenSessionResponse = 3,
    CloseSessionRequest = 4,
    CloseSessionResponse = 5,
    DataClientToServer = 6,
    DataServerToClient = 7,
    AckClientToServer = 8,
    AckServerToClient = 9,
}

impl ProtocolType {
    pub fn from_byte(b: u8) -> Result<Self> {
        Ok(match b {
            0 => Self::CloseConnRequest,
            1 => Self::CloseConnResponse,
            2 => Self::OpenSessionRequest,
            3 => Self::OpenSessionResponse,
            4 => Self::CloseSessionRequest,
            5 => Self::CloseSessionResponse,
            6 => Self::DataClientToServer,
            7 => Self::DataServerToClient,
            8 => Self::AckClientToServer,
            9 => Self::AckServerToClient,
            10 | 11 => return Err(WireError::LowEntropyUnsupported),
            other => return Err(WireError::UnknownProtocol(other)),
        })
    }

    #[must_use]
    pub fn is_session_struct(self) -> bool {
        matches!(
            self,
            Self::OpenSessionRequest
                | Self::OpenSessionResponse
                | Self::CloseSessionRequest
                | Self::CloseSessionResponse
        )
    }

    #[must_use]
    pub fn is_client_to_server(self) -> bool {
        matches!(self, Self::DataClientToServer | Self::AckClientToServer)
    }

    #[must_use]
    pub fn is_server_to_client(self) -> bool {
        matches!(self, Self::DataServerToClient | Self::AckServerToClient)
    }
}

/// `unix_seconds / 60` truncated, as the wire's `u32` minute timestamp.
#[must_use]
pub fn now_minutes() -> u32 {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    #[expect(
        clippy::cast_possible_truncation,
        reason = "u32 minutes only wraps after ~8171 years, far beyond any realistic wall clock"
    )]
    let minutes = (secs / 60) as u32;
    minutes
}

#[must_use]
pub fn timestamp_within_range(current: u32, original: u32, delta: u32) -> bool {
    current.abs_diff(original) <= delta
}

pub fn validate_timestamp(timestamp: u32) -> Result<()> {
    let current = now_minutes();
    if timestamp_within_range(current, timestamp, 1) {
        Ok(())
    } else {
        Err(WireError::TimestampOutOfRange(timestamp, current))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct SessionStruct {
    pub protocol: u8,
    pub timestamp: u32,
    pub session_id: u32,
    pub seq: u32,
    pub status_code: u8,
    pub payload_len: u16,
    pub suffix_len: u8,
}

pub const STATUS_OK: u8 = 0;
pub const STATUS_QUOTA_EXHAUSTED: u8 = 1;

impl SessionStruct {
    #[must_use]
    pub fn marshal(&self) -> [u8; METADATA_LENGTH] {
        let mut buf = [0u8; METADATA_LENGTH];
        buf[0] = self.protocol;
        buf[2..6].copy_from_slice(&self.timestamp.to_be_bytes());
        buf[6..10].copy_from_slice(&self.session_id.to_be_bytes());
        buf[10..14].copy_from_slice(&self.seq.to_be_bytes());
        buf[14] = self.status_code;
        buf[15..17].copy_from_slice(&self.payload_len.to_be_bytes());
        buf[17] = self.suffix_len;
        buf
    }

    pub fn unmarshal(buf: &[u8]) -> Result<Self> {
        let meta: &[u8; METADATA_LENGTH] =
            buf.get(..METADATA_LENGTH).and_then(|s| s.try_into().ok()).ok_or(WireError::TooShort(buf.len()))?;
        Ok(Self {
            protocol: meta[0],
            timestamp: u32::from_be_bytes(meta[2..6].try_into().map_err(|_| WireError::TooShort(buf.len()))?),
            session_id: u32::from_be_bytes(meta[6..10].try_into().map_err(|_| WireError::TooShort(buf.len()))?),
            seq: u32::from_be_bytes(meta[10..14].try_into().map_err(|_| WireError::TooShort(buf.len()))?),
            status_code: meta[14],
            payload_len: u16::from_be_bytes(meta[15..17].try_into().map_err(|_| WireError::TooShort(buf.len()))?),
            suffix_len: meta[17],
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct DataAckStruct {
    pub protocol: u8,
    pub timestamp: u32,
    pub session_id: u32,
    pub seq: u32,
    pub un_ack_seq: u32,
    pub window_size: u16,
    pub fragment: u8,
    pub prefix_len: u8,
    pub payload_len: u16,
    pub suffix_len: u8,
}

impl DataAckStruct {
    #[must_use]
    pub fn marshal(&self) -> [u8; METADATA_LENGTH] {
        let mut buf = [0u8; METADATA_LENGTH];
        buf[0] = self.protocol;
        buf[2..6].copy_from_slice(&self.timestamp.to_be_bytes());
        buf[6..10].copy_from_slice(&self.session_id.to_be_bytes());
        buf[10..14].copy_from_slice(&self.seq.to_be_bytes());
        buf[14..18].copy_from_slice(&self.un_ack_seq.to_be_bytes());
        buf[18..20].copy_from_slice(&self.window_size.to_be_bytes());
        buf[20] = self.fragment;
        buf[21] = self.prefix_len;
        buf[22..24].copy_from_slice(&self.payload_len.to_be_bytes());
        buf[24] = self.suffix_len;
        buf
    }

    pub fn unmarshal(buf: &[u8]) -> Result<Self> {
        let meta: &[u8; METADATA_LENGTH] =
            buf.get(..METADATA_LENGTH).and_then(|s| s.try_into().ok()).ok_or(WireError::TooShort(buf.len()))?;
        Ok(Self {
            protocol: meta[0],
            timestamp: u32::from_be_bytes(meta[2..6].try_into().map_err(|_| WireError::TooShort(buf.len()))?),
            session_id: u32::from_be_bytes(meta[6..10].try_into().map_err(|_| WireError::TooShort(buf.len()))?),
            seq: u32::from_be_bytes(meta[10..14].try_into().map_err(|_| WireError::TooShort(buf.len()))?),
            un_ack_seq: u32::from_be_bytes(meta[14..18].try_into().map_err(|_| WireError::TooShort(buf.len()))?),
            window_size: u16::from_be_bytes(meta[18..20].try_into().map_err(|_| WireError::TooShort(buf.len()))?),
            fragment: meta[20],
            prefix_len: meta[21],
            payload_len: u16::from_be_bytes(meta[22..24].try_into().map_err(|_| WireError::TooShort(buf.len()))?),
            suffix_len: meta[24],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_struct_round_trips() {
        let s = SessionStruct {
            protocol: ProtocolType::OpenSessionRequest as u8,
            timestamp: now_minutes(),
            session_id: 0xdead_beef,
            seq: 7,
            status_code: STATUS_OK,
            payload_len: 42,
            suffix_len: 3,
        };
        let buf = s.marshal();
        assert_eq!(buf.len(), METADATA_LENGTH);
        let parsed = SessionStruct::unmarshal(&buf).expect("unmarshal");
        assert_eq!(parsed, s);
    }

    #[test]
    fn data_ack_struct_round_trips() {
        let d = DataAckStruct {
            protocol: ProtocolType::DataClientToServer as u8,
            timestamp: now_minutes(),
            session_id: 1,
            seq: 99,
            un_ack_seq: 50,
            window_size: 128,
            fragment: 2,
            prefix_len: 0,
            payload_len: 1000,
            suffix_len: 0,
        };
        let buf = d.marshal();
        let parsed = DataAckStruct::unmarshal(&buf).expect("unmarshal");
        assert_eq!(parsed, d);
    }

    #[test]
    fn timestamp_validation_window() {
        let now = now_minutes();
        assert!(validate_timestamp(now).is_ok());
        assert!(validate_timestamp(now.wrapping_sub(1)).is_ok());
        assert!(validate_timestamp(now.wrapping_add(1)).is_ok());
        assert!(validate_timestamp(now.wrapping_add(5)).is_err());
    }

    #[test]
    fn low_entropy_protocol_bytes_are_rejected() {
        assert!(matches!(ProtocolType::from_byte(10), Err(WireError::LowEntropyUnsupported)));
        assert!(matches!(ProtocolType::from_byte(11), Err(WireError::LowEntropyUnsupported)));
    }
}
