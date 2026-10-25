use std::sync::Arc;

use sha2::{Digest, Sha256};

use super::auth::{new_simple_authenticator, Aead, GcmAead};
use super::header::{new_packet_header, PacketHeader};

#[derive(Debug, Clone, Default)]
pub struct Config {
    pub mtu: u32,
    pub tti: u32,
    pub uplink_capacity: u32,
    pub downlink_capacity: u32,
    pub congestion: bool,
    pub write_buffer: u32,
    pub read_buffer: u32,
    pub seed: String,
    pub header: String,
}

impl Config {
    pub(crate) const fn mtu(&self) -> u32 {
        if self.mtu == 0 {
            return 1350;
        }
        self.mtu
    }

    pub(crate) const fn tti(&self) -> u32 {
        if self.tti == 0 {
            return 50;
        }
        self.tti
    }

    pub(crate) const fn uplink_capacity(&self) -> u32 {
        if self.uplink_capacity == 0 {
            return 5;
        }
        self.uplink_capacity
    }

    pub(crate) const fn downlink_capacity(&self) -> u32 {
        if self.downlink_capacity == 0 {
            return 20;
        }
        self.downlink_capacity
    }

    pub(crate) const fn write_buffer(&self) -> u32 {
        if self.write_buffer == 0 {
            return 2 * 1024 * 1024;
        }
        self.write_buffer
    }

    pub(crate) fn sending_in_flight_size(&self) -> u32 {
        let mut size = self.uplink_capacity() * 1024 * 1024 / self.mtu() / (1000 / self.tti());
        if size < 8 {
            size = 8;
        }
        size
    }

    pub(crate) fn receiving_in_flight_size(&self) -> u32 {
        let mut size = self.downlink_capacity() * 1024 * 1024 / self.mtu() / (1000 / self.tti());
        if size < 8 {
            size = 8;
        }
        size
    }

    pub(crate) fn sending_buffer_size(&self) -> u32 {
        self.write_buffer() / self.mtu()
    }

    pub(crate) fn security(&self) -> anyhow::Result<Arc<dyn Aead>> {
        if self.seed.is_empty() {
            return Ok(new_simple_authenticator());
        }
        let hashed_seed = Sha256::digest(self.seed.as_bytes());
        let (key, _) = hashed_seed.split_at(16);
        Ok(Arc::new(GcmAead::new(key)?))
    }

    pub(crate) fn packet_header(&self) -> Box<dyn PacketHeader> {
        new_packet_header(&self.header)
    }
}
