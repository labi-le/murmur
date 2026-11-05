use std::sync::Arc;

use anyhow::Result;
use bytes::{Buf as _, BytesMut};

use murmur_common_net::io::Stream;
use murmur_common_net::EnhancePacketConn;

use super::base::Base;
use super::protocol::{register, Protocol, ProtocolList};

/// the `init` registering `origin`.
pub(crate) fn init(list: &mut ProtocolList) {
    register(list, "origin", new_origin, 0);
}
#[derive(Debug, Default)]
pub(crate) struct Origin;

pub(crate) fn new_origin(_b: &Base) -> Box<dyn Protocol> {
    Box::new(Origin)
}

impl Protocol for Origin {
    fn stream_conn(&self, c: Box<dyn Stream>, _iv: &[u8]) -> Box<dyn Stream> {
        c
    }

    fn packet_conn(&self, c: Arc<dyn EnhancePacketConn>) -> Arc<dyn EnhancePacketConn> {
        c
    }

    /// `dst.ReadFrom(src)`.
    fn decode(&mut self, dst: &mut BytesMut, src: &mut BytesMut) -> Result<()> {
        dst.extend_from_slice(&src.copy_to_bytes(src.remaining()));
        Ok(())
    }

    fn encode(&mut self, buf: &mut BytesMut, b: &[u8]) -> Result<()> {
        buf.extend_from_slice(b);
        Ok(())
    }

    fn decode_packet(&mut self, b: &[u8]) -> Result<Vec<u8>> {
        Ok(b.to_vec())
    }

    fn encode_packet(&mut self, buf: &mut BytesMut, b: &[u8]) -> Result<()> {
        buf.extend_from_slice(b);
        Ok(())
    }
}
