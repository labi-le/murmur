use std::fmt;
use std::sync::Arc;

use uuid::Uuid;

use murmur_common::utils::uuid::new_uuid_v4;
use murmur_constant::adapters::PacketConn as ConstantPacketConn;
use murmur_constant::context::PlainContext;
use murmur_constant::metadata::Metadata;
use murmur_std_compat::net::PacketConn;

pub struct PacketConnContext {
    id: Uuid,
    metadata: Metadata,
    packet_conn: Option<Arc<dyn ConstantPacketConn>>,
}

impl fmt::Debug for PacketConnContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketConnContext")
            .field("id", &self.id)
            .field("metadata", &self.metadata)
            .finish_non_exhaustive()
    }
}

#[must_use]
pub fn new_packet_conn_context(metadata: Metadata) -> PacketConnContext {
    PacketConnContext { id: new_uuid_v4(), metadata, packet_conn: None }
}

impl PacketConnContext {
    /// Installs the packet conn manually.
    pub fn inject_packet_conn(&mut self, pconn: Arc<dyn ConstantPacketConn>) {
        self.packet_conn = Some(pconn);
    }
}

impl PlainContext for PacketConnContext {
    fn id(&self) -> Uuid {
        self.id
    }
}

impl murmur_constant::context::PacketConnContext for PacketConnContext {
    fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    fn metadata_mut(&mut self) -> &mut Metadata {
        &mut self.metadata
    }

    fn packet_conn(&self) -> Option<Arc<dyn PacketConn>> {
        let pconn = self.packet_conn.clone()?;
        let packet_conn: Arc<dyn PacketConn> = pconn;
        Some(packet_conn)
    }
}
