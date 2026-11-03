use std::sync::Arc;

use uuid::Uuid;

use murmur_common::shared_conn::SharedConn;
use murmur_common::utils::uuid::uuid_map;
use murmur_common_net::io::{ExtendedStream, Stream, StreamAsOldConn};
use murmur_component_tls::utls::TlsBufferedIncoming;
use murmur_std_compat::net::{Addr, Conn as NetConn, PacketConn as NetPacketConn, UdpAddr};

use super::config_pb::Addons;
use super::conn::new_conn;
use super::packet::PacketConn;
use super::vision::vision::TlsConnCheck;

pub const XRO: &str = "xtls-rprx-origin";
pub const XRD: &str = "xtls-rprx-direct";
pub const XRS: &str = "xtls-rprx-splice";
pub const XRV: &str = "xtls-rprx-vision";

/// The protocol version. The preview version is zero.
pub const VERSION: u8 = 0;

// Command types
pub const COMMAND_TCP: u8 = 1;
pub const COMMAND_UDP: u8 = 2;
pub const COMMAND_MUX: u8 = 3;

// Addr types
pub const ATYP_IPV4: u8 = 1;
pub const ATYP_DOMAIN_NAME: u8 = 2;
pub const ATYP_IPV6: u8 = 3;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DstAddr {
    pub udp: bool,
    pub addr_type: u8,
    pub addr: Vec<u8>,
    pub port: u16,
    /// Whether the destination is muxed.
    pub mux: bool,
}

#[derive(Debug, Clone)]
pub struct Client {
    pub(crate) uuid: Uuid,
    pub addons: Option<Addons>,
}

impl Client {
    pub fn stream_conn(
        &self,
        conn: Box<dyn Stream>,
        tls_check: TlsConnCheck,
        direct_net: Option<SharedConn>,
        buffered_incoming: Option<Arc<dyn TlsBufferedIncoming>>,
        dst: &DstAddr,
    ) -> anyhow::Result<Box<dyn ExtendedStream>> {
        new_conn(conn, tls_check, direct_net, buffered_incoming, self, dst)
    }

    #[must_use]
    pub fn packet_conn(&self, conn: Box<dyn Stream>, r_addr: std::net::SocketAddr) -> Box<dyn NetPacketConn> {
        let conn: Box<dyn NetConn> = Box::new(StreamAsOldConn::new(conn));
        let r_addr: Box<dyn Addr> = Box::new(UdpAddr::from(r_addr));
        Box::new(PacketConn::new(conn, r_addr))
    }
}

pub fn new_client(uuid_str: &str, addons: Option<Addons>) -> anyhow::Result<Client> {
    let uid = uuid_map(uuid_str);

    Ok(Client { uuid: uid, addons })
}
