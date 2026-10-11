use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Once};

use async_trait::async_trait;
use bytes::Bytes;
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::types::type_ as types;
use murmur_adapter_inbound::addition::Addition;
use murmur_common::atomic::type_::Bool as AtomicBool2;
use murmur_common::xsync::map::Map;
use murmur_common_net::bufconn::BufferedConn;
use murmur_common_net::io::Datagram;
use murmur_common_pool as pool;
use murmur_constant::adapters::{UDPPacket, WriteBack};
use murmur_quic::ReceiveStream;
use murmur_std_compat::net::Conn;
use murmur_transport::socks5::socks5 as socks5_mod;
use subtle::ConstantTimeEq as _;

use super::packet;
use super::protocol;
use crate::quic::Conn as QuicConn;

/// Takes the accepted stream's conn by value: the stream handler hands that conn to the callback
/// and never touches it again.
pub type HandleTcpFn = Arc<dyn Fn(Box<dyn Conn>, socks5_mod::Addr, &[Addition]) -> anyhow::Result<()> + Send + Sync>;
pub type HandleUdpFn =
    Arc<dyn Fn(socks5_mod::Addr, Box<dyn UDPPacket>, &[Addition]) -> anyhow::Result<()> + Send + Sync>;

/// Compares against every configured token without an early return, so neither the position of a
/// match nor the first differing byte is visible through timing (`==` on arrays is `memcmp`).
fn tokens_match(tokens: &[[u8; 32]], candidate: &[u8; 32]) -> bool {
    tokens.iter().fold(false, |acc, tkn| acc | bool::from(tkn.ct_eq(candidate)))
}

pub struct ServerOption {
    pub handle_tcp_fn: HandleTcpFn,
    pub handle_udp_fn: HandleUdpFn,

    pub tokens: Vec<[u8; 32]>,
    pub max_udp_relay_packet_size: usize,
}

/// Redacts the V4 token list, reporting only how many tokens are configured.
impl core::fmt::Debug for ServerOption {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ServerOption")
            .field("tokens", &self.tokens.len())
            .field("max_udp_relay_packet_size", &self.max_udp_relay_packet_size)
            .finish_non_exhaustive()
    }
}

pub(crate) struct ServerHandlerImpl {
    option: Arc<ServerOption>,
    quic_conn: Arc<dyn QuicConn>,
    uuid: Uuid,

    /// Closed once by the timeout handler or the authenticate branch
    /// of the uni-stream handler: a `CancellationToken` gives the same "broadcast once, every
    /// waiter (current and future) unblocks" semantics as a closed channel.
    auth_ch: CancellationToken,
    auth_ok: AtomicBool2,
    auth_once: Once,

    udp_input_map: Map<u32, Arc<AtomicBool2>>,
}

pub fn new_server_handler(
    option: Arc<ServerOption>,
    quic_conn: Arc<dyn QuicConn>,
    uuid: Uuid,
) -> Arc<dyn types::ServerHandler> {
    Arc::new(ServerHandlerImpl {
        option,
        quic_conn,
        uuid,
        auth_ch: CancellationToken::new(),
        auth_ok: AtomicBool2::default(),
        auth_once: Once::new(),
        udp_input_map: Map::default(),
    })
}

impl ServerHandlerImpl {
    async fn parse_packet(&self, packet: &protocol::Packet, udp_relay_mode: types::UdpRelayMode) -> anyhow::Result<()> {
        self.auth_ch.cancelled().await;
        if !self.auth_ok.load() {
            return Ok(());
        }
        let assoc_id = packet.assoc_id;

        let (write_closed, _loaded) =
            self.udp_input_map.load_or_store_fn(assoc_id, || Arc::new(AtomicBool2::default()));
        if write_closed.load() {
            return Ok(());
        }

        let pc = Arc::new(packet::new_quic_stream_packet_conn(
            assoc_id,
            Arc::clone(&self.quic_conn),
            None,
            udp_relay_mode,
            self.option.max_udp_relay_packet_size,
            None,
            None,
            Some(write_closed),
        ));

        let r_addr = murmur_common_net::io::old_addr_to_socket_addr(self.quic_conn.remote_addr().as_ref())?;
        let udp_packet: Box<dyn UDPPacket> =
            Box::new(ServerUdpPacket::new(pc, packet.data.clone(), r_addr, format!("tuic-{}-{assoc_id}", self.uuid)));
        (self.option.handle_udp_fn)(packet.addr.socks_addr(), udp_packet, &[])
    }
}

#[async_trait]
impl types::ServerHandler for ServerHandlerImpl {
    fn auth_ok(&self) -> bool {
        self.auth_ok.load()
    }

    fn handle_timeout(&self) {
        self.auth_once.call_once(|| {
            let _ = self.quic_conn.close_with_error(protocol::AUTHENTICATION_TIMEOUT, "AuthenticationTimeout");
            self.auth_ok.store(false);
            self.auth_ch.cancel();
        });
    }

    async fn handle_message(&self, message: &[u8]) -> anyhow::Result<()> {
        let mut reader = protocol::SliceReader::new(message);
        let packet = protocol::read_packet(&mut reader).await?;
        self.parse_packet(&packet, types::UdpRelayMode::NATIVE).await
    }

    async fn handle_stream(&self, conn: BufferedConn) -> anyhow::Result<()> {
        let mut conn = conn;
        let connect = match protocol::read_connect(&mut conn).await {
            Ok(connect) => connect,
            Err(err) => {
                let _ = conn.close();
                return Err(err);
            }
        };
        self.auth_ch.cancelled().await;
        if !self.auth_ok.load() {
            return conn.close().map_err(anyhow::Error::from);
        }

        // The conn is handed to `HandleTcpFn`, which writes the response to that same conn
        // afterwards; handing over ownership here means the response has to be written first.
        // Both reach the client as the first bytes on the stream, in that order.
        let mut buf = pool::get_buffer();
        if let Err(err) = protocol::new_response_succeed().write_to(&mut buf) {
            pool::put_buffer(buf);
            return Err(err.into());
        }
        let write_result = conn.write_all(&buf).await;
        pool::put_buffer(buf);
        if let Err(err) = write_result {
            let _ = conn.close();
            return Err(err.into());
        }
        (self.option.handle_tcp_fn)(Box::new(conn), connect.addr.socks_addr(), &[])
    }

    async fn handle_uni_stream(&self, version: u8, stream: &mut dyn ReceiveStream) -> anyhow::Result<()> {
        let command_head = protocol::read_command_head_after_ver(version, stream).await?;
        match command_head.type_ {
            protocol::CommandType::AUTHENTICATE_TYPE => {
                let authenticate = protocol::read_authenticate_with_head(command_head, stream).await?;
                let auth_ok = tokens_match(&self.option.tokens, &authenticate.tkn);
                self.auth_once.call_once(|| {
                    if !auth_ok {
                        let _ =
                            self.quic_conn.close_with_error(protocol::AUTHENTICATION_FAILED, "AuthenticationFailed");
                    }
                    self.auth_ok.store(auth_ok);
                    self.auth_ch.cancel();
                });
            }
            protocol::CommandType::PACKET_TYPE => {
                let packet = protocol::read_packet_with_head(command_head, stream).await?;
                return self.parse_packet(&packet, types::UdpRelayMode::QUIC).await;
            }
            protocol::CommandType::DISSOCIATE_TYPE => {
                let dissociate = protocol::read_dissociate_with_head(command_head, stream).await?;
                let (write_closed, loaded) = self.udp_input_map.load_and_delete(&dissociate.assoc_id);
                if loaded {
                    if let Some(write_closed) = write_closed {
                        write_closed.store(true);
                    }
                }
            }
            protocol::CommandType::HEARTBEAT_TYPE => {
                let heartbeat = protocol::read_heartbeat_with_head(command_head)?;
                let _ = heartbeat.bytes_len();
            }
            _ => {}
        }
        Ok(())
    }
}

/// The payload plus an atomic visible length truncated to zero on drop, so `data()` can hand back
/// `&[u8]` borrowed from `&self` without a lock guard in the way.
pub(crate) struct ServerUdpPacket {
    pc: Arc<packet::QuicStreamPacketConn>,
    data: Bytes,
    len: AtomicUsize,
    r_addr: std::net::SocketAddr,
    /// The per-association NAT key, kept apart from `r_addr` (the real peer socket every
    /// association on one QUIC conn shares) so the tunnel's NAT table sees distinct entries.
    nat_key: String,
}

impl ServerUdpPacket {
    fn new(pc: Arc<packet::QuicStreamPacketConn>, data: Bytes, r_addr: std::net::SocketAddr, nat_key: String) -> Self {
        let len = data.len();
        Self { pc, data, len: AtomicUsize::new(len), r_addr, nat_key }
    }
}

#[async_trait]
impl WriteBack for ServerUdpPacket {
    async fn write_back(&self, b: &[u8], addr: Option<std::net::SocketAddr>) -> anyhow::Result<usize> {
        match addr {
            Some(addr) => self.pc.send_to(b, addr).await.map_err(Into::into),
            None => Err(anyhow::anyhow!("tuic: WriteBack requires an address")),
        }
    }
}

impl UDPPacket for ServerUdpPacket {
    fn data(&self) -> &[u8] {
        let visible = self.len.load(Ordering::Acquire).min(self.data.len());
        self.data.get(..visible).unwrap_or_default()
    }

    fn drop_(&self) {
        self.len.store(0, Ordering::Release);
    }

    fn local_addr(&self) -> std::net::SocketAddr {
        self.r_addr
    }

    fn in_addr(&self) -> Option<std::net::SocketAddr> {
        self.pc.local_addr().ok()
    }

    /// The NAT key — see the `nat_key` field doc.
    fn nat_key(&self) -> String {
        self.nat_key.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::tokens_match;

    #[test]
    fn only_a_configured_token_authenticates() {
        let tkn = [0x11u8; 32];
        let other = [0x22u8; 32];
        let mut near_miss = tkn;
        near_miss[31] = 0x12;

        assert!(tokens_match(&[tkn], &tkn));
        assert!(tokens_match(&[other, tkn], &tkn), "a token matching in any position counts");
        assert!(!tokens_match(&[], &tkn), "no configured token authenticates nobody");
        assert!(!tokens_match(&[other], &tkn));
        assert!(!tokens_match(&[near_miss], &tkn), "a token differing in its last byte must not authenticate");
        assert!(!tokens_match(&[other, near_miss], &tkn));
    }
}
