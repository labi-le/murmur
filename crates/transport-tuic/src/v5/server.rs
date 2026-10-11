use std::collections::HashMap;
use std::sync::{Arc, Once};

use tokio_util::sync::CancellationToken;

use crate::quic::Conn as QuicConn;
use crate::types;
use murmur_adapter_inbound::addition::{with_in_user, Addition};
use murmur_common::atomic::type_::Bool as AtomicBoolValue;
use murmur_common::atomic::value::TypedValue;
use murmur_common::xsync;
use murmur_common_net::bufconn::{BufferedConn, BufioReader};
use murmur_common_net::io::Datagram;
use murmur_constant::adapters::{UDPPacket, WriteBack};
use murmur_std_compat::net::Conn as NetConn;
use murmur_transport::socks5::socks5 as socks5_pkg;

use super::packet::QuicStreamPacketConn;
use super::protocol;

/// Takes the accepted stream's conn by value: the stream handler hands that conn to the callback
/// and never touches it again.
pub type HandleTcpFn = Arc<dyn Fn(Box<dyn NetConn>, socks5_pkg::Addr, &[Addition]) -> anyhow::Result<()> + Send + Sync>;

pub type HandleUdpFn =
    Arc<dyn Fn(socks5_pkg::Addr, Arc<dyn UDPPacket>, &[Addition]) -> anyhow::Result<()> + Send + Sync>;

pub struct ServerOption {
    pub handle_tcp_fn: HandleTcpFn,
    pub handle_udp_fn: HandleUdpFn,

    pub users: HashMap<[u8; 16], String>,
    pub max_udp_relay_packet_size: usize,
}

/// Redacts the user password map, reporting only how many users are configured.
impl core::fmt::Debug for ServerOption {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ServerOption")
            .field("users", &self.users.len())
            .field("max_udp_relay_packet_size", &self.max_udp_relay_packet_size)
            .finish_non_exhaustive()
    }
}

struct ServerHandlerImpl {
    option: ServerOption,
    quic_conn: Arc<dyn QuicConn>,
    uuid: uuid::Uuid,

    /// Closed once to broadcast authentication: `cancel()` is the close, `cancelled()` the wait.
    auth_ch: CancellationToken,
    auth_ok: AtomicBoolValue,
    auth_uuid: TypedValue<String>,
    auth_once: Once,

    udp_input_map: xsync::map::Map<u16, Arc<ServerUdpInput>>,
}

#[derive(Default)]
struct ServerUdpInput {
    write_closed: Arc<AtomicBoolValue>,
    de_fragger: super::frag::DeFragger,
}

impl ServerHandlerImpl {
    async fn parse_packet(
        &self,
        packet: protocol::Packet,
        udp_relay_mode: types::type_::UdpRelayMode,
    ) -> anyhow::Result<()> {
        self.auth_ch.cancelled().await;
        if !self.auth_ok.load() {
            return Ok(());
        }
        let assoc_id = packet.assoc_id;

        let (input, _) = self.udp_input_map.load_or_store_fn(assoc_id, || Arc::new(ServerUdpInput::default()));
        if input.write_closed.load() {
            return Ok(());
        }
        let Some(packet) = input.de_fragger.feed(packet) else {
            return Ok(());
        };

        let pc = QuicStreamPacketConn::new(
            assoc_id,
            Arc::clone(&self.quic_conn),
            None,
            udp_relay_mode,
            self.option.max_udp_relay_packet_size,
            None,
            None,
            Some(Arc::clone(&input.write_closed)),
        );

        let socks_addr = packet.addr.socks_addr();
        let r_addr = murmur_common_net::io::old_addr_to_socket_addr(self.quic_conn.remote_addr().as_ref())?;
        let nat_key = format!("tuic-{}-{assoc_id}", self.uuid);
        let udp_packet: Arc<dyn UDPPacket> = Arc::new(ServerUdpPacket { pc, data: packet.data, r_addr, nat_key });
        let additions = [with_in_user(&self.auth_uuid.load())];
        (self.option.handle_udp_fn)(socks_addr, udp_packet, &additions)
    }
}

#[async_trait::async_trait]
impl types::type_::ServerHandler for ServerHandlerImpl {
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
            return conn.close().map_err(Into::into);
        }

        let additions = [with_in_user(&self.auth_uuid.load())];
        (self.option.handle_tcp_fn)(Box::new(conn), connect.addr.socks_addr(), &additions)
    }

    async fn handle_message(&self, message: &[u8]) -> anyhow::Result<()> {
        let mut reader = std::io::Cursor::new(message);
        let command_head = protocol::read_command_head(&mut reader).await?;
        match command_head.type_ {
            protocol::CommandType::PACKET_TYPE => {
                let packet = protocol::read_packet_with_head(command_head, &mut reader).await?;
                self.parse_packet(packet, types::type_::UdpRelayMode::NATIVE).await
            }
            protocol::CommandType::HEARTBEAT_TYPE => {
                let heartbeat = protocol::read_heartbeat_with_head(command_head)?;
                let _ = heartbeat.bytes_len();
                Ok(())
            }
            _ => Ok(()),
        }
    }

    /// The uni-stream handler. A reader that lazily pulls more bytes
    /// from the quic receive stream as needed would be ideal; this crate's [`BufioReader`] carries
    /// no conn of its own (see its doc comment), so the caller is expected to have already filled it
    /// with the whole uni-stream message before calling in. Parsing runs against a `Cursor` over the
    /// already-buffered bytes and the read position is advanced by however much that parse consumed.
    async fn handle_uni_stream(&self, reader: &mut BufioReader) -> anyhow::Result<()> {
        let data = reader.buffered_bytes().to_vec();
        let mut cursor = std::io::Cursor::new(data.as_slice());
        let result = self.handle_uni_stream_inner(&mut cursor).await;
        #[expect(
            clippy::cast_possible_truncation,
            reason = "the cursor is positioned inside `data`, whose length is already a `usize`, so the position always fits"
        )]
        let consumed = cursor.position() as usize;
        reader.r += consumed;
        result
    }
}

impl ServerHandlerImpl {
    async fn handle_uni_stream_inner(&self, cursor: &mut std::io::Cursor<&[u8]>) -> anyhow::Result<()> {
        let command_head = protocol::read_command_head(cursor).await?;
        match command_head.type_ {
            protocol::CommandType::AUTHENTICATE_TYPE => {
                let authenticate = protocol::read_authenticate_with_head(command_head, cursor).await?;
                let mut auth_ok = false;
                let mut auth_uuid = uuid::Uuid::nil();
                if let Some(password) = self.option.users.get(&authenticate.uuid) {
                    let token = protocol::gen_token(self.quic_conn.as_ref(), authenticate.uuid, password)?;
                    if token == authenticate.token {
                        auth_ok = true;
                        auth_uuid = uuid::Uuid::from_bytes(authenticate.uuid);
                    }
                }
                self.auth_once.call_once(|| {
                    if !auth_ok {
                        let _ =
                            self.quic_conn.close_with_error(protocol::AUTHENTICATION_FAILED, "AuthenticationFailed");
                    }
                    self.auth_ok.store(auth_ok);
                    self.auth_uuid.store(auth_uuid.to_string());
                    self.auth_ch.cancel();
                });
                Ok(())
            }
            protocol::CommandType::PACKET_TYPE => {
                let packet = protocol::read_packet_with_head(command_head, cursor).await?;
                self.parse_packet(packet, types::type_::UdpRelayMode::QUIC).await
            }
            protocol::CommandType::DISSOCIATE_TYPE => {
                let dissociate = protocol::read_dissociate_with_head(command_head, cursor).await?;
                if let (Some(input), true) = self.udp_input_map.load_and_delete(&dissociate.assoc_id) {
                    input.write_closed.store(true);
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

struct ServerUdpPacket {
    pc: Arc<QuicStreamPacketConn>,
    /// The payload. A `Drop` that cleared it would let the backing array be collected slightly
    /// earlier, but `bytes::Bytes` is already reference counted and this struct is its only owner
    /// once constructed, so `Drop` is a no-op here: the lifetime is the same.
    data: bytes::Bytes,
    r_addr: std::net::SocketAddr,
    /// The per-association NAT key, kept apart from `r_addr` (the real peer socket every
    /// association on one QUIC conn shares) so the tunnel's NAT table sees distinct entries.
    nat_key: String,
}

impl UDPPacket for ServerUdpPacket {
    fn data(&self) -> &[u8] {
        &self.data
    }

    fn drop_(&self) {}

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

#[async_trait::async_trait]
impl WriteBack for ServerUdpPacket {
    async fn write_back(&self, b: &[u8], addr: Option<std::net::SocketAddr>) -> anyhow::Result<usize> {
        let Some(addr) = addr else {
            anyhow::bail!("tuic v5: WriteBack called without an address");
        };
        self.pc.send_to(b, addr).await.map_err(Into::into)
    }
}

pub fn new_server_handler(
    option: ServerOption,
    quic_conn: Arc<dyn QuicConn>,
    uuid: uuid::Uuid,
) -> Arc<dyn types::type_::ServerHandler> {
    Arc::new(ServerHandlerImpl {
        option,
        quic_conn,
        uuid,
        auth_ch: CancellationToken::new(),
        auth_ok: AtomicBoolValue::default(),
        auth_uuid: TypedValue::default(),
        auth_once: Once::new(),
        udp_input_map: xsync::map::Map::default(),
    })
}

#[cfg(test)]
mod nat_key_tests {
    use std::net::SocketAddr;

    use bytes::Bytes;
    use parking_lot::Mutex as StdMutex;

    use super::*;

    #[derive(Debug)]
    struct FakeAddr(SocketAddr);

    impl murmur_std_compat::net::Addr for FakeAddr {
        fn network(&self) -> &str {
            "udp"
        }

        fn string(&self) -> String {
            self.0.to_string()
        }
    }

    struct FakeQuicConn(SocketAddr);

    #[async_trait::async_trait]
    impl QuicConn for FakeQuicConn {
        fn local_addr(&self) -> Box<dyn murmur_std_compat::net::Addr> {
            Box::new(FakeAddr(self.0))
        }

        fn remote_addr(&self) -> Box<dyn murmur_std_compat::net::Addr> {
            Box::new(FakeAddr(self.0))
        }

        fn close_with_error(&self, _code: protocol::ApplicationErrorCode, _reason: &str) -> anyhow::Result<()> {
            Ok(())
        }

        fn config(&self) -> murmur_quic::Config {
            murmur_quic::Config::default()
        }

        fn connection_stats(&self) -> murmur_quic::ConnectionStats {
            murmur_quic::ConnectionStats::default()
        }

        fn connection_state(&self) -> murmur_quic::ConnectionState {
            murmur_quic::ConnectionState::default()
        }

        fn context(&self) -> CancellationToken {
            CancellationToken::new()
        }

        async fn handshake_complete(&self) {}

        fn export_keying_material(&self, _label: &[u8], _context: &[u8], _length: usize) -> anyhow::Result<Vec<u8>> {
            anyhow::bail!("not exercised by the nat_key test path")
        }

        async fn open_stream(&self, _ctx: &CancellationToken) -> anyhow::Result<Box<dyn murmur_quic::Stream>> {
            anyhow::bail!("not exercised by the nat_key test path")
        }

        async fn open_uni_stream(&self, _ctx: &CancellationToken) -> anyhow::Result<Box<dyn murmur_quic::SendStream>> {
            anyhow::bail!("not exercised by the nat_key test path")
        }

        async fn accept_stream(&self, _ctx: &CancellationToken) -> anyhow::Result<Box<dyn murmur_quic::Stream>> {
            anyhow::bail!("not exercised by the nat_key test path")
        }

        async fn accept_uni_stream(
            &self,
            _ctx: &CancellationToken,
        ) -> anyhow::Result<Box<dyn murmur_quic::ReceiveStream>> {
            anyhow::bail!("not exercised by the nat_key test path")
        }

        fn send_datagram(&self, _data: &[u8]) -> anyhow::Result<()> {
            anyhow::bail!("not exercised by the nat_key test path")
        }

        async fn receive_datagram(&self, _ctx: &CancellationToken) -> anyhow::Result<Vec<u8>> {
            anyhow::bail!("not exercised by the nat_key test path")
        }
    }

    /// Two associations (`assoc_id`s `1` and `2`) sharing one simulated QUIC connection/peer
    /// socket must still key their `ServerUdpPacket`s distinctly, matching the
    /// The per-association NAT key.
    #[tokio::test]
    async fn nat_key_differs_across_associations_sharing_one_quic_conn() {
        let remote: SocketAddr = "198.51.100.7:9".parse().unwrap();
        let quic_conn: Arc<dyn QuicConn> = Arc::new(FakeQuicConn(remote));
        let uuid = uuid::Uuid::new_v4();
        let seen: Arc<StdMutex<Vec<(SocketAddr, String)>>> = Arc::new(StdMutex::new(Vec::new()));
        let seen_for_closure = Arc::clone(&seen);

        let auth_ch = CancellationToken::new();
        auth_ch.cancel();
        let handler = ServerHandlerImpl {
            option: ServerOption {
                handle_tcp_fn: Arc::new(|_conn, _addr, _additions| {
                    anyhow::bail!("tcp not exercised by the nat_key test path")
                }),
                handle_udp_fn: Arc::new(move |_addr, packet, _additions| {
                    seen_for_closure.lock().push((packet.local_addr(), packet.nat_key()));
                    Ok(())
                }),
                users: HashMap::new(),
                max_udp_relay_packet_size: 1500,
            },
            quic_conn,
            uuid,
            auth_ch,
            auth_ok: murmur_common::atomic::type_::new_bool(true),
            auth_uuid: TypedValue::default(),
            auth_once: Once::new(),
            udp_input_map: xsync::map::Map::default(),
        };

        let addr = protocol::new_address_addr_port(remote);
        let packet_one = protocol::new_packet(1, 0, 1, 0, 3, addr.clone(), Bytes::from_static(b"one"));
        let packet_two = protocol::new_packet(2, 0, 1, 0, 3, addr, Bytes::from_static(b"two"));

        handler.parse_packet(packet_one, types::type_::UdpRelayMode::QUIC).await.expect("parse_packet one");
        handler.parse_packet(packet_two, types::type_::UdpRelayMode::QUIC).await.expect("parse_packet two");

        let seen = seen.lock();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].0, remote);
        assert_eq!(seen[1].0, remote);
        assert_ne!(seen[0].1, seen[1].1, "two associations sharing one QUIC connection/peer must not share a NAT key");
    }
}
