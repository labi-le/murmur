use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use parking_lot::Mutex;

use crate::inbound::auth::AuthUsers;
use crate::inbound::base::{config_equal, option_to_string, upcast_config, Base, BaseOption};
use crate::trusttunnel::server as trusttunnel_server;
use murmur_constant::listener::{InboundConfig, InboundListener, MultiAddrListener};
use murmur_constant::tunnel::Tunnel;
use murmur_listener_config::trusttunnel as lc_trusttunnel;
use murmur_log::infoln;

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct TrustTunnelOption {
    pub base: BaseOption,
    pub users: AuthUsers,
    pub certificate: String,
    pub private_key: String,
    pub client_auth_type: String,
    pub client_auth_cert: String,
    pub ech_key: String,
    pub network: Vec<String>,
    pub congestion_controller: String,
    pub cwnd: i32,
    pub bbr_profile: String,
}

impl InboundConfig for TrustTunnelOption {
    fn name(&self) -> String {
        self.base.name()
    }

    fn equal(&self, config: &dyn InboundConfig) -> bool {
        config_equal(self, config)
    }

    fn option_to_string(&self) -> String {
        option_to_string(self)
    }
}

pub struct TrustTunnel {
    base: Base,
    config: Arc<TrustTunnelOption>,
    l: Mutex<Option<Arc<dyn MultiAddrListener>>>,
    vs: lc_trusttunnel::TrustTunnelServer,
}

impl core::fmt::Debug for TrustTunnel {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TrustTunnel").field("config", &self.config).finish_non_exhaustive()
    }
}

impl TrustTunnel {
    pub fn new(options: Arc<TrustTunnelOption>) -> Result<Self> {
        let base = Base::new(Arc::new(options.base.clone()))?;
        let mut users = BTreeMap::new();
        if let Some(option_users) = &options.users {
            for user in option_users {
                users.insert(user.username.clone(), user.password.clone());
            }
        }
        let vs = lc_trusttunnel::TrustTunnelServer {
            enable: true,
            listen: base.raw_address(),
            users,
            certificate: options.certificate.clone(),
            private_key: options.private_key.clone(),
            client_auth_type: options.client_auth_type.clone(),
            client_auth_cert: options.client_auth_cert.clone(),
            ech_key: options.ech_key.clone(),
            network: options.network.clone(),
            congestion_controller: options.congestion_controller.clone(),
            cwnd: options.cwnd,
            bbr_profile: options.bbr_profile.clone(),
        };
        Ok(Self { base, config: options, l: Mutex::new(None), vs })
    }
}

#[async_trait]
impl InboundListener for TrustTunnel {
    fn name(&self) -> String {
        self.config.name()
    }

    async fn listen(&self, tunnel: Arc<dyn Tunnel>) -> Result<()> {
        let listener: Arc<dyn MultiAddrListener> = Arc::new(
            trusttunnel_server::new(self.vs.clone(), self.base.listen_config(), tunnel, &self.base.additions()).await?,
        );
        *self.l.lock() = Some(listener);
        infoln!("TrustTunnel[{}] proxy listening at: {}", self.name(), self.address());
        Ok(())
    }

    fn close(&self) -> Result<()> {
        self.l.lock().as_ref().map_or(Ok(()), |l| l.close())
    }

    fn address(&self) -> String {
        let addr_list: Vec<String> =
            self.l.lock().as_ref().map(|l| l.addr_list().iter().map(|a| a.string()).collect()).unwrap_or_default();
        addr_list.join(",")
    }

    fn raw_address(&self) -> String {
        self.base.raw_address()
    }

    fn config(&self) -> Arc<dyn InboundConfig> {
        upcast_config(Arc::clone(&self.config))
    }
}

#[cfg(test)]
mod tests {

    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;
    use crate::inbound::auth::AuthUser;
    use murmur_adapter_outbound::ech::ECHOptions;
    use murmur_adapter_outbound::trusttunnel::{
        TrustTunnel as OutTrustTunnel, TrustTunnelOption as OutTrustTunnelOption,
    };
    use murmur_component_nat::table::Table;
    use murmur_constant::adapters::{NatTable, PacketConn as CPacketConn, ProxyAdapter as CProxyAdapter, UDPPacket};
    use murmur_constant::metadata::{Metadata, NetWork};
    use murmur_std_compat::net::{Addr, UdpAddr};
    use murmur_testsupport::{
        ech_config_base64, ech_key_pem, tls_auth_certificate, tls_auth_private_key, tls_certificate, tls_fingerprint,
        tls_private_key, HttpTestTunnel, USER_UUID,
    };
    use murmur_testsupport_probe::ensure_test_crypto_provider;
    use tokio_util::sync::CancellationToken;

    async fn test_inbound_trust_tunnel(inbound_options: TrustTunnelOption, mut outbound_options: OutTrustTunnelOption) {
        ensure_test_crypto_provider();
        let inbound_options = TrustTunnelOption {
            base: BaseOption {
                name_str: "trusttunnel_inbound".to_owned(),
                listen: "127.0.0.1".to_owned(),
                port: "0".to_owned(),
                ..Default::default()
            },
            users: Some(vec![AuthUser { username: "test".to_owned(), password: USER_UUID.clone() }]),
            ..inbound_options
        };
        let inbound = TrustTunnel::new(Arc::new(inbound_options)).expect("trusttunnel inbound construction");

        let tunnel = HttpTestTunnel::new();
        let listener_tunnel = Arc::clone(&tunnel);
        inbound.listen(listener_tunnel).await.expect("trusttunnel inbound listen");

        let addr_port: SocketAddr = inbound.address().parse().expect("bound address");

        outbound_options.name = "trusttunnel_outbound".to_owned();
        outbound_options.server = addr_port.ip().to_string();
        outbound_options.port = i32::from(addr_port.port());
        outbound_options.user_name = "test".to_owned();
        outbound_options.password = USER_UUID.clone();
        outbound_options.basic_option.dialer_for_api = Some(tunnel.new_dialer());
        let api_tunnel = Arc::clone(&tunnel);
        outbound_options.basic_option.tunnel_for_api = Some(api_tunnel);

        let out = OutTrustTunnel::new(outbound_options).expect("trusttunnel outbound construction");

        tunnel.do_test(out.as_ref()).await;

        let _ = out.close();
        inbound.close().expect("trusttunnel inbound close");
        tunnel.close();
    }

    async fn test_inbound_trust_tunnel_tls(quic: bool) {
        let mut inbound_options = TrustTunnelOption {
            certificate: tls_certificate().to_owned(),
            private_key: tls_private_key().to_owned(),
            ..Default::default()
        };
        let mut outbound_options = OutTrustTunnelOption {
            fingerprint: tls_fingerprint().to_owned(),
            health_check: true,
            ..Default::default()
        };
        if quic {
            inbound_options.network = vec!["udp".to_owned()];
            inbound_options.congestion_controller = "bbr".to_owned();
            outbound_options.quic = true;
        }
        test_inbound_trust_tunnel(inbound_options.clone(), outbound_options.clone()).await;
        if std::env::var_os("TRUST_FIRST_ONLY").is_some() {
            return;
        }

        let mut ech_inbound = inbound_options.clone();
        ech_inbound.ech_key = ech_key_pem().to_owned();
        let mut ech_outbound = outbound_options.clone();
        ech_outbound.ech_opts =
            ECHOptions { enable: true, config: ech_config_base64().to_owned(), ..Default::default() };
        test_inbound_trust_tunnel(ech_inbound, ech_outbound).await;

        let mut mtls_inbound = inbound_options.clone();
        mtls_inbound.client_auth_cert = tls_auth_certificate().to_owned();
        let mut mtls_outbound = outbound_options.clone();
        mtls_outbound.certificate = tls_auth_certificate().to_owned();
        mtls_outbound.private_key = tls_auth_private_key().to_owned();
        test_inbound_trust_tunnel(mtls_inbound, mtls_outbound).await;

        let mut mtls_ech_inbound = inbound_options;
        mtls_ech_inbound.client_auth_cert = tls_auth_certificate().to_owned();
        mtls_ech_inbound.ech_key = ech_key_pem().to_owned();
        let mut mtls_ech_outbound = outbound_options;
        mtls_ech_outbound.certificate = tls_auth_certificate().to_owned();
        mtls_ech_outbound.private_key = tls_auth_private_key().to_owned();
        mtls_ech_outbound.ech_opts =
            ECHOptions { enable: true, config: ech_config_base64().to_owned(), ..Default::default() };
        test_inbound_trust_tunnel(mtls_ech_inbound, mtls_ech_outbound).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_inbound_trust_tunnel_h2() {
        test_inbound_trust_tunnel_tls(false).await;
    }

    /// Four real defects behind this test were found and fixed: a double UDP bind (the listener
    /// bound the socket, then quinn bound a second one to the same address before the first was
    /// closed), a QUIC client that never checked the server certificate against the configured
    /// fingerprint, an h3 body reader that rebuilt and dropped its read future on every poll
    /// (losing bytes already taken off the stream), and both the client's and the server's h3
    /// `RequestStream` sharing one lock across the send and receive halves — `recv_data` holds
    /// its lock for the whole wait for more peer data, so any write that needed to happen while a
    /// read was pending deadlocked (`h3::client::stream::RequestStream::split`/
    /// `h3::server::stream::RequestStream::split` exist precisely to avoid this). A fifth defect made
    /// `do_concurrent_test` fail intermittently with `Connection error: Remote error: InternalError in
    /// the quic trait implementation: internal error in the http stack`: `h3-quinn`'s `poll_ready`
    /// leaves its internal `writing` slot populated after a routine `Stopped` error from the peer
    /// (`h3-quinn` 0.0.10's `?` on `poll_write` returns before `self.writing = None` runs), and h3's
    /// `finish()` always writes a grease frame first, so the stream's very next `send_data` reported a
    /// misuse error and killed the whole connection instead of just that stream. `H3BodyWriter`/
    /// `H3ServerBodyWriter` now route every write through a dedicated per-stream owner task that sets
    /// a `poisoned` flag once a write returns `Stopped` (or any other error) and skips `finish()` on a
    /// poisoned stream, so a routine peer-side stream stop no longer escalates to a connection-fatal
    /// error.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_inbound_trust_tunnel_quic() {
        if murmur_testsupport_probe::is_wine() {
            eprintln!("skipped under Wine: quinn-udp 0.5 queries IPV6_V6ONLY on IPv4 sockets (WSAEOPNOTSUPP)");
            return;
        }
        test_inbound_trust_tunnel_tls(true).await;
    }

    /// Bounces every UDP payload it receives straight back to its sender, so a round trip through
    /// the inbound proves both read and write directions work.
    struct UdpEchoTunnel;

    impl UdpEchoTunnel {
        fn new() -> Arc<Self> {
            Arc::new(Self)
        }
    }

    #[async_trait]
    impl Tunnel for UdpEchoTunnel {
        async fn handle_tcp_conn(&self, _conn: Box<dyn murmur_common_net::io::Stream>, _metadata: Metadata) {
            unreachable!("test_inbound_trust_tunnel_h2_udp never opens a TCP tunnel");
        }

        fn handle_udp_packet(&self, packet: Arc<dyn UDPPacket>, metadata: Metadata) {
            let data = packet.data().to_vec();
            tokio::spawn(async move {
                let addr = metadata.raw_dst_addr.expect("destination address set by ListenerHandler");
                let Ok(addr) = murmur_common_net::io::old_addr_to_socket_addr(addr.as_ref()) else {
                    return;
                };
                let _ = packet.write_back(&data, Some(addr)).await;
            });
        }

        fn nat_table(&self) -> Arc<dyn NatTable> {
            Arc::new(Table::default())
        }
    }

    /// Regression test for the fix to `Service::serve_udp`: before it, a CONNECT to the UDP magic
    /// address fed the body reader from `request.into_body()`, which hyper's h2 server always
    /// empties for a CONNECT, so `dispatch_udp`'s first `read_packet` saw EOF immediately and every
    /// UDP round trip against a Rust trusttunnel h2 inbound failed.
    #[tokio::test(flavor = "multi_thread")]
    async fn test_inbound_trust_tunnel_h2_udp() {
        ensure_test_crypto_provider();
        let inbound_options = TrustTunnelOption {
            base: BaseOption {
                name_str: "trusttunnel_inbound_udp".to_owned(),
                listen: "127.0.0.1".to_owned(),
                port: "0".to_owned(),
                ..Default::default()
            },
            users: Some(vec![AuthUser { username: "test".to_owned(), password: USER_UUID.clone() }]),
            certificate: tls_certificate().to_owned(),
            private_key: tls_private_key().to_owned(),
            ..Default::default()
        };
        let inbound = TrustTunnel::new(Arc::new(inbound_options)).expect("trusttunnel inbound construction");
        inbound.listen(UdpEchoTunnel::new()).await.expect("trusttunnel inbound listen");

        let addr_port: SocketAddr = inbound.address().parse().expect("bound address");
        let outbound_options = OutTrustTunnelOption {
            name: "trusttunnel_outbound_udp".to_owned(),
            server: addr_port.ip().to_string(),
            port: i32::from(addr_port.port()),
            user_name: "test".to_owned(),
            password: USER_UUID.clone(),
            fingerprint: tls_fingerprint().to_owned(),
            udp: true,
            ..Default::default()
        };
        let out = OutTrustTunnel::new(outbound_options).expect("trusttunnel outbound construction");

        let ctx = CancellationToken::new();
        let mut metadata = Metadata {
            network: NetWork::UDP,
            dst_ip: Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
            dst_port: 53,
            ..Default::default()
        };
        let pc: Arc<dyn CPacketConn> =
            out.listen_packet_context(&ctx, &mut metadata).await.expect("trusttunnel udp listen_packet_context");
        let dest: Box<dyn Addr> = Box::new(UdpAddr::new(metadata.dst_ip.expect("dst_ip set above"), metadata.dst_port));

        for round in 0..5u8 {
            let payload = vec![round; 64];
            pc.write_to(&payload, dest.as_ref()).await.expect("udp write");
            let mut buf = vec![0u8; 128];
            let (n, _from) = tokio::time::timeout(Duration::from_secs(5), pc.read_from(&mut buf))
                .await
                .expect("udp read did not time out")
                .expect("udp read");
            assert_eq!(&buf[..n], payload.as_slice());
        }

        let _ = out.close();
        inbound.close().expect("trusttunnel inbound close");
    }
}
