use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use parking_lot::Mutex;

use crate::inbound::base::{config_equal, option_to_string, upcast_config, Base, BaseOption};
use crate::inbound::mux::MuxOption;
use crate::tuic::server as tuic_server;
use murmur_constant::listener::{InboundConfig, InboundListener};
use murmur_constant::tunnel::Tunnel;
use murmur_listener_config::tuic as lc_tuic;
use murmur_log::infoln;

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct TuicOption {
    pub base: BaseOption,
    pub token: Vec<String>,
    pub users: BTreeMap<String, String>,
    pub certificate: String,
    pub private_key: String,
    pub client_auth_type: String,
    pub client_auth_cert: String,
    pub ech_key: String,
    pub congestion_controller: String,
    pub max_idle_time: i32,
    pub authentication_timeout: i32,
    pub alpn: Vec<String>,
    pub max_udp_relay_packet_size: i32,
    pub cwnd: i32,
    pub bbr_profile: String,
    pub mux_option: MuxOption,
}

impl InboundConfig for TuicOption {
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

pub struct Tuic {
    base: Base,
    config: Arc<TuicOption>,
    l: Mutex<Option<tuic_server::Listener>>,
    ts: lc_tuic::TuicServer,
}

impl core::fmt::Debug for Tuic {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Tuic").field("config", &self.config).finish_non_exhaustive()
    }
}

impl Tuic {
    pub fn new(options: Arc<TuicOption>) -> Result<Self> {
        let base = Base::new(Arc::new(options.base.clone()))?;
        let ts = {
            let lc_tuic::TuicServer { max_datagram_frame_size, .. } = lc_tuic::TuicServer::default();
            lc_tuic::TuicServer {
                enable: true,
                listen: base.raw_address(),
                token: options.token.clone(),
                users: options.users.clone(),
                certificate: options.certificate.clone(),
                private_key: options.private_key.clone(),
                client_auth_type: options.client_auth_type.clone(),
                client_auth_cert: options.client_auth_cert.clone(),
                ech_key: options.ech_key.clone(),
                congestion_controller: options.congestion_controller.clone(),
                max_idle_time: options.max_idle_time,
                authentication_timeout: options.authentication_timeout,
                alpn: options.alpn.clone(),
                max_udp_relay_packet_size: options.max_udp_relay_packet_size,
                max_datagram_frame_size,
                cwnd: options.cwnd,
                bbr_profile: options.bbr_profile.clone(),
                mux_option: options.mux_option.build(),
            }
        };
        Ok(Self { base, config: options, l: Mutex::new(None), ts })
    }
}

#[async_trait]
impl InboundListener for Tuic {
    fn name(&self) -> String {
        self.config.name()
    }

    async fn listen(&self, tunnel: Arc<dyn Tunnel>) -> Result<()> {
        let listener =
            tuic_server::new(self.ts.clone(), self.base.listen_config(), tunnel, &self.base.additions()).await?;
        *self.l.lock() = Some(listener);
        infoln!("Tuic[{}] proxy listening at: {}", self.name(), self.address());
        Ok(())
    }

    fn close(&self) -> Result<()> {
        self.l.lock().as_ref().map_or(Ok(()), tuic_server::Listener::close)
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
    //!
    //! The client side is `murmur_transport_tuic`'s own QUIC+TUIC client rather than
    //! adapter-outbound's dial path, so these tests cover the listener and the inbound protocol
    //! alone. `EchoTunnel` echoes every destination, which measures the handshake, the
    //! authentication and the stream framing without a real tunnel.
    //!
    //! `test_inbound_tuic_v4_round_trip`/`test_inbound_tuic_v5_round_trip` prove one payload
    //! survives each protocol version and comes back;
    //! `test_inbound_tuic_v5_wrong_password_fails_closed` proves a wrong credential carries no
    //! traffic and does not hang the stream.

    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_util::sync::CancellationToken;

    use super::*;
    use murmur_component_tls::utls as tls_c;
    use murmur_constant::metadata::{Metadata, NetWork};
    use murmur_std_compat::net::PacketConn;
    use murmur_testsupport::{tls_certificate, tls_private_key, EchoTunnel, REMOTE_ADDR, USER_UUID};
    use murmur_transport_tuic::quic::{self, ClientTls, CongestionOption};
    use murmur_transport_tuic::tuic::{
        gen_tkn, new_client_v4, new_client_v5, Client, ClientOptionV4, ClientOptionV5, QUIC,
    };
    use murmur_transport_tuic::types::type_::DialFunc;

    const PASSWORD: &str = "tuic-inbound-password";
    const SERVER_NAME: &str = "tuic.test";
    const PAYLOAD: &[u8] = b"tuic inbound round trip";
    const DEST_PORT: u16 = 80;
    const TIMEOUT: Duration = Duration::from_secs(10);

    fn client_tls() -> Arc<ClientTls> {
        let config = tls_c::Config {
            min_version: tls_c::VERSION_TLS13,
            next_protos: vec!["h3".to_owned()],
            server_name: SERVER_NAME.to_owned(),
            insecure_skip_verify: true,
            ..Default::default()
        };
        Arc::new(ClientTls {
            config: Arc::new(tls_c::client_rustls_config(&config).expect("tuic client rustls config")),
            server_name: SERVER_NAME.to_owned(),
        })
    }

    fn dial_fn(addr: SocketAddr) -> DialFunc {
        let tls = client_tls();
        Arc::new(move |ctx: CancellationToken| {
            let tls = Arc::clone(&tls);
            Box::pin(async move {
                let packet_conn: Arc<dyn PacketConn> = Arc::new(tokio::net::UdpSocket::bind("0.0.0.0:0").await?);
                quic::dial(
                    &ctx,
                    packet_conn,
                    addr,
                    tls,
                    quic::effective_config(quic::Config::default()),
                    CongestionOption::default(),
                )
                .await
            })
        })
    }

    async fn start_inbound(options: TuicOption) -> (Tuic, SocketAddr) {
        let options = TuicOption {
            base: BaseOption {
                name_str: "tuic_inbound".to_owned(),
                listen: "127.0.0.1".to_owned(),
                port: "0".to_owned(),
                ..Default::default()
            },
            certificate: tls_certificate().to_owned(),
            private_key: tls_private_key().to_owned(),
            authentication_timeout: 5000,
            ..options
        };
        let inbound = Tuic::new(Arc::new(options)).expect("tuic inbound construction");
        let tunnel: Arc<dyn Tunnel> = Arc::new(EchoTunnel { camouflage_addr: "127.0.0.1:1".to_owned() });
        inbound.listen(tunnel).await.expect("tuic inbound listen");
        let addr = inbound.address().parse().expect("bound address");
        (inbound, addr)
    }

    /// Echoes one payload back. `Ok` only when the bytes really round-trip: a dial failure, a
    /// closed stream and a timeout all become `Err`.
    async fn round_trip(client: &Client) -> Result<Vec<u8>> {
        let mut metadata =
            Metadata { network: NetWork::TCP, dst_ip: Some(*REMOTE_ADDR), dst_port: DEST_PORT, ..Default::default() };
        let ctx = CancellationToken::new();
        let mut conn = tokio::time::timeout(TIMEOUT, client.dial_context(&ctx, &mut metadata))
            .await
            .map_err(|_| anyhow::anyhow!("tuic dial timed out"))??;
        conn.write_all(PAYLOAD).await?;
        let mut echoed = vec![0u8; PAYLOAD.len()];
        tokio::time::timeout(TIMEOUT, conn.read_exact(&mut echoed))
            .await
            .map_err(|_| anyhow::anyhow!("tuic echo timed out"))??;
        Ok(echoed)
    }

    fn v5_client(addr: SocketAddr, password: &str) -> Client {
        let uuid = uuid::Uuid::parse_str(&USER_UUID).expect("USER_UUID parses as a uuid").into_bytes();
        new_client_v5(
            ClientOptionV5 {
                uuid,
                password: password.to_owned(),
                udp_relay_mode: QUIC,
                max_udp_relay_packet_size: 1500,
                max_open_streams: 100,
            },
            false,
            dial_fn(addr),
        )
    }

    fn v4_client(addr: SocketAddr, token: &str) -> Client {
        new_client_v4(
            Arc::new(ClientOptionV4 {
                token: gen_tkn(token),
                udp_relay_mode: QUIC,
                request_timeout: TIMEOUT,
                max_udp_relay_packet_size: 1500,
                fast_open: false,
                max_open_streams: 100,
            }),
            false,
            dial_fn(addr),
        )
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_inbound_tuic_v5_round_trip() {
        let (inbound, addr) = start_inbound(TuicOption {
            users: [(USER_UUID.clone(), PASSWORD.to_owned())].into(),
            ..Default::default()
        })
        .await;

        let client = v5_client(addr, PASSWORD);
        assert_eq!(round_trip(&client).await.expect("v5 round trip"), PAYLOAD);

        inbound.close().expect("tuic inbound close");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_inbound_tuic_v4_round_trip() {
        let token = USER_UUID.clone();
        let (inbound, addr) = start_inbound(TuicOption { token: vec![token.clone()], ..Default::default() }).await;

        let client = v4_client(addr, &token);
        assert_eq!(round_trip(&client).await.expect("v4 round trip"), PAYLOAD);

        inbound.close().expect("tuic inbound close");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_inbound_tuic_v5_wrong_password_fails_closed() {
        let (inbound, addr) = start_inbound(TuicOption {
            users: [(USER_UUID.clone(), PASSWORD.to_owned())].into(),
            ..Default::default()
        })
        .await;

        let client = v5_client(addr, "wrong-password");
        let mut metadata =
            Metadata { network: NetWork::TCP, dst_ip: Some(*REMOTE_ADDR), dst_port: DEST_PORT, ..Default::default() };
        let ctx = CancellationToken::new();
        let mut carried_traffic = false;
        match tokio::time::timeout(TIMEOUT, client.dial_context(&ctx, &mut metadata)).await {
            Ok(Ok(mut conn)) => {
                if conn.write_all(PAYLOAD).await.is_ok() {
                    let mut echoed = vec![0u8; PAYLOAD.len()];
                    carried_traffic = match tokio::time::timeout(TIMEOUT, conn.read_exact(&mut echoed)).await {
                        Ok(Ok(_)) => true,
                        Ok(Err(_)) => false,
                        Err(_) => panic!("the wrong-password stream neither echoed nor died"),
                    };
                }
            }
            Ok(Err(_)) => {}
            Err(_) => panic!("the wrong-password dial hung instead of being refused"),
        }
        assert!(!carried_traffic, "a wrong TUIC password must not carry traffic");

        inbound.close().expect("tuic inbound close");
    }
}
