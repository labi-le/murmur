use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;

use crate::quic;
use crate::quic::{CongestionOption, Conn, EarlyListener, Profile, ServerTls};
use crate::types::type_ as types_type;
use crate::{v4, v5};
use murmur_adapter_inbound::addition::Addition;
use murmur_common::utils::uuid::new_uuid_v4;
use murmur_common_net::bufconn::{new_buffered_conn, BufioReader};
use murmur_common_net::new_extended_conn;
use murmur_constant::adapters::UDPPacket;
use murmur_quic::Config as QuicConfig;
use murmur_std_compat::net::{Conn as NetConn, PacketConn};
use murmur_transport::socks5::socks5 as socks5_pkg;

/// The accepted stream's conn is handed to this callback and never touched again, so it takes
/// ownership here too; the listener spawns the tunnel with it.
pub type HandleTcpFn = Arc<dyn Fn(Box<dyn NetConn>, socks5_pkg::Addr, &[Addition]) -> anyhow::Result<()> + Send + Sync>;

/// Identical in shape to `v5::server::HandleUdpFn`; the v4 backend
/// (`Box<dyn UDPPacket>`) needs an `Arc::from` lift, see `new_server`.
pub type HandleUdpFn =
    Arc<dyn Fn(socks5_pkg::Addr, Arc<dyn UDPPacket>, &[Addition]) -> anyhow::Result<()> + Send + Sync>;

pub struct ServerOption {
    pub handle_tcp_fn: HandleTcpFn,
    pub handle_udp_fn: HandleUdpFn,

    pub tls_config: Arc<ServerTls>,
    pub quic_config: Arc<QuicConfig>,
    /// V4 special.
    pub tokens: Vec<[u8; 32]>,
    /// V5 special.
    pub users: HashMap<[u8; 16], String>,
    pub congestion_controller: String,
    pub authentication_timeout: Duration,
    pub max_udp_relay_packet_size: usize,
    pub cwnd: i32,
    pub bbr_profile: String,
}

/// Redacts the V4 tokens and the V5 user passwords, reporting only how many of each are configured.
impl core::fmt::Debug for ServerOption {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ServerOption")
            .field("tokens", &self.tokens.len())
            .field("users", &self.users.len())
            .field("congestion_controller", &self.congestion_controller)
            .field("authentication_timeout", &self.authentication_timeout)
            .field("max_udp_relay_packet_size", &self.max_udp_relay_packet_size)
            .field("cwnd", &self.cwnd)
            .field("bbr_profile", &self.bbr_profile)
            .finish_non_exhaustive()
    }
}

/// `Server`. the embedded `*ServerOption` is a named field: Rust has no field promotion.
pub struct Server {
    pub option: Arc<ServerOption>,
    option_v4: Option<Arc<v4::server::ServerOption>>,
    option_v5: Option<Arc<v5::server::ServerOption>>,
    listener: Arc<dyn EarlyListener>,
}

impl core::fmt::Debug for Server {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Server")
            .field("option", &self.option)
            .field("option_v4", &self.option_v4)
            .field("option_v5", &self.option_v5)
            .finish_non_exhaustive()
    }
}

impl Server {
    /// Runs the accept loop. Takes `self: &Arc<Self>` so spawned tasks can hold a `'static` handle.
    pub async fn serve(self: &Arc<Self>) -> anyhow::Result<()> {
        loop {
            let ctx = CancellationToken::new();
            let conn = self.listener.accept(&ctx).await?;
            let uuid = new_uuid_v4();
            let v4_handler = self
                .option_v4
                .as_ref()
                .map(|option| v4::server::new_server_handler(Arc::clone(option), Arc::clone(&conn), uuid));
            let v5_handler = self.option_v5.as_ref().map(|option| {
                let v5_option = v5::server::ServerOption {
                    handle_tcp_fn: Arc::clone(&option.handle_tcp_fn),
                    handle_udp_fn: Arc::clone(&option.handle_udp_fn),
                    users: option.users.clone(),
                    max_udp_relay_packet_size: option.max_udp_relay_packet_size,
                };
                v5::server::new_server_handler(v5_option, Arc::clone(&conn), uuid)
            });

            let handler = Arc::new(ServerHandler { server: Arc::clone(self), quic_conn: conn, v4_handler, v5_handler });
            tokio::spawn(async move { handler.handle().await });
        }
    }

    pub fn close(&self) -> anyhow::Result<()> {
        self.listener.close().map_err(anyhow::Error::from)
    }
}

/// The 0-RTT flag is read off the QUIC config; quinn's `QuicServerConfig::try_from`
/// copies rustls's `max_early_data_size` through untouched, so the advertisement has to be set
/// here or the server rejects every early-data flight that would otherwise be accepted.
fn server_tls(tls: &Arc<ServerTls>, allow_0rtt: bool) -> Arc<ServerTls> {
    let mut config = (*tls.config).clone();
    config.max_early_data_size = if allow_0rtt { u32::MAX } else { 0 };
    Arc::new(ServerTls { config: Arc::new(config) })
}

pub fn new_server(option: Arc<ServerOption>, pc: Arc<dyn PacketConn>) -> anyhow::Result<Server> {
    let config = quic::effective_config(option.quic_config.as_ref().clone());
    let congestion = CongestionOption {
        name: option.congestion_controller.clone(),
        cwnd: option.cwnd,
        profile: Profile::from(option.bbr_profile.as_str()),
    };
    let listener =
        quic::listen_early(pc, server_tls(&option.tls_config, option.quic_config.allow_0rtt), config, congestion)?;
    let option_v4 = if option.tokens.is_empty() {
        None
    } else {
        let handle_udp_fn = {
            let f = Arc::clone(&option.handle_udp_fn);
            Arc::new(move |addr: socks5_pkg::Addr, packet: Box<dyn UDPPacket>, additions: &[Addition]| {
                f(addr, Arc::from(packet), additions)
            })
        };
        Some(Arc::new(v4::server::ServerOption {
            handle_tcp_fn: Arc::clone(&option.handle_tcp_fn),
            handle_udp_fn,
            tokens: option.tokens.clone(),
            max_udp_relay_packet_size: option.max_udp_relay_packet_size,
        }))
    };

    let option_v5 = if option.users.is_empty() {
        None
    } else {
        let mut max_udp_relay_packet_size = option.max_udp_relay_packet_size;
        if max_udp_relay_packet_size > *v5::frag::MAX_FRAG_SIZE {
            max_udp_relay_packet_size = *v5::frag::MAX_FRAG_SIZE;
        }
        let handle_tcp_fn = Arc::clone(&option.handle_tcp_fn);
        Some(Arc::new(v5::server::ServerOption {
            handle_tcp_fn,
            handle_udp_fn: Arc::clone(&option.handle_udp_fn),
            users: option.users.clone(),
            max_udp_relay_packet_size,
        }))
    };

    Ok(Server { option, option_v4, option_v5, listener })
}

struct ServerHandler {
    server: Arc<Server>,
    quic_conn: Arc<dyn Conn>,
    v4_handler: Option<Arc<dyn types_type::ServerHandler>>,
    v5_handler: Option<Arc<dyn types_type::ServerHandler>>,
}

impl ServerHandler {
    // cancel-safe: the select only waits for the handshake or the idle timeout, and the worker
    // tasks that own the connection state are spawned before it.
    async fn handle(self: Arc<Self>) {
        {
            let this = Arc::clone(&self);
            tokio::spawn(async move {
                let _ = this.handle_uni_stream().await;
            });
        }
        {
            let this = Arc::clone(&self);
            tokio::spawn(async move {
                let _ = this.handle_stream().await;
            });
        }
        {
            let this = Arc::clone(&self);
            tokio::spawn(async move {
                let _ = this.handle_message().await;
            });
        }

        let handshake_idle_timeout = self.quic_conn.config().handshake_idle_timeout;
        tokio::select! {
            () = self.quic_conn.handshake_complete() => {}
            () = tokio::time::sleep(handshake_idle_timeout) => {}
        }

        let this = Arc::clone(&self);
        tokio::spawn(async move {
            tokio::time::sleep(this.server.option.authentication_timeout).await;

            if let Some(v4_handler) = &this.v4_handler {
                if v4_handler.auth_ok() {
                    return;
                }
            }
            if let Some(v5_handler) = &this.v5_handler {
                if v5_handler.auth_ok() {
                    return;
                }
            }
            if let Some(v4_handler) = &this.v4_handler {
                v4_handler.handle_timeout();
            }
            if let Some(v5_handler) = &this.v5_handler {
                v5_handler.handle_timeout();
            }
        });
    }

    async fn handle_message(&self) -> anyhow::Result<()> {
        let ctx = CancellationToken::new();
        loop {
            let message = self.quic_conn.receive_datagram(&ctx).await?;
            let v4_handler = self.v4_handler.clone();
            let v5_handler = self.v5_handler.clone();
            tokio::spawn(async move {
                let Some(&ver) = message.first() else {
                    return;
                };
                if ver == v4::protocol::VER {
                    if let Some(handler) = v4_handler {
                        let _ = handler.handle_message(&message).await;
                    }
                } else if ver == v5::protocol::VER {
                    if let Some(handler) = v5_handler {
                        let _ = handler.handle_message(&message).await;
                    }
                }
            });
        }
    }

    async fn handle_stream(&self) -> anyhow::Result<()> {
        let ctx = CancellationToken::new();
        loop {
            let quic_stream = self.quic_conn.accept_stream(&ctx).await?;
            let l_addr = self.quic_conn.local_addr();
            let r_addr = self.quic_conn.remote_addr();
            let v4_handler = self.v4_handler.clone();
            let v5_handler = self.v5_handler.clone();
            tokio::spawn(async move {
                let stream = crate::types::stream::new_quic_stream_conn(quic_stream, l_addr, r_addr, None);
                let mut conn = new_buffered_conn(new_extended_conn(stream));

                let ver = {
                    let (peeked, peek_err) = conn.peek(1).await;
                    if peek_err.is_err() {
                        None
                    } else {
                        peeked.first().copied()
                    }
                };
                let Some(ver) = ver else {
                    let _ = conn.close();
                    return;
                };

                if ver == v4::protocol::VER {
                    if let Some(handler) = v4_handler {
                        let _ = handler.handle_stream(conn).await;
                        return;
                    }
                } else if ver == v5::protocol::VER {
                    if let Some(handler) = v5_handler {
                        let _ = handler.handle_stream(conn).await;
                        return;
                    }
                }
                let _ = conn.close();
            });
        }
    }

    /// The reader refills itself from `stream` on
    /// demand; this crate's `BufioReader` cannot (see `v4`/`v5` `handle_uni_stream` doc comments), so
    /// this reads the whole uni-stream message up front before dispatching, since this protocol's
    /// uni streams always carry exactly one bounded command.
    async fn handle_uni_stream(&self) -> anyhow::Result<()> {
        let ctx = CancellationToken::new();
        loop {
            let mut stream = self.quic_conn.accept_uni_stream(&ctx).await?;
            let v4_handler = self.v4_handler.clone();
            let v5_handler = self.v5_handler.clone();
            tokio::spawn(async move {
                let mut reader = BufioReader::new();
                loop {
                    let free = reader.free_space();
                    if free.is_empty() {
                        break;
                    }
                    match stream.read(free).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => reader.commit(n),
                    }
                }

                let ver = reader.buffered_bytes().first().copied();
                if let Some(ver) = ver {
                    if ver == v4::protocol::VER {
                        if let Some(handler) = v4_handler {
                            let _ = handler.handle_uni_stream(&mut reader).await;
                        }
                    } else if ver == v5::protocol::VER {
                        if let Some(handler) = v5_handler {
                            let _ = handler.handle_uni_stream(&mut reader).await;
                        }
                    }
                }
                stream.cancel_read(0);
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UdpSocket;

    use murmur_component_ca::keypair::{new_random_tls_key_pair, x509_key_pair, KeyPairType};
    use murmur_component_tls::utls;

    use super::*;

    fn listener_tls() -> Arc<ServerTls> {
        let (certificate_pem, private_key_pem, _) =
            new_random_tls_key_pair(KeyPairType::P256).expect("a generated test key pair");
        let certificate = x509_key_pair(certificate_pem.as_bytes(), private_key_pem.as_bytes())
            .expect("the generated PEM yields a certificate");
        Arc::new(ServerTls {
            config: Arc::new(
                utls::server_rustls_config(&utls::Config {
                    certificates: vec![certificate],
                    next_protos: vec!["h3".to_owned()],
                    ..Default::default()
                })
                .expect("the listener's rustls config"),
            ),
        })
    }

    /// The 0-RTT advertisement is what lets the listener take a
    /// client's first stream in the 0-RTT flight; without the advertisement the client never gets
    /// early keys, and the stream below only ever arrives after the handshake.
    #[tokio::test(flavor = "multi_thread")]
    async fn allow_0rtt_lets_the_server_take_an_early_data_stream() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind the listener socket");
        let addr = socket.local_addr().expect("the listener socket address");
        let ctx = CancellationToken::new();
        let tls = server_tls(&listener_tls(), true);
        assert_eq!(tls.config.max_early_data_size, u32::MAX, "the 0-RTT advertisement must reach quinn");
        let listener = quic::listen_early(
            Arc::new(socket),
            tls,
            quic::effective_config(QuicConfig::default()),
            CongestionOption::default(),
        )
        .expect("start the listener");

        // quinn defers a server connection's handshake until the application hands the buffered
        // `Incoming` to `accept()` (quinn-proto `endpoint.rs` keeps the first packet in
        // `incoming_buffers`), so the accept loop has to be running while the client dials.
        let (conn_tx, mut conn_rx) = tokio::sync::mpsc::unbounded_channel();
        let accept_ctx = ctx.clone();
        tokio::spawn(async move {
            while let Ok(conn) = listener.accept(&accept_ctx).await {
                let readiness = Arc::clone(&conn);
                let readiness_ctx = accept_ctx.clone();
                tokio::spawn(async move {
                    if let Ok(mut stream) = readiness.open_uni_stream(&readiness_ctx).await {
                        let _ = stream.write_all(b"ready").await;
                        let _ = stream.close();
                    }
                });
                if conn_tx.send(conn).is_err() {
                    break;
                }
            }
        });

        let mut client_rustls = utls::client_rustls_config(&utls::Config {
            insecure_skip_verify: true,
            next_protos: vec!["h3".to_owned()],
            ..Default::default()
        })
        .expect("the dialer's rustls config");
        client_rustls.enable_early_data = true;
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(client_rustls).expect("client config");
        let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));
        client_config.transport_config(Arc::new(quinn::TransportConfig::default()));
        let client_socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind the client socket");
        let mut endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            client_socket,
            quinn::default_runtime().expect("quinn has no async runtime"),
        )
        .expect("client endpoint");
        endpoint.set_default_client_config(client_config);

        // Every full handshake before the resumption hands the client another ticket; `into_0rtt`
        // only succeeds once rustls holds one carrying the server's early-data permission. The
        // readiness byte is a 1-RTT packet the server sends after the ticket, so reading it proves
        // the client processed the ticket before retrying.
        let mut full_handshakes = 0;
        let (conn, accepted) = loop {
            assert!(full_handshakes < 16, "the server never advertised 0-RTT");
            match endpoint.connect(addr, "localhost").expect("connect").into_0rtt() {
                Ok(claimed) => break claimed,
                Err(connecting) => {
                    let conn = connecting.await.expect("handshake");
                    let mut ready = conn.accept_uni().await.expect("server readiness stream");
                    assert_eq!(ready.read_to_end(8).await.expect("readiness byte"), b"ready");
                    full_handshakes += 1;
                }
            }
        };
        let (mut send, _) = conn.open_bi().await.expect("0-RTT stream");
        send.write_all(b"zero").await.expect("0-RTT write");
        send.finish().expect("finish");

        // The listener accepted one connection per full handshake ahead of the resumed one.
        let mut server_conn = None;
        for _ in 0..=full_handshakes {
            server_conn = Some(
                tokio::time::timeout(Duration::from_secs(10), conn_rx.recv())
                    .await
                    .expect("the listener accepted nothing")
                    .expect("the accept loop is running"),
            );
        }
        let server_conn = server_conn.expect("the listener accepted nothing");
        let mut incoming = server_conn.accept_stream(&ctx).await.expect("accept the 0-RTT stream");
        let mut payload = [0u8; 4];
        incoming.read_exact(&mut payload).await.expect("read the 0-RTT payload");
        assert_eq!(&payload, b"zero");
        assert!(accepted.await, "the server rejected the 0-RTT flight");
    }
}
