use std::io;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use murmur_common::shared_conn::SharedConn;
use murmur_common_net::io::{old_addr_to_socket_addr, Datagram, OldConnAsStream};
use murmur_common_net::setup_context_for_conn;
use murmur_component::dialer::bind::join_host_port;
use murmur_component_ca::config::{get_tls_config, Option as CaOption};
use murmur_component_tls::utls::{client as tls_client, ClientAuthType, Config as TlsConfig, RenegotiationSupport};
use murmur_constant::adapters::{
    AdapterType, Conn as CConn, PacketConn as CPacketConn, Proxy, ProxyAdapter as CProxyAdapter, ProxyInfo,
};
use murmur_constant::metadata::Metadata;
use murmur_std_compat::net::Conn as NetConn;
use murmur_transport::socks5::socks5 as socks5t;

use super::base::{new_conn, new_packet_conn, Base, BaseOption, BasicOption, ProxyAdapter as BaseProxyAdapter};
use super::util::{resolve_udp_addr, safe_conn_close, serializes_socks_addr};

pub struct Socks5 {
    base: Base,
    option: Socks5Option,
    user: String,
    pass: String,
    tls: bool,
    tls_config: Option<Arc<TlsConfig>>,
    self_weak: std::sync::Weak<Self>,
}

impl std::fmt::Debug for Socks5 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Socks5")
            .field("name", &self.base.name())
            .field("addr", &self.base.addr())
            .field("user", &self.user)
            .field("pass", &"<redacted>")
            .field("tls", &self.tls)
            .field("option", &self.option)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Default)]
pub struct Socks5Option {
    pub basic_option: BasicOption,
    pub name: String,
    pub server: String,
    pub port: u16,
    pub user_name: String,
    pub password: String,
    pub tls: bool,
    pub udp: bool,
    pub skip_cert_verify: bool,
    pub name_cert_verify: String,
    pub fingerprint: String,
    pub certificate: String,
    pub private_key: String,
}

impl std::fmt::Debug for Socks5Option {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Socks5Option")
            .field("name", &self.name)
            .field("server", &self.server)
            .field("port", &self.port)
            .field("user_name", &self.user_name)
            .field("password", &"<redacted>")
            .field("tls", &self.tls)
            .field("udp", &self.udp)
            .field("skip_cert_verify", &self.skip_cert_verify)
            .field("name_cert_verify", &self.name_cert_verify)
            .field("fingerprint", &self.fingerprint)
            .field("certificate", &self.certificate)
            .field("private_key", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl Socks5 {
    pub fn new(option: Socks5Option) -> Result<Arc<Self>> {
        let tls_config: Option<Arc<TlsConfig>> = if option.tls {
            let config = get_tls_config(CaOption {
                tls_config: Some(TlsConfig {
                    insecure_skip_verify: option.skip_cert_verify,
                    server_name: option.server.clone(),
                    rand: None,
                    time: None,
                    certificates: Vec::new(),
                    get_certificate: None,
                    get_client_certificate: None,
                    verify_peer_certificate: None,
                    verify_connection: None,
                    root_cas: None,
                    next_protos: Vec::new(),
                    client_auth: ClientAuthType::default(),
                    client_cas: None,
                    cipher_suites: None,
                    session_tickets_disabled: false,
                    min_version: 0,
                    max_version: 0,
                    curve_preferences: None,
                    renegotiation: RenegotiationSupport::default(),
                    key_log_writer: None,
                    encrypted_client_hello_config_list: Vec::new(),
                    encrypted_client_hello_rejection_verify: None,
                    encrypted_client_hello_keys: Vec::new(),
                    get_encrypted_client_hello_keys: None,
                    session_id_generator: None,
                }),
                fingerprint: option.fingerprint.clone(),
                name_cert_verify: option.name_cert_verify.clone(),
                certificate: option.certificate.clone(),
                private_key: option.private_key.clone(),
                zero_trust: false,
            })?;
            Some(Arc::new(config))
        } else {
            None
        };

        let mut base = Base::new(BaseOption {
            name: option.name.clone(),
            addr: join_host_port(&option.server, option.port),
            type_: AdapterType::SOCKS5,
            provider_name: option.basic_option.provider_name.clone(),
            udp: option.udp,
            tfo: option.basic_option.tfo,
            mptcp: option.basic_option.mptcp,
            interface: option.basic_option.interface.clone(),
            routing_mark: option.basic_option.routing_mark,
            prefer: option.basic_option.ip_version,
            xudp: false,
        });
        let dial_options = base.dial_options();
        base.dialer = Some(option.basic_option.new_dialer(dial_options));

        Ok(Arc::new_cyclic(|weak| Self {
            base,
            user: option.user_name.clone(),
            pass: option.password.clone(),
            tls: option.tls,
            tls_config,
            option,
            self_weak: std::sync::Weak::clone(weak),
        }))
    }
    async fn stream_conn_context(
        &self,
        ctx: &CancellationToken,
        c: Box<dyn NetConn>,
        metadata: &Metadata,
    ) -> Result<Box<dyn NetConn>> {
        let mut c = c;
        if self.tls {
            let tls_config = self.tls_config.as_ref().ok_or_else(|| anyhow!("tls_config set when tls enabled"))?;
            let cc = tls_client(Box::new(OldConnAsStream(c)), Arc::clone(tls_config));
            if let Err(err) = cc.handshake_context(ctx).await {
                return Err(anyhow!("{} connect error: {err}", self.base.addr()));
            }
            c = Box::new(murmur_common_net::io::StreamAsOldConn::new(cc));
        }

        let user = if self.user.is_empty() {
            None
        } else {
            Some(socks5t::User { username: self.user.clone(), password: self.pass.clone() })
        };

        let addr: socks5t::Addr = serializes_socks_addr(metadata).into();
        let (_, c) = self.client_handshake_context(ctx, c, &addr, socks5t::CMD_CONNECT, user.as_ref()).await?;
        Ok(c)
    }

    async fn client_handshake_context(
        &self,
        ctx: &CancellationToken,
        c: Box<dyn NetConn>,
        addr: &socks5t::Addr,
        command: socks5t::Command,
        user: Option<&socks5t::User>,
    ) -> Result<(socks5t::Addr, Box<dyn NetConn>)> {
        let shared = SharedConn::from_boxed(c);
        let mut done = setup_context_for_conn(ctx, shared.clone());
        let mut rw = shared.clone();
        let result = socks5t::client_handshake(&mut rw, addr, command, user).await;
        let mut err_opt = result.as_ref().err().map(|e: &anyhow::Error| anyhow!("{e}"));
        done.call(&mut err_opt).await;
        match err_opt {
            Some(err) => Err(err),
            None => Ok((result?, Box::new(shared))),
        }
    }

    /// The UDP-associate negotiation and background TCP watcher used by `listen_packet_context`.
    async fn listen_packet_via(
        &self,
        ctx: &CancellationToken,
        dialer: &Arc<dyn murmur_constant::adapters::Dialer>,
        c: Box<dyn NetConn>,
    ) -> Result<Arc<dyn CPacketConn>> {
        let addr = self.base.addr();
        let mut c = c;
        if self.tls {
            let tls_config = self.tls_config.as_ref().ok_or_else(|| anyhow!("tls_config set when tls enabled"))?;
            let cc = tls_client(Box::new(OldConnAsStream(c)), Arc::clone(tls_config));
            cc.handshake_context(ctx).await.map_err(|err| anyhow!("{addr} connect error: {err}"))?;
            c = Box::new(murmur_common_net::io::StreamAsOldConn::new(cc));
        }

        let user = if self.user.is_empty() {
            None
        } else {
            Some(socks5t::User { username: self.user.clone(), password: self.pass.clone() })
        };

        let udp_associate_addr = socks5t::addr_from_std_addr_port(std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            0,
        ));
        let (bind_addr, tcp_conn) = self
            .client_handshake_context(ctx, c, &udp_associate_addr, socks5t::CMD_UDP_ASSOCIATE, user.as_ref())
            .await
            .map_err(|err| anyhow!("client hanshake error: {err}"))?;

        let mut bind_udp_addr = bind_addr.udp_addr().ok_or_else(|| anyhow!("invalid UDP bind address"))?;
        if bind_udp_addr.ip.is_unspecified() {
            let server_addr = resolve_udp_addr(ctx, "udp", &addr, murmur_constant::dns::DNSPrefer::IPV4_PREFER).await?;
            bind_udp_addr.ip = server_addr.ip;
        }

        let socket_addr = std::net::SocketAddr::new(bind_udp_addr.ip, bind_udp_addr.port);
        let pc = dialer.listen_packet(ctx, "udp", "", Some(socket_addr)).await?;
        let pc: Arc<dyn Datagram> = Arc::from(pc);

        let watch_conn = SharedConn::from_boxed(tcp_conn);
        let watch_conn_task = watch_conn.clone();
        let watch_pc = Arc::clone(&pc);
        tokio::spawn(async move {
            let mut reader = watch_conn_task;
            let _ = tokio::io::copy(&mut reader, &mut tokio::io::sink()).await;
            let _ = reader.close();
            let _ = watch_pc.close();
        });

        let this = self.self_weak.upgrade().ok_or_else(|| anyhow!("Socks5 adapter dropped"))?;
        let socks_pc: Arc<dyn Datagram> = Arc::new(Socks5PacketConn {
            inner: pc,
            remote_addr: std::net::SocketAddr::new(bind_udp_addr.ip, bind_udp_addr.port),
            tcp_conn: watch_conn,
        });
        Ok(new_packet_conn(socks_pc, this))
    }
}

#[async_trait]
impl CProxyAdapter for Socks5 {
    fn name(&self) -> String {
        self.base.name()
    }

    fn type_(&self) -> AdapterType {
        self.base.type_()
    }

    fn addr(&self) -> String {
        self.base.addr()
    }

    fn support_udp(&self) -> bool {
        self.base.support_udp()
    }

    fn proxy_info(&self) -> ProxyInfo {
        let mut info = self.base.proxy_info();
        info.dialer_proxy.clone_from(&self.option.basic_option.dialer_proxy);
        info
    }

    fn marshal_json(&self) -> Result<Vec<u8>> {
        self.base.marshal_json()
    }

    async fn dial_context(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<Box<dyn CConn>> {
        let dialer =
            self.base.dialer.as_ref().ok_or_else(|| anyhow!("Socks5.base.dialer must be set before DialContext"))?;
        let addr = self.base.addr();
        let raw = dialer.dial_context(ctx, "tcp", &addr).await.map_err(|err| anyhow!("{addr} connect error: {err}"))?;
        let raw: Box<dyn NetConn> = Box::new(murmur_common_net::io::StreamAsOldConn::new(raw));

        let shared = SharedConn::from_boxed(raw);
        let result = self.stream_conn_context(ctx, Box::new(shared.clone()), metadata).await;
        safe_conn_close(Some(&shared), result.is_err());
        let c = result?;
        Ok(new_conn(Box::new(OldConnAsStream(c)), self))
    }

    async fn listen_packet_context(
        &self,
        ctx: &CancellationToken,
        metadata: &mut Metadata,
    ) -> Result<Arc<dyn CPacketConn>> {
        BaseProxyAdapter::resolve_udp(self, ctx, metadata).await?;
        let dialer = self
            .base
            .dialer
            .as_ref()
            .ok_or_else(|| anyhow!("Socks5.base.dialer must be set before ListenPacketContext"))?;
        let addr = self.base.addr();
        let raw = dialer.dial_context(ctx, "tcp", &addr).await.map_err(|err| anyhow!("{addr} connect error: {err}"))?;
        let raw: Box<dyn NetConn> = Box::new(murmur_common_net::io::StreamAsOldConn::new(raw));

        let shared = SharedConn::from_boxed(raw);
        let result = self.listen_packet_via(ctx, dialer, Box::new(shared.clone())).await;
        safe_conn_close(Some(&shared), result.is_err());
        result
    }

    fn support_uot(&self) -> bool {
        self.base.support_uot()
    }

    fn is_l3_protocol(&self, metadata: &Metadata) -> bool {
        self.base.is_l3_protocol(metadata)
    }

    fn unwrap(&self, metadata: &Metadata, touch: bool) -> Option<Arc<dyn Proxy>> {
        self.base.unwrap(metadata, touch)
    }

    fn close(&self) -> Result<()> {
        self.base.close()
    }
}

#[async_trait]
impl BaseProxyAdapter for Socks5 {
    fn dial_options(&self) -> Vec<murmur_component::dialer::options::Option> {
        self.base.dial_options()
    }

    async fn resolve_udp(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<()> {
        self.base.resolve_udp(ctx, metadata).await
    }
}

struct Socks5PacketConn {
    inner: Arc<dyn Datagram>,
    remote_addr: std::net::SocketAddr,
    tcp_conn: SharedConn,
}

#[async_trait]
impl Datagram for Socks5PacketConn {
    async fn send_to(&self, buf: &[u8], addr: std::net::SocketAddr) -> io::Result<usize> {
        let addr = murmur_common_net::io::udp_addr_from_socket_addr(addr);
        let socks_addr = socks5t::parse_addr_to_socks_addr(&addr).ok_or_else(|| io::Error::other("invalid address"))?;
        let packet = socks5t::encode_udp_packet(&socks_addr, buf).map_err(io::Error::other)?;
        self.inner.send_to(&packet, self.remote_addr).await?;
        Ok(buf.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, std::net::SocketAddr)> {
        let (n, _) = self.inner.recv_from(buf).await?;
        let received = buf.get(..n).ok_or_else(|| io::Error::other("received more bytes than the buffer holds"))?;
        let (addr, payload_start, payload_len) = {
            let (addr, payload) = socks5t::decode_udp_packet(received).map_err(io::Error::other)?;
            let start = payload.as_ptr() as usize - buf.as_ptr() as usize;
            (addr, start, payload.len())
        };
        let udp_addr = addr.udp_addr().ok_or_else(|| io::Error::other("parse udp addr error"))?;
        buf.copy_within(payload_start..payload_start + payload_len, 0);
        Ok((payload_len, old_addr_to_socket_addr(&udp_addr)?))
    }

    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }

    fn close(&self) -> io::Result<()> {
        let _ = self.tcp_conn.close();
        self.inner.close()
    }
}

#[cfg(test)]
mod socks5_packet_conn_tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use tokio::net::{TcpListener, TcpStream, UdpSocket};
    use tokio::sync::Notify;

    use super::*;

    /// Regression test for the socks5 UDP watch task leak: closing the packet conn closes the TCP
    /// conn first, which ends the background copy loop even when the SOCKS server never closes its
    /// end of the association. `Socks5PacketConn::close` must do the same, or the watch task and
    /// its TCP connection outlive the packet conn indefinitely.
    #[tokio::test]
    async fn close_ends_the_watch_task_by_closing_the_tcp_control_conn() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.expect("bind loopback listener");
        let addr = listener.local_addr().expect("listener addr");
        let (client_conn, accept_result) = tokio::join!(TcpStream::connect(addr), listener.accept());
        let client_conn = client_conn.expect("client connect");
        // Kept alive for the whole test: the SOCKS server side of RFC 1928's UDP association
        // never closes its end on its own, so the only thing that may end the watch task is
        // `Socks5PacketConn::close` closing this test's own `client_conn` handle.
        let (_server_conn, _) = accept_result.expect("server accept");

        let tcp_conn: Box<dyn NetConn> = Box::new(client_conn);
        let watch_conn = SharedConn::from_boxed(tcp_conn);
        let watch_conn_task = watch_conn.clone();

        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.expect("bind udp socket");
        let pc: Arc<dyn Datagram> = Arc::new(udp);

        let watch_pc = Arc::clone(&pc);
        let done = Arc::new(Notify::new());
        let done_signal = Arc::clone(&done);
        tokio::spawn(async move {
            let mut reader = watch_conn_task;
            let _ = tokio::io::copy(&mut reader, &mut tokio::io::sink()).await;
            let _ = reader.close();
            let _ = watch_pc.close();
            done_signal.notify_one();
        });

        let socks_pc = Socks5PacketConn {
            inner: pc,
            remote_addr: std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            tcp_conn: watch_conn,
        };

        tokio::time::sleep(Duration::from_millis(50)).await;

        socks_pc.close().expect("close must not fail");

        let waited = tokio::time::timeout(Duration::from_secs(5), done.notified()).await;
        assert!(waited.is_ok(), "closing the packet conn must end the watch task within a bounded time");
    }
}
