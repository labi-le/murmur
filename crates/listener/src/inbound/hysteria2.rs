use std::collections::BTreeMap;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::BodyExt;
use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;
use url::Url;

use murmur_adapter_inbound::addition::{with_in_name, with_special_rules, Addition};
use murmur_common::sockopt::reuse_common::udp_reuseaddr;
use murmur_common::utils::mbps::string_to_bps;
use murmur_common_net::io::{Datagram, DatagramAsOldPacketConn, OldConnAsStream, Stream};
use murmur_common_net::packet::packet_sing::udp_addr;
use murmur_compat::sing_buf::Buffer;
use murmur_component_ca::auth::{
    client_auth_type_from_string, NO_CLIENT_CERT, REQUIRE_AND_VERIFY_CLIENT_CERT, VERIFY_CLIENT_CERT_IF_GIVEN,
};
use murmur_component_ca::keypair::{load_certificates, new_tls_key_pair_loader};
use murmur_component_ech::load_ech_key;
use murmur_component_tls::utls::{self as tls_c, ClientHelloInfo};
use murmur_constant::listener::{InboundConfig, InboundListenConfig, InboundListener};
use murmur_constant::metadata::Type;
use murmur_constant::tunnel::Tunnel;
use murmur_listener_config::hysteria2 as lc_hysteria2;
use murmur_listener_inner::tcp::handle_tcp;
use murmur_listener_sing::context::SingContext;
use murmur_listener_sing::sing::{new_listener_handler, ListenerConfig as SingListenerConfig, UDP_TIMEOUT};
use murmur_log::{debugln, infoln};
use murmur_sing::metadata::{socksaddr_from_net, Metadata as SingMetadata, Socksaddr};
use murmur_sing::network;
use murmur_std_compat::net::{Addr, Conn as NetConn, PacketConn};
use murmur_transport_hysteria2::quic::{CongestionOption, QuicConfig};
use murmur_transport_hysteria2::{MasqueradeHandler, Obfs, ServerHandler, Service, ServiceOptions};

const DEFAULT_IN_NAME: &str = "DEFAULT-HYSTERIA2";
const DEFAULT_ALPN: &str = "h3";

/// The listener's `realm-opts` block. Carried for config parity even though the transport has no
/// realm client: enabling it refuses the listener.
#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct Hysteria2RealmOption {
    pub enable: bool,
    pub server_url: String,
    pub token: String,
    pub realm_id: String,
    pub stun_servers: Vec<String>,
    pub sni: String,
    pub skip_cert_verify: bool,
    pub name_cert_verify: String,
    pub fingerprint: String,
    pub certificate: String,
    pub private_key: String,
    pub alpn: Vec<String>,
    pub proxy: String,
}

impl Hysteria2RealmOption {
    #[must_use]
    pub fn build(&self) -> lc_hysteria2::Hysteria2RealmOption {
        lc_hysteria2::Hysteria2RealmOption {
            enable: self.enable,
            server_url: self.server_url.clone(),
            token: self.token.clone(),
            realm_id: self.realm_id.clone(),
            stun_servers: self.stun_servers.clone(),
            sni: self.sni.clone(),
            skip_cert_verify: self.skip_cert_verify,
            name_cert_verify: self.name_cert_verify.clone(),
            fingerprint: self.fingerprint.clone(),
            certificate: self.certificate.clone(),
            private_key: self.private_key.clone(),
            alpn: self.alpn.clone(),
            proxy: self.proxy.clone(),
        }
    }
}

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct Hysteria2Option {
    pub base: crate::inbound::base::BaseOption,
    pub users: BTreeMap<String, String>,
    pub obfs: String,
    pub obfs_password: String,
    pub obfs_min_packet_size: i32,
    pub obfs_max_packet_size: i32,
    pub certificate: String,
    pub private_key: String,
    pub client_auth_type: String,
    pub client_auth_cert: String,
    pub ech_key: String,
    pub max_idle_time: i32,
    pub alpn: Vec<String>,
    pub up: String,
    pub down: String,
    pub ignore_client_bandwidth: bool,
    pub masquerade: String,
    pub cwnd: i32,
    pub bbr_profile: String,
    pub udp_mtu: i32,
    pub mux_option: crate::inbound::mux::MuxOption,
    pub realm_opts: Hysteria2RealmOption,
    pub initial_stream_receive_window: u64,
    pub max_stream_receive_window: u64,
    pub initial_connection_receive_window: u64,
    pub max_connection_receive_window: u64,
}

impl InboundConfig for Hysteria2Option {
    fn name(&self) -> String {
        self.base.name()
    }

    fn equal(&self, config: &dyn InboundConfig) -> bool {
        crate::inbound::base::config_equal(self, config)
    }

    fn option_to_string(&self) -> String {
        crate::inbound::base::option_to_string(self)
    }
}

#[derive(Debug)]
pub struct Hysteria2 {
    base: crate::inbound::base::Base,
    config: Arc<Hysteria2Option>,
    l: Mutex<Option<Listener>>,
    ts: lc_hysteria2::Hysteria2Server,
}

impl Hysteria2 {
    pub fn new(options: Arc<Hysteria2Option>) -> Result<Self> {
        let base = crate::inbound::base::Base::new(Arc::new(options.base.clone()))?;
        let ts = lc_hysteria2::Hysteria2Server {
            enable: true,
            listen: base.raw_address(),
            users: options.users.clone(),
            obfs: options.obfs.clone(),
            obfs_password: options.obfs_password.clone(),
            obfs_min_packet_size: options.obfs_min_packet_size,
            obfs_max_packet_size: options.obfs_max_packet_size,
            certificate: options.certificate.clone(),
            private_key: options.private_key.clone(),
            client_auth_type: options.client_auth_type.clone(),
            client_auth_cert: options.client_auth_cert.clone(),
            ech_key: options.ech_key.clone(),
            max_idle_time: options.max_idle_time,
            alpn: options.alpn.clone(),
            up: options.up.clone(),
            down: options.down.clone(),
            ignore_client_bandwidth: options.ignore_client_bandwidth,
            masquerade: options.masquerade.clone(),
            cwnd: options.cwnd,
            bbr_profile: options.bbr_profile.clone(),
            udp_mtu: options.udp_mtu,
            mux_option: options.mux_option.build(),
            realm_opts: options.realm_opts.build(),
            initial_stream_receive_window: options.initial_stream_receive_window,
            max_stream_receive_window: options.max_stream_receive_window,
            initial_connection_receive_window: options.initial_connection_receive_window,
            max_connection_receive_window: options.max_connection_receive_window,
        };
        Ok(Self { base, config: options, l: Mutex::new(None), ts })
    }
}

#[async_trait]
impl InboundListener for Hysteria2 {
    fn name(&self) -> String {
        self.config.name()
    }

    async fn listen(&self, tunnel: Arc<dyn Tunnel>) -> Result<()> {
        let listener =
            Listener::new(self.ts.clone(), self.base.listen_config(), tunnel, &self.base.additions()).await?;
        *self.l.lock() = Some(listener);
        infoln!("Hysteria2[{}] proxy listening at: {}", self.name(), self.address());
        Ok(())
    }

    fn close(&self) -> Result<()> {
        self.l.lock().as_ref().ok_or_else(|| anyhow!("Hysteria2::close called before listen"))?.close()
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
        crate::inbound::base::upcast_config(Arc::clone(&self.config))
    }
}

pub struct Listener {
    config: lc_hysteria2::Hysteria2Server,
    udp_listeners: Vec<Arc<dyn Datagram>>,
    endpoints: Vec<quinn::Endpoint>,
}

impl core::fmt::Debug for Listener {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Listener")
            .field("config", &self.config)
            .field("udp_listeners", &self.udp_listeners.len())
            .field("endpoints", &self.endpoints.len())
            .finish_non_exhaustive()
    }
}

/// S11: remove with murmur-std-compat, once `service.start`/`udp_reuseaddr` take `Arc<dyn Datagram>`.
struct SharedDatagram(Arc<dyn Datagram>);

#[async_trait]
impl Datagram for SharedDatagram {
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, std::net::SocketAddr)> {
        self.0.recv_from(buf).await
    }

    async fn send_to(&self, buf: &[u8], addr: std::net::SocketAddr) -> io::Result<usize> {
        self.0.send_to(buf, addr).await
    }

    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.0.local_addr()
    }

    fn close(&self) -> io::Result<()> {
        self.0.close()
    }

    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        self.0.as_socket()
    }
}

impl Listener {
    pub async fn new(
        config: lc_hysteria2::Hysteria2Server,
        lc: Arc<dyn InboundListenConfig>,
        tunnel: Arc<dyn Tunnel>,
        additions: &[Addition],
    ) -> Result<Self> {
        let additions: Vec<Addition> = if additions.is_empty() {
            vec![with_in_name(DEFAULT_IN_NAME), with_special_rules("")]
        } else {
            additions.to_vec()
        };

        let handler = new_listener_handler(SingListenerConfig {
            tunnel: Arc::clone(&tunnel),
            type_: Type::HYSTERIA2,
            additions,
            udp_timeout: UDP_TIMEOUT,
            mux_option: config.mux_option.clone(),
        })?;

        let mut tls_config = crate::tls_server_config(Arc::new(murmur_ntp::time::now));
        tls_config.min_version = tls_c::VERSION_TLS13;
        let cert_loader = new_tls_key_pair_loader(&config.certificate, &config.private_key)?;
        tls_config.get_certificate = Some(Arc::new(move |_info: &ClientHelloInfo| cert_loader().map(Some)));
        tls_config.client_auth = client_auth_type_from_string(&config.client_auth_type);
        if !config.client_auth_cert.is_empty() && tls_config.client_auth == NO_CLIENT_CERT {
            tls_config.client_auth = REQUIRE_AND_VERIFY_CLIENT_CERT;
        }
        if tls_config.client_auth == VERIFY_CLIENT_CERT_IF_GIVEN
            || tls_config.client_auth == REQUIRE_AND_VERIFY_CLIENT_CERT
        {
            tls_config.client_cas = Some(load_certificates(&config.client_auth_cert)?);
        }
        if !config.ech_key.is_empty() {
            load_ech_key(&config.ech_key, &mut tls_config)?;
        }
        tls_config.next_protos =
            if config.alpn.is_empty() { vec![DEFAULT_ALPN.to_owned()] } else { config.alpn.clone() };
        let tls = Arc::new(tls_c::server_rustls_config(&tls_config)?);

        let obfs = if config.obfs.is_empty() {
            None
        } else {
            Some(
                Obfs::new(
                    &config.obfs,
                    &config.obfs_password,
                    usize::try_from(config.obfs_min_packet_size).unwrap_or(usize::MAX),
                    usize::try_from(config.obfs_max_packet_size).unwrap_or(usize::MAX),
                )
                .map_err(|err| anyhow!("{err}"))?,
            )
        };

        let masquerade: Option<Arc<dyn MasqueradeHandler>> = if config.masquerade.is_empty() {
            None
        } else {
            Some(Arc::new(Masquerade::parse(&config.masquerade, Arc::clone(&tunnel))?))
        };

        if config.realm_opts.enable {
            return Err(anyhow!(
                "hysteria2 realm is not supported: murmur-transport-hysteria2 has no realm client (transport-hysteria2/src/lib.rs)"
            ));
        }

        let service = Service::new(ServiceOptions {
            send_bps: string_to_bps(&config.up),
            receive_bps: string_to_bps(&config.down),
            ignore_client_bandwidth: config.ignore_client_bandwidth,
            obfs,
            tls,
            quic: QuicConfig {
                initial_stream_receive_window: config.initial_stream_receive_window,
                max_stream_receive_window: config.max_stream_receive_window,
                initial_connection_receive_window: config.initial_connection_receive_window,
                max_connection_receive_window: config.max_connection_receive_window,
                ..QuicConfig::default()
            },
            udp_disabled: false,
            congestion: CongestionOption { name: "bbr".to_owned(), cwnd: config.cwnd },
            udp_mtu: usize::try_from(config.udp_mtu).unwrap_or(0),
            handler: Arc::new(Hysteria2Handler { handler }),
            masquerade,
        });

        let (user_names, user_passwords): (Vec<String>, Vec<String>) =
            config.users.iter().map(|(name, password)| (name.clone(), password.clone())).unzip();
        service.update_users(user_names, user_passwords);

        let mut udp_listeners: Vec<Arc<dyn Datagram>> = Vec::new();
        let mut endpoints: Vec<quinn::Endpoint> = Vec::new();
        for addr in config.listen.split(',') {
            let datagram: Arc<dyn Datagram> =
                Arc::from(lc.listen_packet(&CancellationToken::new(), "udp", addr).await?);

            if let Err(err) = udp_reuseaddr(&DatagramAsOldPacketConn(SharedDatagram(Arc::clone(&datagram)))) {
                murmur_log::warnln!("Failed to Reuse UDP Address: {err}");
            }

            let packet_conn: Arc<dyn PacketConn> =
                Arc::new(DatagramAsOldPacketConn(SharedDatagram(Arc::clone(&datagram))));
            endpoints.push(service.start(packet_conn)?);
            udp_listeners.push(datagram);
        }

        Ok(Self { config, udp_listeners, endpoints })
    }

    pub fn close(&self) -> Result<()> {
        let mut ret_err: Option<anyhow::Error> = None;
        for endpoint in &self.endpoints {
            endpoint.close(0u32.into(), b"");
        }
        for listener in &self.udp_listeners {
            if let Err(err) = listener.close() {
                ret_err = Some(err.into());
            }
        }
        ret_err.map_or(Ok(()), Err)
    }

    #[must_use]
    pub fn config(&self) -> lc_hysteria2::Hysteria2Server {
        self.config.clone()
    }

    #[must_use]
    pub fn addr_list(&self) -> Vec<Box<dyn Addr>> {
        self.udp_listeners
            .iter()
            .filter_map(|conn| conn.local_addr().ok())
            .map(|addr| -> Box<dyn Addr> { Box::new(murmur_std_compat::net::UdpAddr::from(addr)) })
            .collect()
    }
}

/// The listener handler, adapted to the transport's `ServerHandler`.
struct Hysteria2Handler {
    handler: murmur_listener_sing::sing::ListenerHandler,
}

#[async_trait]
impl ServerHandler for Hysteria2Handler {
    async fn new_connection(&self, source: Socksaddr, destination: Socksaddr, conn: Box<dyn NetConn>) -> Result<()> {
        let metadata = SingMetadata { protocol: String::new(), source, destination };
        self.handler.new_connection(SingContext::default(), Box::new(OldConnAsStream(conn)), metadata).await
    }

    async fn new_packet_connection(
        &self,
        source: Socksaddr,
        destination: Socksaddr,
        conn: Box<dyn PacketConn>,
    ) -> Result<()> {
        let metadata = SingMetadata { protocol: String::new(), source, destination };
        self.handler.new_packet_connection(SingContext::default(), Box::new(Hysteria2PacketConn(conn)), metadata).await
    }
}

/// A hysteria2 UDP session, exposed through the sing packet vocabulary the listener handler reads.
struct Hysteria2PacketConn(Box<dyn PacketConn>);

#[async_trait]
impl network::PacketReader for Hysteria2PacketConn {
    async fn read_packet(&self, buffer: &mut Buffer) -> io::Result<Socksaddr> {
        let (n, addr) = {
            let free = buffer.free_bytes();
            self.0.read_from(free).await?
        };
        buffer.extend(n);
        Ok(socksaddr_from_net(Some(addr.as_ref())))
    }
}

#[async_trait]
impl network::PacketWriter for Hysteria2PacketConn {
    async fn write_packet(&self, buffer: &Buffer, destination: &Socksaddr) -> io::Result<()> {
        self.0.write_to(buffer.bytes(), &udp_addr(destination)).await?;
        Ok(())
    }
}

#[async_trait]
impl network::PacketConn for Hysteria2PacketConn {
    async fn close(&self) -> io::Result<()> {
        self.0.close()
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.0.local_addr()
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.0.set_read_deadline(deadline)
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.0.set_write_deadline(deadline)
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.0.set_deadline(deadline)
    }
}

/// The masquerade switch: a directory to serve files from, or a URL to reverse-proxy to.
enum Masquerade {
    File(PathBuf),
    Proxy { upstream: Url, tunnel: Arc<dyn Tunnel> },
}

impl Masquerade {
    fn parse(spec: &str, tunnel: Arc<dyn Tunnel>) -> Result<Self> {
        let url = Url::parse(spec).map_err(|err| anyhow!("parse masquerade URL: {err}"))?;
        match url.scheme() {
            "file" => Ok(Self::File(PathBuf::from(url.path()))),
            "http" | "https" => Ok(Self::Proxy { upstream: url, tunnel }),
            scheme => Err(anyhow!("unknown masquerade URL scheme: {scheme}")),
        }
    }
}

#[async_trait]
impl MasqueradeHandler for Masquerade {
    async fn serve(&self, request: &http::Request<()>) -> http::Response<Bytes> {
        match self {
            Self::File(root) => serve_file(root, request.uri().path()).await,
            Self::Proxy { upstream, tunnel } => match reverse_proxy(upstream, tunnel, request).await {
                Ok(response) => response,
                Err(err) => {
                    debugln!("hysteria2: masquerade proxy: {err}");
                    let mut response = http::Response::new(Bytes::from_static(b"Bad Gateway"));
                    *response.status_mut() = http::StatusCode::BAD_GATEWAY;
                    response
                }
            },
        }
    }
}

/// Serves a plain GET of a regular file (or the directory's `index.html`): no range requests,
/// conditional GETs or directory listings.
async fn serve_file(root: &Path, raw_path: &str) -> http::Response<Bytes> {
    let root = root.to_path_buf();
    let Some(relative) = sanitize_path(raw_path) else { return not_found() };
    let mut path = root.join(relative);
    if path.is_dir() {
        path = path.join("index.html");
    }
    match tokio::fs::read(&path).await {
        Ok(body) => {
            let mut response = http::Response::new(Bytes::from(body));
            let content_type = content_type(&path);
            if let Ok(value) = http::HeaderValue::from_str(content_type) {
                response.headers_mut().insert(http::header::CONTENT_TYPE, value);
            }
            response
        }
        Err(_) => not_found(),
    }
}

/// The 404 response, matching the standard plain-text body.
fn not_found() -> http::Response<Bytes> {
    let mut response = http::Response::new(Bytes::from_static(b"404 page not found\n"));
    *response.status_mut() = http::StatusCode::NOT_FOUND;
    let headers = response.headers_mut();
    headers.insert(http::header::CONTENT_TYPE, http::HeaderValue::from_static("text/plain; charset=utf-8"));
    headers.insert("X-Content-Type-Options", http::HeaderValue::from_static("nosniff"));
    response
}

/// The path traversal guard: the request path is percent-decoded and then rejected outright if
/// any component escapes the root.
fn sanitize_path(raw_path: &str) -> Option<PathBuf> {
    let decoded = percent_decode(raw_path)?;
    let mut relative = PathBuf::new();
    for component in Path::new(&decoded).components() {
        match component {
            Component::Normal(part) => relative.push(part),
            Component::CurDir | Component::RootDir => {}
            Component::ParentDir | Component::Prefix(_) => return None,
        }
    }
    Some(relative)
}

fn percent_decode(input: &str) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while let Some(byte) = bytes.get(index) {
        if *byte == b'%' {
            let [high, low] = bytes.get(index + 1..index + 3)? else { return None };
            out.push((hex_digit(*high)? << 4) | hex_digit(*low)?);
            index += 3;
        } else {
            out.push(*byte);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn hex_digit(byte: u8) -> Option<u8> {
    char::from(byte).to_digit(16).and_then(|digit| u8::try_from(digit).ok())
}

/// Content type by file extension, narrowed to the types a masquerade directory holds in practice.
fn content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|extension| extension.to_str()).unwrap_or_default() {
        "html" | "htm" => "text/html; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "js" | "mjs" => "text/javascript; charset=utf-8",
        "json" => "application/json",
        "txt" => "text/plain; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "ico" => "image/x-icon",
        "wasm" => "application/wasm",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        _ => "application/octet-stream",
    }
}

/// The TLS client config: every field named so a new `Config` field fails the build instead of
/// silently taking its default.
#[must_use]
#[expect(
    clippy::unneeded_field_pattern,
    reason = "naming every field makes a field added to `tls_c::Config` fail the build instead of silently taking its default"
)]
fn reverse_proxy_tls_config(server_name: String) -> tls_c::Config {
    let tls_c::Config {
        rand,
        time,
        certificates,
        get_certificate,
        get_client_certificate,
        verify_peer_certificate,
        verify_connection,
        root_cas,
        next_protos,
        server_name: _,
        client_auth,
        client_cas,
        insecure_skip_verify: _,
        cipher_suites,
        session_tickets_disabled,
        min_version,
        max_version,
        curve_preferences,
        renegotiation,
        key_log_writer,
        encrypted_client_hello_config_list,
        encrypted_client_hello_rejection_verify,
        encrypted_client_hello_keys,
        get_encrypted_client_hello_keys,
        session_id_generator,
    } = tls_c::Config::default();
    tls_c::Config {
        rand,
        time,
        certificates,
        get_certificate,
        get_client_certificate,
        verify_peer_certificate,
        verify_connection,
        root_cas,
        next_protos,
        server_name,
        client_auth,
        client_cas,
        insecure_skip_verify: true,
        cipher_suites,
        session_tickets_disabled,
        min_version,
        max_version,
        curve_preferences,
        renegotiation,
        key_log_writer,
        encrypted_client_hello_config_list,
        encrypted_client_hello_rejection_verify,
        encrypted_client_hello_keys,
        get_encrypted_client_hello_keys,
        session_id_generator,
    }
}

/// The reverse proxy: the configured URL's scheme/host/path take over, the request path is
/// appended, and the incoming `Host` wins.
async fn reverse_proxy(
    upstream: &Url,
    tunnel: &Arc<dyn Tunnel>,
    request: &http::Request<()>,
) -> Result<http::Response<Bytes>> {
    let upstream_host = upstream.host_str().ok_or_else(|| anyhow!("masquerade URL has no host"))?.to_owned();
    let port = upstream.port_or_known_default().unwrap_or_else(|| if upstream.scheme() == "https" { 443 } else { 80 });
    let target = format!(
        "{}{}",
        single_joining_slash(upstream.path(), request.uri().path()),
        joined_query(upstream.query(), request.uri().query())
    );

    let raw = handle_tcp(Some(Arc::clone(tunnel)), &format!("{upstream_host}:{port}"), "").await?;
    let stream: Box<dyn Stream> = if upstream.scheme() == "https" {
        let config = reverse_proxy_tls_config(upstream_host.clone());
        let conn = tls_c::client(Box::new(OldConnAsStream(raw)), Arc::new(config));
        conn.handshake_context(&CancellationToken::new()).await?;
        Box::new(conn)
    } else {
        Box::new(OldConnAsStream(raw))
    };

    let (mut sender, connection) = hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream)).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let mut builder = http::Request::builder().method(request.method().clone()).uri(target.as_str());
    for (name, value) in request.headers() {
        if is_hop_by_hop(name.as_str()) || name == http::header::HOST {
            continue;
        }
        builder = builder.header(name, value);
    }
    let host = request
        .headers()
        .get(http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .unwrap_or(upstream_host.as_str());
    builder = builder.header(http::header::HOST, host);

    let body = http_body_util::Full::new(Bytes::new());
    let response =
        sender.send_request(builder.body(body)?).await.map_err(|err| anyhow!("masquerade upstream request: {err}"))?;
    let status = response.status();
    let mut headers = response.headers().clone();
    let body =
        response.into_body().collect().await.map_err(|err| anyhow!("masquerade upstream body: {err}"))?.to_bytes();
    if let Ok(length) = http::HeaderValue::from_str(&body.len().to_string()) {
        headers.insert(http::header::CONTENT_LENGTH, length);
    }
    let mut response = http::Response::new(body);
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    Ok(response)
}

fn single_joining_slash(a: &str, b: &str) -> String {
    let a_slash = a.ends_with('/');
    let b_slash = b.starts_with('/');
    match (a_slash, b_slash) {
        (true, true) => format!("{a}{}", b.strip_prefix('/').unwrap_or_default()),
        (false, false) => format!("{a}/{b}"),
        _ => format!("{a}{b}"),
    }
}

/// The query merge for the rewritten request URL.
fn joined_query(upstream: Option<&str>, incoming: Option<&str>) -> String {
    match (upstream, incoming) {
        (Some(upstream), Some(incoming)) if !upstream.is_empty() && !incoming.is_empty() => {
            format!("?{upstream}&{incoming}")
        }
        (Some(upstream), Some(incoming)) => format!("?{upstream}{incoming}"),
        (Some(upstream), None) => format!("?{upstream}"),
        (None, Some(incoming)) => format!("?{incoming}"),
        (None, None) => String::new(),
    }
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "proxy-connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

#[cfg(test)]
mod tests {
    //!
    //! This test drives the listener with `murmur_transport_hysteria2`'s client directly, so the
    //! option mapping, the TLS and obfs wiring, the handler bridge, the masquerade switch and the
    //! UDP session are covered without a real tunnel. `LoopbackTunnel` echoes a stream or a
    //! datagram back, except for the INNER connection the masquerade reverse proxy opens.

    use std::net::SocketAddr;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UdpSocket;

    use murmur_component_nat::table::Table;
    use murmur_constant::adapters::{NatTable, UDPPacket};
    use murmur_constant::metadata::{Metadata, NetWork};
    use murmur_std_compat::net::UdpAddr;
    use murmur_testsupport::{tls_certificate, tls_private_key, REMOTE_ADDR};
    use murmur_transport_hysteria2::{Client, ClientOptions};

    use super::*;

    const PASSWORD: &str = "hysteria2-inbound-password";
    const SERVER_NAME: &str = "hysteria2.test";
    const PAYLOAD: &[u8] = b"hysteria2 inbound round trip";
    const DEST_PORT: u16 = 80;
    const TIMEOUT: Duration = Duration::from_secs(10);

    /// Echoes TCP payloads and UDP datagrams back; a `Type::INNER` connection is the masquerade
    /// reverse proxy's own dial, which a real tunnel routes to the address it names.
    struct LoopbackTunnel {
        seen: Mutex<Vec<Metadata>>,
    }

    impl LoopbackTunnel {
        fn new() -> Self {
            Self { seen: Mutex::new(Vec::new()) }
        }

        fn seen(&self) -> Vec<Metadata> {
            self.seen.lock().clone()
        }
    }

    #[async_trait]
    impl Tunnel for LoopbackTunnel {
        async fn handle_tcp_conn(&self, mut conn: Box<dyn Stream>, metadata: Metadata) {
            self.seen.lock().push(metadata.clone());
            if metadata.type_ == Type::INNER {
                let Ok(mut upstream) = tokio::net::TcpStream::connect(metadata.remote_address()).await else {
                    return;
                };
                let _ = tokio::io::copy_bidirectional(&mut conn, &mut upstream).await;
                return;
            }
            let mut buf = [0u8; 4096];
            loop {
                match conn.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => {
                        if conn.write_all(&buf[..n]).await.is_err() {
                            return;
                        }
                    }
                }
            }
        }

        fn handle_udp_packet(&self, packet: Arc<dyn UDPPacket>, metadata: Metadata) {
            self.seen.lock().push(metadata.clone());
            let from = metadata
                .raw_dst_addr
                .as_ref()
                .and_then(|addr| murmur_common_net::io::old_addr_to_socket_addr(addr.as_ref()).ok())
                .expect("a hysteria2 datagram must carry its destination");
            let data = packet.data().to_vec();
            tokio::spawn(async move {
                let _ = packet.write_back(&data, Some(from)).await;
            });
        }

        fn nat_table(&self) -> Arc<dyn NatTable> {
            Arc::new(Table::default())
        }
    }

    fn inbound_option(options: Hysteria2Option) -> Hysteria2Option {
        Hysteria2Option {
            base: crate::inbound::base::BaseOption {
                name_str: "hysteria2_inbound".to_owned(),
                listen: "127.0.0.1".to_owned(),
                port: "0".to_owned(),
                ..Default::default()
            },
            users: [(String::from("alice"), String::from(PASSWORD))].into(),
            certificate: tls_certificate().to_owned(),
            private_key: tls_private_key().to_owned(),
            ..options
        }
    }

    async fn start_inbound(tunnel: &Arc<LoopbackTunnel>, options: Hysteria2Option) -> (Hysteria2, SocketAddr) {
        murmur_testsupport_probe::ensure_test_crypto_provider();
        let inbound = Hysteria2::new(Arc::new(inbound_option(options))).expect("hysteria2 inbound construction");
        let concrete = Arc::clone(tunnel);
        let listener: Arc<dyn Tunnel> = concrete;
        inbound.listen(listener).await.expect("hysteria2 inbound listen");
        let addr = inbound.address().parse().expect("bound address");
        (inbound, addr)
    }

    async fn client_options(addr: SocketAddr, password: &str) -> ClientOptions {
        let config = tls_c::Config {
            min_version: tls_c::VERSION_TLS13,
            next_protos: vec![DEFAULT_ALPN.to_owned()],
            server_name: SERVER_NAME.to_owned(),
            insecure_skip_verify: true,
            ..Default::default()
        };
        ClientOptions {
            password: password.to_owned(),
            server_address: Socksaddr::from_ip(addr.ip(), addr.port()),
            server_ports: Vec::new(),
            hop_interval: Duration::ZERO,
            hop_interval_max: Duration::ZERO,
            send_bps: 0,
            receive_bps: 0,
            obfs: None,
            server_name: SERVER_NAME.to_owned(),
            tls: Arc::new(tls_c::client_rustls_config(&config).expect("hysteria2 client rustls config")),
            quic: QuicConfig { enable_datagrams: true, ..QuicConfig::default() },
            udp_disabled: false,
            udp_mtu: 0,
            congestion: CongestionOption::default(),
            handshake_timeout: TIMEOUT,
            packet_conn: Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind the client socket")),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_inbound_hysteria2_stream_round_trip() {
        let tunnel = Arc::new(LoopbackTunnel::new());
        let (inbound, addr) = start_inbound(&tunnel, Hysteria2Option::default()).await;
        let client = Client::new(client_options(addr, PASSWORD).await).expect("build the client");
        let ctx = CancellationToken::new();
        let destination = Socksaddr::from_ip(*REMOTE_ADDR, DEST_PORT);

        let mut conn = tokio::time::timeout(TIMEOUT, client.dial_conn(&ctx, destination))
            .await
            .expect("the dial completes in time")
            .expect("the client authenticates");
        conn.write_all(PAYLOAD).await.expect("write the stream payload");
        let mut echoed = vec![0u8; PAYLOAD.len()];
        tokio::time::timeout(TIMEOUT, conn.read_exact(&mut echoed))
            .await
            .expect("the stream echo arrives in time")
            .expect("read the stream echo");
        assert_eq!(echoed, PAYLOAD, "the payload round-trips through the hysteria2 stream");

        let seen = tunnel.seen();
        let metadata = seen.first().expect("the tunnel saw the proxied connection");
        assert_eq!(metadata.type_, Type::HYSTERIA2, "the hysteria2 type reaches the tunnel");
        assert_eq!(metadata.network, NetWork::TCP);
        assert_eq!(metadata.in_name, "hysteria2_inbound", "the inbound name reaches the metadata");
        assert_eq!(
            metadata.remote_address(),
            SocketAddr::new(*REMOTE_ADDR, DEST_PORT).to_string(),
            "the destination comes from the hysteria TCP request"
        );

        client.close_with_error("done").expect("close the client");
        inbound.close().expect("hysteria2 inbound close");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_inbound_hysteria2_datagram_round_trip() {
        let tunnel = Arc::new(LoopbackTunnel::new());
        let (inbound, addr) = start_inbound(&tunnel, Hysteria2Option::default()).await;
        let client = Client::new(client_options(addr, PASSWORD).await).expect("build the client");
        let ctx = CancellationToken::new();

        let packet_conn = client.listen_packet(&ctx).await.expect("open a UDP session");
        packet_conn
            .write_to(PAYLOAD, &UdpAddr::from(SocketAddr::new(*REMOTE_ADDR, DEST_PORT)))
            .await
            .expect("send the datagram");
        let mut buf = vec![0u8; 64];
        let (n, source) = tokio::time::timeout(TIMEOUT, packet_conn.read_from(&mut buf))
            .await
            .expect("the datagram echo arrives in time")
            .expect("read the datagram echo");
        assert_eq!(&buf[..n], PAYLOAD, "the payload round-trips through a hysteria2 session");
        assert_eq!(
            source.string(),
            SocketAddr::new(*REMOTE_ADDR, DEST_PORT).to_string(),
            "the echo is attributed to the dialled destination"
        );

        let seen = tunnel.seen();
        let metadata = seen.first().expect("the tunnel saw the proxied datagram");
        assert_eq!(metadata.type_, Type::HYSTERIA2, "the hysteria2 type reaches the tunnel");
        assert_eq!(metadata.network, NetWork::UDP);
        assert_eq!(
            metadata.remote_address(),
            SocketAddr::new(*REMOTE_ADDR, DEST_PORT).to_string(),
            "the destination comes from the hysteria UDP request"
        );

        client.close_with_error("done").expect("close the client");
        inbound.close().expect("hysteria2 inbound close");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_inbound_hysteria2_wrong_password_fails_closed() {
        let tunnel = Arc::new(LoopbackTunnel::new());
        let (inbound, addr) = start_inbound(&tunnel, Hysteria2Option::default()).await;
        let client = Client::new(client_options(addr, "wrong-password").await).expect("build the client");
        let ctx = CancellationToken::new();
        let destination = Socksaddr::from_ip(*REMOTE_ADDR, DEST_PORT);

        let mut carried_traffic = false;
        match tokio::time::timeout(TIMEOUT, client.dial_conn(&ctx, destination)).await {
            Ok(Ok(mut conn)) => {
                if conn.write_all(PAYLOAD).await.is_ok() {
                    let mut echoed = vec![0u8; PAYLOAD.len()];
                    carried_traffic =
                        matches!(tokio::time::timeout(TIMEOUT, conn.read_exact(&mut echoed)).await, Ok(Ok(_)));
                }
            }
            Ok(Err(_)) => {}
            Err(_) => panic!("the wrong-password dial hung instead of being refused"),
        }
        assert!(!carried_traffic, "a wrong hysteria2 password must not carry traffic");

        inbound.close().expect("hysteria2 inbound close");
    }

    #[test]
    fn parse_listener_maps_hysteria2_options() {
        let yaml = concat!(
            "name: hysteria2-in\n",
            "type: hysteria2\n",
            "port: 8443\n",
            "users:\n",
            "  alice: secret\n",
            "obfs: salamander\n",
            "obfs-password: obfs-secret\n",
            "certificate: cert.pem\n",
            "private-key: key.pem\n",
            "up: 100 Mbps\n",
            "down: 200 Mbps\n",
            "ignore-client-bandwidth: true\n",
            "masquerade: file:///var/www\n",
            "cwnd: 64\n",
            "bbr-profile: conservative\n",
            "udp-mtu: 1400\n",
            "alpn: [h3, h2]\n",
            "max-idle-time: 30000\n",
            "mux-option:\n",
            "  padding: true\n",
            "realm-opts:\n",
            "  enable: false\n",
            "  server-url: https://realm.example.com\n",
            "initial-stream-receive-window: 1024\n",
        );
        let mapping: serde_yaml::Mapping = serde_yaml::from_str(yaml).expect("parse yaml");
        let listener = crate::parse::parse_listener(&mapping).expect("hysteria2 listener parses");
        let option: serde_json::Value =
            serde_json::from_str(&listener.config().option_to_string()).expect("option json");

        assert_eq!(option["users"]["alice"], "secret");
        assert_eq!(option["obfs"], "salamander");
        assert_eq!(option["obfs_password"], "obfs-secret");
        assert_eq!(option["certificate"], "cert.pem");
        assert_eq!(option["private_key"], "key.pem");
        assert_eq!(option["up"], "100 Mbps");
        assert_eq!(option["down"], "200 Mbps");
        assert_eq!(option["ignore_client_bandwidth"], true);
        assert_eq!(option["masquerade"], "file:///var/www");
        assert_eq!(option["cwnd"], 64);
        assert_eq!(option["bbr_profile"], "conservative");
        assert_eq!(option["udp_mtu"], 1400);
        assert_eq!(option["alpn"], serde_json::json!(["h3", "h2"]));
        assert_eq!(option["max_idle_time"], 30000);
        assert_eq!(option["mux_option"]["padding"], true);
        assert_eq!(option["realm_opts"]["server_url"], "https://realm.example.com");
        assert_eq!(option["initial_stream_receive_window"], 1024);
        assert_eq!(option["base"]["port"], "8443");
        assert_eq!(option["base"]["listen"], "", "the 0.0.0.0 default is applied by Base, not by the option");
    }

    #[test]
    fn parse_listener_applies_hysteria2_zero_value_defaults() {
        // The `certificate`/`private-key` fields are required by the config structure.
        let yaml = concat!(
            "name: hysteria2-in\n",
            "type: hysteria2\n",
            "port: 8443\n",
            "certificate: cert.pem\n",
            "private-key: key.pem\n",
        );
        let mapping: serde_yaml::Mapping = serde_yaml::from_str(yaml).expect("parse yaml");
        let listener = crate::parse::parse_listener(&mapping).expect("hysteria2 listener parses");
        let option: serde_json::Value =
            serde_json::from_str(&listener.config().option_to_string()).expect("option json");

        assert_eq!(option["alpn"], serde_json::json!([]), "ALPN defaults to `h3` at listen time, not in the option");
        assert_eq!(option["udp_mtu"], 0, "the 1197-byte default is the transport's, as in sing_hysteria2");
        assert_eq!(option["realm_opts"]["enable"], false);
    }

    #[test]
    fn parse_listener_requires_a_certificate_and_a_private_key() {
        let yaml = "name: hysteria2-in\ntype: hysteria2\nport: 8443\n";
        let mapping: serde_yaml::Mapping = serde_yaml::from_str(yaml).expect("parse yaml");
        let err = crate::parse::parse_listener(&mapping).err().expect("TLS material is required").to_string();
        assert!(err.contains("certificate") && err.contains("private-key"), "{err}");
    }

    async fn listen_error(options: Hysteria2Option) -> String {
        murmur_testsupport_probe::ensure_test_crypto_provider();
        let inbound = Hysteria2::new(Arc::new(inbound_option(options))).expect("hysteria2 inbound construction");
        let tunnel: Arc<dyn Tunnel> = Arc::new(LoopbackTunnel::new());
        inbound.listen(tunnel).await.expect_err("the listen must be refused").to_string()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_unknown_obfs_type_is_rejected() {
        let message = listen_error(Hysteria2Option {
            obfs: "nonesuch".to_owned(),
            obfs_password: "pw".to_owned(),
            ..Default::default()
        })
        .await;
        assert_eq!(message, "unknown obfs type: nonesuch");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_obfs_without_a_password_is_rejected() {
        let message = listen_error(Hysteria2Option { obfs: "salamander".to_owned(), ..Default::default() }).await;
        assert_eq!(message, "missing obfs password");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_unknown_masquerade_scheme_is_rejected() {
        let message =
            listen_error(Hysteria2Option { masquerade: "ftp://example.com".to_owned(), ..Default::default() }).await;
        assert_eq!(message, "unknown masquerade URL scheme: ftp");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn an_enabled_realm_is_rejected() {
        let options = Hysteria2Option {
            realm_opts: Hysteria2RealmOption { enable: true, ..Default::default() },
            ..Default::default()
        };
        let message = listen_error(options).await;
        assert!(message.contains("hysteria2 realm is not supported"), "{message}");
    }

    fn masquerade_request(path: &str) -> http::Request<()> {
        http::Request::builder().uri(path).body(()).expect("build the request")
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_file_masquerade_serves_the_directory_index() {
        let root = std::env::temp_dir().join(format!("hysteria2-masquerade-{}", std::process::id()));
        std::fs::create_dir_all(&root).expect("create the masquerade directory");
        let body = b"<html>masquerade</html>";
        std::fs::write(root.join("index.html"), body).expect("write index.html");

        let tunnel: Arc<dyn Tunnel> = Arc::new(LoopbackTunnel::new());
        let masquerade =
            Masquerade::parse(&format!("file://{}", root.display()), tunnel).expect("parse the file masquerade");
        let response = masquerade.serve(&masquerade_request("/")).await;
        assert_eq!(response.status(), http::StatusCode::OK);
        assert_eq!(
            response.headers()[http::header::CONTENT_TYPE].to_str().expect("content type"),
            "text/html; charset=utf-8"
        );
        assert_eq!(&response.body()[..], &body[..]);

        let traversal = masquerade.serve(&masquerade_request("/../etc/passwd")).await;
        assert_eq!(traversal.status(), http::StatusCode::NOT_FOUND, "a path outside the root is not served");
        let traversal = masquerade.serve(&masquerade_request("/%2e%2e/etc/passwd")).await;
        assert_eq!(traversal.status(), http::StatusCode::NOT_FOUND, "a percent-encoded escape is not served");

        std::fs::remove_dir_all(&root).expect("remove the masquerade directory");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_http_masquerade_proxies_to_its_upstream() {
        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind the upstream");
        let upstream_addr = upstream.local_addr().expect("upstream address");
        tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.expect("accept the proxied request");
            let mut buf = vec![0u8; 4096];
            let n = stream.read(&mut buf).await.expect("read the proxied request");
            let request = String::from_utf8_lossy(&buf[..n]);
            assert!(request.starts_with("GET /root/page?x=1 HTTP/1.1"), "{request}");
            assert!(request.to_ascii_lowercase().contains("host: example.com"), "{request}");
            let body = b"upstream body";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.expect("write the response head");
            stream.write_all(body).await.expect("write the response body");
        });

        let tunnel: Arc<dyn Tunnel> = Arc::new(LoopbackTunnel::new());
        let masquerade =
            Masquerade::parse(&format!("http://{upstream_addr}/root"), tunnel).expect("parse the http masquerade");
        let request = http::Request::builder()
            .uri("/page?x=1")
            .header(http::header::HOST, "example.com")
            .body(())
            .expect("build the request");
        let response = masquerade.serve(&request).await;

        assert_eq!(response.status(), http::StatusCode::OK);
        assert_eq!(&response.body()[..], b"upstream body");
    }
}
