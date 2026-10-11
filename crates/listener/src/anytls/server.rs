//! `NEEDED SHIM ITEM: murmur_sing::metadata::SocksaddrSerializer::ReadAddrPort`, mirroring
//! `transport/anytls/client.rs`'s `write_socksaddr` note for the same
//! unmirrored serializer: `read_socksaddr` below implements the read direction (address then
//! port, no port-then-address option) as a local helper, together with
//! local `parse_socksaddr_host_port`/`parse_socksaddr`/`socksaddr_from_net` copies of the
//! `pub(crate)`-scoped helpers already provided (but not exposed) by `listener::sing::sing`.
//!
//! DEVIATION: the user would be carried in a private context field that
//! `listener::sing::context::SingContext` only reads (`get_additions`). This crate instead folds the
//! authenticated user directly into the context's public `additions` list via
//! `with_additions`/`with_in_user`, which `get_additions` merges identically (the
//! `murmur_listener_sing::context::with_user` setter also exists and is not used here).
//!
//! DEVIATION: a cached conn that shares the live buffer would remove the bytes consumed from
//! it after wrapping (padding) from what the cached conn later replays;
//! `common::net::cached::new_cached_conn` instead snapshots a fixed `Vec<u8>`, so this crate reads
//! the whole handshake header from `b` first and hands the cached conn only the bytes still unread
//! afterward, then releases `b` immediately (the buffer is held until the connection handler
//! returns, via a deferred release). Both are observationally identical: nothing else touches `b`
//! before that release point.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use arc_swap::ArcSwapOption;
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use crate::jls::listener as jls;
use crate::shadowtls::listener::{self as shadowtls, Builder as ShadowTlsBuilder};
use murmur_adapter_inbound::addition::{with_in_name, with_in_user, with_special_rules, Addition};
use murmur_common_net::io::{close_stream, Acceptor, Stream as NetStream};
use murmur_common_net::new_cached_conn;
use murmur_compat::sing_buf;
use murmur_component_ca::auth::{client_auth_type_from_string, NO_CLIENT_CERT};
use murmur_component_ca::keypair::{load_certificates, new_tls_key_pair_loader};
use murmur_component_ech::load_ech_key;
use murmur_component_tls::utls::{self as tls, ClientAuthType, ClientHelloInfo};
use murmur_constant::listener::{InboundListenConfig, MultiAddrListener};
use murmur_constant::metadata::Type;
use murmur_constant::tunnel::Tunnel;
use murmur_listener_config::anytls::AnyTLSServer;
use murmur_listener_sing::context::{with_additions, SingContext};
use murmur_listener_sing::sing::{new_listener_handler, ListenerConfig, ListenerHandler, MuxOption, SingMetadata};
use murmur_ntp::time::now as ntp_now;
use murmur_sing::metadata::Socksaddr;
use murmur_std_compat::net::{Addr, Conn as NetConn, TcpAddr};
use murmur_transport_anytls::padding::padding::{update_padding_scheme, PaddingFactory, DEFAULT_PADDING_SCHEME};
use murmur_transport_anytls::session::session::Session;
use murmur_transport_anytls::session::stream::{Stream, StreamConn};

pub struct Listener {
    closed: AtomicBool,
    config: AnyTLSServer,
    listeners: Vec<Arc<dyn Acceptor>>,
    user_map: HashMap<[u8; 32], String>,
    padding: Arc<ArcSwapOption<PaddingFactory>>,
}

impl std::fmt::Debug for Listener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Listener")
            .field("closed", &self.closed.load(Ordering::Relaxed))
            .field("users", &self.user_map.len())
            .finish_non_exhaustive()
    }
}

pub async fn new(
    config: AnyTLSServer,
    lc: Arc<dyn InboundListenConfig>,
    tunnel: Arc<dyn Tunnel>,
    additions: Vec<Addition>,
) -> Result<Arc<Listener>> {
    let additions =
        if additions.is_empty() { vec![with_in_name("DEFAULT-ANYTLS"), with_special_rules("")] } else { additions };

    let mut shadow_tls_builder: Option<ShadowTlsBuilder> = None;
    let mut jls_builder: Option<jls::Builder> = None;

    let mut tls_config = crate::tls_server_config(Arc::new(ntp_now));
    if !config.certificate.is_empty() && !config.private_key.is_empty() {
        let cert_loader = new_tls_key_pair_loader(&config.certificate, &config.private_key)?;
        tls_config.get_certificate = Some(Arc::new(move |_info: &ClientHelloInfo| cert_loader().map(Some)));

        if !config.ech_key.is_empty() {
            load_ech_key(&config.ech_key, &mut tls_config)?;
        }
    }
    tls_config.client_auth = client_auth_type_from_string(&config.client_auth_type);
    if !config.client_auth_cert.is_empty() && tls_config.client_auth == NO_CLIENT_CERT {
        tls_config.client_auth = ClientAuthType::REQUIRE_AND_VERIFY_CLIENT_CERT;
    }
    if tls_config.client_auth == ClientAuthType::VERIFY_CLIENT_CERT_IF_GIVEN
        || tls_config.client_auth == ClientAuthType::REQUIRE_AND_VERIFY_CLIENT_CERT
    {
        tls_config.client_cas = Some(load_certificates(&config.client_auth_cert)?);
    }
    if tls_config.client_auth != NO_CLIENT_CERT && tls_config.get_certificate.is_none() {
        return Err(anyhow!("client-auth requires certificate"));
    }
    let mut security_modes: Vec<&str> = Vec::with_capacity(4);
    if tls_config.get_certificate.is_some() {
        security_modes.push("certificate");
    }
    if config.shadow_tls.enable {
        security_modes.push("shadow-tls");
    }
    if config.res_tls.enable {
        return Err(anyhow!("res-tls is not supported: Restls has no Rust implementation (see README)"));
    }
    if config.jls_config.enable {
        security_modes.push("jls");
    }
    if security_modes.len() > 1 {
        return Err(anyhow!("security modes are mutually exclusive: {}", security_modes.join(", ")));
    }
    if config.shadow_tls.enable {
        shadow_tls_builder = Some(shadowtls::new(&config.shadow_tls, Arc::clone(&tunnel))?);
    }
    if config.jls_config.enable {
        jls_builder = Some(jls::new(&config.jls_config, Arc::clone(&tunnel))?);
    }

    let mut user_map: HashMap<[u8; 32], String> = HashMap::new();
    for (user, password) in &config.users {
        let digest = Sha256::digest(password.as_bytes());
        let mut key = [0u8; 32];
        key.copy_from_slice(&digest);
        user_map.insert(key, user.clone());
    }

    let padding: Arc<ArcSwapOption<PaddingFactory>> = Arc::new(ArcSwapOption::default());
    if config.padding_scheme.is_empty() {
        update_padding_scheme(DEFAULT_PADDING_SCHEME, &padding);
    } else if !update_padding_scheme(config.padding_scheme.as_bytes(), &padding) {
        return Err(anyhow!("incorrect padding scheme format"));
    }

    let h = Arc::new(new_listener_handler(ListenerConfig {
        tunnel,
        type_: Type::ANYTLS,
        additions,
        udp_timeout: std::time::Duration::ZERO,
        mux_option: MuxOption::default(),
    })?);

    let tls_config = Arc::new(tls_config);
    let listen_ctx = CancellationToken::new();
    let mut listeners: Vec<Arc<dyn Acceptor>> = Vec::new();
    for addr in config.listen.split(',') {
        let l: Box<dyn Acceptor> = lc.listen(&listen_ctx, "tcp", addr).await?;
        let l: Box<dyn Acceptor> = if let Some(builder) = &shadow_tls_builder {
            builder.new_listener(l)
        } else if let Some(builder) = &jls_builder {
            builder.new_listener(l)
        } else if tls_config.get_certificate.is_some() {
            tls::new_listener(Arc::from(l), Arc::clone(&tls_config))
        } else if !config.allow_insecure {
            return Err(anyhow!("disallow using AnyTLS without certificates/shadow-tls/allow-insecure config"));
        } else {
            l
        };
        listeners.push(Arc::from(l));
    }

    let sl = Arc::new(Listener { closed: AtomicBool::new(false), config, listeners, user_map, padding });

    for l in &sl.listeners {
        tokio::spawn(accept_loop(Arc::clone(&sl), Arc::clone(l), Arc::clone(&h)));
    }

    Ok(sl)
}

async fn accept_loop(sl: Arc<Listener>, l: Arc<dyn Acceptor>, h: Arc<ListenerHandler>) {
    loop {
        let Ok(c) = l.accept().await else {
            if sl.closed.load(Ordering::SeqCst) {
                break;
            }
            continue;
        };
        let sl = Arc::clone(&sl);
        let h = Arc::clone(&h);
        tokio::spawn(async move { sl.handle_conn(c, h).await });
    }
}

impl MultiAddrListener for Listener {
    fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        let mut ret_err = None;
        for lis in &self.listeners {
            if let Err(err) = lis.close() {
                ret_err = Some(err);
            }
        }
        match ret_err {
            Some(err) => Err(err.into()),
            None => Ok(()),
        }
    }

    fn config(&self) -> String {
        self.config.to_string()
    }

    fn addr_list(&self) -> Vec<Box<dyn Addr>> {
        fn boxed_addr(addr: SocketAddr) -> Box<dyn Addr> {
            Box::new(TcpAddr::from(addr))
        }
        self.listeners.iter().filter_map(|lis| lis.addr().ok()).map(boxed_addr).collect()
    }
}

impl Listener {
    pub async fn handle_conn(&self, conn: Box<dyn NetStream>, h: Arc<ListenerHandler>) {
        let mut conn = conn;

        let mut b = sing_buf::new_packet();
        if b.read_once_from(&mut conn).await.is_err() {
            b.release();
            let _ = close_stream(&*conn);
            return;
        }

        let password_sha256: [u8; 32] = if let Ok(Ok(arr)) = b.read_bytes(32).map(<[u8; 32]>::try_from) {
            arr
        } else {
            b.release();
            let _ = close_stream(&*conn);
            return;
        };
        let user = if let Some(user) = self.user_map.get(&password_sha256) {
            user.clone()
        } else {
            b.release();
            let _ = close_stream(&*conn);
            return;
        };
        let ctx = with_additions(&SingContext::default(), vec![with_in_user(&user)]);

        let padding_len = if let Ok(Ok(arr)) = b.read_bytes(2).map(<[u8; 2]>::try_from) {
            u16::from_be_bytes(arr)
        } else {
            b.release();
            let _ = close_stream(&*conn);
            return;
        };
        if padding_len > 0 && b.read_bytes(padding_len as usize).is_err() {
            b.release();
            let _ = close_stream(&*conn);
            return;
        }

        let remaining = b.bytes().to_vec();
        b.release();

        // S11: remove with murmur-std-compat, once transport_anytls::session::Session::server takes/returns
        // Box<dyn Stream> instead of the old murmur_std_compat::net::Conn.
        let cached: Box<dyn NetConn> = Box::new(new_cached_conn(conn, remaining));

        let padding = Arc::clone(&self.padding);
        let session = Arc::new(Session::server(
            cached,
            Some(Arc::new(move |stream: Arc<Stream>| {
                let h = Arc::clone(&h);
                let ctx = ctx.clone();
                tokio::spawn(async move { handle_stream(stream, h, ctx).await });
            })),
            padding,
        ));
        session.run().await;
        let _ = session.close();
    }
}

/// The per-stream handler passed to the server session.
async fn handle_stream(stream: Arc<Stream>, h: Arc<ListenerHandler>, ctx: SingContext) {
    let Ok(destination) = read_socksaddr(&stream).await else {
        let _ = stream.close().await;
        return;
    };

    if stream.handshake_success().await.is_err() {
        let _ = stream.close().await;
        return;
    }

    let source = socksaddr_from_net(stream.remote_addr().ok());
    let conn: Box<dyn NetStream> = Box::new(StreamConn::new(Arc::clone(&stream)));
    let _ = h.new_connection(ctx, conn, SingMetadata { protocol: String::new(), source, destination }).await;
    let _ = stream.close().await;
}

async fn read_full(stream: &Stream, buf: &mut [u8]) -> io::Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = match buf.get_mut(filled..) {
            Some(slot) => stream.read(slot).await?,
            None => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF")),
        };
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"));
        }
        filled += n;
    }
    Ok(())
}

/// `ReadAddrPort` for the default serializer; see the module doc.
async fn read_socksaddr(stream: &Stream) -> Result<Socksaddr> {
    let mut family = [0u8; 1];
    read_full(stream, &mut family).await?;
    let mut addr = match family[0] {
        0x01 => {
            let mut octets = [0u8; 4];
            read_full(stream, &mut octets).await?;
            Socksaddr { fqdn: String::new(), addr: Some(IpAddr::V4(Ipv4Addr::from(octets))), port: 0 }
        }
        0x04 => {
            let mut octets = [0u8; 16];
            read_full(stream, &mut octets).await?;
            Socksaddr { fqdn: String::new(), addr: Some(IpAddr::V6(Ipv6Addr::from(octets))), port: 0 }
        }
        0x03 => {
            let mut len_buf = [0u8; 1];
            read_full(stream, &mut len_buf).await?;
            let mut fqdn_buf = vec![0u8; len_buf[0] as usize];
            read_full(stream, &mut fqdn_buf).await?;
            let fqdn = String::from_utf8(fqdn_buf)?;
            parse_socksaddr_host_port(&fqdn, 0)
        }
        other => return Err(anyhow!("unknown address family: {other}")),
    };
    if addr.is_valid() {
        let mut port_buf = [0u8; 2];
        read_full(stream, &mut port_buf).await?;
        addr.port = u16::from_be_bytes(port_buf);
    }
    Ok(addr)
}

/// Parses a host and port into a SOCKS address; see the module doc.
fn parse_socksaddr_host_port(host: &str, port: u16) -> Socksaddr {
    let unwrapped = host.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')).unwrap_or(host);
    match unwrapped.parse::<IpAddr>() {
        Ok(addr) => Socksaddr { fqdn: String::new(), addr: Some(addr), port },
        Err(_) => Socksaddr { fqdn: host.to_owned(), addr: None, port },
    }
}

/// The SOCKS address parser; see the module doc.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "ports are wire-encoded as u16 and the serializer casts the parsed integer the same way"
)]
fn parse_socksaddr(address: &str) -> Socksaddr {
    match murmur_common_net::split_host_port(address) {
        Ok((host, port, _)) => parse_socksaddr_host_port(&host, murmur_constant::metadata::parse_int(&port) as u16),
        Err(_) => parse_socksaddr_host_port(address, 0),
    }
}

/// Builds a SOCKS address from a socket address; see the module doc.
fn socksaddr_from_net(addr: Option<Box<dyn Addr>>) -> Socksaddr {
    let Some(addr) = addr else {
        return Socksaddr::default();
    };
    match murmur_std_compat::net::sock_addr_of(addr.as_ref()) {
        Some(murmur_std_compat::net::SockAddr::Tcp(tcp)) => return Socksaddr::from_ip(tcp.ip, tcp.port),
        Some(murmur_std_compat::net::SockAddr::Udp(udp)) => return Socksaddr::from_ip(udp.ip, udp.port),
        None => {}
    }
    if let Some(addr_port) = addr.addr_port() {
        return Socksaddr { fqdn: addr_port.fqdn.unwrap_or_default(), addr: addr_port.ip, port: addr_port.port };
    }
    parse_socksaddr(&addr.string())
}
