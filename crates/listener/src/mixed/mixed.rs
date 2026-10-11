use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};

use crate::auth::auth::DEFAULT;
use crate::http::proxy::handle_conn as http_handle_conn;
use crate::socks::tcp::{handle_socks4, handle_socks5};
use murmur_adapter_inbound::addition::{with_in_name, with_special_rules, Addition};
use murmur_adapter_inbound::auth::skip_auth_remote_addr;
use murmur_adapter_inbound::ipfilter::is_remote_addr_dis_allowed;
use murmur_adapter_inbound::listen::default_listen_config;
use murmur_common_net::io::{Acceptor, Stream};
use murmur_component::auth::auth::AuthStore;
use murmur_component_ca::auth::client_auth_type_from_string;
use murmur_component_ca::keypair::{load_certificates, new_tls_key_pair_loader};
use murmur_component_ech::load_ech_key;
use murmur_component_tls::utls::{new_listener as tls_new_listener, ClientAuthType, ClientHelloInfo};
use murmur_constant::listener::{InboundListenConfig, Listener as ConstListener};
use murmur_constant::tunnel::Tunnel;
use murmur_listener_config::auth::AuthServer;
use murmur_ntp as ntp;
use murmur_std_compat::net::{Addr, TcpAddr};
use murmur_transport::socks4::socks4;
use murmur_transport::socks5::socks5;

fn boxed_tcp_addr(addr: std::net::SocketAddr) -> Box<dyn Addr> {
    Box::new(TcpAddr::from(addr))
}

pub struct Listener {
    acceptor: Box<dyn Acceptor>,
    addr: String,
    closed: AtomicBool,
}

impl core::fmt::Debug for Listener {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Listener").field("addr", &self.addr).field("closed", &self.closed).finish_non_exhaustive()
    }
}

impl ConstListener for Listener {
    fn raw_address(&self) -> String {
        self.addr.clone()
    }

    fn address(&self) -> String {
        self.acceptor.addr().map(|addr| addr.to_string()).unwrap_or_default()
    }

    fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        Ok(self.acceptor.close()?)
    }
}

pub async fn new(addr: &str, tunnel: Arc<dyn Tunnel>, additions: Vec<Addition>) -> Result<Arc<Listener>> {
    new_with_config(
        AuthServer {
            enable: true,
            listen: addr.to_owned(),
            auth_store: DEFAULT.clone(),
            certificate: String::new(),
            private_key: String::new(),
            client_auth_type: String::new(),
            client_auth_cert: String::new(),
            ech_key: String::new(),
            reality_config: None,
        },
        default_listen_config(),
        tunnel,
        additions,
    )
    .await
}

pub async fn new_with_config(
    config: AuthServer,
    lc: Arc<dyn InboundListenConfig>,
    tunnel: Arc<dyn Tunnel>,
    additions: Vec<Addition>,
) -> Result<Arc<Listener>> {
    let is_default = additions.is_empty();
    let additions = if is_default { vec![with_in_name("DEFAULT-MIXED"), with_special_rules("")] } else { additions };

    let mut l: Box<dyn Acceptor> =
        lc.listen(&tokio_util::sync::CancellationToken::new(), "tcp", &config.listen).await?;

    let mut tls_config = crate::tls_server_config(Arc::new(ntp::time::now));

    if !config.certificate.is_empty() && !config.private_key.is_empty() {
        let cert_loader = new_tls_key_pair_loader(&config.certificate, &config.private_key)?;
        tls_config.get_certificate = Some(Arc::new(move |_info: &ClientHelloInfo| cert_loader().map(Some)));

        if !config.ech_key.is_empty() {
            load_ech_key(&config.ech_key, &mut tls_config)?;
        }
    }
    tls_config.client_auth = client_auth_type_from_string(&config.client_auth_type);
    if !config.client_auth_cert.is_empty() && tls_config.client_auth == ClientAuthType::NO_CLIENT_CERT {
        tls_config.client_auth = ClientAuthType::REQUIRE_AND_VERIFY_CLIENT_CERT;
    }
    if tls_config.client_auth == ClientAuthType::VERIFY_CLIENT_CERT_IF_GIVEN
        || tls_config.client_auth == ClientAuthType::REQUIRE_AND_VERIFY_CLIENT_CERT
    {
        tls_config.client_cas = Some(load_certificates(&config.client_auth_cert)?);
    }

    let reality_server_config = match &config.reality_config {
        Some(reality_config) => {
            if tls_config.get_certificate.is_some() {
                return Err(anyhow!("certificate is unavailable in reality"));
            }
            if tls_config.client_auth != ClientAuthType::NO_CLIENT_CERT {
                return Err(anyhow!("client-auth is unavailable in reality"));
            }
            Some(crate::reality::build_server_config(reality_config, Arc::<dyn Tunnel>::clone(&tunnel)))
        }
        None => None,
    };

    if reality_server_config.is_none() && tls_config.get_certificate.is_some() {
        l = tls_new_listener(Arc::from(l), Arc::new(tls_config));
    }

    let ml = Arc::new(Listener { acceptor: l, addr: config.listen.clone(), closed: AtomicBool::new(false) });

    {
        let ml = Arc::clone(&ml);
        let tunnel = Arc::clone(&tunnel);
        let auth_store = Arc::<dyn AuthStore>::clone(&config.auth_store);
        tokio::spawn(async move {
            loop {
                let Ok(conn) = ml.acceptor.accept().await else {
                    if ml.closed.load(Ordering::SeqCst) {
                        break;
                    }
                    continue;
                };
                let mut store = Arc::<dyn AuthStore>::clone(&auth_store);
                let is_default = is_default;
                let tunnel = Arc::clone(&tunnel);
                let additions = additions.clone();
                crate::reality::spawn_conn(conn, reality_server_config.clone(), move |conn| async move {
                    if is_default || Arc::ptr_eq(&store, &DEFAULT) {
                        let remote_addr = conn.peer_addr().ok().map(boxed_tcp_addr);
                        if !is_remote_addr_dis_allowed(remote_addr.as_deref()) {
                            let _ = murmur_common_net::io::close_stream(conn.as_ref());
                            return;
                        }
                        if skip_auth_remote_addr(remote_addr.as_deref()) {
                            store = crate::auth::auth::NIL.clone();
                        }
                    }
                    handle_conn(conn, &tunnel, store, &additions).await;
                });
            }
        });
    }

    Ok(ml)
}

pub(crate) async fn handle_conn(
    conn: Box<dyn Stream>,
    tunnel: &Arc<dyn Tunnel>,
    store: Arc<dyn AuthStore>,
    additions: &[Addition],
) {
    let mut buf_conn = murmur_common_net::new_buffered_conn(murmur_common_net::new_extended_conn(conn));
    let (head, err) = buf_conn.peek(1).await;
    if err.is_err() {
        let _ = murmur_common_net::io::close_stream(&buf_conn);
        return;
    }
    let Some(head0) = head.first().copied() else {
        let _ = murmur_common_net::io::close_stream(&buf_conn);
        return;
    };
    let conn: Box<dyn Stream> = Box::new(buf_conn);

    match head0 {
        socks4::VERSION => handle_socks4(conn, tunnel, store, additions).await,
        socks5::VERSION => handle_socks5(conn, tunnel, store, additions).await,
        _ => http_handle_conn(conn, Arc::clone(tunnel), store, additions).await,
    }
}
