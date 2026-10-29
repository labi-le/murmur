use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};

use crate::auth::auth::{DEFAULT as AUTH_DEFAULT, NIL as AUTH_NIL};
use murmur_adapter_inbound::addition::{with_in_name, with_special_rules, Addition};
use murmur_adapter_inbound::auth::skip_auth_remote_addr;
use murmur_adapter_inbound::ipfilter::is_remote_addr_dis_allowed;
use murmur_adapter_inbound::listen::default_listen_config;
use murmur_common_net::io::Acceptor;
use murmur_component_ca::auth::{client_auth_type_from_string, NO_CLIENT_CERT};
use murmur_component_ca::keypair::{load_certificates, new_tls_key_pair_loader};
use murmur_component_ech::load_ech_key;
use murmur_component_tls::utls::{self as tls, ClientAuthType};
use murmur_constant::listener::InboundListenConfig;
use murmur_constant::tunnel::Tunnel;
use murmur_listener_config::auth::AuthServer;

use super::proxy::handle_conn;

fn boxed_tcp_addr(addr: std::net::SocketAddr) -> Box<dyn murmur_std_compat::net::Addr> {
    Box::new(murmur_std_compat::net::TcpAddr::from(addr))
}

pub struct Listener {
    acceptor: Arc<dyn Acceptor>,
    addr: String,
    closed: Arc<AtomicBool>,
}

impl core::fmt::Debug for Listener {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Listener").field("addr", &self.addr).field("closed", &self.closed).finish_non_exhaustive()
    }
}

impl Listener {
    #[must_use]
    pub fn raw_address(&self) -> String {
        self.addr.clone()
    }

    #[must_use]
    pub fn address(&self) -> String {
        self.acceptor.addr().map(|addr| addr.to_string()).unwrap_or_default()
    }

    pub fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        self.acceptor.close()?;
        Ok(())
    }
}

pub async fn new(addr: &str, tunnel: Arc<dyn Tunnel>, additions: &[Addition]) -> Result<Listener> {
    new_with_config(
        AuthServer {
            enable: true,
            listen: addr.to_owned(),
            auth_store: AUTH_DEFAULT.clone(),
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

/// Builds a listener that authenticates when the flag is set. The type traits must not change,
/// as external callers depend on them.
pub async fn new_with_authenticate(
    addr: &str,
    tunnel: Arc<dyn Tunnel>,
    authenticate: bool,
    additions: &[Addition],
) -> Result<Listener> {
    let store = if authenticate { AUTH_DEFAULT.clone() } else { AUTH_NIL.clone() };
    new_with_config(
        AuthServer {
            enable: true,
            listen: addr.to_owned(),
            auth_store: store,
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
    additions: &[Addition],
) -> Result<Listener> {
    let is_default = additions.is_empty();
    let additions: Vec<Addition> =
        if is_default { vec![with_in_name("DEFAULT-HTTP"), with_special_rules("")] } else { additions.to_vec() };

    let ctx = tokio_util::sync::CancellationToken::new();
    let mut l: Box<dyn Acceptor> = lc.listen(&ctx, "tcp", &config.listen).await?;

    let mut tls_config = crate::tls_server_config(Arc::new(murmur_ntp::time::now));

    if !config.certificate.is_empty() && !config.private_key.is_empty() {
        let cert_loader = new_tls_key_pair_loader(&config.certificate, &config.private_key)?;
        tls_config.get_certificate = Some(Arc::new(move |_info: &tls::ClientHelloInfo| cert_loader().map(Some)));

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

    let reality_server_config = match &config.reality_config {
        Some(reality_config) => {
            if tls_config.get_certificate.is_some() {
                return Err(anyhow!("certificate is unavailable in reality"));
            }
            if tls_config.client_auth != NO_CLIENT_CERT {
                return Err(anyhow!("client-auth is unavailable in reality"));
            }
            Some(crate::reality::build_server_config(reality_config, Arc::clone(&tunnel)))
        }
        None => None,
    };

    if reality_server_config.is_none() && tls_config.get_certificate.is_some() {
        l = tls::new_listener(Arc::from(l), Arc::new(tls_config));
    }

    let listener: Arc<dyn Acceptor> = Arc::from(l);
    let closed = Arc::new(AtomicBool::new(false));

    let auth_store = config.auth_store;
    let listener_for_task = Arc::clone(&listener);
    let closed_for_task = Arc::clone(&closed);
    tokio::spawn(async move {
        loop {
            let Ok(conn) = listener_for_task.accept().await else {
                if closed_for_task.load(Ordering::SeqCst) {
                    break;
                }
                continue;
            };
            let reality_cfg = reality_server_config.clone();
            let tunnel = Arc::clone(&tunnel);
            let additions = additions.clone();
            let auth_store = Arc::clone(&auth_store);
            crate::reality::spawn_conn(conn, reality_cfg, move |conn| async move {
                let mut store = auth_store;
                let is_default = is_default;
                if is_default || Arc::ptr_eq(&store, &*AUTH_DEFAULT) {
                    let remote_addr = conn.peer_addr().ok().map(boxed_tcp_addr);
                    if !is_remote_addr_dis_allowed(remote_addr.as_deref()) {
                        let _ = murmur_common_net::io::close_stream(conn.as_ref());
                        return;
                    }
                    if skip_auth_remote_addr(remote_addr.as_deref()) {
                        store = AUTH_NIL.clone();
                    }
                }
                handle_conn(conn, tunnel, store, &additions).await;
            });
        }
    });

    Ok(Listener { acceptor: listener, addr: config.listen.clone(), closed })
}
