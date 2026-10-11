#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Result;
use tokio::net::TcpListener as TokioTcpListener;

use murmur_adapter_inbound::addition::{with_in_addr, with_in_name, with_special_rules, Addition};
use murmur_adapter_inbound::socket::new_socket;
use murmur_component::keepalive::tcp_keepalive::tcp_keep_alive;
use murmur_constant::listener::Listener as ConstListener;
use murmur_constant::metadata::Type;
use murmur_constant::tunnel::Tunnel;
use murmur_transport::socks5::socks5;

#[cfg(target_os = "linux")]
use super::setsockopt_linux::setsockopt;

#[derive(Debug)]
pub struct Listener {
    inner: TokioTcpListener,
    addr: String,
    closed: AtomicBool,
}

impl ConstListener for Listener {
    fn raw_address(&self) -> String {
        self.addr.clone()
    }

    fn address(&self) -> String {
        self.inner.local_addr().map(|addr| addr.to_string()).unwrap_or_default()
    }

    fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        Ok(())
    }
}

impl Listener {
    fn handle_tproxy(self: &Arc<Self>, conn: tokio::net::TcpStream, tunnel: Arc<dyn Tunnel>, additions: &[Addition]) {
        let _ = conn.set_nodelay(true);
        let Ok(local_addr) = conn.local_addr() else { return };
        let Some(target) = socks5::parse_addr_to_socks_addr(&murmur_std_compat::net::TcpAddr::from(local_addr)) else {
            return;
        };
        tcp_keep_alive(&conn);
        // TProxy's conn.LocalAddr() is target address, so we set from l.inner.
        let mut additions = additions.to_vec();
        let in_addr = self.inner.local_addr().ok().map(|addr| -> Box<dyn murmur_std_compat::net::Addr> {
            Box::new(murmur_std_compat::net::TcpAddr::from(addr))
        });
        additions.insert(0, with_in_addr(in_addr));
        let (conn, metadata) = new_socket(&target, Box::new(conn), Type::TPROXY, &additions);
        tokio::spawn(async move { tunnel.handle_tcp_conn(conn, metadata).await });
    }
}

pub async fn new(addr: &str, tunnel: Arc<dyn Tunnel>, additions: Vec<Addition>) -> Result<Arc<Listener>> {
    let mut additions = additions;
    if additions.is_empty() {
        additions = vec![with_in_name("DEFAULT-TPROXY"), with_special_rules("")];
    }

    // MPTCP is forced off for tproxy: it can malfunction on certain Linux kernels, and tokio's
    // `TcpListener` never opts a socket into MPTCP anyway.
    let listener = TokioTcpListener::bind(addr).await?;

    #[cfg(target_os = "linux")]
    setsockopt(&listener, addr)?;
    #[cfg(not(target_os = "linux"))]
    super::setsockopt_other::setsockopt(addr)?;

    let rl = Arc::new(Listener { inner: listener, addr: addr.to_owned(), closed: AtomicBool::new(false) });

    {
        let rl = Arc::clone(&rl);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = rl.inner.accept().await else {
                    if rl.closed.load(Ordering::SeqCst) {
                        break;
                    }
                    continue;
                };
                let tunnel = Arc::clone(&tunnel);
                let additions = additions.clone();
                let rl = Arc::clone(&rl);
                tokio::spawn(async move { rl.handle_tproxy(stream, tunnel, &additions) });
            }
        });
    }

    Ok(rl)
}
