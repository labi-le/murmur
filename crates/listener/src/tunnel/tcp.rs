use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use tokio_util::sync::CancellationToken;

use murmur_adapter_inbound::addition::{with_special_proxy, Addition};
use murmur_adapter_inbound::socket::new_socket;
use murmur_common_net::io::{Acceptor, Stream};
use murmur_constant::listener::{InboundListenConfig, Listener as ConstListener};
use murmur_constant::metadata::Type;
use murmur_constant::tunnel::Tunnel;
use murmur_transport::socks5::socks5;

pub struct Listener {
    acceptor: Box<dyn Acceptor>,
    addr: String,
    target: socks5::Addr,
    closed: AtomicBool,
}

impl core::fmt::Debug for Listener {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Listener")
            .field("addr", &self.addr)
            .field("target", &self.target)
            .field("closed", &self.closed.load(Ordering::Relaxed))
            .finish_non_exhaustive()
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

async fn handle_tcp(conn: Box<dyn Stream>, target: &socks5::Addr, tunnel: &Arc<dyn Tunnel>, additions: &[Addition]) {
    let (conn, metadata) = new_socket(target, conn, Type::TUNNEL, additions);
    tunnel.handle_tcp_conn(conn, metadata).await;
}

pub async fn new(
    addr: &str,
    target: &str,
    proxy: &str,
    lc: Arc<dyn InboundListenConfig>,
    tunnel: Arc<dyn Tunnel>,
    additions: Vec<Addition>,
) -> Result<Arc<Listener>> {
    let listener: Box<dyn Acceptor> = lc.listen(&CancellationToken::new(), "tcp", addr).await?;

    let target_addr = socks5::parse_addr(target).ok_or_else(|| anyhow!("invalid target address {target}"))?;

    let rl = Arc::new(Listener {
        acceptor: listener,
        addr: addr.to_owned(),
        target: target_addr,
        closed: AtomicBool::new(false),
    });

    let mut additions = additions;
    if !proxy.is_empty() {
        additions.insert(0, with_special_proxy(proxy));
    }

    {
        let rl = Arc::clone(&rl);
        tokio::spawn(async move {
            loop {
                let Ok(conn) = rl.acceptor.accept().await else {
                    if rl.closed.load(Ordering::SeqCst) {
                        break;
                    }
                    continue;
                };
                let tunnel = Arc::clone(&tunnel);
                let target = rl.target.clone();
                let additions = additions.clone();
                tokio::spawn(async move { handle_tcp(conn, &target, &tunnel, &additions).await });
            }
        });
    }

    Ok(rl)
}
