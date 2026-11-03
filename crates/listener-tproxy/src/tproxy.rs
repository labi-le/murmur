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
use super::setsockopt_linux::tcp_listener;

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

#[cfg_attr(
    target_os = "linux",
    expect(clippy::unused_async, reason = "every caller awaits this; only the non-linux arm binds asynchronously")
)]
pub async fn new(addr: &str, tunnel: Arc<dyn Tunnel>, additions: Vec<Addition>) -> Result<Arc<Listener>> {
    let mut additions = additions;
    if additions.is_empty() {
        additions = vec![with_in_name("DEFAULT-TPROXY"), with_special_rules("")];
    }

    // MPTCP is forced off for tproxy: it can malfunction on certain Linux kernels, and tokio's
    // `TcpListener` never opts a socket into MPTCP anyway.
    #[cfg(target_os = "linux")]
    let listener = tcp_listener(addr)?;
    #[cfg(not(target_os = "linux"))]
    let listener = {
        let listener = TokioTcpListener::bind(addr).await?;
        super::setsockopt_other::setsockopt(addr)?;
        listener
    };

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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use murmur_constant::adapters::{NatTable, UDPPacket};
    use murmur_constant::metadata::Metadata;

    use super::*;

    struct NoTunnel;

    #[async_trait::async_trait]
    impl Tunnel for NoTunnel {
        async fn handle_tcp_conn(&self, _conn: Box<dyn murmur_common_net::io::Stream>, _metadata: Metadata) {}

        fn handle_udp_packet(&self, _packet: Arc<dyn UDPPacket>, _metadata: Metadata) {}

        fn nat_table(&self) -> Arc<dyn NatTable> {
            unimplemented!("not exercised by this test")
        }
    }

    /// Whether the kernel denies the transparent pair, which decides what the error below can
    /// distinguish.
    fn transparent_is_denied() -> bool {
        socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, Some(socket2::Protocol::TCP))
            .and_then(|socket| socket.set_ip_transparent_v4(true))
            .is_err()
    }

    /// The transparent pair has to be in force before the bind, and the port `probe` holds makes
    /// the two orders report different errors: a denial of the option can only come from a pass
    /// that ran before the bind, a bind failure from one that ran after it.
    #[tokio::test]
    async fn the_transparent_options_are_applied_before_the_listener_binds() {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("an ephemeral port is free");
        let addr = probe.local_addr().expect("the probe is bound").to_string();
        let err = match new(&addr, Arc::new(NoTunnel), Vec::new()).await {
            Err(err) => err,
            Ok(listener) => panic!("the held port cannot be bound: {}", listener.address()),
        };
        let os_error = err.downcast_ref::<std::io::Error>().and_then(std::io::Error::raw_os_error);
        if transparent_is_denied() {
            assert_eq!(os_error, Some(libc::EPERM), "the option pass must fail before the bind: {err}");
        } else {
            assert_eq!(os_error, Some(libc::EADDRINUSE), "the option pass ran, then the held port was bound: {err}");
        }
    }
}
