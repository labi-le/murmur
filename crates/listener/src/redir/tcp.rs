//! DEVIATION: this crate keeps the concrete `tokio::net::TcpListener`, not a bare interface.
//!
//! The socket is shared through an `Arc` instead of `Box<dyn murmur_std_compat::net::Listener>`
//! so the accept loop and `parser_packet` retain the concrete `TcpStream` the platform files
//! need for `AsRawFd`/`TCPKeepAlive`, which is what a concrete TCP listener returns under the
//! interface.
//!
//! DEVIATION: `Close` cancels a shared signal to stop the accept loop from starting new accepts,
//! rather than closing the OS listener. A pending
//! `accept().await` still resolves on the next incoming connection or process exit instead of
//! failing immediately. Closing the connection on the parse-failure path is replaced by simply
//! dropping it, which closes the socket deterministically through Rust's `Drop`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Result;
use tokio::net::TcpStream;

use murmur_adapter_inbound as inbound;
use murmur_adapter_inbound::addition::Addition;
use murmur_common_net::deadline::pipe::CloseSignal;
use murmur_component::keepalive::tcp_keepalive::tcp_keep_alive;
use murmur_constant::metadata::Type;
use murmur_constant::tunnel::Tunnel;

#[cfg(target_os = "macos")]
use super::tcp_darwin::parser_packet;
#[cfg(target_os = "freebsd")]
use super::tcp_freebsd::parser_packet;
#[cfg(target_os = "linux")]
use super::tcp_linux::parser_packet;
#[cfg(not(any(target_os = "macos", target_os = "freebsd", target_os = "linux")))]
use super::tcp_other::parser_packet;

#[derive(Debug)]
pub struct Listener {
    socket: Arc<tokio::net::TcpListener>,
    addr: String,
    closed: Arc<AtomicBool>,
    close_signal: Arc<CloseSignal>,
}

impl murmur_constant::listener::Listener for Listener {
    fn raw_address(&self) -> String {
        self.addr.clone()
    }

    fn address(&self) -> String {
        self.socket.local_addr().map(|addr| addr.to_string()).unwrap_or_default()
    }

    fn close(&self) -> Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        self.close_signal.close();
        Ok(())
    }
}

/// A bound socket whose accept loop has not started, so a multi-address listener can bind
/// every address before any of them serves.
pub struct BoundListener {
    listener: Listener,
    tunnel: Arc<dyn Tunnel>,
    additions: Vec<Addition>,
}

impl core::fmt::Debug for BoundListener {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BoundListener").field("listener", &self.listener).finish_non_exhaustive()
    }
}

impl BoundListener {
    #[must_use]
    pub fn serve(self) -> Listener {
        let Self { listener: rl, tunnel, additions } = self;
        let socket = Arc::clone(&rl.socket);
        let closed = Arc::clone(&rl.closed);
        let close_signal = Arc::clone(&rl.close_signal);

        // cancel-safe: the task owns only the listener handle it was given, so a drop stops accepting and loses nothing.
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    () = close_signal.wait() => break,
                    result = socket.accept() => {
                        match result {
                            Ok((conn, _)) => {
                                tokio::spawn(handle_redir(conn, Arc::clone(&tunnel), additions.clone()));
                            }
                            Err(_) => {
                                if closed.load(Ordering::SeqCst) {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        });

        rl
    }
}

pub async fn bind(addr: &str, tunnel: Arc<dyn Tunnel>, additions: &[Addition]) -> Result<BoundListener> {
    let additions: Vec<Addition> = if additions.is_empty() {
        vec![inbound::addition::with_in_name("DEFAULT-REDIR"), inbound::addition::with_special_rules("")]
    } else {
        additions.to_vec()
    };

    let socket = Arc::new(tokio::net::TcpListener::bind(addr).await?);
    let closed = Arc::new(AtomicBool::new(false));
    let close_signal = Arc::new(CloseSignal::new());

    let rl = Listener {
        socket: Arc::clone(&socket),
        addr: addr.to_owned(),
        closed: Arc::clone(&closed),
        close_signal: Arc::clone(&close_signal),
    };

    Ok(BoundListener { listener: rl, tunnel, additions })
}

pub async fn new(addr: &str, tunnel: Arc<dyn Tunnel>, additions: &[Addition]) -> Result<Listener> {
    Ok(bind(addr, tunnel, additions).await?.serve())
}

async fn handle_redir(conn: TcpStream, tunnel: Arc<dyn Tunnel>, additions: Vec<Addition>) {
    let _ = conn.set_nodelay(true);
    let Ok(target) = parser_packet(&conn) else {
        return;
    };
    tcp_keep_alive(&conn);
    let (conn, metadata) = inbound::socket::new_socket(&target, Box::new(conn), Type::REDIR, &additions);
    tunnel.handle_tcp_conn(conn, metadata).await;
}
