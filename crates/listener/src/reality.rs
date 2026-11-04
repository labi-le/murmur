//! Shared REALITY wiring for the six listener server-construction files (`socks::tcp`,
//! `http::server`, `mixed::mixed`, `sing_vless::server`, `sing_vmess::server`, `trojan::server`).
//!
//! Each of those builds a REALITY listener around its raw TCP `Acceptor` when a private key is
//! configured. `murmur-reality`'s
//! `reality_server_accept` only wraps one already-accepted connection, so callers wrap their own
//! accept loop instead of the listener; see [`accept`].

use std::future::Future;
use std::sync::Arc;

use murmur_common_net::io::{OldConnAsStream, Stream};
use murmur_constant::tunnel::Tunnel;
use murmur_listener_config::reality::RealityConfig;
use murmur_listener_inner::tcp::handle_tcp;
use murmur_reality::{reality_server_accept, BoxedStream, DialDest, FallbackLimit, RealityCloser, RealityServerConfig};

/// The REALITY config build, minus the decode/validation work
/// `listener::parse::build_reality_config` already did at config-parse time.
///
/// Builds the tunnel-dependent half only.
pub fn build_server_config(config: &RealityConfig, tunnel: Arc<dyn Tunnel>) -> Arc<RealityServerConfig> {
    let dest = config.dest.clone();
    let proxy = config.proxy.clone();
    let dial_dest: DialDest = Arc::new(move || {
        let tunnel = Arc::clone(&tunnel);
        let dest = dest.clone();
        let proxy = proxy.clone();
        Box::pin(async move {
            handle_tcp(Some(tunnel), &dest, &proxy)
                .await
                .map(|conn| -> BoxedStream { Box::new(OldConnAsStream(conn)) })
                .map_err(|err| std::io::Error::other(err.to_string()))
        })
    });
    let mut server_config = RealityServerConfig::new(
        config.private_key,
        config.server_names.clone(),
        config.short_ids.clone(),
        config.max_time_diff,
        dial_dest,
    );
    server_config.limit_fallback_upload = FallbackLimit {
        after_bytes: config.limit_fallback_upload.after_bytes,
        bytes_per_sec: config.limit_fallback_upload.bytes_per_sec,
        burst_bytes_per_sec: config.limit_fallback_upload.burst_bytes_per_sec,
    };
    server_config.limit_fallback_download = FallbackLimit {
        after_bytes: config.limit_fallback_download.after_bytes,
        bytes_per_sec: config.limit_fallback_download.bytes_per_sec,
        burst_bytes_per_sec: config.limit_fallback_download.burst_bytes_per_sec,
    };
    Arc::new(server_config)
}

/// The wrapped accept, narrowed to one already-accepted raw connection.
///
/// `Some` is an authenticated REALITY client, ready for the listener's normal
/// protocol dispatch with its original `local_addr`/`peer_addr` preserved. `None` means the
/// connection has already been fully relayed to `dest` (or dropped, on a raw-address lookup
/// failure); the caller should just move on to its next `accept()`.
// NOT cancel-safe: the accepted connection is driven through a handshake that writes to it, so a dropped call loses that connection.
pub async fn accept(conn: Box<dyn Stream>, cfg: &RealityServerConfig) -> Option<Box<dyn Stream>> {
    let local = conn.local_addr().ok()?;
    let peer = conn.peer_addr().ok()?;
    let closer = RealityCloser::capture(&*conn);
    match reality_server_accept(conn, cfg).await {
        Ok(stream) => {
            let mut stream = stream.with_addrs(local, peer);
            if let Some(closer) = closer {
                stream = stream.with_closer(closer);
            }
            Some(Box::new(stream))
        }
        Err(err) => {
            murmur_log::debugln!("REALITY: connection not authenticated, relayed to dest: {err}");
            None
        }
    }
}

/// The REALITY handshake runs on a per-connection task.
///
/// Awaiting [`accept`] inline in an accept loop instead lets one connection's handshake -- which includes
/// relaying an unauthenticated peer to `dest` for the rest of its life -- stall every later
/// accept. This spawns the handshake and then the listener's own dispatch, so the acceptor keeps
/// accepting while connections are in flight.
pub fn spawn_conn<F, Fut>(conn: Box<dyn Stream>, cfg: Option<Arc<RealityServerConfig>>, handle: F)
where
    F: FnOnce(Box<dyn Stream>) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    tokio::spawn(async move {
        let conn = match cfg {
            Some(cfg) => match accept(conn, &cfg).await {
                Some(conn) => conn,
                None => return,
            },
            None => conn,
        };
        handle(conn).await;
    });
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    use super::*;

    /// A TLS handshake record whose payload is not a `ClientHello`. The declared length is exact so
    /// the server's record read completes immediately and the rejection (and so the relay to
    /// `dest`) happens without waiting for bytes that never arrive.
    const NOT_A_CLIENT_HELLO: [u8; 10] = [0x16, 0x03, 0x01, 0x00, 0x05, 0xde, 0xad, 0xbe, 0xef, 0x00];

    /// The REALITY handshake runs per connection, so one
    /// connection parked inside it cannot stop the listener accepting the next. Awaiting the
    /// handshake inline in the accept loop serialised them instead: an unauthenticated peer is
    /// relayed to `dest` for the rest of its life, and until that relay ended no later connection
    /// was accepted at all.
    ///
    /// Each `dest` dial here parks forever (the far end never sends and never closes), so the
    /// first connection stays inside its relay for the whole test. The second connection
    /// reaching `dest` at all is what proves accepts are no longer serialised.
    #[tokio::test]
    async fn a_stalled_connection_does_not_block_later_accepts() {
        let dials = Arc::new(AtomicUsize::new(0));
        let mut server_names = HashSet::new();
        server_names.insert("example.test".to_owned());
        let mut short_ids = HashSet::new();
        short_ids.insert([0x11u8; 8]);
        let dial_dest: DialDest = {
            let dials = Arc::clone(&dials);
            Arc::new(move || {
                dials.fetch_add(1, Ordering::SeqCst);
                Box::pin(async {
                    let (mut far, near) = tokio::io::duplex(1024);
                    tokio::spawn(async move {
                        let mut buf = [0u8; 256];
                        while matches!(far.read(&mut buf).await, Ok(n) if n > 0) {}
                        std::future::pending::<()>().await;
                    });
                    let boxed: BoxedStream = Box::new(near);
                    Ok(boxed)
                })
            })
        };
        let cfg = Arc::new(RealityServerConfig::new([0x22u8; 32], server_names, short_ids, None, dial_dest));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { return };
                spawn_conn(Box::new(OldConnAsStream(stream)), Some(Arc::clone(&cfg)), |_conn| async {});
            }
        });

        // Wait for the first connection to be accepted and parked in its relay to `dest`.
        let mut first = tokio::net::TcpStream::connect(addr).await.expect("connect first");
        first.write_all(&NOT_A_CLIENT_HELLO).await.expect("write garbage");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while dials.load(Ordering::SeqCst) == 0 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(dials.load(Ordering::SeqCst), 1, "the first connection must be relayed to dest");

        // The first connection is still parked in that relay. A second one must still be accepted.
        let mut second = tokio::net::TcpStream::connect(addr).await.expect("connect second");
        second.write_all(&NOT_A_CLIENT_HELLO).await.expect("write garbage");
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while dials.load(Ordering::SeqCst) < 2 && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(dials.load(Ordering::SeqCst), 2, "a stalled REALITY connection must not block later accepts");
    }
}
