//! The physical UDP wire: the sockets a ZeroTier node exchanges raw packets
//! over, and the receive pump that surfaces inbound datagrams.
//!
//! This is the transport floor that `bonding` and `node` build on. It performs
//! no protocol interpretation: it owns sockets, enforces the protocol's MTU
//! bounds, and moves datagrams. Path selection, packet armor and peer state
//! live above it.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::packet::MAX_PHYSICAL_MTU;

/// Bounds the inbound queue so a flood cannot grow memory without limit. The
/// protocol core drops rather than blocks.
const INBOUND_QUEUE_DEPTH: usize = 2048;

/// Reports a physical-wire operation that could not complete.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("ZeroTier physical transport is closed")]
    Closed,
    #[error("ZeroTier physical transport is not started")]
    NotStarted,
    #[error("ZeroTier physical transport I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("ZeroTier packet of {0} bytes exceeds the {1} byte physical MTU limit")]
    TooLarge(usize, usize),
}

/// Where a datagram should be sent and which local socket should send it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WirePath {
    /// The peer, root, or planet endpoint.
    pub remote: SocketAddr,
    /// Index into [`UdpWire::local_endpoints`]. `bonding` picks the socket that
    /// owns a learned path; `None` is not accepted here so every path names the
    /// socket whose port the peer must observe.
    pub socket: usize,
}

/// The physical UDP transport.
///
/// Sockets are bound once at start and reused for the lifetime of the wire, so
/// the local port a peer learns stays stable. Inbound datagrams from every
/// socket are merged into one ordered queue.
#[derive(Debug)]
pub struct UdpWire {
    sockets: Vec<Arc<UdpSocket>>,
    local_endpoints: Vec<SocketAddr>,
    /// Held so the queue outlives the pumps that `close` aborts: a caller already suspended in
    /// `recv_from` must stay suspended, never observe a channel that closed under it.
    _inbound_tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    inbound_rx: mpsc::Receiver<(Vec<u8>, SocketAddr)>,
    tasks: Vec<JoinHandle<()>>,
    closed: bool,
}

impl UdpWire {
    /// Binds the primary port and, when it differs, a secondary port on both
    /// IPv4 and IPv6 where the platform allows it.
    ///
    /// A port of 0 asks the OS to choose; the chosen ports are then readable
    /// from [`UdpWire::local_endpoints`].
    pub async fn bind(primary_port: u16, secondary_port: u16) -> Result<Self, WireError> {
        let mut ports = vec![primary_port];
        if secondary_port != 0 && secondary_port != primary_port {
            ports.push(secondary_port);
        }

        let mut sockets = Vec::with_capacity(ports.len());
        let mut local_endpoints = Vec::with_capacity(ports.len());
        for port in ports {
            let socket = bind_any(port).await?;
            local_endpoints.push(socket.local_addr()?);
            sockets.push(Arc::new(socket));
        }

        let (inbound_tx, inbound_rx) = mpsc::channel(INBOUND_QUEUE_DEPTH);
        let mut tasks = Vec::with_capacity(sockets.len());
        for socket in &sockets {
            tasks.push(tokio::spawn(receive_loop(Arc::clone(socket), inbound_tx.clone())));
        }

        Ok(Self { sockets, local_endpoints, _inbound_tx: inbound_tx, inbound_rx, tasks, closed: false })
    }

    /// The addresses the wire actually bound, in socket order. Path indices
    /// passed to [`UdpWire::send`] refer to this list.
    #[must_use]
    pub fn local_endpoints(&self) -> &[SocketAddr] {
        &self.local_endpoints
    }

    /// Sends one datagram on the socket named by `path`.
    // cancel-safe: the datagram is handed to the socket in one call, so a dropped call either sent it or did not.
    pub async fn send(&self, path: WirePath, datagram: &[u8]) -> Result<usize, WireError> {
        if self.closed {
            return Err(WireError::Closed);
        }
        if datagram.len() > MAX_PHYSICAL_MTU {
            return Err(WireError::TooLarge(datagram.len(), MAX_PHYSICAL_MTU));
        }
        let socket = self.sockets.get(path.socket).ok_or(WireError::NotStarted)?;
        socket.send_to(datagram, path.remote).await.map_err(WireError::Io)
    }

    /// Receives the next inbound datagram with its source endpoint, which the
    /// protocol core needs to authenticate and match a learned path.
    pub async fn recv_from(&mut self) -> Option<(Vec<u8>, SocketAddr)> {
        self.inbound_rx.recv().await
    }

    /// Receives the next inbound datagram, discarding its source.
    // cancel-safe: takes its item from a queue/channel, so a dropped call leaves the item queued for the next one.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.inbound_rx.recv().await.map(|(datagram, _)| datagram)
    }

    /// Releases every socket and stops the receive pumps. Idempotent, and safe
    /// to call from a teardown path that cannot report errors.
    pub fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        for task in self.tasks.drain(..) {
            task.abort();
        }
        self.sockets.clear();
        self.local_endpoints.clear();
    }
}

impl Drop for UdpWire {
    fn drop(&mut self) {
        self.close();
    }
}

/// Binds one port on every available family, preferring IPv4 so a default
/// single-stack configuration still reports a usable endpoint.
async fn bind_any(port: u16) -> Result<UdpSocket, WireError> {
    let v4 = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port)).await;
    match v4 {
        Ok(socket) => Ok(socket),
        Err(_) => UdpSocket::bind((std::net::Ipv6Addr::UNSPECIFIED, port)).await.map_err(WireError::Io),
    }
}

/// Reads datagrams until the wire is closed, forwarding each with its source.
async fn receive_loop(socket: Arc<UdpSocket>, outbound: mpsc::Sender<(Vec<u8>, SocketAddr)>) {
    // One reusable buffer per task: at the physical MTU this is the only
    // per-packet allocation on the receive path, and the queue takes ownership.
    let mut buffer = vec![0u8; MAX_PHYSICAL_MTU];
    loop {
        let Ok((read, source)) = socket.recv_from(&mut buffer).await else {
            return;
        };
        let Some(datagram) = buffer.get(..read) else {
            return;
        };
        if outbound.send((datagram.to_vec(), source)).await.is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{timeout, Duration};

    fn any_ipv4(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    /// The OS must hand us a real port so the test never collides with a
    /// production listener.
    async fn ephemeral_wire() -> UdpWire {
        UdpWire::bind(0, 0).await.expect("bind ephemeral UDP wire")
    }

    #[tokio::test]
    async fn loopback_datagram_reaches_the_wire() {
        let mut receiver = ephemeral_wire().await;
        let sender = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await.expect("bind sender");
        let sender_endpoint = sender.local_addr().expect("sender endpoint");
        let peer = receiver.local_endpoints()[0];
        assert_ne!(peer.port(), 0);

        let datagram = vec![0xabu8; 900];
        sender.send_to(&datagram, peer).await.expect("send loopback datagram");

        let (received, source) = timeout(Duration::from_secs(5), receiver.recv_from())
            .await
            .expect("datagram arrived before timeout")
            .expect("wire still open");
        assert_eq!(received, datagram);
        // The reported source is the peer that sent the datagram, which is what
        // the protocol core matches a learned path against.
        assert_eq!(source.port(), sender_endpoint.port());
    }

    #[tokio::test]
    async fn send_uses_the_named_socket() {
        let mut peer = ephemeral_wire().await;
        let wire = ephemeral_wire().await;
        let target = peer.local_endpoints()[0];

        let written = wire
            .send(WirePath { remote: target, socket: 0 }, b"zerotier-hello")
            .await
            .expect("send over the first socket");
        assert_eq!(written, b"zerotier-hello".len());

        let (received, _) = timeout(Duration::from_secs(5), peer.recv_from())
            .await
            .expect("datagram arrived before timeout")
            .expect("wire still open");
        assert_eq!(received, b"zerotier-hello");
    }

    #[tokio::test]
    async fn a_distinct_secondary_port_binds_a_second_socket() {
        // A std socket releases its port synchronously on drop, unlike tokio's
        // reactor-backed socket, so the port is genuinely free here.
        let secondary = {
            let probe = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("probe free port");
            probe.local_addr().expect("probe endpoint").port()
        };

        let wire = UdpWire::bind(0, secondary).await.expect("bind primary and secondary");
        assert_eq!(wire.local_endpoints().len(), 2);
        assert_eq!(wire.local_endpoints()[1].port(), secondary);
    }

    #[tokio::test]
    async fn an_omitted_secondary_port_binds_a_single_socket() {
        let wire = UdpWire::bind(0, 0).await.expect("bind primary only");
        assert_eq!(wire.local_endpoints().len(), 1);
        assert_ne!(wire.local_endpoints()[0].port(), 0);
    }

    #[tokio::test]
    async fn rejects_oversized_datagrams_and_unknown_sockets() {
        let wire = ephemeral_wire().await;
        let target = any_ipv4(9);

        let oversized = vec![0u8; MAX_PHYSICAL_MTU + 1];
        assert!(matches!(
            wire.send(WirePath { remote: target, socket: 0 }, &oversized).await,
            Err(WireError::TooLarge(_, _))
        ));

        assert!(matches!(wire.send(WirePath { remote: target, socket: 7 }, b"x").await, Err(WireError::NotStarted)));
    }

    #[tokio::test]
    async fn close_is_idempotent_and_stops_delivery() {
        let mut wire = ephemeral_wire().await;
        let target = wire.local_endpoints()[0];

        wire.close();
        wire.close();
        assert!(wire.local_endpoints().is_empty());
        assert!(matches!(wire.send(WirePath { remote: target, socket: 0 }, b"x").await, Err(WireError::Closed)));

        // A closed wire must not leave a receive pump running or hang callers.
        assert!(timeout(Duration::from_millis(200), wire.recv()).await.is_err());
    }
}
