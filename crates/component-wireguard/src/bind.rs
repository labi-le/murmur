//! The UDP transport under the WireGuard device.
//!
//! Callers reach it through murmur's own dialer, so this crate takes the already-dialed
//! datagram or stream instead of building one.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

use anyhow::Result;
use async_trait::async_trait;
use murmur_common::net::Datagram;

/// The bind surface the device uses.
#[async_trait]
pub trait Bind: Send + Sync {
    /// write one message to `endpoint`.
    async fn send_to(&self, packet: &[u8], endpoint: SocketAddr) -> io::Result<()>;
    /// read one message and report its source.
    async fn recv_from(&self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
    fn local_addr(&self) -> io::Result<SocketAddr>;
    fn close(&self) -> io::Result<()>;
}

/// The unconnected socket the `ClientBind` opens when a configuration has more than one
/// peer: every peer keeps its own endpoint, and a message may arrive from a new one.
pub struct DatagramBind {
    conn: Box<dyn Datagram>,
}

impl core::fmt::Debug for DatagramBind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DatagramBind").finish_non_exhaustive()
    }
}

impl DatagramBind {
    /// Binds a datagram socket on the unspecified address.
    #[must_use]
    pub fn new(conn: Box<dyn Datagram>) -> Self {
        Self { conn }
    }
}

#[async_trait]
impl Bind for DatagramBind {
    async fn send_to(&self, packet: &[u8], endpoint: SocketAddr) -> io::Result<()> {
        self.conn.send_to(packet, endpoint).await.map(|_| ())
    }

    async fn recv_from(&self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        // cancel-safe: an unread datagram stays queued in the socket.
        self.conn.recv_from(buffer).await
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.conn.local_addr()
    }

    fn close(&self) -> io::Result<()> {
        self.conn.close()
    }
}

/// The connected socket the `ClientBind` opens for a single-peer configuration.
///
/// It is the dialed UDP conn wrapped as a packet conn: the kernel drops anything that does not
/// come from the peer, so the reported source is always the connected address.
pub struct ConnectedBind {
    conn: tokio::sync::Mutex<Box<dyn murmur_common_net::io::Stream>>,
    endpoint: SocketAddr,
}

impl core::fmt::Debug for ConnectedBind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ConnectedBind").field("endpoint", &self.endpoint).finish_non_exhaustive()
    }
}

impl ConnectedBind {
    pub fn new(conn: Box<dyn murmur_common_net::io::Stream>, endpoint: SocketAddr) -> Result<Self> {
        let local_addr = conn.local_addr()?;
        if local_addr.ip().is_unspecified() && local_addr.port() == 0 {
            return Err(anyhow::anyhow!("connected UDP bind has no local address"));
        }
        Ok(Self { conn: tokio::sync::Mutex::new(conn), endpoint })
    }
}

#[async_trait]
impl Bind for ConnectedBind {
    async fn send_to(&self, packet: &[u8], _endpoint: SocketAddr) -> io::Result<()> {
        use tokio::io::AsyncWriteExt as _;
        let mut conn = self.conn.lock().await;
        conn.write_all(packet).await?;
        conn.flush().await
    }

    async fn recv_from(&self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        use tokio::io::AsyncReadExt as _;
        // cancel-safe: a dropped read consumes no datagram, and the guard is released before the
        // source address is read.
        let read = {
            let mut conn = self.conn.lock().await;
            conn.read(buffer).await?
        };
        Ok((read, self.endpoint))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.conn.try_lock().map_err(|_| busy_bind())?.local_addr()
    }

    fn close(&self) -> io::Result<()> {
        match self.conn.try_lock() {
            Ok(conn) => murmur_common::net::close_stream(&**conn),
            Err(_) => Ok(()),
        }
    }
}

fn busy_bind() -> io::Error {
    io::Error::other("connected UDP bind is busy")
}

/// The reserved-bytes camouflage, layered over the transport.
///
/// Bytes 1..4 of every message in each direction are replaced on the way out and zeroed on the
/// way in, so the traffic no longer carries WireGuard's three zero bytes there. Reserved-byte
/// parsing is enabled here because it is only cleared for AmneziaWG, which this crate does not
/// implement;
/// `adapter::outbound::wireguard` rejects that option rather than running plain WireGuard under
/// a name that promises obfuscation.
pub struct ReservedBind {
    inner: Arc<dyn Bind>,
    default: [u8; 3],
    for_endpoint: RwLock<HashMap<SocketAddr, [u8; 3]>>,
}

impl core::fmt::Debug for ReservedBind {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ReservedBind").field("default", &self.default).finish_non_exhaustive()
    }
}

impl ReservedBind {
    pub fn new(inner: Arc<dyn Bind>, default: [u8; 3]) -> Self {
        Self { inner, default, for_endpoint: RwLock::new(HashMap::new()) }
    }

    pub fn set_reserved_for_endpoint(&self, destination: SocketAddr, reserved: [u8; 3]) {
        if let Ok(mut map) = self.for_endpoint.write() {
            map.insert(destination, reserved);
        }
    }

    pub fn reset_reserved_for_endpoint(&self) {
        if let Ok(mut map) = self.for_endpoint.write() {
            map.clear();
        }
    }

    fn reserved_for(&self, endpoint: SocketAddr) -> [u8; 3] {
        self.for_endpoint.read().ok().and_then(|map| map.get(&endpoint).copied()).unwrap_or(self.default)
    }

    /// Sends a message with the reserved bytes patched in.
    pub async fn send_to(&self, packet: &[u8], endpoint: SocketAddr) -> io::Result<()> {
        if packet.len() <= 3 {
            return self.inner.send_to(packet, endpoint).await;
        }
        let mut buffer = packet.to_vec();
        if let Some(reserved) = buffer.get_mut(1..4) {
            reserved.copy_from_slice(&self.reserved_for(endpoint));
        }
        self.inner.send_to(&buffer, endpoint).await
    }

    /// Receives a message, zeroing the reserved bytes of what it hands the
    /// device so the protocol code sees a plain WireGuard message.
    pub async fn recv_from(&self, buffer: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        // cancel-safe: the reserved bytes are zeroed only once a message has been received.
        let (size, source) = self.inner.recv_from(buffer).await?;
        if size > 3 {
            if let Some(reserved) = buffer.get_mut(1..4) {
                reserved.fill(0);
            }
        }
        Ok((size, source))
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    pub fn close(&self) -> io::Result<()> {
        self.inner.close()
    }
}
