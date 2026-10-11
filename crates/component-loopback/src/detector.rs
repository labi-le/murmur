//! Loopback detector and its absent-receiver dispatch.
//!
//! DEVIATION: Rust has no absent-receiver methods, so `new_detector` returns `Option<Arc<Detector>>`
//! and the disabled case lives in the [`DetectorExt`] extension trait implemented for that
//! `Option`, returning its input unchanged (or `None`); the enabled logic is an inherent
//! `Detector` method or associated function.

use std::net::SocketAddr;
use std::sync::{Arc, LazyLock};

use anyhow::Result;

use murmur_common::xsync::map::Map;
use murmur_common_callback::close_callback::{new_close_callback_conn, new_close_callback_packet_conn, CloseFunc};
use murmur_component::iface::iface::is_local_ip;
use murmur_constant::adapters::{Conn as ConstantConn, PacketConn as ConstantPacketConn};
use murmur_constant::metadata::Metadata;
use murmur_constant_features::CMFA;

/// Folded together with the environment override into one lazily evaluated flag.
static DISABLE_LOOP_BACK_DETECTOR: LazyLock<bool> = LazyLock::new(|| {
    let disabled =
        std::env::var("DISABLE_LOOPBACK_DETECTOR").ok().and_then(|v| v.parse::<bool>().ok()).unwrap_or(false);
    disabled || CMFA
});

/// `ErrReject`: the formatted remote address is carried in the error itself, and callers match it
/// with `downcast_ref`.
#[derive(Debug, thiserror::Error)]
#[error("reject loopback connection to: {remote}")]
pub struct ErrReject {
    pub remote: String,
}

pub struct Detector {
    conn_map: Map<SocketAddr, ()>,
    packet_conn_map: Map<u16, ()>,
}

// `Map` has no `Debug`, so the tables themselves cannot be printed.
impl std::fmt::Debug for Detector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Detector")
            .field("conn_map_len", &self.conn_map.size())
            .field("packet_conn_map_len", &self.packet_conn_map.size())
            .finish_non_exhaustive()
    }
}

impl Detector {
    #[must_use]
    pub fn new_detector() -> Option<Arc<Self>> {
        if *DISABLE_LOOP_BACK_DETECTOR {
            return None;
        }
        Some(Arc::new(Self { conn_map: Map::default(), packet_conn_map: Map::default() }))
    }

    /// Registers the conn's address and wraps it in a close callback.
    fn new_conn(detector: &Arc<Self>, conn: Box<dyn ConstantConn>) -> Box<dyn ConstantConn> {
        let mut metadata = Metadata::default();
        let local_addr = conn.local_addr().ok().map(murmur_std_compat::net::TcpAddr::from);
        let local_addr: Option<&dyn murmur_std_compat::net::Addr> =
            local_addr.as_ref().map(|a| -> &dyn murmur_std_compat::net::Addr { a });
        if metadata.set_remote_addr(local_addr).is_err() {
            return conn;
        }
        let Some(conn_addr) = metadata.addr_port() else {
            return conn;
        };

        detector.conn_map.store(conn_addr, ());
        let this = Arc::clone(detector);
        let close_func: CloseFunc = Box::new(move || {
            this.conn_map.delete(conn_addr);
        });
        new_close_callback_conn(conn, close_func)
    }

    /// Registers the packet conn's port and wraps it in a close callback.
    fn new_packet_conn(detector: &Arc<Self>, conn: Arc<dyn ConstantPacketConn>) -> Arc<dyn ConstantPacketConn> {
        let mut metadata = Metadata::default();
        let local_addr = conn.local_addr().ok();
        if metadata.set_remote_addr(local_addr.as_deref()).is_err() {
            return conn;
        }
        let Some(conn_addr) = metadata.addr_port() else {
            return conn;
        };

        let port = conn_addr.port();
        detector.packet_conn_map.store(port, ());
        let this = Arc::clone(detector);
        let close_func: CloseFunc = Box::new(move || {
            this.packet_conn_map.delete(port);
        });
        new_close_callback_packet_conn(conn, close_func)
    }

    /// Rejects a conn whose source address is already registered.
    fn check_conn(&self, metadata: &Metadata) -> Result<()> {
        let Some(conn_addr) = metadata.source_addr_port() else {
            return Ok(());
        };
        if self.conn_map.load(&conn_addr).is_some() {
            return Err(ErrReject { remote: metadata.remote_address() }.into());
        }
        Ok(())
    }

    /// Rejects a packet conn whose source address is already registered. `is_local_ip` resolves
    /// interface addresses asynchronously, so this method (and the [`DetectorExt`] wrapper) is
    /// `async`.
    async fn check_packet_conn(&self, metadata: &Metadata) -> Result<()> {
        let Some(conn_addr) = metadata.source_addr_port() else {
            return Ok(());
        };

        let is_local_ip = is_local_ip(conn_addr.ip()).await?;
        if !is_local_ip && !conn_addr.ip().is_loopback() {
            return Ok(());
        }

        if self.packet_conn_map.load(&conn_addr.port()).is_some() {
            return Err(ErrReject { remote: metadata.remote_address() }.into());
        }
        Ok(())
    }
}

/// Absent-receiver dispatch for every detector method, implemented for the `Option` that stands
/// in for a possibly-absent detector.
#[async_trait::async_trait]
pub trait DetectorExt {
    fn new_conn(&self, conn: Box<dyn ConstantConn>) -> Box<dyn ConstantConn>;
    fn new_packet_conn(&self, conn: Arc<dyn ConstantPacketConn>) -> Arc<dyn ConstantPacketConn>;
    fn check_conn(&self, metadata: &Metadata) -> Result<()>;
    async fn check_packet_conn(&self, metadata: &Metadata) -> Result<()>;
}

#[async_trait::async_trait]
impl DetectorExt for Option<Arc<Detector>> {
    fn new_conn(&self, conn: Box<dyn ConstantConn>) -> Box<dyn ConstantConn> {
        match self {
            Some(l) => Detector::new_conn(l, conn),
            None => conn,
        }
    }

    fn new_packet_conn(&self, conn: Arc<dyn ConstantPacketConn>) -> Arc<dyn ConstantPacketConn> {
        match self {
            Some(l) => Detector::new_packet_conn(l, conn),
            None => conn,
        }
    }

    fn check_conn(&self, metadata: &Metadata) -> Result<()> {
        match self {
            Some(l) => l.check_conn(metadata),
            None => Ok(()),
        }
    }

    async fn check_packet_conn(&self, metadata: &Metadata) -> Result<()> {
        match self {
            Some(l) => l.check_packet_conn(metadata).await,
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_socketaddr_map_key() {
        let m = Map::<SocketAddr, i32>::new(&[]);
        let a1: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let a2: SocketAddr = "127.0.0.1:8081".parse().unwrap();
        m.store(a1, 1);
        m.store(a2, 2);
        assert_eq!(m.load(&a1), Some(1));
        assert_eq!(m.load(&a2), Some(2));
        m.delete(a1);
        assert!(m.load(&a1).is_none());
        assert_eq!(m.load(&a2), Some(2));
    }
}
