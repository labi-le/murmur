use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;

use crate::conns::faketcp;
use crate::conns::udp;
use crate::conns::wechat::obfs::ObfsWeChatUDPConn;
use crate::obfs::dummy::DummyObfuscator;
use crate::obfs::obfs::Obfuscator;
use crate::transport::quic::{Config, Conn, TlsConfig, TransportFactory};
use crate::utils::misc::PacketDialer;
use murmur_std_compat::net::{Addr, PacketConn};

/// Carries the QUIC transport factory injected by the caller; the crate itself implements no QUIC
/// transport.
pub struct ClientTransport {
    quic_transport_factory: TransportFactory,
}

impl std::fmt::Debug for ClientTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientTransport").finish_non_exhaustive()
    }
}

impl ClientTransport {
    pub fn new(quic_transport_factory: TransportFactory) -> Self {
        Self { quic_transport_factory }
    }

    pub async fn quic_packet_conn(
        &self,
        proto: &str,
        r_addr: &dyn Addr,
        server_ports: &str,
        obfs: Option<Arc<dyn Obfuscator>>,
        hop_interval: Duration,
        dialer: Arc<dyn PacketDialer>,
    ) -> anyhow::Result<Box<dyn PacketConn>> {
        let server = r_addr.string();
        if proto.is_empty() || proto == "udp" {
            let conn = dialer.listen_packet(r_addr).await?;
            if let Some(obfs) = obfs {
                if !server_ports.is_empty() {
                    return udp::new_obfs_udp_hop_client_packet_conn(
                        &server,
                        server_ports,
                        hop_interval,
                        Some(obfs),
                        dialer,
                    )
                    .await;
                }
                let oc = udp::ObfsUDPConn::new(conn, obfs);
                Ok(Box::new(oc))
            } else if !server_ports.is_empty() {
                udp::new_obfs_udp_hop_client_packet_conn(&server, server_ports, hop_interval, None, dialer).await
            } else {
                Ok(conn)
            }
        } else if proto == "wechat-video" {
            let conn = dialer.listen_packet(r_addr).await?;
            let obfs = obfs.unwrap_or_else(|| Arc::new(DummyObfuscator::new()));
            Ok(Box::new(ObfsWeChatUDPConn::new(conn, obfs)))
        } else if proto == "faketcp" {
            let conn = faketcp::dial("tcp", &server).await?;
            if let Some(obfs) = obfs {
                let oc = faketcp::obfs::ObfsFakeTCPConn::new(conn, obfs);
                Ok(Box::new(oc))
            } else {
                Ok(Box::new(conn))
            }
        } else {
            Err(anyhow!("unsupported protocol: {proto}"))
        }
    }

    pub async fn quic_dial(
        &self,
        proto: &str,
        server: &str,
        server_ports: &str,
        tls_config: &dyn TlsConfig,
        quic_config: &Config,
        obfs: Option<Arc<dyn Obfuscator>>,
        hop_interval: Duration,
        dialer: Arc<dyn PacketDialer>,
    ) -> anyhow::Result<Arc<dyn Conn>> {
        let server_udp_addr = dialer.remote_addr(server).await?;

        let pkt_conn: Arc<dyn PacketConn> = Arc::from(
            self.quic_packet_conn(proto, &*server_udp_addr, server_ports, obfs, hop_interval, Arc::clone(&dialer))
                .await?,
        );

        let transport = (self.quic_transport_factory)(Arc::clone(&pkt_conn));
        // auto close conn
        transport.set_created_conn(true);
        // auto close transport
        transport.set_single_use(true);
        match transport.dial(dialer.context(), &*server_udp_addr, tls_config, quic_config).await {
            Ok(qs) => Ok(qs),
            Err(err) => {
                let _ = pkt_conn.close();
                Err(err)
            }
        }
    }
}
