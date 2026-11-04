use std::sync::Arc;

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use murmur_common::shared_conn::SharedConn;
use murmur_common_net::io::{Acceptor, AcceptorAsOldListener, OldListenerAsAcceptor};
use murmur_common_net::new_handle_context_listener;
use murmur_constant::adapters::{NatTable, UDPPacket};
use murmur_constant::metadata::{Metadata, NetWork};
use murmur_constant::tunnel::Tunnel;
use murmur_listener_inner::tcp::handle_tcp;
use murmur_log::{errorln, warnln};
use murmur_std_compat::net::{Conn as NetConn, Listener as NetListener};
use murmur_transport_tlsmirror::config::{
    decode_primary_key, ConnectionEnrolment, ServerConfig, TimeSpec, TransportLayerPadding,
};
use murmur_transport_tlsmirror::enrollment::serve_enrollment_control_connection;
use murmur_transport_tlsmirror::enrollment::server_identifier_host;
use murmur_transport_tlsmirror::server::serve_conn_ready;

#[derive(Clone, Default)]
pub struct Config {
    pub primary_key: String,
    pub dest: String,
    pub proxy: String,
    pub explicit_nonce_cipher_suites: Vec<u16>,
    pub defer_instance_derived_write_time: TimeSpec,
    pub transport_layer_padding: TransportLayerPadding,
    pub connection_enrolment: Option<ConnectionEnrolment>,
    pub sequence_watermarking_enabled: bool,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config").finish_non_exhaustive()
    }
}

impl Config {
    pub fn build(&self, tunnel: Arc<dyn Tunnel>) -> Builder {
        Builder { config: self.clone(), tunnel }
    }
}

#[derive(Clone)]
pub struct Builder {
    config: Config,
    tunnel: Arc<dyn Tunnel>,
}

impl std::fmt::Debug for Builder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Builder").finish_non_exhaustive()
    }
}

impl Builder {
    pub fn wrap_tunnel(&self, tunnel: Arc<dyn Tunnel>) -> Arc<dyn Tunnel> {
        let Some(_) = &self.config.connection_enrolment else {
            return tunnel;
        };
        let Ok(key) = decode_primary_key(&self.config.primary_key) else {
            return tunnel;
        };
        let Ok(control_host) = server_identifier_host(&key) else {
            return tunnel;
        };
        Arc::new(EnrollmentTunnel { tunnel, primary_key: self.config.primary_key.clone(), control_host })
    }

    #[must_use]
    pub fn new_listener(&self, l: Box<dyn Acceptor>) -> Box<dyn Acceptor> {
        let config = self.config.clone();
        let tunnel = Arc::clone(&self.tunnel);
        // S11: remove with murmur-std-compat — `new_handle_context_listener`/`SharedConn` (common-net,
        // common) are still `murmur_std_compat::net::{Listener,Conn}`-typed.
        let l: Box<dyn NetListener> = Box::new(AcceptorAsOldListener(l));
        Box::new(OldListenerAsAcceptor(new_handle_context_listener(
            &CancellationToken::new(),
            l,
            Arc::new(move |ctx, conn: SharedConn| {
                let config = config.clone();
                let tunnel = Arc::clone(&tunnel);
                Box::pin(async move {
                    let forward_conn = handle_tcp(Some(tunnel), &config.dest, &config.proxy).await?;
                    let forward_conn = SharedConn::from_boxed(forward_conn);
                    let server_config: ServerConfig = ServerConfig {
                        primary_key: config.primary_key,
                        explicit_nonce_cipher_suites: config.explicit_nonce_cipher_suites,
                        defer_instance_derived_write: config.defer_instance_derived_write_time,
                        transport_layer_padding: config.transport_layer_padding,
                        connection_enrolment: config.connection_enrolment,
                        sequence_watermarking_enabled: config.sequence_watermarking_enabled,
                        ..ServerConfig::default()
                    };
                    let hidden_conn: Box<dyn NetConn> = Box::new(conn.clone());
                    let forward_conn_boxed: Box<dyn NetConn> = Box::new(forward_conn.clone());
                    let hidden = serve_conn_ready(&ctx, hidden_conn, forward_conn_boxed, server_config)
                        .await
                        .inspect_err(|_| {
                            let _ = forward_conn.close();
                        })?;
                    let result: Box<dyn NetConn> = Box::new(murmur_common_net::io::StreamAsOldConn::new(hidden));
                    Ok(SharedConn::from_boxed(result))
                })
            }),
            Arc::new(|payload| {
                let stack = std::backtrace::Backtrace::force_capture();
                errorln!("tlsmirror server panic: {}\n{stack}", panic_message(payload));
            }),
        )))
    }
}

struct EnrollmentTunnel {
    tunnel: Arc<dyn Tunnel>,
    primary_key: String,
    control_host: String,
}

#[async_trait]
impl Tunnel for EnrollmentTunnel {
    async fn handle_tcp_conn(&self, conn: Box<dyn murmur_common_net::io::Stream>, metadata: Metadata) {
        if metadata.network == NetWork::TCP
            && metadata.dst_port == 80
            && metadata.host.to_lowercase() == self.control_host.to_lowercase()
        {
            if let Err(err) = serve_enrollment_control_connection(
                &CancellationToken::new(),
                Box::new(murmur_common_net::io::StreamAsOldConn::new(conn)),
                &self.primary_key,
            )
            .await
            {
                warnln!("tlsmirror enrollment control connection failed: {err}");
            }
            return;
        }
        self.tunnel.handle_tcp_conn(conn, metadata).await;
    }

    fn handle_udp_packet(&self, packet: Arc<dyn UDPPacket>, metadata: Metadata) {
        self.tunnel.handle_udp_packet(packet, metadata);
    }

    fn nat_table(&self) -> Arc<dyn NatTable> {
        self.tunnel.nat_table()
    }
}
/// The rendering of the value recovered from a panic.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_owned()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        String::from("tlsmirror: panic")
    }
}
