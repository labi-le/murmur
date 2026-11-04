use std::sync::Arc;

use anyhow::{anyhow, Result};
use parking_lot::RwLock;

use murmur_constant::dns::DNSMode;
use murmur_constant::metadata::{Metadata, NetWork, Type};
use murmur_constant::tunnel::Tunnel;
use murmur_constant::version::PROJECT_NAME;
use murmur_std_compat::net::Conn;

static TUNNEL: RwLock<Option<Arc<dyn Tunnel>>> = RwLock::new(None);

pub fn new(t: Arc<dyn Tunnel>) {
    *TUNNEL.write() = Some(t);
}

pub fn get_tunnel() -> Option<Arc<dyn Tunnel>> {
    TUNNEL.read().clone()
}

/// cancel-safe: no await points; the metadata build and the spawn both run on the first poll.
#[expect(
    clippy::unused_async,
    reason = "the async signature is load-bearing: this public entry point is awaited by callers across the workspace, and the body hands the work to a spawned tunnel task"
)]
pub async fn handle_tcp(tunnel: Option<Arc<dyn Tunnel>>, address: &str, proxy: &str) -> Result<Box<dyn Conn>> {
    let Some(tunnel) = tunnel else {
        return Err(anyhow!("tunnel uninitialized"));
    };

    let (conn1, conn2) = murmur_common_net::pipe();

    let mut metadata = Metadata {
        network: NetWork::TCP,
        type_: Type::INNER,
        src_ip: None,
        dst_ip: None,
        src_geo_ip: None,
        dst_geo_ip: None,
        src_ipasn: String::new(),
        dst_ipasn: String::new(),
        src_port: 0,
        dst_port: 0,
        in_ip: None,
        in_port: 0,
        in_name: String::new(),
        in_user: String::new(),
        rematch_name: String::new(),
        host: String::new(),
        dns_mode: DNSMode::DNS_NORMAL,
        uid: 0,
        process: PROJECT_NAME.to_owned(),
        process_path: String::new(),
        special_proxy: String::new(),
        special_rules: String::new(),
        remote_dst: String::new(),
        dscp: 0,
        raw_src_addr: None,
        raw_dst_addr: None,
        sniff_host: String::new(),
    };
    if !proxy.is_empty() {
        proxy.clone_into(&mut metadata.special_proxy);
    }
    metadata.set_remote_address(address)?;

    tokio::spawn(async move {
        tunnel.handle_tcp_conn(Box::new(murmur_common_net::io::OldConnAsStream(conn2)), metadata).await;
    });
    Ok(Box::new(conn1))
}
