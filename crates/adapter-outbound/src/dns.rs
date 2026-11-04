use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::sync::CancellationToken;

use murmur_common_net::io::Datagram;
use murmur_common_net::pipe;
use murmur_common_pool as pool;
use murmur_component::resolver::relay::{relay_dns_conn, relay_dns_packet, SAFE_DNS_PACKET_SIZE};
use murmur_constant::adapters::{
    AdapterType, Conn as CConn, PacketConn as CPacketConn, Proxy, ProxyAdapter as CProxyAdapter, ProxyInfo,
};
use murmur_constant::metadata::Metadata;
use murmur_log::debugln;

use super::base::{new_conn, new_packet_conn, Base, BaseOption, BasicOption, ProxyAdapter as BaseProxyAdapter};

pub struct Dns {
    base: Base,
    self_weak: std::sync::Weak<Self>,
}

#[derive(Clone, Default)]
pub struct DnsOption {
    pub basic_option: BasicOption,
    pub name: String,
}

impl core::fmt::Debug for DnsOption {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // `basic_option` has no `Debug`.
        f.debug_struct("DnsOption").field("name", &self.name).finish_non_exhaustive()
    }
}

impl core::fmt::Debug for Dns {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Dns").field("name", &self.base.name).finish_non_exhaustive()
    }
}

#[async_trait]
impl CProxyAdapter for Dns {
    fn name(&self) -> String {
        self.base.name()
    }

    fn type_(&self) -> AdapterType {
        self.base.type_()
    }

    fn addr(&self) -> String {
        self.base.addr()
    }

    fn support_udp(&self) -> bool {
        self.base.support_udp()
    }

    fn proxy_info(&self) -> ProxyInfo {
        self.base.proxy_info()
    }

    fn marshal_json(&self) -> Result<Vec<u8>> {
        self.base.marshal_json()
    }

    async fn dial_context(&self, _ctx: &CancellationToken, _metadata: &mut Metadata) -> Result<Box<dyn CConn>> {
        let (left, right) = pipe();
        tokio::spawn(async move {
            // S11: remove with std-compat
            let _ = relay_dns_conn(
                &CancellationToken::new(),
                Box::new(murmur_common_net::io::OldConnAsStream(right)),
                std::time::Duration::ZERO,
            )
            .await;
        });
        // S11: remove with std-compat
        Ok(new_conn(Box::new(murmur_common_net::io::OldConnAsStream(left)), self))
    }

    async fn listen_packet_context(
        &self,
        ctx: &CancellationToken,
        metadata: &mut Metadata,
    ) -> Result<Arc<dyn CPacketConn>> {
        debugln!("[DNS] hijack udp:{} from {:?}", metadata.remote_address(), metadata.source_addr_port());
        BaseProxyAdapter::resolve_udp(self, ctx, metadata).await?;

        let child = ctx.child_token();
        let this = self.self_weak.upgrade().ok_or_else(|| anyhow::anyhow!("Dns adapter dropped"))?;
        Ok(new_packet_conn(Arc::new(DnsPacketConn::new(child)), this))
    }

    fn support_uot(&self) -> bool {
        self.base.support_uot()
    }

    fn is_l3_protocol(&self, metadata: &Metadata) -> bool {
        self.base.is_l3_protocol(metadata)
    }

    fn unwrap(&self, metadata: &Metadata, touch: bool) -> Option<Arc<dyn Proxy>> {
        self.base.unwrap(metadata, touch)
    }

    fn close(&self) -> Result<()> {
        self.base.close()
    }
}

#[async_trait]
impl BaseProxyAdapter for Dns {
    fn dial_options(&self) -> Vec<murmur_component::dialer::options::Option> {
        self.base.dial_options()
    }

    async fn resolve_udp(&self, _ctx: &CancellationToken, metadata: &mut Metadata) -> Result<()> {
        if !metadata.resolved() {
            metadata.dst_ip = Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)));
        }
        Ok(())
    }
}

impl Dns {
    #[must_use]
    pub fn new(option: DnsOption) -> Arc<Self> {
        let base = Base::new(BaseOption {
            name: option.name,
            type_: AdapterType::DNS,
            provider_name: option.basic_option.provider_name.clone(),
            udp: true,
            tfo: option.basic_option.tfo,
            mptcp: option.basic_option.mptcp,
            interface: option.basic_option.interface.clone(),
            routing_mark: option.basic_option.routing_mark,
            prefer: option.basic_option.ip_version,
            addr: String::new(),
            xudp: false,
        });
        Arc::new_cyclic(|weak| Self { base, self_weak: std::sync::Weak::clone(weak) })
    }
}

struct DnsPacket {
    data: Vec<u8>,
    addr: std::net::SocketAddr,
}

/// The packet-conn side of the DNS outbound.
struct DnsPacketConn {
    response: AsyncMutex<tokio::sync::mpsc::Receiver<DnsPacket>>,
    sender: tokio::sync::mpsc::Sender<DnsPacket>,
    ctx: CancellationToken,
}

impl DnsPacketConn {
    fn new(ctx: CancellationToken) -> Self {
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        Self { response: AsyncMutex::new(receiver), sender, ctx }
    }
}

#[async_trait]
impl Datagram for DnsPacketConn {
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, std::net::SocketAddr)> {
        // cancel-safe: the queue guard and the pending receive unwind with the future, and an
        // unclaimed packet stays queued for the next call.
        let mut response = self.response.lock().await;
        let packet = tokio::select! {
            packet = response.recv() => packet,
            () = self.ctx.cancelled() => return Err(io::ErrorKind::NotConnected.into()),
        };
        drop(response);
        let Some(packet) = packet else {
            return Err(io::ErrorKind::NotConnected.into());
        };
        let n = packet.data.len().min(buf.len());
        let (dst, _) = buf.split_at_mut(n);
        dst.copy_from_slice(packet.data.get(..n).unwrap_or_default());
        Ok((n, packet.addr))
    }

    async fn send_to(&self, buf: &[u8], addr: std::net::SocketAddr) -> io::Result<usize> {
        // cancel-safe: it has no suspension point of its own; the relay it starts runs detached.
        if self.ctx.is_cancelled() {
            return Err(io::ErrorKind::NotConnected.into());
        }

        if buf.len() > SAFE_DNS_PACKET_SIZE {
            return Err(io::Error::other(format!(
                "dns query of {} bytes exceeds the {SAFE_DNS_PACKET_SIZE} byte relay buffer",
                buf.len()
            )));
        }

        let mut relay_buf = pool::get(SAFE_DNS_PACKET_SIZE);
        let (relay_head, _) = relay_buf.split_at_mut(buf.len());
        relay_head.copy_from_slice(buf);
        let payload_len = buf.len();

        let sender = self.sender.clone();
        let ctx = self.ctx.clone();
        let n = buf.len();
        tokio::spawn(async move {
            let timeout_ctx = ctx.child_token();
            let timeout_ctx_for_sleep = timeout_ctx.clone();
            tokio::spawn(async move {
                tokio::select! {
                    () = tokio::time::sleep(murmur_component::resolver::relay::DEFAULT_DNS_RELAY_TIMEOUT) => timeout_ctx_for_sleep.cancel(),
                    () = timeout_ctx_for_sleep.cancelled() => {}
                }
            });

            let payload = relay_buf.get(..payload_len).unwrap_or_default().to_vec();
            let data = if let Ok(data) = relay_dns_packet(&timeout_ctx, &payload, &mut relay_buf).await {
                data.into_owned()
            } else {
                let _ = pool::put(relay_buf);
                timeout_ctx.cancel();
                return;
            };
            let _ = pool::put(relay_buf);
            timeout_ctx.cancel();

            let packet = DnsPacket { data, addr };
            tokio::select! {
                _ = sender.send(packet) => {}
                () = ctx.cancelled() => {}
            }
        });

        Ok(n)
    }

    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        Ok(std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53))
    }

    fn close(&self) -> io::Result<()> {
        self.ctx.cancel();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use super::*;

    #[tokio::test]
    async fn an_oversize_udp_query_fails_closed_instead_of_reporting_success() {
        let pc = DnsPacketConn::new(CancellationToken::new());
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 53));
        let query = vec![0u8; SAFE_DNS_PACKET_SIZE + 1];

        let err = pc.send_to(&query, addr).await.expect_err("a discarded query must not be reported as sent");
        let err = err.to_string();
        assert!(err.contains(&query.len().to_string()), "{err}");
        assert!(err.contains(&SAFE_DNS_PACKET_SIZE.to_string()), "{err}");

        let mut response = pc.response.lock().await;
        assert!(response.try_recv().is_err(), "a rejected query must not queue a reply");
    }
}
