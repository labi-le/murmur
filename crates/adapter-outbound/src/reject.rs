use std::io;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;

use murmur_common_net::io::{Datagram, Stream};
use murmur_constant::adapters::{
    AdapterType, Conn as CConn, PacketConn as CPacketConn, Proxy, ProxyAdapter as CProxyAdapter, ProxyInfo,
};
use murmur_constant::metadata::Metadata;

use super::base::{new_conn, new_packet_conn, Base, BaseOption, BasicOption, ProxyAdapter as BaseProxyAdapter};

pub struct Reject {
    base: Base,
    drop: bool,
    self_weak: std::sync::Weak<Self>,
}

impl std::fmt::Debug for Reject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reject").field("drop", &self.drop).finish_non_exhaustive()
    }
}

#[derive(Clone, Default)]
pub struct RejectOption {
    pub basic_option: BasicOption,
    pub name: String,
}

impl std::fmt::Debug for RejectOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RejectOption").field("name", &self.name).finish_non_exhaustive()
    }
}

#[async_trait]
impl CProxyAdapter for Reject {
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
        if self.drop {
            return Ok(new_conn(Box::new(DropConn), self));
        }
        Ok(new_conn(Box::new(NopConn), self))
    }

    async fn listen_packet_context(
        &self,
        ctx: &CancellationToken,
        metadata: &mut Metadata,
    ) -> Result<Arc<dyn CPacketConn>> {
        BaseProxyAdapter::resolve_udp(self, ctx, metadata).await?;
        let this = self.self_weak.upgrade().ok_or_else(|| anyhow::anyhow!("Reject adapter dropped"))?;
        Ok(new_packet_conn(Arc::new(NopPacketConn), this))
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
impl BaseProxyAdapter for Reject {
    fn dial_options(&self) -> Vec<murmur_component::dialer::options::Option> {
        self.base.dial_options()
    }

    async fn resolve_udp(&self, _ctx: &CancellationToken, metadata: &mut Metadata) -> Result<()> {
        if !metadata.resolved() {
            metadata.dst_ip = Some(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
        }
        Ok(())
    }
}

impl Reject {
    #[must_use]
    pub fn new(option: RejectOption) -> Arc<Self> {
        Arc::new_cyclic(|weak| Self {
            base: Base::new(BaseOption {
                name: option.name,
                type_: AdapterType::REJECT,
                udp: true,
                addr: String::new(),
                provider_name: String::new(),
                xudp: false,
                tfo: false,
                mptcp: false,
                interface: String::new(),
                routing_mark: 0,
                prefer: murmur_constant::dns::DNSPrefer::default(),
            }),
            drop: false,
            self_weak: std::sync::Weak::clone(weak),
        })
    }
}

#[must_use]
pub fn new_reject() -> Arc<Reject> {
    Arc::new_cyclic(|weak| Reject {
        base: Base::new(BaseOption {
            name: "REJECT".to_owned(),
            type_: AdapterType::REJECT,
            udp: true,
            prefer: murmur_constant::dns::DNSPrefer::DUAL_STACK,
            addr: String::new(),
            provider_name: String::new(),
            xudp: false,
            tfo: false,
            mptcp: false,
            interface: String::new(),
            routing_mark: 0,
        }),
        drop: false,
        self_weak: std::sync::Weak::clone(weak),
    })
}

#[must_use]
pub fn new_reject_drop() -> Arc<Reject> {
    Arc::new_cyclic(|weak| Reject {
        base: Base::new(BaseOption {
            name: "REJECT-DROP".to_owned(),
            type_: AdapterType::REJECT_DROP,
            udp: true,
            prefer: murmur_constant::dns::DNSPrefer::DUAL_STACK,
            addr: String::new(),
            provider_name: String::new(),
            xudp: false,
            tfo: false,
            mptcp: false,
            interface: String::new(),
            routing_mark: 0,
        }),
        drop: true,
        self_weak: std::sync::Weak::clone(weak),
    })
}

#[must_use]
pub fn new_pass() -> Arc<Reject> {
    Arc::new_cyclic(|weak| Reject {
        base: Base::new(BaseOption {
            name: "PASS".to_owned(),
            type_: AdapterType::PASS,
            udp: true,
            prefer: murmur_constant::dns::DNSPrefer::DUAL_STACK,
            addr: String::new(),
            provider_name: String::new(),
            xudp: false,
            tfo: false,
            mptcp: false,
            interface: String::new(),
            routing_mark: 0,
        }),
        drop: false,
        self_weak: std::sync::Weak::clone(weak),
    })
}

#[must_use]
pub fn new_pass_rule() -> Arc<Reject> {
    Arc::new_cyclic(|weak| Reject {
        base: Base::new(BaseOption {
            name: "PASS-RULE".to_owned(),
            type_: AdapterType::PASS_RULE,
            udp: true,
            prefer: murmur_constant::dns::DNSPrefer::DUAL_STACK,
            addr: String::new(),
            provider_name: String::new(),
            xudp: false,
            tfo: false,
            mptcp: false,
            interface: String::new(),
            routing_mark: 0,
        }),
        drop: false,
        self_weak: std::sync::Weak::clone(weak),
    })
}

pub(crate) struct NopConn;

impl AsyncRead for NopConn {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for NopConn {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::task::Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()))
    }
    fn poll_flush(self: std::pin::Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl Stream for NopConn {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        Err(io::Error::from(io::ErrorKind::NotConnected))
    }
    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        Err(io::Error::from(io::ErrorKind::NotConnected))
    }
}

pub(crate) struct NopPacketConn;

#[async_trait]
impl Datagram for NopPacketConn {
    async fn recv_from(&self, _buf: &mut [u8]) -> io::Result<(usize, std::net::SocketAddr)> {
        Err(io::ErrorKind::UnexpectedEof.into())
    }

    async fn send_to(&self, buf: &[u8], _addr: std::net::SocketAddr) -> io::Result<usize> {
        Ok(buf.len())
    }

    /// The local address is always the unspecified IPv4 address.
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        Ok(std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0))
    }
}

pub(crate) struct DropConn;

impl AsyncRead for DropConn {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()))
    }
}

impl AsyncWrite for DropConn {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::task::Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()))
    }
    fn poll_flush(self: std::pin::Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

impl Stream for DropConn {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        Err(io::Error::from(io::ErrorKind::NotConnected))
    }
    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        Err(io::Error::from(io::ErrorKind::NotConnected))
    }
}
