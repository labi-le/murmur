use std::io;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use murmur_common::shared_conn::SharedConn;
use murmur_common_net::io::{
    old_addr_to_socket_addr, udp_addr_from_socket_addr, Datagram, OldConnAsStream, Stream as NetStream, StreamAsOldConn,
};
use murmur_common_net::{setup_context_for_conn, EnhancePacketConn};
use murmur_component::dialer::bind::join_host_port;
use murmur_constant::adapters::{
    AdapterType, Conn as CConn, PacketConn as CPacketConn, Proxy, ProxyAdapter as CProxyAdapter, ProxyInfo,
};
use murmur_constant::metadata::Metadata;
use murmur_std_compat::net::Conn as NetConn;
use murmur_transport::socks5::socks5 as socks5t;
use murmur_transport_shadowsocks::core::cipher::{kdf, pick_cipher, Cipher as CoreCipher};
use murmur_transport_shadowsocks::shadowstream;
use murmur_transport_ssr::obfs::{self, obfs::Obfs};
use murmur_transport_ssr::protocol::{self, protocol::Protocol};

use super::base::{new_conn, new_packet_conn, Base, BaseOption, BasicOption, ProxyAdapter as BaseProxyAdapter};
use super::util::{resolve_udp_addr, safe_conn_close, serializes_socks_addr};

/// A stream cipher picked for SSR, retaining what's needed to construct a fresh
/// `shadowstream::stream::Conn` per connection (the stream-cipher type
/// assertion, which the erased `core::Cipher` trait does not expose).
enum SsrCipher {
    Dummy,
    Stream { key: Vec<u8>, new_fn: fn(&[u8]) -> Result<Box<dyn shadowstream::cipher::Cipher>> },
}

pub struct ShadowSocksR {
    base: Base,
    option: ShadowSocksROption,
    /// The cipher; used for the UDP path, which needs no concrete type.
    core_cipher: Box<dyn CoreCipher>,
    /// The classification behind `core_cipher` needed for the per-connection TCP write IV.
    stream_cipher: SsrCipher,
    obfs: Box<dyn Obfs>,
    protocol: Box<dyn Protocol>,
    self_weak: std::sync::Weak<Self>,
}

impl std::fmt::Debug for ShadowSocksR {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShadowSocksR")
            .field("name", &self.base.name())
            .field("addr", &self.base.addr())
            .field("option", &self.option)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Default)]
pub struct ShadowSocksROption {
    pub basic_option: BasicOption,
    pub name: String,
    pub server: String,
    pub port: u16,
    pub password: String,
    pub cipher: String,
    pub obfs: String,
    pub obfs_param: String,
    pub protocol: String,
    pub protocol_param: String,
    pub udp: bool,
}

impl std::fmt::Debug for ShadowSocksROption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShadowSocksROption")
            .field("name", &self.name)
            .field("server", &self.server)
            .field("port", &self.port)
            .field("password", &"<redacted>")
            .field("cipher", &self.cipher)
            .field("obfs", &self.obfs)
            .field("obfs_param", &self.obfs_param)
            .field("protocol", &self.protocol)
            .field("protocol_param", &"<redacted>")
            .field("udp", &self.udp)
            .finish_non_exhaustive()
    }
}

impl ShadowSocksR {
    pub fn new(mut option: ShadowSocksROption) -> Result<Arc<Self>> {
        if option.cipher == "none" {
            "dummy".clone_into(&mut option.cipher);
        }

        let addr = join_host_port(&option.server, option.port);
        let cipher_name = option.cipher.clone();
        let password = option.password.clone();

        let core_cipher = pick_cipher(&cipher_name, None, &password)?;
        let (iv_size, key, stream_cipher): (i32, Vec<u8>, SsrCipher) = if option.cipher == "dummy" {
            (0, kdf(&option.password, 16), SsrCipher::Dummy)
        } else {
            let upper = cipher_name.to_uppercase();
            let choice = murmur_transport_shadowsocks::core::cipher::STREAM_LIST
                .get(upper.as_str())
                .ok_or_else(|| anyhow!("{cipher_name} is not none or a supported stream cipher in ssr"))?;
            let key = kdf(&password, choice.key_size);
            let iv_size =
                i32::try_from(((choice.new)(&key)?).iv_size()).map_err(|_| anyhow!("cipher IV size exceeds i32"))?;
            (iv_size, key.clone(), SsrCipher::Stream { key, new_fn: choice.new })
        };

        let (obfs_impl, obfs_overhead) = obfs::obfs::pick_obfs(
            &option.obfs,
            &obfs::base::Base {
                host: option.server.clone(),
                port: i32::from(option.port),
                key: key.clone(),
                iv_size,
                param: option.obfs_param.clone(),
            },
        )
        .map_err(|err| anyhow!("ssr {addr} initialize obfs error: {err}"))?;

        let protocol_impl = protocol::protocol::pick_protocol(
            &option.protocol,
            &protocol::base::Base { key, overhead: obfs_overhead, param: option.protocol_param.clone() },
        )
        .map_err(|err| anyhow!("ssr {addr} initialize protocol error: {err}"))?;

        let mut base = Base::new(BaseOption {
            name: option.name.clone(),
            addr,
            type_: AdapterType::SHADOWSOCKS_R,
            provider_name: option.basic_option.provider_name.clone(),
            udp: option.udp,
            tfo: option.basic_option.tfo,
            mptcp: option.basic_option.mptcp,
            interface: option.basic_option.interface.clone(),
            routing_mark: option.basic_option.routing_mark,
            prefer: option.basic_option.ip_version,
            xudp: false,
        });
        let dial_options = base.dial_options();
        base.dialer = Some(option.basic_option.new_dialer(dial_options));

        Ok(Arc::new_cyclic(|weak| Self {
            base,
            option,
            core_cipher,
            stream_cipher,
            obfs: obfs_impl,
            protocol: protocol_impl,
            self_weak: std::sync::Weak::clone(weak),
        }))
    }
    async fn stream_conn_context(
        &self,
        ctx: &CancellationToken,
        c: Box<dyn NetConn>,
        metadata: &Metadata,
    ) -> Result<Box<dyn NetConn>> {
        let c: Box<dyn NetStream> = self.obfs.stream_conn(Box::new(OldConnAsStream(c)));

        let (c, iv): (Box<dyn NetStream>, Vec<u8>) = match &self.stream_cipher {
            SsrCipher::Dummy => (c, Vec::new()),
            SsrCipher::Stream { key, new_fn } => {
                let ciph = (new_fn)(key)?;
                let mut stream_conn = shadowstream::stream::new_conn(c, ciph);
                let iv = stream_conn.obtain_write_iv()?.to_vec();
                (Box::new(stream_conn), iv)
            }
        };

        let c = self.protocol.stream_conn(c, &iv);
        let c: Box<dyn NetConn> = Box::new(StreamAsOldConn::new(c));

        let shared = SharedConn::from_boxed(c);
        let mut done = setup_context_for_conn(ctx, shared.clone());
        let writer = shared.clone();
        let result = { writer.write_all(&serializes_socks_addr(metadata)).await };
        let mut err_opt = result.err().map(anyhow::Error::from);
        done.call(&mut err_opt).await;
        match err_opt {
            Some(err) => Err(err),
            None => Ok(Box::new(shared)),
        }
    }
}

#[async_trait]
impl CProxyAdapter for ShadowSocksR {
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
        let mut info = self.base.proxy_info();
        info.dialer_proxy.clone_from(&self.option.basic_option.dialer_proxy);
        info
    }

    fn marshal_json(&self) -> Result<Vec<u8>> {
        self.base.marshal_json()
    }

    async fn dial_context(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<Box<dyn CConn>> {
        let dialer = self
            .base
            .dialer
            .as_ref()
            .ok_or_else(|| anyhow!("ShadowSocksR.base.dialer must be set before DialContext"))?;
        let addr = self.base.addr();
        let raw = dialer.dial_context(ctx, "tcp", &addr).await.map_err(|err| anyhow!("{addr} connect error: {err}"))?;
        // S11: remove with std-compat (murmur_common::shared_conn::SharedConn is old-Conn-based)
        let raw: Box<dyn murmur_std_compat::net::Conn> = Box::new(StreamAsOldConn::new(raw));

        let shared = SharedConn::from_boxed(raw);
        let result = self.stream_conn_context(ctx, Box::new(shared.clone()), metadata).await;
        safe_conn_close(Some(&shared), result.is_err());
        let c = result?;
        // S11: remove with std-compat (stream_conn_context hands back SharedConn's old Conn)
        let c: Box<dyn NetStream> = Box::new(OldConnAsStream(c));
        Ok(new_conn(c, self))
    }

    async fn listen_packet_context(
        &self,
        ctx: &CancellationToken,
        metadata: &mut Metadata,
    ) -> Result<Arc<dyn CPacketConn>> {
        BaseProxyAdapter::resolve_udp(self, ctx, metadata).await?;
        let addr = self.base.addr();
        let resolved = resolve_udp_addr(ctx, "udp", &addr, self.base.prefer).await?;

        let dialer = self.base.dialer.as_ref();
        let dialer =
            dialer.ok_or_else(|| anyhow!("ShadowSocksR.base.dialer must be set before ListenPacketContext"))?;
        let socket_addr = std::net::SocketAddr::new(resolved.ip, resolved.port);
        let pc = dialer.listen_packet(ctx, "udp", "", Some(socket_addr)).await?;
        // S11: remove with std-compat (transport_shadowsocks::core::cipher / transport_ssr::protocol::Protocol require the old EnhancePacketConn)
        let pc: Arc<dyn murmur_std_compat::net::PacketConn> =
            Arc::new(murmur_common_net::io::DatagramAsOldPacketConn(pc));

        let epc = murmur_common_net::new_enhance_packet_conn(pc);
        let epc = self.core_cipher.packet_conn(epc)?;
        let epc = self.protocol.packet_conn(epc);

        let this = self.self_weak.upgrade().ok_or_else(|| anyhow!("ShadowSocksR adapter dropped"))?;
        let ssr_pc: Arc<dyn Datagram> = Arc::new(SsrPacketConn { inner: epc, remote_addr: resolved });
        Ok(new_packet_conn(ssr_pc, this))
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
impl BaseProxyAdapter for ShadowSocksR {
    fn dial_options(&self) -> Vec<murmur_component::dialer::options::Option> {
        self.base.dial_options()
    }

    async fn resolve_udp(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<()> {
        self.base.resolve_udp(ctx, metadata).await
    }
}

struct SsrPacketConn {
    inner: Arc<dyn EnhancePacketConn>,
    remote_addr: murmur_std_compat::net::UdpAddr,
}

#[async_trait]
impl Datagram for SsrPacketConn {
    async fn send_to(&self, buf: &[u8], addr: std::net::SocketAddr) -> io::Result<usize> {
        let addr = udp_addr_from_socket_addr(addr);
        let socks_addr = socks5t::parse_addr_to_socks_addr(&addr).ok_or_else(|| io::Error::other("invalid address"))?;
        let mut packet = socks5t::encode_udp_packet(&socks_addr, buf).map_err(io::Error::other)?;
        packet.drain(..3);
        self.inner.as_packet_conn().write_to(&packet, &self.remote_addr).await?;
        Ok(buf.len())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, std::net::SocketAddr)> {
        let (n, _) = self.inner.as_packet_conn().read_from(buf).await?;
        let received = buf.get(..n).ok_or_else(|| io::Error::other("received more bytes than the buffer holds"))?;
        let addr = socks5t::split_addr(received).ok_or_else(|| io::Error::other("parse addr error"))?;
        let udp_addr = addr.udp_addr().ok_or_else(|| io::Error::other("parse addr error"))?;
        let addr_len = addr.len();
        buf.copy_within(addr_len..n, 0);
        Ok((n - addr_len, old_addr_to_socket_addr(&udp_addr)?))
    }

    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        old_addr_to_socket_addr(self.inner.as_packet_conn().local_addr()?.as_ref())
    }

    fn close(&self) -> io::Result<()> {
        self.inner.as_packet_conn().close()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::AsyncReadExt;

    use super::*;
    use murmur_constant::metadata::NetWork;

    async fn dial(tfo: bool, cipher: &str, obfs: &str, protocol: &str) -> (Box<dyn CConn>, tokio::net::TcpStream) {
        let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = ln.local_addr().unwrap().port();
        let ssr = ShadowSocksR::new(ShadowSocksROption {
            name: "p".into(),
            server: "127.0.0.1".into(),
            port,
            password: "pw".into(),
            cipher: cipher.into(),
            obfs: obfs.into(),
            protocol: protocol.into(),
            basic_option: BasicOption { tfo, ..Default::default() },
            ..Default::default()
        })
        .unwrap();
        let ctx = CancellationToken::new();
        let mut md = Metadata {
            network: NetWork::TCP,
            dst_ip: Some("1.2.3.4".parse().unwrap()),
            dst_port: 80,
            ..Default::default()
        };
        let (c, a) = tokio::join!(ssr.dial_context(&ctx, &mut md), ln.accept());
        let (srv, _) = a.unwrap();
        srv.set_nodelay(true).unwrap();
        (c.unwrap(), srv)
    }

    async fn drain(srv: &mut tokio::net::TcpStream) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        while let Ok(Ok(n)) = tokio::time::timeout(Duration::from_millis(300), srv.read(&mut buf)).await {
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
        out
    }

    async fn sees_eof(srv: &mut tokio::net::TcpStream) -> bool {
        let mut buf = [0u8; 64];
        matches!(tokio::time::timeout(Duration::from_secs(2), srv.read(&mut buf)).await, Ok(Ok(0) | Err(_)))
    }

    /// Regression for `agent://ReviewS9Ssr`'s finding: through the obfs/protocol `Stream` chain
    /// (`StreamAsOldConn(Wrapper{conn: OldConnAsStream(raw)})`), `close()` used to only shut down
    /// the bridge's own `Stream` half, never reaching the dialed conn (or, with `tfo=true`, the
    /// `TfoConn` dial-cancel); the peer never saw the TCP FIN. `old_conn()` forwarding through
    /// every obfs/protocol wrapper `Stream` fixes it for plain and obfuscated chains, with and
    /// without TFO. `close_write()` is asserted only for `tfo=false`: `TfoConn` itself never
    /// overrides `close_write` (a separate, pre-existing gap outside this bridge, reported not
    /// fixed), so it stays the old trait's no-op default there regardless of `old_conn`
    /// forwarding — `close_write` for `tfo=true` is only logged, not asserted.
    #[tokio::test(flavor = "multi_thread")]
    async fn close_and_half_close_reach_the_dialed_conn() {
        for tfo in [false, true] {
            for (cipher, obfs, proto) in [("dummy", "plain", "origin"), ("rc4-md5", "http_simple", "auth_aes128_md5")] {
                let (conn, mut srv) = dial(tfo, cipher, obfs, proto).await;
                let _ = drain(&mut srv).await;
                if let Some(old) = murmur_common_net::io::Stream::old_conn(conn.as_ref()) {
                    let _ = old.close();
                }
                let closed = sees_eof(&mut srv).await;
                assert!(closed, "tfo={tfo} {cipher}/{obfs}/{proto}: close() must reach the dialed conn");

                let (conn2, mut srv2) = dial(tfo, cipher, obfs, proto).await;
                let _ = drain(&mut srv2).await;
                if let Some(old) = murmur_common_net::io::Stream::old_conn(conn2.as_ref()) {
                    let _ = old.close_write();
                }
                let half = sees_eof(&mut srv2).await;
                println!("tfo={tfo} {cipher}/{obfs}/{proto}: close_write->peer_eof={half}");
                if !tfo {
                    assert!(half, "tfo={tfo} {cipher}/{obfs}/{proto}: close_write() must reach the dialed conn");
                }
                drop((conn, conn2));
            }
        }
    }
}
