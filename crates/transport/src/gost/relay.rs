use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::sync::CancellationToken;

use murmur_common::shared_conn::SharedConn;
use murmur_common_net::io::{Datagram, OldConnAsStream, Stream, StreamAsOldConn};
use murmur_constant::adapters::Dialer;
use murmur_std_compat::net::{Addr, Conn as NetConn, PacketConn as NetPacketConn, UdpAddr};
use murmur_transport_vmess::tls as vmess_tls;

use super::websocket::MuxConn;

const RELAY_VERSION1: u8 = 0x01;

const RELAY_CMD_CONNECT: u8 = 0x01;
const RELAY_FLAG_UDP: u8 = 0x80;

const RELAY_STATUS_OK: u8 = 0x00;
const RELAY_STATUS_BAD_REQUEST: u8 = 0x01;
const RELAY_STATUS_UNAUTHORIZED: u8 = 0x02;
const RELAY_STATUS_FORBIDDEN: u8 = 0x03;
const RELAY_STATUS_TIMEOUT: u8 = 0x04;
const RELAY_STATUS_SERVICE_UNAVAILABLE: u8 = 0x05;
const RELAY_STATUS_HOST_UNREACHABLE: u8 = 0x06;
const RELAY_STATUS_NETWORK_UNREACHABLE: u8 = 0x07;
const RELAY_STATUS_INTERNAL_SERVER_ERROR: u8 = 0x08;

const RELAY_FEATURE_USER_AUTH: u8 = 0x01;
const RELAY_FEATURE_ADDR: u8 = 0x02;
const RELAY_FEATURE_NETWORK: u8 = 0x04;

const RELAY_ADDR_IPV4: u8 = 0x01;
const RELAY_ADDR_DOMAIN: u8 = 0x03;
const RELAY_ADDR_IPV6: u8 = 0x04;

const RELAY_NETWORK_TCP: u16 = 0x0000;
const RELAY_NETWORK_UDP: u16 = 0x0001;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[expect(clippy::struct_excessive_bools, reason = "the option struct mirrors the protocol's flag set field for field")]
pub struct RelayOption {
    #[serde(rename = "server", default)]
    pub server: String,
    #[serde(rename = "port", default)]
    pub port: i32,
    #[serde(rename = "forward", default)]
    pub forward: bool,
    #[serde(rename = "tls", default)]
    pub tls: bool,
    #[serde(rename = "mux", default)]
    pub mux: bool,
    #[serde(rename = "sni", default)]
    pub sni: String,
    #[serde(rename = "username", default)]
    pub username: String,
    #[serde(rename = "password", default)]
    pub password: String,
    #[serde(rename = "skip-cert-verify", default)]
    pub skip_cert_verify: bool,
    #[serde(rename = "name-cert-verify", default)]
    pub name_cert_verify: String,
    #[serde(rename = "fingerprint", default)]
    pub fingerprint: String,
    #[serde(rename = "certificate", default)]
    pub certificate: String,
    #[serde(rename = "private-key", default)]
    pub private_key: String,
    #[serde(rename = "client-fingerprint", default)]
    pub client_fingerprint: String,
}

pub(crate) struct RelayDialer {
    base: Arc<dyn Dialer>,
    option: RelayOption,
}

pub fn new_relay_dialer(base: Arc<dyn Dialer>, option: Option<&RelayOption>) -> Arc<dyn Dialer> {
    match option {
        None => base,
        Some(option) => Arc::new(RelayDialer { base, option: option.clone() }),
    }
}

#[async_trait]
impl Dialer for RelayDialer {
    async fn dial_context(&self, ctx: &CancellationToken, network: &str, address: &str) -> Result<Box<dyn Stream>> {
        if !network.starts_with("tcp") {
            return Err(anyhow!("gost relay only supports tcp dial, got {network}"));
        }

        let mut conn = self.dial_relay_server(ctx, address).await?;

        let target_address = if self.option.forward { "" } else { address };
        if let Err(err) = write_relay_request(
            &mut conn,
            RELAY_CMD_CONNECT,
            target_address,
            RELAY_NETWORK_TCP,
            &self.option.username,
            &self.option.password,
        )
        .await
        {
            let _ = conn.close();
            return Err(err);
        }
        if let Err(err) = read_relay_connect_response(&mut conn).await {
            let _ = conn.close();
            return Err(err);
        }

        Ok(Box::new(OldConnAsStream(conn))) // S11: remove when the legacy conn bridge is deleted.
    }

    async fn listen_packet(
        &self,
        ctx: &CancellationToken,
        network: &str,
        _address: &str,
        r_addr_port: Option<SocketAddr>,
    ) -> Result<Box<dyn Datagram>> {
        if !network.starts_with("udp") {
            return Err(anyhow!("gost relay only supports udp packet dial, got {network}"));
        }
        let Some(r_addr_port) = r_addr_port else {
            return Err(anyhow!("gost relay udp target address is required"));
        };

        let raddr = UdpAddr::from(r_addr_port);
        let mut conn = self.dial_relay_server(ctx, &raddr.string()).await?;

        let target_address = if self.option.forward { String::new() } else { raddr.string() };
        if let Err(err) = write_relay_request(
            &mut conn,
            RELAY_CMD_CONNECT | RELAY_FLAG_UDP,
            &target_address,
            RELAY_NETWORK_UDP,
            &self.option.username,
            &self.option.password,
        )
        .await
        {
            let _ = conn.close();
            return Err(err);
        }
        if let Err(err) = read_relay_connect_response(&mut conn).await {
            let _ = conn.close();
            return Err(err);
        }

        Ok(Box::new(murmur_common_net::io::OldPacketConnAsDatagram(RelayPacketConn::new(conn, raddr))))
        // S11: remove when the legacy conn bridge is deleted.
    }
}

impl RelayDialer {
    async fn dial_relay_server(&self, ctx: &CancellationToken, fallback_address: &str) -> Result<Box<dyn NetConn>> {
        let mut relay_address = String::new();
        if !self.option.server.is_empty() || self.option.port > 0 {
            if self.option.server.is_empty() || self.option.port <= 0 {
                return Err(anyhow!("gost relay server and port are required"));
            }
            relay_address = join_host_port(&self.option.server, &self.option.port.to_string());
        } else if self.option.forward {
            relay_address = fallback_address.to_owned();
        }
        if relay_address.is_empty() {
            return Err(anyhow!("gost relay server and port are required"));
        }

        let mut conn: Box<dyn NetConn> =
            Box::new(StreamAsOldConn::new(self.base.dial_context(ctx, "tcp", &relay_address).await?)); // S11: remove when the legacy conn bridge is deleted.

        if self.option.tls {
            let vmess_tls::TlsConfig {
                next_protos,
                ech,
                shadow_tls,
                restls,
                jls,
                tls_mirror,
                tls_mirror_dialer,
                reality,
                ..
            } = vmess_tls::TlsConfig::default();
            let tls_config = vmess_tls::TlsConfig {
                host: self.server_name(&relay_address),
                skip_cert_verify: self.option.skip_cert_verify,
                name_cert_verify: self.option.name_cert_verify.clone(),
                finger_print: self.option.fingerprint.clone(),
                certificate: self.option.certificate.clone(),
                private_key: self.option.private_key.clone(),
                client_fingerprint: self.option.client_fingerprint.clone(),
                next_protos,
                ech,
                shadow_tls,
                restls,
                jls,
                tls_mirror,
                tls_mirror_dialer,
                reality,
            };
            conn = Box::new(StreamAsOldConn::new(
                vmess_tls::stream_tls_conn(ctx, Box::new(OldConnAsStream(conn)), &tls_config).await?,
            ));
        }

        if self.option.mux {
            let mut mux_config = murmur_smux::default_config();
            mux_config.keep_alive_disabled = true;

            let session = murmur_smux::client(Box::new(OldConnAsStream(conn)), &mux_config)?;

            let stream = match session.open_stream().await {
                Ok(stream) => stream,
                Err(err) => {
                    let _ = session.close();
                    return Err(err);
                }
            };

            conn = Box::new(StreamAsOldConn::new(MuxConn::new(stream, session)));
        }

        Ok(conn)
    }

    fn server_name(&self, relay_address: &str) -> String {
        if !self.option.sni.is_empty() {
            return self.option.sni.clone();
        }
        if !self.option.server.is_empty() {
            return self.option.server.clone();
        }
        match split_host_port(relay_address) {
            Ok((host, _)) => host,
            Err(_) => relay_address.to_owned(),
        }
    }
}

async fn write_relay_request<W: AsyncWrite + Unpin>(
    w: &mut W,
    command: u8,
    address: &str,
    network: u16,
    username: &str,
    password: &str,
) -> Result<()> {
    let mut features: Vec<Vec<u8>> = Vec::with_capacity(3);
    if !username.is_empty() || !password.is_empty() {
        features.push(encode_relay_feature(RELAY_FEATURE_USER_AUTH, &encode_relay_user_auth(username, password)?)?);
    }

    if !address.is_empty() {
        let addr_payload = encode_relay_addr(address)?;
        features.push(encode_relay_feature(RELAY_FEATURE_ADDR, &addr_payload)?);
    }

    features.push(encode_relay_feature(RELAY_FEATURE_NETWORK, &network.to_be_bytes())?);

    let payload_len: usize = features.iter().map(Vec::len).sum();
    let payload_len = u16::try_from(payload_len).map_err(|_| anyhow!("gost relay feature list too large"))?;

    let payload_len_bytes = payload_len.to_be_bytes();
    let header = [RELAY_VERSION1, command, payload_len_bytes[0], payload_len_bytes[1]];
    w.write_all(&header).await?;
    for feature in &features {
        w.write_all(feature).await?;
    }
    w.flush().await?;
    Ok(())
}

pub(crate) struct RelayPacketConn {
    conn: SharedConn,
    raddr: UdpAddr,
    wmu: AsyncMutex<()>,
}

impl RelayPacketConn {
    fn new(conn: Box<dyn NetConn>, raddr: UdpAddr) -> Self {
        Self { conn: SharedConn::from_boxed(conn), raddr, wmu: AsyncMutex::new(()) }
    }
}

#[async_trait]
impl NetPacketConn for RelayPacketConn {
    async fn read_from(&self, p: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        let mut conn = self.conn.clone();
        let mut header = [0u8; 2];
        conn.read_exact(&mut header).await?;

        let packet_len = u16::from_be_bytes(header) as usize;
        if packet_len <= p.len() {
            let (head, _) = p.split_at_mut(packet_len);
            conn.read_exact(head).await?;
            return Ok((packet_len, Box::new(self.raddr.clone())));
        }

        let mut buf = vec![0u8; packet_len];
        conn.read_exact(&mut buf).await?;
        let n = p.len().min(buf.len());
        let (dst, _) = p.split_at_mut(n);
        let (src, _) = buf.split_at(n);
        dst.copy_from_slice(src);
        Ok((n, Box::new(self.raddr.clone())))
    }

    async fn write_to(&self, p: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        let packet_len = u16::try_from(p.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("gost relay udp packet too large: {}", p.len()))
        })?;
        if addr.string() != self.raddr.string() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("gost relay udp association is bound to {}, got {}", self.raddr.string(), addr.string()),
            ));
        }

        let _guard = self.wmu.lock().await;
        let mut conn = self.conn.clone();
        conn.write_all(&packet_len.to_be_bytes()).await?;
        conn.write_all(p).await?;
        conn.flush().await?;
        Ok(p.len())
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.conn.local_addr()
    }

    fn close(&self) -> io::Result<()> {
        self.conn.close()
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.conn.set_deadline(deadline)
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.conn.set_read_deadline(deadline)
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.conn.set_write_deadline(deadline)
    }
}

async fn read_relay_connect_response<R: AsyncRead + Unpin>(r: &mut R) -> Result<()> {
    let mut header = [0u8; 4];
    r.read_exact(&mut header).await?;
    if header[0] != RELAY_VERSION1 {
        return Err(anyhow!("gost relay bad version: {}", header[0]));
    }
    if header[1] != RELAY_STATUS_OK {
        return Err(anyhow!(
            "gost relay connect failed with status 0x{:02x} ({})",
            header[1],
            relay_status_text(header[1])
        ));
    }

    let feature_len = u16::from_be_bytes([header[2], header[3]]) as usize;
    if feature_len == 0 {
        return Ok(());
    }

    let mut discard = vec![0u8; feature_len];
    r.read_exact(&mut discard).await?;
    Ok(())
}

fn encode_relay_feature(feature_type: u8, payload: &[u8]) -> Result<Vec<u8>> {
    let payload_len = u16::try_from(payload.len()).map_err(|_| anyhow!("gost relay feature payload too large"))?;

    let mut out = Vec::with_capacity(3 + payload.len());
    out.push(feature_type);
    out.extend_from_slice(&payload_len.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

fn encode_relay_user_auth(username: &str, password: &str) -> Result<Vec<u8>> {
    let username_len = u8::try_from(username.len()).map_err(|_| anyhow!("gost relay username or password too long"))?;
    let password_len = u8::try_from(password.len()).map_err(|_| anyhow!("gost relay username or password too long"))?;

    let mut out = Vec::with_capacity(2 + username.len() + password.len());
    out.push(username_len);
    out.extend_from_slice(username.as_bytes());
    out.push(password_len);
    out.extend_from_slice(password.as_bytes());
    Ok(out)
}

fn encode_relay_addr(address: &str) -> Result<Vec<u8>> {
    let (host, port_string) =
        split_host_port(address).map_err(|err| anyhow!("invalid relay target address {address:?}: {err}"))?;

    let port: i64 = port_string.parse().map_err(|_| anyhow!("invalid relay target port in {address:?}"))?;
    let port = u16::try_from(port).map_err(|_| anyhow!("invalid relay target port in {address:?}"))?;

    let mut out = Vec::with_capacity(1 + 1 + host.len() + 2);
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        let ip4 = match ip {
            std::net::IpAddr::V4(v4) => Some(v4),
            std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped(),
        };
        if let Some(v4) = ip4 {
            out.push(RELAY_ADDR_IPV4);
            out.extend_from_slice(&v4.octets());
        } else if let std::net::IpAddr::V6(v6) = ip {
            out.push(RELAY_ADDR_IPV6);
            out.extend_from_slice(&v6.octets());
        }
    } else {
        let host_len = u8::try_from(host.len()).map_err(|_| anyhow!("relay target host too long"))?;
        out.push(RELAY_ADDR_DOMAIN);
        out.push(host_len);
        out.extend_from_slice(host.as_bytes());
    }

    out.extend_from_slice(&port.to_be_bytes());
    Ok(out)
}

const fn relay_status_text(status: u8) -> &'static str {
    match status {
        RELAY_STATUS_OK => "ok",
        RELAY_STATUS_BAD_REQUEST => "bad request",
        RELAY_STATUS_UNAUTHORIZED => "unauthorized",
        RELAY_STATUS_FORBIDDEN => "forbidden",
        RELAY_STATUS_TIMEOUT => "timeout",
        RELAY_STATUS_SERVICE_UNAVAILABLE => "service unavailable",
        RELAY_STATUS_HOST_UNREACHABLE => "host unreachable",
        RELAY_STATUS_NETWORK_UNREACHABLE => "network unreachable",
        RELAY_STATUS_INTERNAL_SERVER_ERROR => "internal server error",
        _ => "unknown",
    }
}

fn join_host_port(host: &str, port: &str) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn split_host_port(hostport: &str) -> Result<(String, String)> {
    if let Some(rest) = hostport.strip_prefix('[') {
        let (host, remainder) =
            rest.split_once(']').ok_or_else(|| anyhow!("address {hostport}: missing ']' in address"))?;
        let port = remainder.strip_prefix(':').ok_or_else(|| anyhow!("address {hostport}: missing port in address"))?;
        return Ok((host.to_owned(), port.to_owned()));
    }
    let (host, port) =
        hostport.rsplit_once(':').ok_or_else(|| anyhow!("address {hostport}: missing port in address"))?;
    if host.contains(':') {
        return Err(anyhow!("address {hostport}: too many colons in address"));
    }
    Ok((host.to_owned(), port.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_relay_addr_ipv4() {
        let out = encode_relay_addr("192.0.2.1:443").unwrap();
        assert_eq!(out, vec![RELAY_ADDR_IPV4, 192, 0, 2, 1, 0x01, 0xBB]);
    }

    #[test]
    fn encode_relay_addr_domain() {
        let out = encode_relay_addr("example.com:80").unwrap();
        assert_eq!(
            out,
            vec![RELAY_ADDR_DOMAIN, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', 0x00, 0x50]
        );
    }

    #[test]
    fn relay_status_text_known_and_unknown() {
        assert_eq!(relay_status_text(RELAY_STATUS_OK), "ok");
        assert_eq!(relay_status_text(0xFF), "unknown");
    }

    #[test]
    fn split_host_port_bracketed_ipv6() {
        assert_eq!(split_host_port("[::1]:443").unwrap(), ("::1".to_owned(), "443".to_owned()));
    }
}

#[cfg(test)]
mod review_stutter {
    struct Stutter {
        inner: tokio::net::TcpStream,
        armed: std::sync::Arc<std::sync::atomic::AtomicBool>,
        skip: bool,
    }

    impl tokio::io::AsyncRead for Stutter {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
        }
    }

    impl tokio::io::AsyncWrite for Stutter {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            let this = self.get_mut();
            if this.armed.load(std::sync::atomic::Ordering::SeqCst) && !this.skip {
                this.skip = true;
                cx.waker().wake_by_ref();
                return std::task::Poll::Pending;
            }
            this.skip = false;
            std::pin::Pin::new(&mut this.inner).poll_write(cx, buf)
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }

    impl murmur_common_net::io::Stream for Stutter {
        fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
            self.inner.local_addr()
        }
        fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr> {
            self.inner.peer_addr()
        }
        fn shutdown_read(&self) -> std::io::Result<()> {
            murmur_common_net::io::Stream::shutdown_read(&self.inner)
        }
        fn shutdown_write(&self) -> std::io::Result<()> {
            murmur_common_net::io::Stream::shutdown_write(&self.inner)
        }
    }

    async fn stutter_tls_pair() -> (
        murmur_component_tls::utls::Conn,
        murmur_component_tls::utls::Conn,
        std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) {
        use murmur_component_tls::utls;
        use murmur_testsupport::TLS_CONFIG;
        use murmur_testsupport_probe::ensure_test_crypto_provider;
        ensure_test_crypto_provider();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (client_raw, (server_raw, _)) =
            tokio::try_join!(tokio::net::TcpStream::connect(addr), listener.accept()).expect("pair");
        let armed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stutter = Stutter { inner: client_raw, armed: std::sync::Arc::clone(&armed), skip: false };
        let client_config = std::sync::Arc::new(utls::Config { insecure_skip_verify: true, ..Default::default() });
        let client_tls = utls::client(Box::new(stutter), client_config);
        let server_tls = utls::server(Box::new(server_raw), TLS_CONFIG.clone());
        let ctx = tokio_util::sync::CancellationToken::new();
        tokio::try_join!(client_tls.handshake_context(&ctx), server_tls.handshake_context(&ctx)).expect("handshake");
        (client_tls, server_tls, armed)
    }

    /// Regression test for the handshake-style flush defect: `write_relay_request` used to
    /// write the header and each feature with `write_all` and never flush. `tokio_rustls`
    /// drains ciphertext to the socket inside `poll_write` itself as long as the socket
    /// accepts it, so on an idle loopback pair the request reaches the peer even without a
    /// flush; the defect only strands ciphertext when the underlying `poll_write` returns
    /// `Pending` partway through draining — real backpressure, or (here) a conn that stutters
    /// once on purpose, right after the handshake.
    #[tokio::test]
    async fn write_relay_request_flushes_after_partial_socket_write() {
        use tokio::io::AsyncReadExt;
        let (mut client_tls, mut server_tls, armed) = stutter_tls_pair().await;
        armed.store(true, std::sync::atomic::Ordering::SeqCst);

        super::write_relay_request(&mut client_tls, super::RELAY_CMD_CONNECT, "", super::RELAY_NETWORK_TCP, "", "")
            .await
            .expect("write relay request");

        let feature =
            super::encode_relay_feature(super::RELAY_FEATURE_NETWORK, &super::RELAY_NETWORK_TCP.to_be_bytes()).unwrap();
        let mut received = vec![0u8; 4 + feature.len()];
        tokio::time::timeout(std::time::Duration::from_secs(5), server_tls.read_exact(&mut received))
            .await
            .expect("write_relay_request must flush TLS ciphertext stranded by a partial socket write")
            .expect("read");
        assert_eq!(received[0], super::RELAY_VERSION1);
        assert_eq!(received[1], super::RELAY_CMD_CONNECT);
        assert_eq!(u16::from_be_bytes([received[2], received[3]]), feature.len() as u16);
        assert_eq!(&received[4..], feature.as_slice());
    }
}
