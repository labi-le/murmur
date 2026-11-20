use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf};
use tokio_util::sync::CancellationToken;

use murmur_common::shared_conn::SharedConn;
use murmur_common_net::setup_context_for_conn;
use murmur_component::dialer::bind::join_host_port;
use murmur_component_ca::config::{get_tls_config, Option as CaOption};
use murmur_component_tls::utls::{client as tls_client, ClientAuthType, Config as TlsConfig, RenegotiationSupport};
use murmur_constant::adapters::{
    AdapterType, Conn as CConn, PacketConn as CPacketConn, Proxy, ProxyAdapter as CProxyAdapter, ProxyInfo,
};
use murmur_constant::metadata::Metadata;
use murmur_std_compat::net::{Addr, Conn as NetConn};

use super::base::{new_conn, Base, BaseOption, BasicOption, ProxyAdapter as BaseProxyAdapter};
use super::util::safe_conn_close;

pub struct Http {
    base: Base,
    user: String,
    pass: String,
    tls_config: Option<Arc<TlsConfig>>,
    option: HttpOption,
}

impl std::fmt::Debug for Http {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Http")
            .field("name", &self.base.name())
            .field("addr", &self.base.addr())
            .field("user", &self.user)
            .field("pass", &"<redacted>")
            .field("tls", &self.tls_config.is_some())
            .field("option", &self.option)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Default)]
pub struct HttpOption {
    pub basic_option: BasicOption,
    pub name: String,
    pub server: String,
    pub port: u16,
    pub user_name: String,
    pub password: String,
    pub tls: bool,
    pub sni: String,
    pub skip_cert_verify: bool,
    pub name_cert_verify: String,
    pub fingerprint: String,
    pub certificate: String,
    pub private_key: String,
    pub headers: HashMap<String, String>,
}

impl std::fmt::Debug for HttpOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpOption")
            .field("name", &self.name)
            .field("server", &self.server)
            .field("port", &self.port)
            .field("user_name", &self.user_name)
            .field("password", &"<redacted>")
            .field("tls", &self.tls)
            .field("sni", &self.sni)
            .field("skip_cert_verify", &self.skip_cert_verify)
            .field("name_cert_verify", &self.name_cert_verify)
            .field("fingerprint", &self.fingerprint)
            .field("certificate", &self.certificate)
            .field("private_key", &"<redacted>")
            .field("headers", &self.headers)
            .finish_non_exhaustive()
    }
}

impl Http {
    pub fn new(option: HttpOption) -> Result<Self> {
        let tls_config: Option<Arc<TlsConfig>> = if option.tls {
            let sni = if option.sni.is_empty() { option.server.clone() } else { option.sni.clone() };
            let config = get_tls_config(CaOption {
                tls_config: Some(TlsConfig {
                    insecure_skip_verify: option.skip_cert_verify,
                    server_name: sni,
                    rand: None,
                    time: None,
                    certificates: Vec::new(),
                    get_certificate: None,
                    get_client_certificate: None,
                    verify_peer_certificate: None,
                    verify_connection: None,
                    root_cas: None,
                    next_protos: Vec::new(),
                    client_auth: ClientAuthType::default(),
                    client_cas: None,
                    cipher_suites: None,
                    session_tickets_disabled: false,
                    min_version: 0,
                    max_version: 0,
                    curve_preferences: None,
                    renegotiation: RenegotiationSupport::default(),
                    key_log_writer: None,
                    encrypted_client_hello_config_list: Vec::new(),
                    encrypted_client_hello_rejection_verify: None,
                    encrypted_client_hello_keys: Vec::new(),
                    get_encrypted_client_hello_keys: None,
                    session_id_generator: None,
                }),
                fingerprint: option.fingerprint.clone(),
                name_cert_verify: option.name_cert_verify.clone(),
                certificate: option.certificate.clone(),
                private_key: option.private_key.clone(),
                zero_trust: false,
            })?;
            Some(Arc::new(config))
        } else {
            None
        };

        let mut base = Base::new(BaseOption {
            name: option.name.clone(),
            addr: join_host_port(&option.server, option.port),
            type_: AdapterType::HTTP,
            provider_name: option.basic_option.provider_name.clone(),
            tfo: option.basic_option.tfo,
            mptcp: option.basic_option.mptcp,
            interface: option.basic_option.interface.clone(),
            routing_mark: option.basic_option.routing_mark,
            prefer: option.basic_option.ip_version,
            udp: false,
            xudp: false,
        });
        let dial_options = base.dial_options();
        base.dialer = Some(option.basic_option.new_dialer(dial_options));

        Ok(Self { base, user: option.user_name.clone(), pass: option.password.clone(), tls_config, option })
    }

    async fn stream_conn_context(
        &self,
        ctx: &CancellationToken,
        c: Box<dyn NetConn>,
        metadata: &Metadata,
    ) -> Result<Box<dyn NetConn>> {
        let mut c = c;
        if let Some(tls_config) = &self.tls_config {
            let cc = tls_client(Box::new(murmur_common_net::io::OldConnAsStream(c)), Arc::clone(tls_config));
            if let Err(err) = cc.handshake_context(ctx).await {
                return Err(anyhow!("{} connect error: {err}", self.base.addr()));
            }
            c = Box::new(murmur_common_net::io::StreamAsOldConn::new(cc));
        }

        self.shake_hand_context(ctx, c, metadata).await
    }

    async fn shake_hand_context(
        &self,
        ctx: &CancellationToken,
        c: Box<dyn NetConn>,
        metadata: &Metadata,
    ) -> Result<Box<dyn NetConn>> {
        let shared = SharedConn::from_boxed(c);
        let mut done = setup_context_for_conn(ctx, shared.clone());
        let (buffered, mut err_opt) = match self.shake_hand_io(&shared, metadata).await {
            Ok(buffered) => (buffered, None),
            Err(err) => (None, Some(err)),
        };
        done.call(&mut err_opt).await;
        if let Some(err) = err_opt {
            return Err(err);
        }
        match buffered {
            Some(conn) => Ok(Box::new(conn)),
            None => Ok(Box::new(shared)),
        }
    }

    /// The header write and status-line read of the CONNECT handshake. Returns the bytes that
    /// arrived behind the response headers, still unsent by the proxy, when there are any.
    async fn shake_hand_io(&self, c: &SharedConn, metadata: &Metadata) -> Result<Option<BufferedConnectConn>> {
        let addr = metadata.remote_address();
        let mut header_string = format!("CONNECT {addr} HTTP/1.1\r\n");
        let mut temp_headers: HashMap<String, String> = HashMap::new();
        temp_headers.insert("Host".to_owned(), addr.clone());
        temp_headers.insert("User-Agent".to_owned(), murmur_constant::version::USER_AGENT.to_owned());
        temp_headers.insert("Proxy-Connection".to_owned(), "Keep-Alive".to_owned());

        for (key, value) in &self.option.headers {
            temp_headers.insert(key.clone(), value.clone());
        }

        if !self.user.is_empty() && !self.pass.is_empty() {
            let auth = format!("{}:{}", self.user, self.pass);
            temp_headers.insert("Proxy-Authorization".to_owned(), format!("Basic {}", STANDARD.encode(auth)));
        }

        for (key, value) in &temp_headers {
            header_string.push_str(key);
            header_string.push_str(": ");
            header_string.push_str(value);
            header_string.push_str("\r\n");
        }
        header_string += "\r\n";

        c.write_all(header_string.as_bytes()).await?;
        c.clone().flush().await?;

        let (status_code, status, buffered) = read_connect_response(c.clone()).await?;

        if status_code == 200 {
            return Ok(buffered);
        }
        if status_code == 407 {
            return Err(anyhow!("HTTP need auth"));
        }
        if status_code == 405 {
            return Err(anyhow!("CONNECT method not allowed by proxy"));
        }
        if status_code >= 500 {
            return Err(anyhow!("{status}"));
        }
        Err(anyhow!("can not connect remote err code: {status_code}"))
    }
}

/// A tunnel conn that returns the bytes the proxy sent behind its 200 response before reading
/// the underlying connection; those bytes are the tunnel's first payload, not handshake text.
struct BufferedConnectConn {
    reader: BufReader<SharedConn>,
}

impl AsyncRead for BufferedConnectConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for BufferedConnectConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(self.get_mut().reader.get_mut()).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self.get_mut().reader.get_mut()).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(self.get_mut().reader.get_mut()).poll_shutdown(cx)
    }
}

impl NetConn for BufferedConnectConn {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.reader.get_ref().local_addr()
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.reader.get_ref().remote_addr()
    }

    fn close(&self) -> io::Result<()> {
        self.reader.get_ref().close()
    }

    fn close_read(&self) -> io::Result<()> {
        self.reader.get_ref().close_read()
    }

    fn close_write(&self) -> io::Result<()> {
        self.reader.get_ref().close_write()
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.reader.get_ref().set_deadline(deadline)
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.reader.get_ref().set_read_deadline(deadline)
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.reader.get_ref().set_write_deadline(deadline)
    }
}

/// Parses the CONNECT status line, reduced to the status code and text this caller inspects.
/// A proxy may send the target's first bytes in the same segment as the response headers, so
/// those bytes come back on the returned conn instead of being dropped with the read buffer.
async fn read_connect_response(r: SharedConn) -> Result<(u16, String, Option<BufferedConnectConn>)> {
    let mut reader = BufReader::new(r);
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    let line = line.trim_end_matches(['\r', '\n']);
    let mut parts = line.splitn(3, ' ');
    let _proto = parts.next().ok_or_else(|| anyhow!("malformed HTTP response"))?;
    let code_str = parts.next().ok_or_else(|| anyhow!("malformed HTTP response"))?;
    let reason = parts.next().unwrap_or_default();
    let status_code: u16 = code_str.parse().map_err(|_| anyhow!("malformed HTTP response"))?;
    loop {
        let mut header_line = String::new();
        let n = reader.read_line(&mut header_line).await?;
        if n == 0 || header_line.trim_end_matches(['\r', '\n']).is_empty() {
            break;
        }
    }
    let buffered = if reader.buffer().is_empty() { None } else { Some(BufferedConnectConn { reader }) };
    Ok((status_code, format!("{status_code} {reason}"), buffered))
}

#[async_trait]
impl CProxyAdapter for Http {
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
        let dialer =
            self.base.dialer.as_ref().ok_or_else(|| anyhow!("Http.base.dialer must be set before DialContext"))?;
        let addr = self.base.addr();
        let raw = dialer.dial_context(ctx, "tcp", &addr).await.map_err(|err| anyhow!("{addr} connect error: {err}"))?;
        let raw: Box<dyn murmur_std_compat::net::Conn> = Box::new(murmur_common_net::io::StreamAsOldConn::new(raw));

        let shared = SharedConn::from_boxed(raw);
        let result = self.stream_conn_context(ctx, Box::new(shared.clone()), metadata).await;
        safe_conn_close(Some(&shared), result.is_err());
        let c = result?;
        Ok(new_conn(Box::new(murmur_common_net::io::OldConnAsStream(c)), self))
    }

    async fn listen_packet_context(
        &self,
        ctx: &CancellationToken,
        metadata: &mut Metadata,
    ) -> Result<Arc<dyn CPacketConn>> {
        self.base.listen_packet_context(ctx, metadata).await
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
impl BaseProxyAdapter for Http {
    fn dial_options(&self) -> Vec<murmur_component::dialer::options::Option> {
        self.base.dial_options()
    }

    async fn resolve_udp(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<()> {
        self.base.resolve_udp(ctx, metadata).await
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncReadExt;
    use tokio::net::{TcpListener, TcpStream};

    use super::*;

    /// The proxy writes its 200 response and the target's first bytes in one segment, so the
    /// status-line reader buffers both. The tunnel must still deliver the target's bytes.
    #[tokio::test]
    async fn connect_response_payload_buffered_behind_the_header_reaches_the_tunnel() {
        const PAYLOAD: &[u8] = b"hello-from-target";
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mock proxy");
        let proxy_addr = listener.local_addr().expect("mock proxy address");
        let proxy = tokio::spawn(async move {
            let (mut conn, _) = listener.accept().await.expect("accept CONNECT");
            let mut request = [0u8; 4096];
            let read = conn.read(&mut request).await.expect("read CONNECT request");
            assert_ne!(read, 0, "CONNECT request was empty");
            let mut response = b"HTTP/1.1 200 Connection established\r\n\r\n".to_vec();
            response.extend_from_slice(PAYLOAD);
            conn.write_all(&response).await.expect("write CONNECT response");
            conn.flush().await.expect("flush CONNECT response");
        });

        let adapter = Http::new(HttpOption {
            name: "http-connect-test".to_owned(),
            server: "127.0.0.1".to_owned(),
            port: proxy_addr.port(),
            ..HttpOption::default()
        })
        .expect("create http adapter");
        let client = TcpStream::connect(proxy_addr).await.expect("connect to mock proxy");
        let metadata = Metadata { host: "target.example".to_owned(), dst_port: 22, ..Metadata::default() };
        let mut tunnel = adapter
            .stream_conn_context(&CancellationToken::new(), Box::new(client), &metadata)
            .await
            .expect("HTTP CONNECT handshake");

        let mut received = Vec::new();
        tunnel.read_to_end(&mut received).await.expect("read tunnel");
        assert_eq!(received, PAYLOAD);
        proxy.await.expect("mock proxy task");
    }
}
