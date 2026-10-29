use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWriteExt, BufReader};
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
use murmur_std_compat::net::Conn as NetConn;

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
        let result = self.shake_hand_io(&shared, metadata).await;
        let mut err_opt = result.err();
        done.call(&mut err_opt).await;
        match err_opt {
            Some(err) => Err(err),
            None => Ok(Box::new(shared)),
        }
    }

    /// The header write and status-line read of the CONNECT handshake.
    async fn shake_hand_io(&self, c: &SharedConn, metadata: &Metadata) -> Result<()> {
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

        let (status_code, status) = read_connect_response(c.clone()).await?;

        if status_code == 200 {
            return Ok(());
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

/// Parses the CONNECT status line, reduced to the status code and text this caller inspects.
async fn read_connect_response<R: AsyncRead + Unpin>(r: R) -> Result<(u16, String)> {
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
    Ok((status_code, format!("{status_code} {reason}")))
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
