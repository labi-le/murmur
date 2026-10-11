//! No SSH client crate is pinned in `rust/Cargo.toml`.
//!
//! The implementation targets `russh` (see `NEEDED CRATE` in the wave report) and keeps the SSH
//! wire-protocol surface behind the small `SshBackend` seam below, so the control flow reads
//! statement by statement.

use std::fmt::Write as _;
use std::future::Future;
use std::io;
use std::path::Path as FsPath;
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::task::{Context as TaskContext, Poll};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use parking_lot::Mutex;
use rand::Rng;
use tokio_util::sync::CancellationToken;

use murmur_common::shared_conn::SharedConn;
use murmur_common_net::io::OldConnAsStream;
use murmur_common_net::setup_context_for_conn;
use murmur_component::dialer::bind::join_host_port;
use murmur_constant::adapters::{
    AdapterType, Conn as CConn, PacketConn as CPacketConn, Proxy, ProxyAdapter as CProxyAdapter, ProxyInfo,
};
use murmur_constant::metadata::Metadata;
use murmur_constant::path::PATH;
use murmur_std_compat::net::Conn as NetConn;

use super::base::{new_conn, Base, BaseOption, BasicOption, ProxyAdapter as BaseProxyAdapter};
use super::util::safe_conn_close;

/// Wraps a `russh` direct-tcpip channel stream as a `murmur_std_compat::net::Conn`; it carries no real socket
/// address (it is a virtual channel multiplexed over the SSH connection), so its
/// `LocalAddr`/`RemoteAddr` are synthetic, as they are for a dialled SSH channel.
struct SshChannelConn {
    stream: russh::ChannelStream<russh::client::Msg>,
}

impl tokio::io::AsyncRead for SshChannelConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for SshChannelConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

impl NetConn for SshChannelConn {
    fn local_addr(&self) -> io::Result<Box<dyn murmur_std_compat::net::Addr>> {
        Ok(Box::new(murmur_std_compat::net::TcpAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)))
    }
    fn remote_addr(&self) -> io::Result<Box<dyn murmur_std_compat::net::Addr>> {
        Ok(Box::new(murmur_std_compat::net::TcpAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)))
    }
    fn close(&self) -> io::Result<()> {
        Ok(())
    }
}
/// A private key that can sign the client authentication exchange.
pub(crate) trait SshSigner: Send + Sync {
    fn as_russh_private_key(&self) -> Option<&Arc<russh::keys::PrivateKey>> {
        None
    }
}

/// A host key or authorized key.
pub(crate) trait SshPublicKey: Send + Sync {
    fn marshal(&self) -> Vec<u8>;
    fn type_(&self) -> String;
}

pub(crate) enum SshAuthMethod {
    PublicKeys(Arc<dyn SshSigner>),
    Password(String),
}

/// The client config. The host-key mismatch message is built by the backend's host-key check, since
/// the check itself now lives there.
pub(crate) struct SshClientConfig {
    pub user: String,
    pub auth: Vec<SshAuthMethod>,
    pub host_key_algorithms: Vec<String>,
    pub host_keys: Option<Vec<Arc<dyn SshPublicKey>>>,
    pub client_version: String,
}

/// An established SSH connection that can open direct TCP/IP channels.
#[async_trait]
pub(crate) trait SshClientHandle: Send + Sync {
    async fn dial_context(&self, ctx: &CancellationToken, network: &str, address: &str) -> Result<Box<dyn NetConn>>;
    /// the resolves once the underlying session has shut down.
    async fn wait(&self);
    fn close(&self) -> Result<()>;
}

/// Backend seam over the SSH wire protocol; see the module doc for why this exists.
#[async_trait]
pub(crate) trait SshBackend: Send + Sync {
    fn parse_private_key(&self, pem: &[u8]) -> Result<Arc<dyn SshSigner>>;
    fn parse_private_key_with_passphrase(&self, pem: &[u8], passphrase: &[u8]) -> Result<Arc<dyn SshSigner>>;
    fn parse_authorized_key(&self, line: &[u8]) -> Result<Arc<dyn SshPublicKey>>;
    async fn new_client_conn(
        &self,
        c: Box<dyn NetConn>,
        addr: &str,
        config: &SshClientConfig,
    ) -> Result<Arc<dyn SshClientHandle>>;
}

fn default_backend() -> Arc<dyn SshBackend> {
    Arc::new(RusshBackend)
}

struct RusshSigner(Arc<russh::keys::PrivateKey>);
impl SshSigner for RusshSigner {
    fn as_russh_private_key(&self) -> Option<&Arc<russh::keys::PrivateKey>> {
        Some(&self.0)
    }
}

struct RusshPublicKey(russh::keys::ssh_key::PublicKey);
impl SshPublicKey for RusshPublicKey {
    fn marshal(&self) -> Vec<u8> {
        self.0.to_bytes().unwrap_or_default()
    }
    fn type_(&self) -> String {
        self.0.algorithm().to_string()
    }
}

/// The client handler: checks the server's host key against the configured `host_keys`, or accepts
/// any key when none were configured (verification disabled).
struct RusshHandler {
    host_keys: Option<Vec<Arc<dyn SshPublicKey>>>,
}

impl russh::client::Handler for RusshHandler {
    type Error = anyhow::Error;

    async fn check_server_key(&mut self, server_public_key: &russh::keys::PublicKeyOrCertificate) -> Result<bool> {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;
        let Some(host_keys) = &self.host_keys else {
            return Ok(true);
        };
        let russh::keys::PublicKeyOrCertificate::PublicKey { key: server_key, .. } = server_public_key else {
            return Ok(false);
        };
        let server_pub_key = RusshPublicKey(server_key.clone());
        let server_bytes = server_pub_key.marshal();
        if host_keys.iter().any(|key| key.marshal() == server_bytes) {
            return Ok(true);
        }
        Err(anyhow!("host key mismatch, server send :{} {}", server_pub_key.type_(), STANDARD.encode(&server_bytes)))
    }
}

struct RusshClientHandle {
    handle: tokio::sync::Mutex<russh::client::Handle<RusshHandler>>,
}

#[async_trait]
impl SshClientHandle for RusshClientHandle {
    async fn dial_context(&self, _ctx: &CancellationToken, _network: &str, address: &str) -> Result<Box<dyn NetConn>> {
        let (host, port, _) = murmur_common_net::split_host_port(address)?;
        let port_num: u32 = port.parse().map_err(|_| anyhow!("invalid port {port}"))?;
        let channel = self.handle.lock().await.channel_open_direct_tcpip(host, port_num, "0.0.0.0", 0).await?;
        Ok(Box::new(SshChannelConn { stream: channel.into_stream() }))
    }

    /// the polls the underlying `Handle`'s own `Future` impl (which
    /// resolves when its background connection task exits) instead of busy-polling
    /// `is_closed()`, while only holding the mutex for the instant of each poll so concurrent
    /// `dial_context` calls are never starved for longer than a single poll.
    // cancel-safe: polls `self`'s own state machine through `poll_fn`, so dropping the future only stops polling and the handshake resumes where it left off on the next call.
    async fn wait(&self) {
        let _ = std::future::poll_fn(|cx| {
            if let Ok(mut guard) = self.handle.try_lock() {
                Pin::new(&mut *guard).poll(cx)
            } else {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        })
        .await;
    }

    fn close(&self) -> Result<()> {
        Ok(())
    }
}

/// The client connect and handshake are folded into one call, since there is no separate
/// transport/connection/session split.
struct RusshBackend;

#[async_trait]
impl SshBackend for RusshBackend {
    fn parse_private_key(&self, pem: &[u8]) -> Result<Arc<dyn SshSigner>> {
        let text = String::from_utf8_lossy(pem);
        let key = russh::keys::decode_secret_key(&text, None)?;
        Ok(Arc::new(RusshSigner(Arc::new(key))))
    }

    fn parse_private_key_with_passphrase(&self, pem: &[u8], passphrase: &[u8]) -> Result<Arc<dyn SshSigner>> {
        let text = String::from_utf8_lossy(pem);
        let passphrase = String::from_utf8_lossy(passphrase);
        let key = russh::keys::decode_secret_key(&text, Some(&passphrase))?;
        Ok(Arc::new(RusshSigner(Arc::new(key))))
    }

    fn parse_authorized_key(&self, line: &[u8]) -> Result<Arc<dyn SshPublicKey>> {
        let text = String::from_utf8_lossy(line);
        let key = russh::keys::ssh_key::PublicKey::from_openssh(text.trim())?;
        Ok(Arc::new(RusshPublicKey(key)))
    }

    async fn new_client_conn(
        &self,
        c: Box<dyn NetConn>,
        _addr: &str,
        config: &SshClientConfig,
    ) -> Result<Arc<dyn SshClientHandle>> {
        let russh::client::Config {
            limits,
            window_size,
            maximum_packet_size,
            channel_buffer_size,
            preferred,
            inactivity_timeout,
            keepalive_interval,
            keepalive_max,
            anonymous,
            gex,
            nodelay,
            ..
        } = russh::client::Config::default();
        let mut client_config = russh::client::Config {
            client_id: russh::SshId::Standard(config.client_version.clone().into()),
            limits,
            window_size,
            maximum_packet_size,
            channel_buffer_size,
            preferred,
            inactivity_timeout,
            keepalive_interval,
            keepalive_max,
            anonymous,
            gex,
            nodelay,
        };
        if !config.host_key_algorithms.is_empty() {
            let algorithms: Vec<russh::keys::Algorithm> =
                config.host_key_algorithms.iter().filter_map(|name| name.parse().ok()).collect();
            if !algorithms.is_empty() {
                client_config.preferred.key = std::borrow::Cow::Owned(algorithms);
            }
        }
        let handler = RusshHandler { host_keys: config.host_keys.clone() };
        let mut handle = russh::client::connect_stream(Arc::new(client_config), c, handler).await?;

        let mut authenticated = false;
        for auth in &config.auth {
            let result = match auth {
                SshAuthMethod::PublicKeys(signer) => {
                    let signer = signer.as_russh_private_key().ok_or_else(|| anyhow!("ssh: unexpected signer type"))?;
                    let key = Arc::clone(signer);
                    handle
                        .authenticate_publickey(config.user.clone(), russh::keys::PrivateKeyWithHashAlg::new(key, None))
                        .await?
                }
                SshAuthMethod::Password(password) => {
                    handle.authenticate_password(config.user.clone(), password.clone()).await?
                }
            };
            if matches!(result, russh::client::AuthResult::Success) {
                authenticated = true;
                break;
            }
        }
        if !authenticated && config.auth.is_empty() {
            return Err(anyhow!("ssh: no authentication method configured"));
        }

        Ok(Arc::new(RusshClientHandle { handle: tokio::sync::Mutex::new(handle) }))
    }
}

pub struct Ssh {
    base: Base,
    option: SshOption,
    config: SshClientConfig,
    client: Mutex<Option<Arc<dyn SshClientHandle>>>,
    backend: Arc<dyn SshBackend>,
    self_weak: Weak<Self>,
}

impl core::fmt::Debug for Ssh {
    /// Redacts the SSH credentials so accidental `{:?}` logging cannot leak them.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ssh")
            .field("name", &self.base.name)
            .field("addr", &self.base.addr)
            .field("user", &self.config.user)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Default)]
pub struct SshOption {
    pub basic_option: BasicOption,
    pub name: String,
    pub server: String,
    pub port: u16,
    pub user_name: String,
    pub password: String,
    pub private_key: String,
    pub private_key_passphrase: String,
    pub host_key: Vec<String>,
    pub host_key_algorithms: Vec<String>,
}

impl core::fmt::Debug for SshOption {
    /// Redacts the SSH credentials so accidental `{:?}` logging cannot leak them.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SshOption")
            .field("name", &self.name)
            .field("server", &self.server)
            .field("port", &self.port)
            .field("user_name", &self.user_name)
            .field("password", &"<redacted>")
            .field("private_key", &"<redacted>")
            .field("private_key_passphrase", &"<redacted>")
            .field("host_key", &self.host_key)
            .field("host_key_algorithms", &self.host_key_algorithms)
            .finish_non_exhaustive()
    }
}

impl Ssh {
    pub fn new(option: SshOption) -> Result<Arc<Self>> {
        let addr = join_host_port(&option.server, option.port);
        let backend = default_backend();

        let mut config = SshClientConfig {
            user: option.user_name.clone(),
            auth: Vec::new(),
            host_key_algorithms: option.host_key_algorithms.clone(),
            host_keys: None,
            client_version: String::new(),
        };

        if !option.private_key.is_empty() {
            let bytes: Vec<u8> = if option.private_key.contains("PRIVATE KEY") {
                option.private_key.as_bytes().to_vec()
            } else {
                let path = PATH.resolve(&option.private_key);
                if !PATH.is_safe_path(&path) {
                    return Err(PATH.err_not_safe_path(&path).into());
                }
                std::fs::read(FsPath::new(&path))?
            };
            let signer = if option.private_key_passphrase.is_empty() {
                backend.parse_private_key(&bytes)?
            } else {
                backend.parse_private_key_with_passphrase(&bytes, option.private_key_passphrase.as_bytes())?
            };
            config.auth.push(SshAuthMethod::PublicKeys(signer));
        }

        if !option.password.is_empty() {
            config.auth.push(SshAuthMethod::Password(option.password.clone()));
        }

        if !option.host_key.is_empty() {
            let mut keys = Vec::with_capacity(option.host_key.len());
            for host_key in &option.host_key {
                let key = backend
                    .parse_authorized_key(host_key.as_bytes())
                    .map_err(|_| anyhow!("parse host key :{host_key}"))?;
                keys.push(key);
            }
            config.host_keys = Some(keys);
        }

        let mut version = "SSH-2.0-OpenSSH_".to_owned();
        let mut rng = rand::rng();
        if rng.random_range(0..2) == 0 {
            let _ = write!(version, "7.{}", rng.random_range(0..10));
        } else {
            let _ = write!(version, "8.{}", rng.random_range(0..9));
        }
        config.client_version = version;

        let mut base = Base::new(BaseOption {
            name: option.name.clone(),
            addr,
            type_: AdapterType::SSH,
            provider_name: option.basic_option.provider_name.clone(),
            udp: false,
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
            config,
            client: Mutex::new(None),
            backend,
            self_weak: Weak::clone(weak),
        }))
    }

    async fn connect(&self, ctx: &CancellationToken, addr: &str) -> Result<Arc<dyn SshClientHandle>> {
        let cached = self.client.lock().clone();
        if let Some(client) = cached {
            return Ok(client);
        }

        let dialer = self.base.dialer.as_ref();
        let dialer = dialer.ok_or_else(|| anyhow!("Ssh.base.dialer must be set before connect"))?;
        let c = dialer.dial_context(ctx, "tcp", addr).await?;
        // S11: remove with std-compat (murmur_common::shared_conn::SharedConn is old-Conn-based)
        let c: Box<dyn murmur_std_compat::net::Conn> = Box::new(murmur_common_net::io::StreamAsOldConn::new(c));

        let shared = SharedConn::from_boxed(c);
        let mut done = setup_context_for_conn(ctx, shared.clone());
        let result = self.backend.new_client_conn(Box::new(shared.clone()), addr, &self.config).await;
        let mut err_opt = result.as_ref().err().map(|e: &anyhow::Error| anyhow!("{e}"));
        done.call(&mut err_opt).await;
        safe_conn_close(Some(&shared), err_opt.is_some());
        if let Some(err) = err_opt {
            return Err(err);
        }
        let client = result?;

        *self.client.lock() = Some(Arc::clone(&client));

        let self_weak = Weak::clone(&self.self_weak);
        let client_for_wait = Arc::clone(&client);
        tokio::spawn(async move {
            client_for_wait.wait().await;
            let _ = client_for_wait.close();
            if let Some(this) = self_weak.upgrade() {
                let mut guard = this.client.lock();
                if guard.as_ref().is_some_and(|current| Arc::ptr_eq(current, &client_for_wait)) {
                    *guard = None;
                }
            }
        });

        Ok(client)
    }
}

#[async_trait]
impl CProxyAdapter for Ssh {
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
        let addr = self.base.addr();
        let client = self.connect(ctx, &addr).await?;
        let c = client.dial_context(ctx, "tcp", &metadata.remote_address()).await?;
        // S11: remove with std-compat (SshClientHandle::dial_context hands back the russh-channel SshChannelConn, an old Conn)
        Ok(new_conn(Box::new(OldConnAsStream(c)), self))
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
        let client = self.client.lock().clone();
        if let Some(client) = client {
            return client.close();
        }
        Ok(())
    }
}

#[async_trait]
impl BaseProxyAdapter for Ssh {
    fn dial_options(&self) -> Vec<murmur_component::dialer::options::Option> {
        self.base.dial_options()
    }

    async fn resolve_udp(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<()> {
        self.base.resolve_udp(ctx, metadata).await
    }
}
