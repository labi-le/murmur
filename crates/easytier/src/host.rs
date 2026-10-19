//! The instance manager and the `api.manage.WebClientService.*` management handler are **not**
//! implemented.
//!
//! murmur drives an instance through `CreateInstanceTOML`, `Start`, the data plane and the
//! `api.instance.PeerManageRpc.*` RPCs only. No management handler is installed, so a guest
//! reaching for that channel gets a status error instead of a manager this crate lacks.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::{anyhow, ensure, Context as _, Result};
use prost::Message;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use murmur_common_net::io::{Acceptor, Datagram, Stream};
use murmur_component_easytier::platform::platform::Services;

use crate::engine;
use crate::proto::error::{error::ErrorKind as RpcErrorKind, Error as RpcError};
use crate::proto::{DirectRpcRequest, ListRouteResponse, RpcResponse, ShowNodeInfoResponse};
use crate::wire::DataPlaneSocketAddr;

pub use crate::engine::Event;
pub use crate::engine::State;

/// Method names of the management RPCs this host calls.
const LIST_ROUTE_RPC_METHOD: &str = "api.instance.PeerManageRpc.ListRoute";
const SHOW_NODE_INFO_RPC_METHOD: &str = "api.instance.PeerManageRpc.ShowNodeInfo";

/// Host construction parameters.
#[derive(Debug)]
pub struct Options {
    /// Platform capabilities handed to the embedded core. The `PacketQueueCapacity` is left at
    /// the engine default because nothing here reads from the guest's packet sink.
    pub platform: Services,
}

/// This instance's own node information.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NodeInfo {
    pub hostname: String,
    pub ipv4_addr: String,
}

/// One routing-table entry.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Route {
    pub hostname: String,
    /// Overlay IPv4 as a host-order `u32`, absent for a route with no IPv4 assignment.
    pub ipv4_addr: Option<u32>,
}

/// Owns the embedded EasyTier core for the lifetime of one outbound.
#[derive(Debug)]
pub struct Host {
    engine: engine::Host,
}

impl Host {
    /// Compiles and instantiates the embedded core. Must run inside a Tokio runtime.
    pub fn new(options: Options) -> Result<Self> {
        let engine =
            engine::Host::new(engine::Options { services: Arc::new(options.platform), packet_queue_capacity: 0 })
                .context("create EasyTier host")?;
        Ok(Self { engine })
    }

    /// Creates an instance from raw TOML. `instance_id` is the persisted instance UUID: an empty
    /// string mints a new one, and any `instance_id`/`instance_name` already in `config_toml` is
    /// stripped first so the caller's values win.
    pub async fn create_instance_toml(
        &self,
        ctx: &CancellationToken,
        instance_name: &str,
        instance_id: &str,
        config_toml: &str,
    ) -> Result<Instance> {
        ensure!(!ctx.is_cancelled(), "create EasyTier instance with a cancelled context");
        ensure!(!config_toml.trim().is_empty(), "EasyTier TOML configuration is empty");
        let name = if instance_name.is_empty() { "easytier" } else { instance_name };
        let id = if instance_id.is_empty() { Uuid::new_v4() } else { parse_instance_uuid(instance_id)? };
        let id_string = id.hyphenated().to_string();
        let bound = bind_instance_identity(&strip_instance_identity(config_toml), &id_string, name);
        let engine = self.engine.create_instance(bound).await?;
        Ok(Instance { engine, id: id_string })
    }

    /// Closes every instance and tears the guest module down.
    pub async fn close(&self, ctx: &CancellationToken) -> Result<()> {
        ensure!(!ctx.is_cancelled(), "close EasyTier host with a cancelled context");
        self.engine.close().await
    }
}

/// One EasyTier instance running inside a [`Host`].
#[derive(Clone, Debug)]
pub struct Instance {
    engine: engine::Instance,
    id: String,
}

impl Instance {
    /// The instance's stable UUID.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Last state the guest reported.
    #[must_use]
    pub fn state(&self) -> State {
        self.engine.state()
    }

    /// Starts the instance and blocks until it reports [`State::Running`].
    pub async fn start(&self, ctx: &CancellationToken) -> Result<()> {
        self.engine.start(ctx).await
    }

    /// Stops the instance and blocks until it reports [`State::Stopped`].
    pub async fn stop(&self, ctx: &CancellationToken) -> Result<()> {
        self.engine.stop(ctx).await
    }

    /// Takes the instance's event stream; `None` once a caller already took it.
    #[must_use]
    pub fn events(&self) -> Option<mpsc::Receiver<Event>> {
        self.engine.events()
    }

    /// Blocks until the instance stops.
    // cancel-safe: waits on a level-triggered notification and re-checks the state before parking, so a dropped wait misses nothing -- the next call re-reads the same state.
    pub async fn wait(&self, ctx: &CancellationToken) -> Result<()> {
        self.engine.wait(ctx).await
    }

    /// This instance's node information. A guest that answered without one is reported as an
    /// error rather than a missing node, so a caller cannot mistake "no node yet" for a resolved
    /// answer.
    pub async fn show_node_info(&self, ctx: &CancellationToken) -> Result<NodeInfo> {
        let payload = self.call_rpc(ctx, SHOW_NODE_INFO_RPC_METHOD).await?;
        let response =
            ShowNodeInfoResponse::decode(payload.as_slice()).context("decode EasyTier ShowNodeInfo payload")?;
        response
            .node_info
            .map(|node| NodeInfo { hostname: node.hostname, ipv4_addr: node.ipv4_addr })
            .ok_or_else(|| anyhow!("EasyTier ShowNodeInfo returned no node info"))
    }

    /// The instance's routing table.
    pub async fn list_route(&self, ctx: &CancellationToken) -> Result<Vec<Route>> {
        let payload = self.call_rpc(ctx, LIST_ROUTE_RPC_METHOD).await?;
        let response = ListRouteResponse::decode(payload.as_slice()).context("decode EasyTier ListRoute payload")?;
        Ok(response
            .routes
            .into_iter()
            .map(|route| Route {
                hostname: route.hostname,
                ipv4_addr: route.ipv4_addr.and_then(|inet| inet.address).map(|address| address.addr),
            })
            .collect())
    }

    /// Dials an overlay peer. `network` is `tcp`/`tcp4` for a stream and `udp`/`udp4` for a
    /// connected datagram socket; `address` must be an IPv4 `host:port` literal.
    pub async fn dial(&self, ctx: &CancellationToken, network: &str, address: &str) -> Result<Box<dyn Stream>> {
        let peer = parse_dial_address(address)?;
        match network {
            "tcp" | "tcp4" => Ok(Box::new(self.engine.dial(ctx, peer).await?)),
            "udp" | "udp4" => Ok(Box::new(self.engine.dial_udp(ctx, peer).await?)),
            other => Err(anyhow!("easytier: unsupported dial network {other:?}")),
        }
    }

    /// Binds an overlay TCP listener. `address` is a port with an empty or unspecified host.
    pub async fn listen(&self, network: &str, address: &str) -> Result<Box<dyn Acceptor>> {
        if !matches!(network, "tcp" | "tcp4") {
            return Err(anyhow!("easytier: unsupported listen network {network:?}"));
        }
        let port = parse_bind_port(address)?;
        Ok(Box::new(self.engine.listen(port).await?))
    }

    /// Binds an overlay UDP socket. `address` is a port with an empty or unspecified host.
    pub async fn listen_packet(&self, network: &str, address: &str) -> Result<Box<dyn Datagram>> {
        if !matches!(network, "udp" | "udp4") {
            return Err(anyhow!("easytier: unsupported listen network {network:?}"));
        }
        let port = parse_bind_port(address)?;
        Ok(Box::new(self.engine.listen_packet(port).await?))
    }

    /// Releases the instance's guest resources.
    pub async fn close(&self, ctx: &CancellationToken) -> Result<()> {
        ensure!(!ctx.is_cancelled(), "close EasyTier instance with a cancelled context");
        self.engine.close().await
    }

    /// Calls an RPC with an empty typed request: wrap the method name in
    /// `DirectRpcRequest`, submit it, and unwrap the `RpcResponse` envelope. The
    /// RPC channel carries no deadline here, so the guest's `timeout_ms` stays unset.
    async fn call_rpc(&self, ctx: &CancellationToken, method: &str) -> Result<Vec<u8>> {
        let encoded = DirectRpcRequest { full_method_name: method.to_owned(), request: Vec::new(), timeout_ms: None }
            .encode_to_vec();
        let response = self.engine.rpc(ctx, encoded).await?;
        let envelope = RpcResponse::decode(response.as_slice()).context("decode EasyTier RPC envelope")?;
        if let Some(error) = envelope.error {
            return Err(anyhow!("EasyTier RPC {method} failed: {}", render_rpc_error(&error)));
        }
        Ok(envelope.response)
    }
}

fn render_rpc_error(error: &RpcError) -> String {
    let Some(kind) = &error.error_kind else {
        return "unknown EasyTier RPC error".to_owned();
    };
    match kind {
        RpcErrorKind::OtherError(inner) => inner.error_message.clone(),
        RpcErrorKind::InvalidMethodIndex(inner) => {
            format!("invalid method index {} for service {:?}", inner.method_index, inner.service_name)
        }
        RpcErrorKind::InvalidService(inner) => format!("invalid service {:?}", inner.service_name),
        RpcErrorKind::ProstDecodeError(_) => "protobuf decode failure".to_owned(),
        RpcErrorKind::ProstEncodeError(_) => "protobuf encode failure".to_owned(),
        RpcErrorKind::ExecuteError(inner) => inner.error_message.clone(),
        RpcErrorKind::MalformatRpcPacket(inner) => inner.error_message.clone(),
        RpcErrorKind::Timeout(inner) => inner.error_message.clone(),
    }
}

/// The overlay data plane is IPv4-only.
fn parse_dial_address(address: &str) -> Result<DataPlaneSocketAddr> {
    let parsed: SocketAddr = address.parse().with_context(|| format!("easytier: parse dial address {address:?}"))?;
    let IpAddr::V4(ip) = parsed.ip() else {
        return Err(anyhow!("easytier: data plane requires an IPv4 literal, got {address:?}"));
    };
    Ok(DataPlaneSocketAddr { ip, port: parsed.port() })
}

/// Listeners bind every overlay IPv4 address, so only a bare or unspecified host is accepted.
fn parse_bind_port(address: &str) -> Result<u16> {
    let (host, port) =
        address.rsplit_once(':').ok_or_else(|| anyhow!("easytier: listen address {address:?} has no port"))?;
    if !host.is_empty() && host != "0.0.0.0" && host != "::" {
        return Err(anyhow!("easytier: listeners bind all overlay IPv4 addresses, got {address:?}"));
    }
    port.parse::<u16>().with_context(|| format!("easytier: parse listen port in {address:?}"))
}

/// Parses an instance UUID: 32 hex digits, hyphens tolerated anywhere.
fn parse_instance_uuid(text: &str) -> Result<Uuid> {
    let normalized: String = text.trim().chars().filter(|c| *c != '-').collect();
    ensure!(normalized.len() == 32, "easytier: invalid instance ID {text:?}");
    Uuid::parse_str(&normalized).map_err(|_| anyhow!("easytier: invalid instance ID {text:?}"))
}

/// Strips the instance identity: drops any pre-existing identity lines before rebinding.
fn strip_instance_identity(config_toml: &str) -> String {
    let kept: Vec<&str> = config_toml
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            if !trimmed.starts_with("instance_id") && !trimmed.starts_with("instance_name") {
                return true;
            }
            let key = match trimmed.split_once('=') {
                Some((key, _)) => key.trim(),
                None => trimmed,
            };
            key != "instance_id" && key != "instance_name"
        })
        .collect();
    kept.join("\n").trim().to_owned()
}

/// Binds the instance identity and writes the TOML string fields.
fn bind_instance_identity(config_toml: &str, id: &str, name: &str) -> String {
    format!("instance_id = {}\ninstance_name = {}\n{}", quote_toml_string(id), quote_toml_string(name), config_toml)
}

/// TOML basic strings and JSON strings share an escape grammar, so JSON quoting emits a valid
/// TOML basic string.
fn quote_toml_string(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_owned())
}

#[cfg(test)]
mod tests {
    use parking_lot::Mutex;

    use super::*;
    use crate::proto::error::{InvalidService, OtherError, ProstDecodeError, Timeout};
    use murmur_component_easytier::platform::platform::{TCPConnectOptions, TCPListenOptions, UDPBindOptions};
    use murmur_std_compat::net::Addr;

    #[test]
    fn strip_removes_only_exact_identity_keys() {
        let toml =
            "instance_id = \"old\"\nhostname = \"host\"\ninstance_name_extra = \"keep\"\n# instance_id = \"comment\"\n";
        assert_eq!(
            strip_instance_identity(toml),
            "hostname = \"host\"\ninstance_name_extra = \"keep\"\n# instance_id = \"comment\""
        );
    }

    #[test]
    fn bind_prefers_the_caller_identity() {
        assert_eq!(
            bind_instance_identity("network_name = \"n\"", "uuid", "name"),
            "instance_id = \"uuid\"\ninstance_name = \"name\"\nnetwork_name = \"n\""
        );
    }

    #[test]
    fn rpc_error_renders_each_oneof_arm() {
        let message = |kind| crate::proto::error::Error { error_kind: Some(kind) };
        assert_eq!(
            render_rpc_error(&message(RpcErrorKind::OtherError(OtherError { error_message: "boom".to_owned() }))),
            "boom"
        );
        assert_eq!(
            render_rpc_error(&message(RpcErrorKind::Timeout(Timeout { error_message: "slow".to_owned() }))),
            "slow"
        );
        assert_eq!(
            render_rpc_error(&message(RpcErrorKind::ProstDecodeError(ProstDecodeError {}))),
            "protobuf decode failure"
        );
        assert_eq!(
            render_rpc_error(&message(RpcErrorKind::InvalidService(InvalidService { service_name: "svc".to_owned() }))),
            "invalid service \"svc\""
        );
        assert_eq!(render_rpc_error(&crate::proto::error::Error { error_kind: None }), "unknown EasyTier RPC error");
    }

    #[test]
    fn quote_escapes_like_toml() {
        assert_eq!(quote_toml_string("a\"b\\c"), "\"a\\\"b\\\\c\"");
    }
    #[test]
    fn instance_id_accepts_both_uuid_spellings() {
        let hyphenated = Uuid::new_v4();
        let simple = hyphenated.simple().to_string();
        assert_eq!(parse_instance_uuid(&hyphenated.hyphenated().to_string()).ok(), Some(hyphenated));
        assert_eq!(parse_instance_uuid(&simple).ok(), Some(hyphenated));
    }

    #[test]
    fn instance_id_rejects_short_and_non_hex_text() {
        assert!(parse_instance_uuid("abcd").is_err());
        assert!(parse_instance_uuid("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").is_err());
    }

    #[test]
    fn bind_port_accepts_wildcard_hosts_only() {
        assert_eq!(parse_bind_port(":11010").ok(), Some(11010));
        assert_eq!(parse_bind_port("0.0.0.0:11010").ok(), Some(11010));
        assert!(parse_bind_port("10.0.0.1:11010").is_err());
        assert!(parse_bind_port(":70000").is_err());
        assert!(parse_bind_port("11010").is_err());
    }

    #[test]
    fn dial_address_requires_ipv4() {
        assert_eq!(parse_dial_address("10.0.0.1:80").ok().map(|addr| addr.port), Some(80));
        assert!(parse_dial_address("[::1]:80").is_err());
        assert!(parse_dial_address("example.com:80").is_err());
    }

    /// A solo overlay: no peers, no listeners, one fixed IPv4. The guest has nothing to dial, so
    /// the whole embed path — compile, instantiate, host imports, drive loop, RPC — runs without
    /// touching the network.
    const SOLO_TOML: &str = r#"
instance_name = "murmur-solo"
ipv4 = "10.126.126.126/24"
network_name = "murmur-solo"
hostname = "murmur-solo"
dhcp = false
no_listener = true
"#;

    /// The solo overlay never dials: refusing every dial is a real failure the guest can observe,
    /// which is what the test wants if the guest tries to reach anything.
    struct SoloDialer;

    #[async_trait::async_trait]
    impl murmur_constant::adapters::Dialer for SoloDialer {
        async fn dial_context(
            &self,
            _ctx: &CancellationToken,
            _network: &str,
            address: &str,
        ) -> Result<Box<dyn Stream>> {
            Err(anyhow!("solo test overlay refuses to dial {address}"))
        }

        async fn listen_packet(
            &self,
            _ctx: &CancellationToken,
            _network: &str,
            _address: &str,
            _r_addr_port: Option<SocketAddr>,
        ) -> Result<Box<dyn Datagram>> {
            Err(anyhow!("solo test overlay refuses to bind a packet socket"))
        }
    }

    /// `system_resolver()` panics when the dns module never installed one, and the guest
    /// resolves peer names through it during start-up. Answering every lookup with an error keeps
    /// the solo overlay's "nothing to resolve" intent instead of panicking a worker thread.
    struct SoloResolver;

    #[async_trait::async_trait]
    impl murmur_component::resolver::resolver::Resolver for SoloResolver {
        async fn lookup_ip(&self, _ctx: &CancellationToken, host: &str) -> Result<Vec<IpAddr>> {
            Err(anyhow!("solo test overlay does not resolve {host}"))
        }

        async fn lookup_ipv4(&self, _ctx: &CancellationToken, host: &str) -> Result<Vec<IpAddr>> {
            Err(anyhow!("solo test overlay does not resolve {host}"))
        }

        async fn lookup_ipv6(&self, _ctx: &CancellationToken, host: &str) -> Result<Vec<IpAddr>> {
            Err(anyhow!("solo test overlay does not resolve {host}"))
        }

        async fn resolve_ech(&self, _ctx: &CancellationToken, _host: &str) -> Result<Vec<u8>> {
            Err(anyhow!("solo test overlay has no ECH"))
        }

        async fn exchange_context(
            &self,
            _ctx: &CancellationToken,
            _message: &hickory_proto::op::Message,
        ) -> Result<hickory_proto::op::Message> {
            Err(anyhow!("solo test overlay has no DNS server"))
        }

        fn invalid(&self) -> bool {
            true
        }

        fn clear_cache(&self) {}

        fn reset_connection(&self) {}
    }

    fn solo_services() -> Services {
        murmur_component_easytier::platform::services(Arc::new(SoloDialer))
    }

    /// Real host sockets, reached through the same functions `BasicDialer` wraps, so the
    /// dialer assertion holds and EasyTier may bind its own listeners.
    struct LoopbackDialer {
        opt: murmur_component::dialer::options::Options,
    }

    #[async_trait::async_trait]
    impl murmur_constant::adapters::Dialer for LoopbackDialer {
        async fn dial_context(&self, ctx: &CancellationToken, network: &str, address: &str) -> Result<Box<dyn Stream>> {
            let options = vec![murmur_component::dialer::options::with_option(self.opt.clone())];
            murmur_component::dialer::dialer::dial_context(ctx, network, address, options).await
        }

        async fn listen_packet(
            &self,
            ctx: &CancellationToken,
            network: &str,
            address: &str,
            r_addr_port: Option<SocketAddr>,
        ) -> Result<Box<dyn Datagram>> {
            let options = vec![murmur_component::dialer::options::with_option(self.opt.clone())];
            murmur_component::dialer::dialer::listen_packet(ctx, network, address, r_addr_port, options).await
        }
    }

    fn label(outcome: &std::result::Result<(), &anyhow::Error>) -> String {
        match outcome {
            Ok(()) => "ok".to_owned(),
            Err(err) => format!("{err:#}"),
        }
    }

    /// Records what the guest asked the host for before delegating to the real factory, so a
    /// refused listener names the call that refused it instead of only the guest's summary.
    struct TracedSockets {
        inner: murmur_component_easytier::platform::SocketFactory,
        trace: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait::async_trait]
    impl murmur_component_easytier::platform::platform::SocketFactory for TracedSockets {
        async fn connect_tcp(
            &self,
            ctx: &CancellationToken,
            options: TCPConnectOptions,
        ) -> Result<Box<dyn murmur_std_compat::net::Conn>> {
            let remote = options.remote_addr.as_ref().map(Addr::string);
            let outcome = self.inner.connect_tcp(ctx, options).await;
            self.trace.lock().push(format!("connect_tcp {remote:?} -> {}", label(&outcome.as_ref().map(|_| ()))));
            outcome
        }

        async fn bind_udp(
            &self,
            ctx: &CancellationToken,
            options: UDPBindOptions,
        ) -> Result<Box<dyn murmur_std_compat::net::PacketConn>> {
            let local = options.local_addr.clone();
            let outcome = self.inner.bind_udp(ctx, options).await;
            self.trace.lock().push(format!("bind_udp {local:?} -> {}", label(&outcome.as_ref().map(|_| ()))));
            outcome
        }

        async fn listen_tcp(
            &self,
            ctx: &CancellationToken,
            options: TCPListenOptions,
        ) -> Result<Box<dyn murmur_std_compat::net::Listener>> {
            let local = options.bind.local_addr;
            let outcome = self.inner.listen_tcp(ctx, options).await;
            self.trace.lock().push(format!("listen_tcp {local:?} -> {}", label(&outcome.as_ref().map(|_| ()))));
            outcome
        }
    }

    fn loopback_services(trace: Arc<Mutex<Vec<String>>>) -> Services {
        let opt = murmur_component::dialer::dialer::new_dialer(Vec::new()).opt;
        let dialer: Arc<dyn murmur_constant::adapters::Dialer> = Arc::new(LoopbackDialer { opt: opt.clone() });
        let sockets = murmur_component_easytier::platform::SocketFactory::new_direct(Arc::clone(&dialer), Some(opt));
        Services {
            sockets: Arc::new(TracedSockets { inner: sockets, trace }),
            dns: Arc::new(murmur_component_easytier::platform::DNSResolver {}),
            environment: Arc::new(murmur_component_easytier::platform::ConnectorEnvironment { dialer }),
            snapshot: murmur_component_easytier::platform::platform::EnvironmentSnapshot::default(),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn embeds_the_core_and_answers_the_management_rpcs() {
        let ctx = CancellationToken::new();
        let previous = murmur_component::resolver::resolver::system_resolver_opt();
        murmur_component::resolver::resolver::set_system_resolver(Some(Arc::new(SoloResolver)));
        let result = tokio::time::timeout(std::time::Duration::from_secs(180), async {
            let host = Host::new(Options { platform: solo_services() }).expect("embed the EasyTier core");
            let instance =
                host.create_instance_toml(&ctx, "murmur-solo", "", SOLO_TOML).await.expect("create EasyTier instance");
            assert_eq!(instance.state(), State::Created);
            assert_eq!(instance.id().len(), 36, "a minted instance ID must be a hyphenated UUID");

            instance.start(&ctx).await.expect("start EasyTier instance");
            assert_eq!(instance.state(), State::Running);

            let node = instance.show_node_info(&ctx).await.expect("ShowNodeInfo over the real guest");
            assert_eq!(node.hostname, "murmur-solo");
            assert!(
                node.ipv4_addr.starts_with("10.126.126.126"),
                "the configured overlay IPv4 must reach the guest, got {:?}",
                node.ipv4_addr
            );
            // A peerless overlay has no routes to advertise, but the RPC must still round-trip.
            let routes = instance.list_route(&ctx).await.expect("ListRoute over the real guest");
            assert!(routes.is_empty(), "a peerless overlay must advertise no routes, got {routes:?}");

            let mut events = instance.events().expect("the instance stream is taken once");
            instance.close(&ctx).await.expect("close EasyTier instance");
            assert_eq!(instance.state(), State::Stopped, "a closed instance reports the terminal state");
            instance.wait(&ctx).await.expect("waiting on a closed instance is not a failure");
            // The stream ending is the only restart signal an outbound's serve loop ever sees; the
            // close itself still emits its teardown events, so drain until the stream ends.
            while let Some(event) = events.recv().await {
                let _ = event;
            }
            host.close(&ctx).await.expect("close EasyTier host");
        })
        .await;
        murmur_component::resolver::resolver::set_system_resolver(previous);
        if let Err(elapsed) = result {
            panic!("embedded EasyTier core did not finish within the deadline: {elapsed:?}");
        }
    }

    /// Two real nodes of one overlay over loopback: the only proof that the peer transport, the
    /// host imports and the guest data plane are wired to each other. A fake socket pair would
    /// exercise none of that, and the document is rendered through this crate's own renderer so the
    /// guest parses exactly what an outbound sends it.
    const LOOPBACK_PORT: u16 = 21_010;
    const OVERLAY_PORT: u16 = 9_001;

    fn loopback_node(name: &str, ipv4: &str, dials_peer: bool) -> String {
        let config = murmur_component_easytier::toml::Config {
            network_name: "murmur-loopback".to_owned(),
            network_secret: "loopback-secret".to_owned(),
            hostname: name.to_owned(),
            ipv4: ipv4.to_owned(),
            instance_name: name.to_owned(),
            peers: if dials_peer { vec![format!("tcp://127.0.0.1:{LOOPBACK_PORT}")] } else { Vec::new() },
            listeners: if dials_peer { Vec::new() } else { vec![format!("tcp://0.0.0.0:{LOOPBACK_PORT}")] },
            no_listener: Some(dials_peer),
            ..Default::default()
        };
        murmur_component_easytier::toml::apply_required_flags(&config.render_toml().expect("render the node config"))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_loopback_nodes_carry_an_overlay_connection() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let ctx = CancellationToken::new();
        let previous = murmur_component::resolver::resolver::system_resolver_opt();
        murmur_component::resolver::resolver::set_system_resolver(Some(Arc::new(SoloResolver)));
        let trace = Arc::new(Mutex::new(Vec::new()));
        let result = tokio::time::timeout(std::time::Duration::from_secs(300), async {
            let server =
                Host::new(Options { platform: loopback_services(Arc::clone(&trace)) }).expect("host the listener node");
            let listener = server
                .create_instance_toml(&ctx, "node-a", "", &loopback_node("node-a", "10.99.0.1/24", false))
                .await
                .expect("create the listener node");
            let mut events = listener.events().expect("the stream is taken once");
            let started = listener.start(&ctx).await;
            let mut seen = Vec::new();
            while let Ok(event) = events.try_recv() {
                seen.push(format!("{}: {}", event.kind, event.message));
            }
            let imports = crate::host_abi::test_import_failures();
            assert!(started.is_ok(), "SOCKETS {trace:?} IMPORTS {imports:?} EVENTS {seen:?} ERROR {started:?}");
            let overlay = listener.listen("tcp4", &format!(":{OVERLAY_PORT}")).await.expect("bind an overlay TCP port");

            let client =
                Host::new(Options { platform: loopback_services(Arc::clone(&trace)) }).expect("host the dialing node");
            let dialer = client
                .create_instance_toml(&ctx, "node-b", "", &loopback_node("node-b", "10.99.0.2/24", true))
                .await
                .expect("create the dialing node");
            let started = dialer.start(&ctx).await;
            assert!(started.is_ok(), "dialing node did not start: {started:?}; sockets: {trace:?}");

            let peer_ipv4 = u32::from_be_bytes([10, 99, 0, 1]);
            let mut routed = false;
            for _ in 0..120 {
                let routes = dialer.list_route(&ctx).await.expect("ListRoute over the real guest");
                if routes.iter().any(|route| route.ipv4_addr == Some(peer_ipv4)) {
                    routed = true;
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
            assert!(routed, "the peering nodes never learned each other's overlay address; sockets: {trace:?}");

            let stream =
                dialer.dial(&ctx, "tcp4", &format!("10.99.0.1:{OVERLAY_PORT}")).await.expect("dial the overlay peer");
            let (mut inbound, mut outbound) = tokio::io::split(stream);
            let accepted = tokio::time::timeout(std::time::Duration::from_secs(30), overlay.accept())
                .await
                .expect("the overlay listener must accept the peer")
                .expect("accept over the overlay");
            let (mut accepted_in, mut accepted_out) = tokio::io::split(accepted);

            outbound.write_all(b"ping").await.expect("write across the overlay");
            let mut seen = [0u8; 4];
            accepted_in.read_exact(&mut seen).await.expect("read across the overlay");
            assert_eq!(&seen, b"ping");
            accepted_out.write_all(b"pong").await.expect("reply across the overlay");
            inbound.read_exact(&mut seen).await.expect("read the reply across the overlay");
            assert_eq!(&seen, b"pong");

            client.close(&ctx).await.expect("close the dialing host");
            server.close(&ctx).await.expect("close the listener host");
        })
        .await;
        murmur_component::resolver::resolver::set_system_resolver(previous);
        if let Err(elapsed) = result {
            panic!("the loopback overlay did not finish within the deadline: {elapsed:?}");
        }
    }
}
