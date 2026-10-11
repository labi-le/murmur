//! The HTTP client drives `hyper`'s HTTP/1.1 client connection directly over the already-dialed
//! proxy connection, with no pooling transport that negotiates HTTP/2 automatically.
//!
//! See `component/http/http.rs` for the same constraint already recorded in this crate.
//! Connection-pool idle limits have nothing to configure since there is no pool; the overall
//! client `Timeout` becomes an explicit [`CLIENT_TIMEOUT`] race.
//!
//! Closing the instance becomes [`DeferClose`], a thin wrapper whose `Drop` closes the underlying
//! connection once every owner (the TLS layer and the hyper connection task) has released it.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;
use http_body_util::Empty;
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use serde::ser::{Serialize, SerializeMap, Serializer};
use serde_json::{Map as JsonMap, Value as JsonValue};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;

use murmur_common::atomic::type_::{new_bool, Bool};
use murmur_common::queue::{self, Queue};
use murmur_common::utils::ranges::IntRanges;
use murmur_common::xsync::map::Map as XMap;
use murmur_common_net::io::Stream;
use murmur_component::dialer::bind::join_host_port;
use murmur_component_ca::config::{get_tls_config, Option as CaOption};
use murmur_component_tls::utls::client as tls_client;
use murmur_constant::adapters::{
    AdapterType, Conn as CConn, DelayHistory, PacketConn as CPacketConn, Proxy as CProxy,
    ProxyAdapter as CProxyAdapter, ProxyInfo, ProxyState,
};
use murmur_constant::metadata::Metadata;
use murmur_log::{errorln, warnln};

pub static UNIFIED_DELAY: Bool = new_bool(false);

const DEFAULT_HISTORIES_NUM: i64 = 10;

const CLIENT_TIMEOUT: Duration = Duration::from_secs(30);

/// A wrapper's own JSON field, kept in declaration order for the `history`/`extra` entries.
enum Field {
    Value(JsonValue),
    History(Vec<DelayHistory>),
    Extra(BTreeMap<String, ProxyState>),
}

impl Serialize for Field {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Value(value) => value.serialize(serializer),
            Self::History(history) => history.serialize(serializer),
            Self::Extra(extra) => extra.serialize(serializer),
        }
    }
}

struct InternalProxyState {
    alive: Bool,
    history: Queue<DelayHistory>,
}

pub struct Proxy {
    inner: Arc<dyn CProxyAdapter>,
    alive: Bool,
    history: Queue<DelayHistory>,
    extra: XMap<String, Arc<InternalProxyState>>,
}

impl fmt::Debug for Proxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Proxy").field("name", &self.inner.name()).finish_non_exhaustive()
    }
}

#[async_trait]
impl CProxyAdapter for Proxy {
    fn name(&self) -> String {
        self.inner.name()
    }

    fn type_(&self) -> AdapterType {
        self.inner.type_()
    }

    fn addr(&self) -> String {
        self.inner.addr()
    }

    fn support_udp(&self) -> bool {
        self.inner.support_udp()
    }

    fn proxy_info(&self) -> ProxyInfo {
        self.inner.proxy_info()
    }

    fn marshal_json(&self) -> Result<Vec<u8>> {
        let raw = self.inner.marshal_json()?;

        let mut mapping: JsonMap<String, JsonValue> = serde_json::from_slice(&raw).unwrap_or_default();
        mapping.insert("alive".to_owned(), JsonValue::Bool(self.alive.load()));
        mapping.insert("name".to_owned(), JsonValue::String(self.inner.name()));
        mapping.insert("udp".to_owned(), JsonValue::Bool(self.inner.support_udp()));
        mapping.insert("uot".to_owned(), JsonValue::Bool(self.inner.support_uot()));

        let proxy_info = self.inner.proxy_info();
        mapping.insert("xudp".to_owned(), JsonValue::Bool(proxy_info.xudp));
        mapping.insert("tfo".to_owned(), JsonValue::Bool(proxy_info.tfo));
        mapping.insert("mptcp".to_owned(), JsonValue::Bool(proxy_info.mptcp));
        mapping.insert("smux".to_owned(), JsonValue::Bool(proxy_info.smux));
        mapping.insert("interface".to_owned(), JsonValue::String(proxy_info.interface));
        mapping.insert("routing-mark".to_owned(), JsonValue::from(proxy_info.routing_mark));
        mapping.insert("provider-name".to_owned(), JsonValue::String(proxy_info.provider_name));
        mapping.insert("dialer-proxy".to_owned(), JsonValue::String(proxy_info.dialer_proxy));

        // The wrapper's own keys sort at the top level, while `history`/`extra` keep the
        // `DelayHistory`/`ProxyState` declaration order a `Value` cannot hold, since its map is
        // sorted and would rewrite `time`/`delay` as `delay`/`time`.
        let mut fields: Vec<(String, Field)> =
            mapping.into_iter().map(|(key, value)| (key, Field::Value(value))).collect();
        fields.retain(|(key, _)| key != "history" && key != "extra");
        fields.push(("history".to_owned(), Field::History(self.delay_history())));
        fields.push(("extra".to_owned(), Field::Extra(self.extra_delay_histories().into_iter().collect())));
        fields.sort_by(|left, right| left.0.cmp(&right.0));

        let mut serializer = serde_json::Serializer::new(Vec::new());
        let mut map = serializer.serialize_map(Some(fields.len()))?;
        for (key, value) in &fields {
            map.serialize_entry(key, value)?;
        }
        map.end()?;
        Ok(serializer.into_inner())
    }

    async fn dial_context(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<Box<dyn CConn>> {
        self.inner.dial_context(ctx, metadata).await
    }

    async fn listen_packet_context(
        &self,
        ctx: &CancellationToken,
        metadata: &mut Metadata,
    ) -> Result<Arc<dyn CPacketConn>> {
        self.inner.listen_packet_context(ctx, metadata).await
    }

    fn support_uot(&self) -> bool {
        self.inner.support_uot()
    }

    fn is_l3_protocol(&self, metadata: &Metadata) -> bool {
        self.inner.is_l3_protocol(metadata)
    }

    fn unwrap(&self, metadata: &Metadata, touch: bool) -> Option<Arc<dyn CProxy>> {
        self.inner.unwrap(metadata, touch)
    }

    fn close(&self) -> Result<()> {
        self.inner.close()
    }
}

#[async_trait]
impl CProxy for Proxy {
    fn adapter(&self) -> Arc<dyn CProxyAdapter> {
        Arc::clone(&self.inner)
    }

    fn alive_for_test_url(&self, url: &str) -> bool {
        if let Some(state) = self.extra.load(&url.to_owned()) {
            return state.alive.load();
        }
        self.alive.load()
    }

    fn delay_history(&self) -> Vec<DelayHistory> {
        self.history.copy()
    }

    fn extra_delay_histories(&self) -> HashMap<String, ProxyState> {
        let mut histories = HashMap::new();
        self.extra.range(|test_url, state| {
            histories.insert(test_url.clone(), ProxyState { alive: state.alive.load(), history: state.history.copy() });
            true
        });
        histories
    }

    fn last_delay_for_test_url(&self, url: &str) -> u16 {
        const MAX_DELAY: u16 = 0xffff;

        let state = self.extra.load(&url.to_owned());
        let alive = state.as_ref().is_some_and(|state| state.alive.load());
        let delay = state.as_ref().map_or(0, |state| state.history.last().map_or(0, |history| history.delay));

        if !alive || delay == 0 {
            return MAX_DELAY;
        }
        delay
    }

    async fn url_test(&self, ctx: &CancellationToken, url: &str, expected_status: IntRanges<u16>) -> Result<u16> {
        let outcome = self.url_test_inner(ctx, url, &expected_status).await;

        let (t, err_is_none, satisfied) = match &outcome {
            Ok((t, satisfied)) => (*t, true, *satisfied),
            Err(_) => (0u16, false, false),
        };

        let alive = err_is_none;
        let mut record = DelayHistory { time: Utc::now(), delay: 0 };
        if alive {
            record.delay = t;
        }

        self.alive.store(alive);
        self.history.put([record.clone()]);
        if self.history.len() > DEFAULT_HISTORIES_NUM {
            self.history.pop();
        }

        let (state, _) = self.extra.load_or_store_fn(url.to_owned(), || {
            Arc::new(InternalProxyState { history: queue::new(DEFAULT_HISTORIES_NUM), alive: new_bool(true) })
        });

        let mut state_alive = alive;
        let mut state_record = record;
        if !satisfied {
            state_record.delay = 0;
            state_alive = false;
        }

        state.alive.store(state_alive);
        state.history.put([state_record]);
        if state.history.len() > DEFAULT_HISTORIES_NUM {
            state.history.pop();
        }

        outcome.map(|(t, _)| t)
    }
}

impl Proxy {
    /// Not part of the `Proxy` trait; kept as an inherent method for callers that hold the
    /// concrete type.
    pub fn delay_history_for_test_url(&self, url: &str) -> Vec<DelayHistory> {
        self.extra.load(&url.to_owned()).map(|state| state.history.copy()).unwrap_or_default()
    }

    async fn url_test_inner(
        &self,
        ctx: &CancellationToken,
        url: &str,
        expected_status: &IntRanges<u16>,
    ) -> Result<(u16, bool)> {
        let unified_delay = UNIFIED_DELAY.load();

        let mut addr = url_to_metadata(url)?;

        let mut start = Instant::now();
        let instance = self.inner.dial_context(ctx, &mut addr).await?;
        let instance: Box<dyn Stream> = Box::new(DeferClose(instance));

        let parsed = url::Url::parse(url)?;
        let host = parsed.host_str().unwrap_or_default().to_owned();
        let is_https = parsed.scheme() == "https";

        let build_request = || -> Result<hyper::Request<Empty<Bytes>>> {
            Ok(hyper::Request::builder().method(hyper::Method::HEAD).uri(url).body(Empty::<Bytes>::new())?)
        };

        let phase1 = async {
            let conn: Box<dyn Stream> = if is_https {
                let mut tls_config = get_tls_config(CaOption::default())?;
                if tls_config.server_name.is_empty() {
                    tls_config.server_name = host.clone();
                }
                let tls_conn = tls_client(instance, Arc::new(tls_config));
                tls_conn.handshake_context(ctx).await?;
                Box::new(tls_conn)
            } else {
                instance
            };

            let io = TokioIo::new(conn);
            let (mut sender, connection) = hyper::client::conn::http1::handshake(io).await?;
            tokio::spawn(async move {
                let _ = connection.await;
            });

            sender.ready().await?;
            let resp = sender.send_request(build_request()?).await?;
            Ok::<_, anyhow::Error>((sender, resp))
        };

        let (mut sender, mut resp) = tokio::select! {
            result = phase1 => result?,
            () = ctx.cancelled() => return Err(anyhow!("context canceled")),
            () = tokio::time::sleep(CLIENT_TIMEOUT) => return Err(anyhow!("proxy test timed out after {CLIENT_TIMEOUT:?}")),
        };

        if unified_delay {
            let second_start = Instant::now();
            let second_send = async {
                sender.ready().await?;
                let resp = sender.send_request(build_request()?).await?;
                Ok::<_, anyhow::Error>(resp)
            };

            let second_result: Result<hyper::Response<Incoming>> = tokio::select! {
                result = second_send => result,
                () = ctx.cancelled() => Err(anyhow!("context canceled")),
                () = tokio::time::sleep(CLIENT_TIMEOUT) => Err(anyhow!("proxy test timed out after {CLIENT_TIMEOUT:?}")),
            };

            match second_result {
                Ok(second_resp) => {
                    resp = second_resp;
                    start = second_start;
                }
                Err(ignored_err) => {
                    if url.starts_with("http://") {
                        errorln!("{} failed to get the second response from {url}: {ignored_err}", self.inner.name());
                        warnln!(
                            "It is recommended to use HTTPS for provider.health-check.url and group.url to ensure better reliability. Due to some proxy providers hijacking test addresses and not being compatible with repeated HEAD requests, using HTTP may result in failed tests."
                        );
                    }
                }
            }
        }

        let satisfied = expected_status.check(resp.status().as_u16());
        #[expect(
            clippy::cast_possible_truncation,
            reason = "the test delay is a u16 wire field, so the millisecond count truncates exactly as the original did"
        )]
        let t = (start.elapsed().as_millis() as u64) as u16;

        Ok((t, satisfied))
    }

    pub fn new(adapter: Arc<dyn CProxyAdapter>) -> Arc<Self> {
        Arc::new(Self {
            inner: adapter,
            alive: new_bool(true),
            history: queue::new(DEFAULT_HISTORIES_NUM),
            extra: XMap::default(),
        })
    }
}

fn url_to_metadata(raw_url: &str) -> Result<Metadata> {
    let parsed = url::Url::parse(raw_url)?;

    let port = match parsed.port() {
        Some(port) => port.to_string(),
        None => match parsed.scheme() {
            "https" => "443".to_owned(),
            "http" => "80".to_owned(),
            _ => return Err(anyhow!("{raw_url} scheme not Support")),
        },
    };

    let mut addr = Metadata::default();
    addr.set_remote_address(&join_host_port(parsed.host_str().unwrap_or_default(), &port))?;
    Ok(addr)
}

/// Closes the dialed proxy connection once every wrapper built on top
/// of it (the TLS layer, the hyper connection driver) has released its last reference.
struct DeferClose(Box<dyn CConn>);

impl Drop for DeferClose {
    fn drop(&mut self) {
        let _ = self.0.shutdown_read();
        let _ = self.0.shutdown_write();
    }
}

impl AsyncRead for DeferClose {
    fn poll_read(self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl AsyncWrite for DeferClose {
    fn poll_write(self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

impl Stream for DeferClose {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.0.local_addr()
    }

    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.0.peer_addr()
    }

    fn shutdown_read(&self) -> io::Result<()> {
        self.0.shutdown_read()
    }

    fn shutdown_write(&self) -> io::Result<()> {
        self.0.shutdown_write()
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;

    use super::*;

    impl Proxy {
        fn put_history_for_test(&self, record: DelayHistory) {
            self.history.put([record]);
        }

        fn put_extra_history_for_test(&self, url: &str, state: ProxyState) {
            let (slot, _) = self.extra.load_or_store_fn(url.to_owned(), || {
                Arc::new(InternalProxyState { history: queue::new(DEFAULT_HISTORIES_NUM), alive: new_bool(true) })
            });
            slot.alive.store(state.alive);
            slot.history.put(state.history);
        }
    }

    struct StubAdapter;

    #[async_trait]
    impl CProxyAdapter for StubAdapter {
        fn name(&self) -> String {
            "STUB".to_owned()
        }

        fn type_(&self) -> AdapterType {
            AdapterType::DIRECT
        }

        fn addr(&self) -> String {
            String::new()
        }

        fn support_udp(&self) -> bool {
            false
        }

        fn proxy_info(&self) -> ProxyInfo {
            ProxyInfo::default()
        }

        fn marshal_json(&self) -> Result<Vec<u8>> {
            Ok(br#"{"type":"Stub"}"#.to_vec())
        }

        async fn dial_context(&self, _ctx: &CancellationToken, _metadata: &mut Metadata) -> Result<Box<dyn CConn>> {
            Err(anyhow!("the stub adapter never dials"))
        }

        async fn listen_packet_context(
            &self,
            _ctx: &CancellationToken,
            _metadata: &mut Metadata,
        ) -> Result<Arc<dyn CPacketConn>> {
            Err(anyhow!("the stub adapter never listens"))
        }

        fn support_uot(&self) -> bool {
            false
        }

        fn is_l3_protocol(&self, _metadata: &Metadata) -> bool {
            false
        }

        fn unwrap(&self, _metadata: &Metadata, _touch: bool) -> Option<Arc<dyn CProxy>> {
            None
        }

        fn close(&self) -> Result<()> {
            Ok(())
        }
    }

    /// The wrapper's own keys sort, while `history`/`extra` hold
    /// structs whose declaration order survives, so a `DelayHistory` stays `{"time":…,"delay":…}`.
    #[test]
    fn history_and_extra_keep_the_field_order() {
        let time = Utc.with_ymd_and_hms(2026, 9, 24, 13, 0, 0).unwrap();
        let url = "http://192.0.2.1/";
        let proxy = Proxy::new(Arc::new(StubAdapter));
        proxy.put_history_for_test(DelayHistory { time, delay: 42 });
        proxy.put_extra_history_for_test(
            url,
            ProxyState { alive: true, history: vec![DelayHistory { time, delay: 7 }] },
        );

        let body = String::from_utf8(proxy.marshal_json().expect("marshal")).expect("JSON is UTF-8");
        let stamp = murmur_common::time_rfc3339::to_wire_string(&time);
        assert!(body.starts_with(r#"{"alive":true,"dialer-proxy":"","extra":{"#), "{body}");
        assert!(body.contains(&format!(r#""history":[{{"time":"{stamp}","delay":42}}]"#)), "{body}");
        assert!(
            body.contains(&format!(r#""{url}":{{"alive":true,"history":[{{"time":"{stamp}","delay":7}}]}}"#)),
            "{body}"
        );
    }
}
