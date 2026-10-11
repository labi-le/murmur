use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use chrono::{Duration as ChronoDuration, Utc};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::svcb::SvcParamValue;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use tokio_util::sync::CancellationToken;

use murmur_common::picker;
use murmur_component::resolver::relay::set_rcode;
use murmur_component::resolver::resolver::SharedResolver;
use murmur_component_ech::echparser::echparser::parse_ech_config_list;
use murmur_log::{debugln, warnln};

use super::resolver::{DnsCache, DnsClient, NameServer, NsNetType};

pub(crate) const MAX_MSG_SIZE: usize = 65535;
const SERVER_FAILURE_CACHE_TTL: u32 = 5;

/// A random id, the recursion-desired bit and a single IN question.
#[must_use]
pub fn question(name: Name, query_type: RecordType) -> Message {
    let mut message = Message::query();
    message.metadata.recursion_desired = true;
    message.queries = vec![Query::query(name, query_type)];
    message
}

pub(crate) fn minimal_ttl(records: &[Record]) -> u32 {
    records.iter().map(|record| record.ttl).min().unwrap_or(0)
}

fn set_record_ttl(record: &mut Record, ttl: u32) {
    let current = record.ttl;
    record.decrement_ttl(current.saturating_sub(ttl));
}

pub(crate) fn update_ttl(records: &mut [Record], ttl: u32) {
    if records.is_empty() {
        return;
    }
    let delta = minimal_ttl(records).wrapping_sub(ttl);
    for record in records.iter_mut() {
        let original = record.ttl;
        let target = if original == 0 { 0 } else { original.wrapping_sub(delta).clamp(1, original) };
        set_record_ttl(record, target);
    }
}

fn query_key(q: &Query) -> String {
    format!("{}|{}|{}", q.name, q.query_type, q.query_class)
}

pub(crate) fn get_msg_from_cache(
    c: &dyn DnsCache,
    q: &Query,
) -> (Option<Message>, Option<chrono::DateTime<Utc>>, bool) {
    c.get_with_expire(&query_key(q))
}

pub(crate) fn put_msg_to_cache(c: &dyn DnsCache, q: &Query, msg: &Message) {
    if q.query_type == RecordType::TXT && q.name.to_string().starts_with("_acme-challenge.") {
        debugln!("[DNS] dns cache ignored because of acme challenge for: {}", q.name);
        return;
    }

    let mut msg = msg.clone();
    msg.additionals.retain(|rr| rr.record_type() != RecordType::OPT);
    msg.edns = None;

    let ttl = if msg.metadata.response_code == ResponseCode::ServFail {
        SERVER_FAILURE_CACHE_TTL
    } else {
        msg.answers
            .iter()
            .chain(msg.authorities.iter())
            .chain(msg.additionals.iter())
            .map(|rr| rr.ttl)
            .min()
            .unwrap_or(0)
    };
    if ttl == 0 {
        return;
    }

    c.set_with_expire(&query_key(q), msg, Utc::now() + ChronoDuration::seconds(i64::from(ttl)));
}

pub(crate) fn set_msg_ttl(msg: &mut Message, ttl: u32) {
    for answer in &mut msg.answers {
        set_record_ttl(answer, ttl);
    }
    for ns in &mut msg.authorities {
        set_record_ttl(ns, ttl);
    }
    for extra in &mut msg.additionals {
        if extra.record_type() == RecordType::OPT {
            continue;
        }
        set_record_ttl(extra, ttl);
    }
}

pub(crate) fn update_msg_ttl(msg: &mut Message, ttl: u32) {
    update_ttl(&mut msg.answers, ttl);
    update_ttl(&mut msg.authorities, ttl);
    update_ttl(&mut msg.additionals, ttl);
}

pub(crate) fn is_ip_request(q: &Query) -> bool {
    q.query_class == hickory_proto::rr::DNSClass::IN
        && matches!(q.query_type, RecordType::A | RecordType::AAAA | RecordType::CNAME)
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "the config layer calls this by value and each nameserver clones the shared handle; taking a reference would change the crate-visible signature"
)]
pub(crate) fn transform(servers: &[NameServer], resolver: Option<SharedResolver>) -> Vec<Arc<dyn DnsClient>> {
    let mut ret = Vec::with_capacity(servers.len());
    for s in servers {
        let c: Arc<dyn DnsClient> = match s.net {
            NsNetType::Tls => {
                super::dot::new_dot_client(&s.addr, resolver.clone(), &s.params, s.proxy_adapter.clone(), &s.proxy_name)
            }
            NsNetType::Https => super::doh::new_doh_client(
                &s.addr,
                resolver.clone(),
                s.prefer_h3,
                &s.params,
                s.proxy_adapter.clone(),
                &s.proxy_name,
            ),
            NsNetType::Dhcp => super::dhcp::new_dhcp_client(&s.addr),
            NsNetType::System => super::system::new_system_client(),
            NsNetType::Tailscale => super::tailscale::new_tailscale_client(&s.addr),
            NsNetType::Easytier => super::easytier::new_easytier_client(&s.addr),
            NsNetType::Rcode => Arc::new(super::rcode::new_rcode_client(&s.addr)),
            NsNetType::Quic => {
                super::doq::new_doq(&s.addr, resolver.clone(), &s.params, s.proxy_adapter.clone(), &s.proxy_name)
            }
            NsNetType::Udp | NsNetType::Tcp => super::client::new_client(
                &s.addr,
                resolver.clone(),
                s.net == NsNetType::Tcp,
                &s.params,
                s.proxy_adapter.clone(),
                &s.proxy_name,
            ),
        };
        ret.push(rewrap_client(c, &s.params));
    }
    ret
}

pub(crate) fn rewrap_client(mut c: Arc<dyn DnsClient>, params: &HashMap<String, String>) -> Arc<dyn DnsClient> {
    while let Some(inner) = c.unwrap_inner() {
        c = inner;
    }
    let c = wrap_client_with_edns0_subnet(c, params);
    wrap_client_with_disable_types(c, params)
}

pub(crate) fn is_wrapper_only_param(key: &str) -> bool {
    is_disable_types_param(key) || is_edns0_subnet_param(key)
}

pub(crate) struct ClientWithDisableTypes {
    dns_client: Arc<dyn DnsClient>,
    disable_types: HashSet<RecordType>,
}

#[async_trait::async_trait]
impl DnsClient for ClientWithDisableTypes {
    async fn exchange_context(&self, ctx: &CancellationToken, m: &Message) -> Result<Message> {
        if m.queries.iter().any(|q| self.disable_types.contains(&q.query_type)) {
            return Ok(handle_msg_with_empty_answer(m));
        }

        let mut msg = self.dns_client.exchange_context(ctx, m).await?;
        msg.answers.retain(|rr| !self.disable_types.contains(&rr.record_type()));
        msg.authorities.retain(|rr| !self.disable_types.contains(&rr.record_type()));
        msg.additionals.retain(|rr| !self.disable_types.contains(&rr.record_type()));
        Ok(msg)
    }

    fn address(&self) -> String {
        self.dns_client.address()
    }

    fn reset_connection(&self) {
        self.dns_client.reset_connection();
    }

    fn unwrap_inner(&self) -> Option<Arc<dyn DnsClient>> {
        Some(Arc::clone(&self.dns_client))
    }
}

fn is_disable_types_param(key: &str) -> bool {
    matches!(key, "disable-ipv4" | "disable-ipv6") || key.starts_with("disable-qtype-")
}

pub(crate) fn wrap_client_with_disable_types(
    c: Arc<dyn DnsClient>,
    params: &HashMap<String, String>,
) -> Arc<dyn DnsClient> {
    const PREFIX: &str = "disable-qtype-";
    let mut disable_types = HashSet::new();
    if params.get("disable-ipv4").map(String::as_str) == Some("true") {
        disable_types.insert(RecordType::A);
    }
    if params.get("disable-ipv6").map(String::as_str) == Some("true") {
        disable_types.insert(RecordType::AAAA);
    }
    for (key, value) in params {
        if let Some(rest) = key.strip_prefix(PREFIX) {
            if value != "true" {
                continue;
            }
            let Ok(q_type) = rest.parse::<u16>() else { continue };
            let record_type = RecordType::from(q_type);
            if matches!(record_type, RecordType::Unknown(_)) {
                continue;
            }
            disable_types.insert(record_type);
        }
    }
    if disable_types.is_empty() {
        c
    } else {
        Arc::new(ClientWithDisableTypes { dns_client: c, disable_types })
    }
}

pub(crate) struct ClientWithEdns0Subnet {
    dns_client: Arc<dyn DnsClient>,
    ecs_prefix: ipnet::IpNet,
    ecs_override: bool,
}

#[async_trait::async_trait]
impl DnsClient for ClientWithEdns0Subnet {
    async fn exchange_context(&self, ctx: &CancellationToken, m: &Message) -> Result<Message> {
        let mut m = m.clone();
        super::edns0_subnet::set_edns0_subnet(&mut m, self.ecs_prefix, self.ecs_override);
        self.dns_client.exchange_context(ctx, &m).await
    }

    fn address(&self) -> String {
        self.dns_client.address()
    }

    fn reset_connection(&self) {
        self.dns_client.reset_connection();
    }

    fn unwrap_inner(&self) -> Option<Arc<dyn DnsClient>> {
        Some(Arc::clone(&self.dns_client))
    }
}

fn is_edns0_subnet_param(key: &str) -> bool {
    matches!(key, "ecs" | "ecs-override")
}

pub(crate) fn wrap_client_with_edns0_subnet(
    c: Arc<dyn DnsClient>,
    params: &HashMap<String, String>,
) -> Arc<dyn DnsClient> {
    let mut ecs_prefix: Option<ipnet::IpNet> = None;
    if let Some(ecs) = params.get("ecs").filter(|s| !s.is_empty()) {
        if let Ok(prefix) = ecs.parse::<ipnet::IpNet>() {
            ecs_prefix = Some(prefix);
        } else if let Ok(addr) = ecs.parse::<std::net::IpAddr>() {
            let bits = if addr.is_ipv4() { 32 } else { 128 };
            if let Ok(prefix) = ipnet::IpNet::new(addr, bits) {
                ecs_prefix = Some(prefix);
            }
        } else {
            warnln!("DNS [{}] config with invalid ecs: {}", c.address(), ecs);
        }
    }

    if let Some(ecs_prefix) = ecs_prefix {
        debugln!("DNS [{}] config with ecs: {}", c.address(), ecs_prefix);
        let ecs_override = params.get("ecs-override").map(String::as_str) == Some("true");
        Arc::new(ClientWithEdns0Subnet { dns_client: c, ecs_prefix, ecs_override })
    } else {
        c
    }
}

pub(crate) fn handle_msg_with_empty_answer(r: &Message) -> Message {
    let mut msg = Message::new(0, MessageType::Response, OpCode::Query);
    msg.answers = Vec::new();
    set_rcode(&mut msg, r, ResponseCode::NoError);
    msg.metadata.authoritative = true;
    msg.metadata.recursion_available = true;
    msg
}

pub(crate) fn msg_to_ip(msg: &Message) -> Vec<std::net::IpAddr> {
    let mut ips = Vec::new();
    for answer in &msg.answers {
        let ip = if let RData::AAAA(aaaa) = &answer.data {
            std::net::IpAddr::V6(aaaa.0)
        } else if let RData::A(a) = &answer.data {
            std::net::IpAddr::V4(a.0)
        } else {
            continue;
        };
        ips.push(ip);
    }
    ips
}

pub(crate) fn msg_to_domain(msg: &Message) -> String {
    match msg.queries.first() {
        Some(q) => q.name.to_string().trim_end_matches('.').to_owned(),
        None => String::new(),
    }
}

pub(crate) fn msg_to_qtype(msg: &Message) -> (RecordType, String) {
    match msg.queries.first() {
        Some(q) => (q.query_type, q.query_type.to_string()),
        None => (RecordType::from(0), String::new()),
    }
}

pub(crate) fn msg_to_https_rr_info(msg: &Message) -> String {
    let mut alpns: Vec<String> = Vec::new();
    let mut public_name = String::new();
    let mut has_ipv4 = false;
    let mut has_ipv6 = false;

    let mut collect = |rrs: &[Record]| {
        for rr in rrs {
            let RData::HTTPS(https) = &rr.data else { continue };
            for (_, value) in &https.0.svc_params {
                if let SvcParamValue::Alpn(alpn) = value {
                    if alpns.is_empty() && !alpn.0.is_empty() {
                        alpns.extend(alpn.0.iter().cloned());
                    }
                } else if let SvcParamValue::Ipv4Hint(hint) = value {
                    if !hint.0.is_empty() {
                        has_ipv4 = true;
                    }
                } else if let SvcParamValue::Ipv6Hint(hint) = value {
                    if !hint.0.is_empty() {
                        has_ipv6 = true;
                    }
                } else if let SvcParamValue::EchConfigList(ech) = value {
                    if public_name.is_empty() && !ech.0.is_empty() {
                        if let Ok(cfgs) = parse_ech_config_list(&ech.0) {
                            if let Some(first) = cfgs.first() {
                                public_name = String::from_utf8_lossy(&first.public_name).into_owned();
                            }
                        }
                    }
                }
            }
        }
    };

    collect(&msg.answers);

    if alpns.is_empty() && public_name.is_empty() && !has_ipv4 && !has_ipv6 {
        return String::new();
    }

    let mut parts = Vec::new();
    if !alpns.is_empty() {
        parts.push(format!("alpn:{}", alpns.join(",")));
    }
    if !public_name.is_empty() {
        parts.push(format!("pn:{public_name}"));
    }
    if has_ipv4 {
        parts.push("ipv4hint".to_owned());
    }
    if has_ipv6 {
        parts.push("ipv6hint".to_owned());
    }
    parts.join(";")
}

pub(crate) fn msg_to_log_string(msg: &Message) -> String {
    let (q_type, q_type_str) = msg_to_qtype(msg);
    if q_type == RecordType::HTTPS {
        format!("[{}] {}", msg_to_https_rr_info(msg), q_type_str)
    } else {
        // The IPs are rendered as `[a b]` (space separated, bracketed); Rust's Debug for
        // Vec<IpAddr> would insert `, ` between the elements.
        let ips = msg_to_ip(msg);
        let joined = ips.iter().map(ToString::to_string).collect::<Vec<_>>().join(" ");
        format!("[{joined}] {q_type_str}")
    }
}

// cancel-safe: the per-client lookups run as picker tasks driven by a child context, so a dropped wait
// leaves them to complete or cancel on their own.
pub(crate) async fn batch_exchange(
    ctx: &CancellationToken,
    clients: &[Arc<dyn DnsClient>],
    m: &Message,
) -> Result<(Message, bool)> {
    let (mut fast, ctx) =
        picker::with_timeout::<Message>(ctx, murmur_component::resolver::resolver::default_dns_timeout());
    let domain = msg_to_domain(m);
    let (_, q_type_str) = msg_to_qtype(m);

    for client in clients {
        if client.is_rcode_client() {
            let result = client.exchange_context(&ctx, m).await;
            fast.close();
            return result.map(|msg| (msg, false));
        }

        let client = Arc::clone(client);
        let domain = domain.clone();
        let q_type_str = q_type_str.clone();
        let m = m.clone();
        let ctx_for_task = ctx.clone();
        fast.spawn(async move {
            debugln!("[DNS] resolve {} {} from {}", domain, q_type_str, client.address());
            let msg = client.exchange_context(&ctx_for_task, &m).await?;
            if msg.metadata.response_code == ResponseCode::ServFail
                || msg.metadata.response_code == ResponseCode::Refused
            {
                return Err(anyhow!("server failure: {}", msg.metadata.response_code));
            }
            debugln!("[DNS] {} --> {} from {}", domain, msg_to_log_string(&msg), client.address());
            Ok(msg)
        });
    }

    let msg = fast.wait().await;
    fast.close();
    match msg {
        Some(msg) => Ok((msg, true)),
        None => Err(match fast.error() {
            Some(first) => anyhow!("all DNS requests failed, first error: {first}"),
            None => anyhow!("all DNS requests failed"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::Mutex;

    use hickory_proto::rr::{Name, RData};

    use super::*;

    struct RecordingCache {
        recorded: Mutex<Option<(String, Message, chrono::DateTime<Utc>)>>,
    }

    impl DnsCache for RecordingCache {
        fn get_with_expire(&self, _key: &str) -> (Option<Message>, Option<chrono::DateTime<Utc>>, bool) {
            (None, None, false)
        }

        fn set_with_expire(&self, key: &str, value: Message, expire: chrono::DateTime<Utc>) {
            *self.recorded.lock().expect("lock") = Some((key.to_owned(), value, expire));
        }

        fn clear(&self) {}
    }

    fn record(name: &Name, ttl: u32) -> Record {
        Record::from_rdata(name.clone(), ttl, RData::from(Ipv4Addr::new(1, 2, 3, 4)))
    }

    #[test]
    fn msg_to_log_string_joins_ips_and_qtype() {
        let name = Name::from_ascii("example.com.").expect("name");
        let mut msg = Message::new(0, MessageType::Response, OpCode::Query);
        msg.metadata.response_code = ResponseCode::NoError;
        msg.queries.push(Query::query(name.clone(), RecordType::A));
        msg.answers.push(record(&name, 300));
        msg.answers.push(Record::from_rdata(name.clone(), 300, RData::from(Ipv4Addr::new(5, 6, 7, 8))));

        // Format: `[<ips space-joined>] <qtype>`, with empty brackets when there are no answers.
        assert_eq!(msg_to_log_string(&msg), "[1.2.3.4 5.6.7.8] A");

        let empty = Message::new(0, MessageType::Response, OpCode::Query);
        assert_eq!(msg_to_log_string(&empty), "[] ");
    }

    #[test]
    fn put_msg_to_cache_uses_the_minimum_ttl_across_all_sections() {
        for (answers_ttl, authorities_ttl, additionals_ttl) in [(30, 300, 120), (300, 30, 120), (300, 120, 30)] {
            let name = Name::from_ascii("example.com.").expect("name");
            let q = Query::query(name.clone(), RecordType::A);

            let mut msg = Message::new(0, MessageType::Response, OpCode::Query);
            msg.metadata.response_code = ResponseCode::NoError;
            msg.answers.push(record(&name, answers_ttl));
            msg.authorities.push(record(&name, authorities_ttl));
            msg.additionals.push(record(&name, additionals_ttl));

            let cache = RecordingCache { recorded: Mutex::new(None) };
            let before = Utc::now();
            put_msg_to_cache(&cache, &q, &msg);

            let (_, _, expire) = cache.recorded.lock().expect("lock").clone().expect("cached");
            let ttl_secs = (expire - before).num_seconds();
            assert!(
                (29..=30).contains(&ttl_secs),
                "answers={answers_ttl} authorities={authorities_ttl} additionals={additionals_ttl}: expected ~30s TTL, got {ttl_secs}s"
            );
        }
    }

    #[test]
    fn put_msg_to_cache_strips_upstream_edns() {
        let name = Name::from_ascii("example.com.").expect("name");
        let q = Query::query(name.clone(), RecordType::A);

        let mut msg = Message::new(0, MessageType::Response, OpCode::Query);
        msg.metadata.response_code = ResponseCode::NoError;
        msg.answers.push(record(&name, 300));
        let mut edns = hickory_proto::op::Edns::new();
        edns.set_max_payload(4096);
        edns.set_dnssec_ok(true);
        msg.edns = Some(edns);

        let cache = RecordingCache { recorded: Mutex::new(None) };
        put_msg_to_cache(&cache, &q, &msg);

        let (_, cached, _) = cache.recorded.lock().expect("lock").clone().expect("cached");
        // the cache drops the resolver's OPT before caching, so a cache hit gets a fresh
        // OPT (1232, DO copied from the request) rather than the resolver's own.
        assert!(cached.edns.is_none());
    }

    #[test]
    fn put_msg_to_cache_uses_server_failure_ttl_on_servfail() {
        let name = Name::from_ascii("example.com.").expect("name");
        let q = Query::query(name.clone(), RecordType::A);

        let mut msg = Message::new(0, MessageType::Response, OpCode::Query);
        msg.metadata.response_code = ResponseCode::ServFail;
        msg.answers.push(record(&name, 300));

        let cache = RecordingCache { recorded: Mutex::new(None) };
        let before = Utc::now();
        put_msg_to_cache(&cache, &q, &msg);

        let (_, _, expire) = cache.recorded.lock().expect("lock").clone().expect("cached");
        let ttl_secs = (expire - before).num_seconds();
        assert!(
            (i64::from(SERVER_FAILURE_CACHE_TTL) - 1..=i64::from(SERVER_FAILURE_CACHE_TTL)).contains(&ttl_secs),
            "expected the server-failure TTL, got {ttl_secs}s"
        );
    }

    #[test]
    fn put_msg_to_cache_skips_caching_when_every_ttl_is_zero() {
        let name = Name::from_ascii("example.com.").expect("name");
        let q = Query::query(name.clone(), RecordType::A);

        let mut msg = Message::new(0, MessageType::Response, OpCode::Query);
        msg.metadata.response_code = ResponseCode::NoError;
        msg.answers.push(record(&name, 0));

        let cache = RecordingCache { recorded: Mutex::new(None) };
        put_msg_to_cache(&cache, &q, &msg);

        assert!(cache.recorded.lock().expect("lock").is_none());
    }
}
