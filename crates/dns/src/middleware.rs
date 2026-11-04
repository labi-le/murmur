//! The `handler`/`middleware` function types compose via closures returning closures.
//!
//! This crate spells the same composition as trait objects (`Handler`/`Middleware`) to avoid
//! boxed-future higher-ranked closures; the wrapping order and observable behaviour are unchanged.

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use chrono::Utc;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::rdata::CNAME;
use hickory_proto::rr::{Name, RData, Record, RecordType};

use murmur_common::lru::LruCache;
use murmur_component::dialer::bind::{is_global_unicast, unmap_addr};
use murmur_component::resolver::host::HostValue;
use murmur_component::resolver::relay::set_rcode;
use murmur_component::resolver::resolver::{default_hosts, SharedResolver};
use murmur_component_fakeip::pool::Pool;
use murmur_component_fakeip::skipper::Skipper;
use murmur_constant::dns::DNSMode;
use murmur_context::dns::{DNSContext, DNS_TYPE_FAKE_IP, DNS_TYPE_HOST, DNS_TYPE_RAW};
use murmur_log::{debugln, warnln};

use super::enhancer::ResolverEnhancer;
use super::server::DNS_DEFAULT_TTL;
use super::util::{handle_msg_with_empty_answer, is_ip_request, set_msg_ttl};

#[async_trait]
pub(crate) trait Handler: Send + Sync {
    async fn handle(&self, ctx: &mut DNSContext, r: &Message) -> Result<Message>;
}

pub(crate) type BoxHandler = Arc<dyn Handler>;

pub(crate) trait Middleware: Send + Sync {
    fn wrap(&self, next: BoxHandler) -> BoxHandler;
}

struct WithHosts {
    mapping: Option<Arc<LruCache<IpAddr, String>>>,
}

struct WithHostsHandler {
    mapping: Option<Arc<LruCache<IpAddr, String>>>,
    next: BoxHandler,
}

impl Middleware for WithHosts {
    fn wrap(&self, next: BoxHandler) -> BoxHandler {
        Arc::new(WithHostsHandler { mapping: self.mapping.clone(), next })
    }
}

fn handle_cname(resp: &mut Message, q_name: &Name, domain: &str) {
    let name = Name::from_str(&format!("{domain}.")).unwrap_or_else(|_| q_name.clone());
    let rr = Record::from_rdata(q_name.clone(), 10, RData::CNAME(CNAME(name)));
    resp.answers.insert(0, rr);
}

fn handle_ips(
    msg: &mut Message,
    q_name: &Name,
    q_type: RecordType,
    record: &HostValue,
    mapping: Option<&Arc<LruCache<IpAddr, String>>>,
    host: &str,
) {
    for ip_addr in &record.ips {
        let matches =
            (ip_addr.is_ipv4() && q_type == RecordType::A) || (ip_addr.is_ipv6() && q_type == RecordType::AAAA);
        if !matches {
            continue;
        }
        let rr = Record::from_rdata(q_name.clone(), 10, RData::from(*ip_addr));
        msg.answers.push(rr);
        if let Some(mapping) = mapping {
            mapping.set_with_expire(*ip_addr, host.to_owned(), Utc::now() + chrono::Duration::seconds(10));
        }
    }
}

#[async_trait]
impl Handler for WithHostsHandler {
    async fn handle(&self, ctx: &mut DNSContext, r: &Message) -> Result<Message> {
        let Some(q) = r.queries.first().cloned() else {
            return self.next.handle(ctx, r).await;
        };
        if !is_ip_request(&q) {
            return self.next.handle(ctx, r).await;
        }

        let host = q.name().to_string();
        let host = host.trim_end_matches('.');

        let is_domain_query = q.query_type() != RecordType::A && q.query_type() != RecordType::AAAA;
        let found = default_hosts().search(host, is_domain_query).await;

        match found {
            None => self.next.handle(ctx, r).await,
            Some((record, ok)) if !ok => {
                if record.is_domain {
                    let mut new_r = r.clone();
                    if let Some(first) = new_r.queries.first_mut() {
                        first.set_name(Name::from_str(&format!("{}.", record.domain))?);
                    }
                    match self.next.handle(ctx, &new_r).await {
                        Ok(mut resp) => {
                            resp.metadata.id = r.metadata.id;
                            resp.queries.clone_from(&r.queries);
                            handle_cname(&mut resp, q.name(), &record.domain);
                            Ok(resp)
                        }
                        Err(err) => Err(err),
                    }
                } else {
                    self.next.handle(ctx, r).await
                }
            }
            Some((record, _ok)) => {
                let mut msg = r.clone();
                let q_type = q.query_type();
                if matches!(q_type, RecordType::A | RecordType::AAAA) {
                    handle_ips(&mut msg, q.name(), q_type, &record, self.mapping.as_ref(), host);
                } else if q_type == RecordType::CNAME {
                    handle_cname(&mut msg, q.name(), &record.domain);
                } else {
                    return self.next.handle(ctx, r).await;
                }

                ctx.set_type(DNS_TYPE_HOST);
                set_rcode(&mut msg, r, ResponseCode::NoError);
                msg.metadata.authoritative = true;
                msg.metadata.recursion_available = true;
                Ok(msg)
            }
        }
    }
}

struct WithMapping {
    mapping: Option<Arc<LruCache<IpAddr, String>>>,
}

struct WithMappingHandler {
    mapping: Option<Arc<LruCache<IpAddr, String>>>,
    next: BoxHandler,
}

impl Middleware for WithMapping {
    fn wrap(&self, next: BoxHandler) -> BoxHandler {
        Arc::new(WithMappingHandler { mapping: self.mapping.clone(), next })
    }
}

#[async_trait]
impl Handler for WithMappingHandler {
    async fn handle(&self, ctx: &mut DNSContext, r: &Message) -> Result<Message> {
        let Some(q) = r.queries.first().cloned() else {
            return self.next.handle(ctx, r).await;
        };
        if !is_ip_request(&q) {
            return self.next.handle(ctx, r).await;
        }

        let msg = self.next.handle(ctx, r).await?;

        if let Some(mapping) = &self.mapping {
            let host = q.name().to_string();
            let host = host.trim_end_matches('.');

            for answer in &msg.answers {
                let Some(ip) = answer.data.ip_addr() else {
                    continue;
                };
                if !is_global_unicast(Some(ip)) {
                    continue;
                }
                let ip = unmap_addr(Some(ip)).unwrap_or(ip);
                let ttl = answer.ttl.max(1);
                mapping.set_with_expire(ip, host.to_owned(), Utc::now() + chrono::Duration::seconds(i64::from(ttl)));
            }
        }

        Ok(msg)
    }
}

struct WithFakeIp {
    skipper: Arc<Skipper>,
    fake_pool: Option<Arc<Pool>>,
    fake_pool6: Option<Arc<Pool>>,
    fake_ip_ttl: i32,
}

struct WithFakeIpHandler {
    skipper: Arc<Skipper>,
    fake_pool: Option<Arc<Pool>>,
    fake_pool6: Option<Arc<Pool>>,
    fake_ip_ttl: i32,
    next: BoxHandler,
}

impl Middleware for WithFakeIp {
    fn wrap(&self, next: BoxHandler) -> BoxHandler {
        Arc::new(WithFakeIpHandler {
            skipper: Arc::clone(&self.skipper),
            fake_pool: self.fake_pool.clone(),
            fake_pool6: self.fake_pool6.clone(),
            fake_ip_ttl: self.fake_ip_ttl,
            next,
        })
    }
}

#[async_trait]
impl Handler for WithFakeIpHandler {
    async fn handle(&self, ctx: &mut DNSContext, r: &Message) -> Result<Message> {
        let Some(q) = r.queries.first().cloned() else {
            return Ok(handle_msg_with_empty_answer(r));
        };
        let host = q.name().to_string();
        let host = host.trim_end_matches('.');

        if self.skipper.should_skipped(host) {
            return self.next.handle(ctx, r).await;
        }

        let q_type = q.query_type();
        let pool = if q_type == RecordType::A {
            self.fake_pool.as_ref()
        } else if q_type == RecordType::AAAA {
            self.fake_pool6.as_ref()
        } else if matches!(q_type, RecordType::SVCB | RecordType::HTTPS) {
            return Ok(handle_msg_with_empty_answer(r));
        } else {
            return self.next.handle(ctx, r).await;
        };
        let Some(pool) = pool else {
            return Ok(handle_msg_with_empty_answer(r));
        };
        let rr = Record::from_rdata(q.name().clone(), DNS_DEFAULT_TTL, RData::from(pool.lookup(host)));

        let mut msg = r.clone();
        msg.answers = vec![rr];

        ctx.set_type(DNS_TYPE_FAKE_IP);
        set_msg_ttl(&mut msg, u32::try_from(self.fake_ip_ttl).unwrap_or_default());
        set_rcode(&mut msg, r, ResponseCode::NoError);
        msg.metadata.authoritative = true;
        msg.metadata.recursion_available = true;

        Ok(msg)
    }
}

struct WithResolverHandler {
    resolver: SharedResolver,
    ipv6: bool,
}

#[async_trait]
impl Handler for WithResolverHandler {
    async fn handle(&self, ctx: &mut DNSContext, r: &Message) -> Result<Message> {
        ctx.set_type(DNS_TYPE_RAW);

        let Some(q) = r.queries.first() else {
            return Ok(handle_msg_with_empty_answer(r));
        };
        if !self.ipv6 && q.query_type() == RecordType::AAAA {
            return Ok(handle_msg_with_empty_answer(r));
        }

        let mut msg = match self.resolver.exchange_context(ctx.ctx(), r).await {
            Ok(msg) => msg,
            Err(err) => {
                debugln!("[DNS Server] Exchange {q} failed: {err}");
                return Err(err);
            }
        };
        let rcode = msg.metadata.response_code;
        set_rcode(&mut msg, r, rcode);
        msg.metadata.authoritative = true;
        Ok(msg)
    }
}

fn compose(middlewares: &[Arc<dyn Middleware>], endpoint: BoxHandler) -> BoxHandler {
    let mut h = endpoint;
    for middleware in middlewares.iter().rev() {
        h = middleware.wrap(h);
    }
    h
}

pub(crate) fn new_handler(resolver: SharedResolver, mapper: &ResolverEnhancer) -> BoxHandler {
    let mut middlewares: Vec<Arc<dyn Middleware>> = Vec::new();

    if mapper.use_hosts {
        middlewares.push(Arc::new(WithHosts { mapping: mapper.mapping.clone() }));
    }

    if mapper.mode == DNSMode::DNS_FAKE_IP {
        if let Some(skipper) = &mapper.fake_ip_skipper {
            middlewares.push(Arc::new(WithFakeIp {
                skipper: Arc::clone(skipper),
                fake_pool: mapper.fake_ip_pool.clone(),
                fake_pool6: mapper.fake_ip_pool6.clone(),
                fake_ip_ttl: mapper.fake_ip_ttl,
            }));
        } else {
            warnln!("[DNS] fake-ip mode without a fake ip skipper; serving fake ips is disabled");
        }
    }

    if mapper.mode != DNSMode::DNS_NORMAL {
        middlewares.push(Arc::new(WithMapping { mapping: mapper.mapping.clone() }));
    }

    compose(&middlewares, Arc::new(WithResolverHandler { resolver, ipv6: mapper.ipv6 }))
}
