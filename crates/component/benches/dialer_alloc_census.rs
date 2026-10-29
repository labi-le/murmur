//! Heap allocation census of the dialer and resolver paths.
//!
//! Every figure is per operation, not per connection or per lookup.
//! Allocation counts come from dhat as the global allocator, deltaed across a warm loop, so state built in setup is excluded.
//!
//! What is measured is the allocation a dial attempt or a resolver lookup performs before any socket is opened: option application, the string and address helpers every attempt runs, the hosts-table search every resolver lookup starts with, and the literal-IP short circuit. What cannot be measured is stated below rather than estimated.
//!
//! The socket work itself is not measured, because it cannot be reached from a bench without a live peer: every connect path in this crate ends in a real connect to a real address. The blocker is a missing listener and a missing peer, not a missing constructor. All of those entry points are already public, so no constructor was added in order to measure them.
//!
//! The resolver leg is likewise unmeasured. A bench can implement the resolver trait, and one does so below, but what that measures is the host's own delegation, hosts miss and literal-IP handling around the call. A real resolver builds and parses DNS messages over a real socket; a stub returns a list it allocated itself. The stub's cost is therefore inside every figure that mentions it, and those figures describe the harness as much as the code. They are labelled as such in the table.
//!
//! The DNS middleware crate installs a resolver, but the resolver the dialer and the rule path actually call lives in this crate under the resolver module, and that is what this bench measures.
//!
//! Neither path builds a connection descriptor, so this table carries no figure.
//!
//! The arithmetic column counts heap-owning fields that a hand reading of the source says must allocate, and it is arithmetic rather than a measurement. It is printed beside the measured figure so that a disagreement is visible rather than merely arguable.//!
//! The two columns can differ for reasons a field count cannot see. An empty owned string allocates nothing, because it points at a static buffer. A list built by a collecting iterator may or may not grow, depending on the size hint the iterator carries. And a field can be moved rather than copied.
//!
//! An earlier audit of this tree reached its number for a connection descriptor copy by counting fields instead of measuring, and it was wrong. The rules-common census is the one that measured. Where this bench has no independent reason to state a hand count, it prints a dash rather than a guess.
#![allow(
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::unreachable,
    clippy::todo,
    clippy::unimplemented,
    clippy::pedantic,
    clippy::nursery
)]

use std::hint::black_box;
use std::net::IpAddr;
use std::process::ExitCode;
use std::sync::Arc;

use hickory_proto::op::Message;
use tokio_util::sync::CancellationToken;

use murmur_component::dialer::bind::{join_host_port, parse_addr_port};
use murmur_component::dialer::dialer::new_dialer;
use murmur_component::dialer::options::{
    is_zero_options, with_interface, with_option, with_prefer_ipv4, with_routing_mark,
};
use murmur_component::resolver::host::{new_hosts, HostValue, Hosts};
use murmur_component::resolver::ip4p::lookup_ip4p;
use murmur_component::resolver::resolver::{
    lookup_ipv4_with_resolver, set_default_hosts, set_disable_ipv6, sortation_addr,
};
use murmur_component::resolver::resolver::{Resolver, ResolverError};
use murmur_component_trie::domain::DomainTrie;

use murmur_common::net_addr::split_host_port;

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

const ITERATIONS: usize = 2_000;

/// One case: `setup` builds everything that must not be counted, `run` is the measured operation.
struct Case {
    name: &'static str,
    /// The hand count over the struct fields, when there is an independent reason to state one.
    arithmetic: Option<u64>,
    /// The note printed under a figure that describes the harness rather than the code.
    note: &'static str,
    setup: Box<dyn Fn() -> Box<dyn FnMut() -> u64>>,
}

fn fixture_hosts() -> Hosts {
    let mut trie = DomainTrie::new();
    let value = HostValue::by_ips(vec![
        "198.51.100.7".parse().expect("valid ipv4"),
        "2001:db8::7".parse().expect("valid ipv6"),
    ])
    .expect("a non-empty ip list builds a host value");
    trie.insert("host.example.com", value).expect("valid domain key");
    new_hosts(trie)
}

fn install_fixture_hosts() {
    set_default_hosts(fixture_hosts());
}

/// A stand-in for a live peer. Its own two list allocations sit inside every figure below that
/// mentions it, which is why those rows are not a DNS measurement.
struct StubResolver;

#[async_trait::async_trait]
impl Resolver for StubResolver {
    async fn lookup_ip(&self, _ctx: &CancellationToken, _host: &str) -> anyhow::Result<Vec<IpAddr>> {
        Ok(vec!["198.51.100.10".parse().expect("valid ipv4")])
    }
    async fn lookup_ipv4(&self, _ctx: &CancellationToken, _host: &str) -> anyhow::Result<Vec<IpAddr>> {
        Ok(vec!["198.51.100.10".parse().expect("valid ipv4")])
    }
    async fn lookup_ipv6(&self, _ctx: &CancellationToken, _host: &str) -> anyhow::Result<Vec<IpAddr>> {
        Ok(vec!["2001:db8::10".parse().expect("valid ipv6")])
    }
    async fn resolve_ech(&self, _ctx: &CancellationToken, _host: &str) -> anyhow::Result<Vec<u8>> {
        Ok(Vec::new())
    }
    async fn exchange_context(&self, _ctx: &CancellationToken, _m: &Message) -> anyhow::Result<Message> {
        Err(ResolverError::IpNotFound.into())
    }
    /// A passed resolver is consulted only when it reports itself invalid, so the stub says yes.
    fn invalid(&self) -> bool {
        true
    }
    fn clear_cache(&self) {}
    fn reset_connection(&self) {}
}

fn current_thread_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread().enable_all().build().expect("a runtime builds")
}

fn ip4p_disabled_setup() -> Box<dyn FnMut() -> u64> {
    Box::new(|| {
        let (ip, port) = lookup_ip4p("198.51.100.7".parse().expect("valid ipv4"), "443");
        u64::from(ip.is_ipv4()) + port.len() as u64
    })
}

fn sortation_setup() -> Box<dyn FnMut() -> u64> {
    let ips = vec![
        "198.51.100.1".parse().expect("valid ipv4"),
        "198.51.100.2".parse().expect("valid ipv4"),
        "2001:db8::1".parse().expect("valid ipv6"),
    ];
    Box::new(move || {
        let (v4, v6) = sortation_addr(&ips);
        (v4.len() + v6.len()) as u64
    })
}

/// The hosts search copies the matched value, which owns one address list and one string.
fn hosts_search_hit_setup() -> Box<dyn FnMut() -> u64> {
    let hosts = fixture_hosts();
    let runtime = current_thread_runtime();
    Box::new(move || match runtime.block_on(hosts.search("host.example.com", false)) {
        None => 0,
        Some((value, is_domain)) => u64::from(is_domain) + value.ips.len() as u64,
    })
}

fn lookup_hosts_hit_setup() -> Box<dyn FnMut() -> u64> {
    install_fixture_hosts();
    let ctx = CancellationToken::new();
    let runtime = current_thread_runtime();
    Box::new(move || match runtime.block_on(lookup_ipv4_with_resolver(&ctx, "host.example.com", None)) {
        Ok(ips) => ips.len() as u64,
        Err(_) => 0,
    })
}

fn lookup_literal_ip_setup() -> Box<dyn FnMut() -> u64> {
    install_fixture_hosts();
    let ctx = CancellationToken::new();
    let runtime = current_thread_runtime();
    Box::new(move || match runtime.block_on(lookup_ipv4_with_resolver(&ctx, "198.51.100.7", None)) {
        Ok(ips) => ips.len() as u64,
        Err(_) => 0,
    })
}

fn lookup_delegates_setup() -> Box<dyn FnMut() -> u64> {
    install_fixture_hosts();
    let resolver: Arc<StubResolver> = Arc::new(StubResolver);
    let ctx = CancellationToken::new();
    let runtime = current_thread_runtime();
    Box::new(move || {
        match runtime.block_on(lookup_ipv4_with_resolver(&ctx, "absent.example.net", Some(resolver.as_ref()))) {
            Ok(ips) => ips.len() as u64,
            Err(_) => 0,
        }
    })
}

fn cases() -> Vec<Case> {
    vec![
        Case {
            name: "dialer_apply_no_options",
            arithmetic: None,
            note: "",
            setup: Box::new(|| {
                let owned: Vec<murmur_component::dialer::options::Option> = Vec::new();
                Box::new(move || u64::from(is_zero_options(&owned)))
            }),
        },
        Case {
            name: "dialer_apply_two_options",
            arithmetic: None,
            note: "",
            setup: Box::new(|| {
                let owned = vec![with_interface("eth0"), with_routing_mark(100)];
                Box::new(move || u64::from(is_zero_options(&owned)))
            }),
        },
        Case {
            name: "dialer_options_clone_into_option",
            arithmetic: None,
            note: "one clone plus one boxed option; not separable from outside the crate",
            setup: Box::new(|| {
                let dialer = new_dialer(vec![with_interface("eth0")]);
                Box::new(move || {
                    let cloned = dialer.opt.clone();
                    u64::from(!is_zero_options(&[with_option(cloned)]))
                })
            }),
        },
        Case {
            name: "dialer_with_option_box",
            arithmetic: None,
            note: "",
            setup: Box::new(|| {
                let dialer = new_dialer(vec![with_prefer_ipv4()]);
                Box::new(move || {
                    let option = with_option(dialer.opt.clone());
                    u64::from(!is_zero_options(&[option]))
                })
            }),
        },
        Case {
            name: "bind_join_host_port_v4",
            arithmetic: None,
            note: "",
            setup: Box::new(|| Box::new(move || join_host_port("198.51.100.7", 443).len() as u64)),
        },
        Case {
            name: "bind_join_host_port_v6",
            arithmetic: None,
            note: "",
            setup: Box::new(|| Box::new(move || join_host_port("2001:db8::7", 443).len() as u64)),
        },
        Case {
            name: "bind_parse_addr_port",
            arithmetic: None,
            note: "",
            setup: Box::new(|| Box::new(move || u64::from(parse_addr_port("198.51.100.7:443").is_some()))),
        },
        Case {
            name: "split_host_port",
            arithmetic: None,
            note: "",
            setup: Box::new(|| {
                Box::new(move || match split_host_port("198.51.100.7:443") {
                    Ok((host, port)) => (host.len() + port.len()) as u64,
                    Err(_) => 0,
                })
            }),
        },
        Case {
            name: "resolver_lookup_ip4p_disabled",
            arithmetic: None,
            note: "",
            setup: Box::new(ip4p_disabled_setup),
        },
        Case {
            name: "resolver_sortation_addr_3",
            arithmetic: None,
            note: "two lists, each grown once",
            setup: Box::new(sortation_setup),
        },
        Case {
            name: "resolver_hosts_search_hit",
            arithmetic: Some(1),
            note: "the copied string is empty, so only the address list allocates",
            setup: Box::new(hosts_search_hit_setup),
        },
        Case {
            name: "resolver_lookup_ipv4_hosts_hit",
            arithmetic: Some(2),
            note: "the copied list from the search, then the filtered list",
            setup: Box::new(lookup_hosts_hit_setup),
        },
        Case {
            name: "resolver_lookup_ipv4_literal_ip",
            arithmetic: Some(1),
            note: "",
            setup: Box::new(lookup_literal_ip_setup),
        },
        Case {
            name: "resolver_lookup_ipv4_takes_invalid_resolver",
            arithmetic: None,
            note: "includes the stub's own allocations; not a DNS measurement",
            setup: Box::new(lookup_delegates_setup),
        },
    ]
}

fn measure(case: &Case, iterations: usize) -> u64 {
    let mut operation = (case.setup)();
    let mut accumulator = operation();
    let before = dhat::HeapStats::get();
    for _ in 0..iterations {
        accumulator = accumulator.wrapping_add(operation());
    }
    let after = dhat::HeapStats::get();
    black_box(accumulator);
    after.total_blocks - before.total_blocks
}

fn main() -> ExitCode {
    set_disable_ipv6(true);
    let cases = cases();
    if std::env::args().skip(1).any(|arg| arg == "--list") {
        for case in &cases {
            println!("{}", case.name);
        }
        return ExitCode::SUCCESS;
    }

    let _profiler = dhat::Profiler::builder().testing().trim_backtraces(Some(0)).build();

    println!("dialer_alloc_census: heap allocations per operation, not per connection");
    println!("{:<42} {:>11} {:>12} {:>9}", "case", "blocks/op", "arithmetic", "delta");
    for case in &cases {
        let allocations = measure(case, ITERATIONS);
        let per_op = allocations as f64 / ITERATIONS as f64;
        match case.arithmetic {
            Some(arithmetic) => {
                println!("{:<42} {per_op:>11.3} {arithmetic:>12} {:>9.3}", case.name, per_op - arithmetic as f64)
            }
            None => println!("{:<42} {per_op:>11.3} {:>12} {:>9}", case.name, "-", "-"),
        }
        if !case.note.is_empty() {
            println!("{:<42} {}", "", case.note);
        }
    }
    println!();
    println!("unmeasured: every connect path, because it needs a live listener and a live peer.");
    println!("unmeasured: the DNS leg, because a bench can only supply a trait stub.");
    ExitCode::SUCCESS
}
