//! Heap allocation census for the established-flow dispatch in the UDP connection loop.
//!
//! Two shapes of the work `handle_udp_conn` does on every datagram *before* it hands the packet to
//! the sender are measured against a NAT table that already holds the key:
//!
//! - `established_hit_before` reproduces the call sequence that ran before the borrowed-key
//!   lookup: `PacketAdapter::key`, the `Metadata` clone inside the cell, the boxed maker, the
//!   packet `Arc`, and the `key.to_owned` inside `get_or_create`.
//! - `established_hit_after` is the current fast path: `PacketAdapterImpl::key_ref`,
//!   `NatTable::get`, and the packet `Arc` that `sender.send` needs.
//!
//! Counts come from `dhat` as the global allocator, deltaed across the measured loop; setup,
//! including building one `PacketAdapterImpl` per iteration, sits outside the window. This is a
//! model of the pre-send dispatch, not the whole function: `handle_udp_conn` lives in a lib target
//! and is private, and the `send`/dial arms belong to integration tests. The `metadata_clone` case
//! is the calibration: `crates/constant/src/metadata.rs` has twelve heap-backed `String` fields and
//! two `Option<Vec<String>>` fields, so with every string and both vectors populated a clone must
//! report eighteen blocks (twelve strings, two vectors, four vector elements). `alloc_census` uses
//! its own fixture, which leaves three strings empty and reports fourteen.
//!
//! The miss path is deliberately not measured here: it still builds the metadata cell and the
//! maker, and `udp_path.rs` covers the clone it performs.
//!
//! A benchmark is allowed to panic: it is a measurement harness, not a runtime path, and a panic
//! means "this number is not trustworthy", which is the correct outcome here.
#![allow(
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
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::ExitCode;
use std::sync::Arc;

use parking_lot::Mutex;

use murmur_component_nat as nat;
use murmur_constant::adapters::{
    new_packet_adapter, NatTable, PacketAdapter, PacketAdapterImpl, PacketConn, PacketSender, UDPPacket, WriteBack,
    WriteBackProxy,
};
use murmur_constant::dns::DNSMode;
use murmur_constant::metadata::{Metadata, NetWork, Type};

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

/// Iterations per case. Large enough that the per-datagram shape dominates the loop, small enough
/// that the pre-built adapter vector stays modest.
const ITERATIONS: usize = 2_000;
/// Twelve heap-backed `String` fields, all non-empty in `populated_metadata`.
const METADATA_STRINGS: u64 = 12;
/// Two `Option<Vec<String>>` fields: one vector allocation each plus their four strings.
const METADATA_GEO_BLOCKS: u64 = 6;
/// What `Metadata::clone` allocates for the fixture below.
const METADATA_CLONE_BLOCKS: u64 = METADATA_STRINGS + METADATA_GEO_BLOCKS;
/// `key` + cell `Arc` + clone + packet `Arc` + maker box + `key.to_owned`.
const HIT_BEFORE_BLOCKS: u64 = METADATA_CLONE_BLOCKS + 5;
/// The packet `Arc` is the only allocation the hit still needs.
const HIT_AFTER_BLOCKS: u64 = 1;

struct Case {
    name: &'static str,
    expected: u64,
    setup: Box<dyn Fn() -> Box<dyn FnMut() -> u64>>,
}

fn populated_metadata() -> Metadata {
    Metadata {
        network: NetWork::UDP,
        type_: Type::TUN,
        src_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7))),
        dst_ip: Some(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))),
        src_geo_ip: Some(vec!["private".to_owned(), "vpn".to_owned()]),
        dst_geo_ip: Some(vec!["US".to_owned(), "cloudflare".to_owned()]),
        src_ipasn: "AS64500".to_owned(),
        dst_ipasn: "AS13335".to_owned(),
        src_port: 53_000,
        dst_port: 443,
        in_ip: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5))),
        in_port: 7890,
        in_name: "tun-in".to_owned(),
        in_user: "bench".to_owned(),
        rematch_name: "rematch".to_owned(),
        host: "example.com".to_owned(),
        dns_mode: DNSMode::DNS_NORMAL,
        uid: 1000,
        process: "murmur".to_owned(),
        process_path: "/usr/bin/murmur".to_owned(),
        special_proxy: "DIRECT".to_owned(),
        special_rules: "GEOSITE,cn".to_owned(),
        remote_dst: "remote.example.net:443".to_owned(),
        dscp: 0,
        raw_src_addr: None,
        raw_dst_addr: None,
        sniff_host: "target.example.com".to_owned(),
    }
}

const LOCAL: &str = "198.51.100.7:53000";

struct BenchPacket {
    local: SocketAddr,
    data: Vec<u8>,
}

#[async_trait::async_trait]
impl WriteBack for BenchPacket {
    async fn write_back(&self, _b: &[u8], _addr: Option<SocketAddr>) -> anyhow::Result<usize> {
        Ok(self.data.len())
    }
}

impl UDPPacket for BenchPacket {
    fn data(&self) -> &[u8] {
        &self.data
    }

    fn drop_(&self) {}

    fn local_addr(&self) -> SocketAddr {
        self.local
    }
}

struct BenchSender;

#[async_trait::async_trait]
impl PacketSender for BenchSender {
    async fn send(&self, _packet: Arc<dyn PacketAdapter>) {}

    async fn process(&self, _conn: Arc<dyn PacketConn>, _proxy: Arc<dyn WriteBackProxy>) {}

    fn close(&self) {}

    async fn do_sniff(&self, _metadata: &mut Metadata) -> anyhow::Result<()> {
        Ok(())
    }

    fn add_mapping(&self, _origin_metadata: &Metadata, _metadata: &Metadata) {}

    fn restore_read_from(&self, addr: IpAddr) -> IpAddr {
        addr
    }
}

/// One adapter per measured call: the real loop receives an owned `PacketAdapterImpl`, and moving
/// it into the packet `Arc` consumes it.
fn adapters(count: usize) -> Vec<PacketAdapterImpl> {
    let local: SocketAddr = LOCAL.parse().expect("valid bench address");
    let packet: Arc<dyn UDPPacket> = Arc::new(BenchPacket { local, data: vec![0x2a; 64] });
    (0..count).map(|_| new_packet_adapter(Arc::clone(&packet), populated_metadata())).collect()
}

fn metadata_clone_setup() -> Box<dyn FnMut() -> u64> {
    let metadata = populated_metadata();
    Box::new(move || {
        let cloned = black_box(metadata.clone());
        black_box(&cloned).host.len() as u64
    })
}

fn hit_before_setup() -> Box<dyn FnMut() -> u64> {
    let local: SocketAddr = LOCAL.parse().expect("valid bench address");
    let key = local.to_string();
    let mut adapters = adapters(ITERATIONS + 1);
    let table: Arc<dyn NatTable> = Arc::new(nat::new());
    let (sender, loaded) = table.get_or_create(&key, Box::new(|| Arc::new(BenchSender)));
    assert!(!loaded, "the bench registers the key itself");
    black_box(sender);

    Box::new(move || {
        let adapter = adapters.pop().expect("setup builds one adapter per iteration");
        let key = adapter.key();
        let raw_packet = Arc::clone(&adapter.packet);
        let metadata_cell = Arc::new(Mutex::new(adapter.metadata().clone()));
        let sniff_packet: Arc<dyn PacketAdapter> = Arc::new(adapter);
        let maker: Box<dyn FnOnce() -> Arc<dyn PacketSender> + Send> = {
            let sniff_packet = Arc::clone(&sniff_packet);
            let metadata_cell = Arc::clone(&metadata_cell);
            Box::new(move || {
                let _ = (&sniff_packet, &metadata_cell);
                Arc::new(BenchSender)
            })
        };
        let (sender, loaded) = table.get_or_create(&key, maker);
        black_box((&raw_packet, &sender, loaded));
        sniff_packet.data().len() as u64
    })
}

fn hit_after_setup() -> Box<dyn FnMut() -> u64> {
    let local: SocketAddr = LOCAL.parse().expect("valid bench address");
    let key = local.to_string();
    let mut adapters = adapters(ITERATIONS + 1);
    let table: Arc<dyn NatTable> = Arc::new(nat::new());
    let (sender, loaded) = table.get_or_create(&key, Box::new(|| Arc::new(BenchSender)));
    assert!(!loaded, "the bench registers the key itself");
    black_box(sender);

    Box::new(move || {
        let adapter = adapters.pop().expect("setup builds one adapter per iteration");
        let sender = table.get(adapter.key_ref()).expect("the setup stored the key");
        let packet: Arc<dyn PacketAdapter> = Arc::new(adapter);
        let len = packet.data().len() as u64;
        black_box((&sender, &packet));
        len
    })
}

fn cases() -> Vec<Case> {
    vec![
        Case { name: "metadata_clone", expected: METADATA_CLONE_BLOCKS, setup: Box::new(metadata_clone_setup) },
        Case { name: "established_hit_before", expected: HIT_BEFORE_BLOCKS, setup: Box::new(hit_before_setup) },
        Case { name: "established_hit_after", expected: HIT_AFTER_BLOCKS, setup: Box::new(hit_after_setup) },
    ]
}

fn measure(case: &Case) -> f64 {
    let mut operation = (case.setup)();
    let mut accumulator = operation();
    let before = dhat::HeapStats::get();
    for _ in 0..ITERATIONS {
        accumulator = accumulator.wrapping_add(operation());
    }
    let after = dhat::HeapStats::get();
    black_box(accumulator);
    (after.total_blocks - before.total_blocks) as f64 / ITERATIONS as f64
}

fn main() -> ExitCode {
    let cases = cases();
    if std::env::args().skip(1).any(|arg| arg == "--list") {
        for case in &cases {
            println!("{}", case.name);
        }
        return ExitCode::SUCCESS;
    }

    let _profiler = dhat::Profiler::builder().testing().trim_backtraces(Some(0)).build();

    println!("udp_hit_path: heap allocations per datagram on an established NAT key");
    println!("{:<24} {:>11} {:>9} {:>9}", "case", "blocks/op", "expected", "delta");
    for case in &cases {
        let per_op = measure(case);
        let expected = case.expected as f64;
        println!("{:<24} {per_op:>11.3} {expected:>9} {:>9.3}", case.name, per_op - expected);
    }
    ExitCode::SUCCESS
}
