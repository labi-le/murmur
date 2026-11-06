//! Allocation and elapsed-time census of the real UDP dispatch entry point.
//!
//! Each case calls `handle_udp_conn` itself with a pre-built `PacketAdapterImpl`: established hits
//! come from a NAT entry the case installs and a `PacketSender` stub, misses use a key that is not
//! in the table so the real `get_or_create`/maker path runs. One adapter per measured call is built
//! outside the window; the miss case drains the failed dial task (`update_proxies` leaves no proxy
//! to resolve) outside its per-call window, so a miss figure is the dispatch plus its first-packet
//! ownership, not the dial.
//!
//! Sniffing on installs a QUIC dispatcher over the destination port; sniffing off clears the flag.
//! For hits the dispatcher is never consulted (the maker is the only caller), which is the property
//! under test. For misses it runs the real `Dispatcher::udp_sniff` branch.
//!
//! Numbers are `dhat` blocks and wall-clock nanoseconds per dispatch; no throughput claim is made.
//! The harness is revision-comparable: run it on a baseline checkout after applying the one-line
//! `pub` to `handle_udp_conn` (the function is exposed for measurement in the candidate commit).
//! `udp_hit_path.rs` remains the modeled subset and says so in its own header.
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

use std::collections::HashMap;
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;

use murmur_common::utils::range::new_range;
use murmur_common::utils::ranges::IntRanges;
use murmur_component_sniffer::base_sniffer::SnifferConfig;
use murmur_component_sniffer::dispatcher::{new_dispatcher, Config as DispatcherConfig};
use murmur_constant::adapters::{
    new_packet_adapter, PacketAdapter, PacketAdapterImpl, PacketConn, PacketSender, UDPPacket, WriteBack,
    WriteBackProxy,
};
use murmur_constant::metadata::{Metadata, NetWork, Type};
use murmur_constant::sniffer::sniffer::Type as SnifferType;
use murmur_log::{set_level, LogLevel};
use murmur_tunnel::tunnel::{
    begin_config_apply, handle_udp_conn, nat_table, on_suspend, set_sniffing, update_proxies, update_sniffer,
};

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

const HIT_ITERATIONS: usize = 2_000;
const MISS_ITERATIONS: usize = 1_000;
const DST_PORT: u16 = 443;

struct BenchPacket {
    key: String,
    data: Vec<u8>,
    local: SocketAddr,
}

#[async_trait]
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

    fn nat_key(&self) -> String {
        self.key.clone()
    }
}

/// The sender a case installs for its established key. `send` is the per-datagram handoff; it drops
/// the packet as a closed real sender would.
struct HitSender;

#[async_trait]
impl PacketSender for HitSender {
    async fn send(&self, packet: Arc<dyn PacketAdapter>) {
        black_box(packet.data().len());
    }

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

fn metadata() -> Metadata {
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
        dst_port: DST_PORT,
        in_ip: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5))),
        in_port: 7890,
        in_name: "tun-in".to_owned(),
        in_user: "bench".to_owned(),
        rematch_name: "rematch".to_owned(),
        // Left empty: a populated host would send `pre_handle_metadata` through the hosts table,
        // whose await would let a spawned miss task run inside the measured window.
        host: String::new(),
        dns_mode: murmur_constant::dns::DNSMode::DNS_NORMAL,
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

fn packet(key: String) -> BenchPacket {
    BenchPacket { key, data: vec![0x2a; 64], local: SocketAddr::from((Ipv4Addr::new(198, 51, 100, 7), 53_000)) }
}

fn adapters(keys: impl IntoIterator<Item = String>) -> Vec<PacketAdapterImpl> {
    keys.into_iter().map(|key| new_packet_adapter(Arc::new(packet(key)), metadata())).collect()
}

fn hit_adapters(key: &str, count: usize) -> Vec<PacketAdapterImpl> {
    adapters(std::iter::repeat_n(key.to_owned(), count))
}

fn miss_adapters(tag: &str, count: usize) -> Vec<PacketAdapterImpl> {
    adapters((0..count).map(|index| format!("{tag}-{index}")))
}

fn configure_sniffing(on: bool) {
    if !on {
        set_sniffing(false);
        return;
    }
    let sniffers = HashMap::from([(
        SnifferType::QUIC,
        SnifferConfig { override_dest: false, ports: IntRanges::from(vec![new_range(DST_PORT, DST_PORT)]) },
    )]);
    let config = DispatcherConfig {
        enable: true,
        sniffers,
        force_domain: Vec::new(),
        skip_src_address: Vec::new(),
        skip_dst_address: Vec::new(),
        skip_domain: Vec::new(),
        force_dns_mapping: false,
        parse_pure_ip: true,
    };
    let dispatcher = new_dispatcher(&config).expect("the QUIC sniffer config builds");
    update_sniffer(Arc::new(dispatcher));
    set_sniffing(true);
}

/// Gives the spawned dial task its turn. `update_proxies` leaves no proxy, so the dial returns
/// without I/O; the yields and the short sleep are outside every measured window.
async fn drain_failed_dial() {
    for _ in 0..32 {
        tokio::task::yield_now().await;
    }
    tokio::time::sleep(Duration::from_millis(1)).await;
}

struct Measured {
    blocks: f64,
    nanos: f64,
}

async fn measure_hit(key: &str, sniff: bool, iterations: usize) -> Measured {
    configure_sniffing(sniff);
    let (sender, loaded) = nat_table().get_or_create(key, Box::new(|| Arc::new(HitSender)));
    assert!(!loaded, "the hit fixture installs the key itself");
    black_box(sender);

    let mut adapters = hit_adapters(key, iterations + 2);
    let warm = adapters.pop().expect("setup builds one warm-up adapter");
    handle_udp_conn(warm).await;

    let mut blocks = 0u64;
    let mut nanos = 0u128;
    for _ in 0..iterations {
        let adapter = adapters.pop().expect("setup builds one adapter per iteration");
        let before = dhat::HeapStats::get();
        let start = Instant::now();
        handle_udp_conn(adapter).await;
        nanos += start.elapsed().as_nanos();
        let after = dhat::HeapStats::get();
        blocks += after.total_blocks - before.total_blocks;
    }

    nat_table().delete(key);
    Measured { blocks: blocks as f64 / iterations as f64, nanos: nanos as f64 / iterations as f64 }
}

async fn measure_miss(tag: &str, sniff: bool, iterations: usize) -> Measured {
    configure_sniffing(sniff);
    let mut adapters = miss_adapters(tag, iterations + 2);
    let warm = adapters.pop().expect("setup builds one warm-up adapter");
    handle_udp_conn(warm).await;
    drain_failed_dial().await;

    let mut blocks = 0u64;
    let mut nanos = 0u128;
    for _ in 0..iterations {
        let adapter = adapters.pop().expect("setup builds one adapter per iteration");
        let before = dhat::HeapStats::get();
        let start = Instant::now();
        handle_udp_conn(adapter).await;
        nanos += start.elapsed().as_nanos();
        let after = dhat::HeapStats::get();
        blocks += after.total_blocks - before.total_blocks;
        drain_failed_dial().await;
    }

    Measured { blocks: blocks as f64 / iterations as f64, nanos: nanos as f64 / iterations as f64 }
}

fn main() -> ExitCode {
    if std::env::args().skip(1).any(|arg| arg == "--list") {
        println!("hit_sniff_off\nhit_sniff_on\nmiss_sniff_off\nmiss_sniff_on");
        return ExitCode::SUCCESS;
    }

    set_level(LogLevel::ERROR);
    let _profiler = dhat::Profiler::builder().testing().trim_backtraces(Some(0)).build();
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("the bench runtime builds");

    runtime.block_on(async {
        begin_config_apply()
            .expect("the benchmark owns configuration application")
            .finish()
            .expect("no shutdown races");
        // No DIRECT proxy, no rules: the miss dial fails without I/O, which keeps the drain bounded.
        update_proxies(HashMap::new(), HashMap::new());

        let cases: [(&str, Measured); 4] = [
            ("hit_sniff_off", measure_hit("bench-hit-off", false, HIT_ITERATIONS).await),
            ("hit_sniff_on", measure_hit("bench-hit-on", true, HIT_ITERATIONS).await),
            ("miss_sniff_off", measure_miss("bench-miss-off", false, MISS_ITERATIONS).await),
            ("miss_sniff_on", measure_miss("bench-miss-on", true, MISS_ITERATIONS).await),
        ];

        println!("udp_dispatch: real handle_udp_conn, per dispatch");
        println!("{:<20} {:>11} {:>12}", "case", "blocks/op", "ns/op");
        for (name, result) in cases {
            println!("{name:<20} {:>11.3} {:>12.1}", result.blocks, result.nanos);
        }
        on_suspend();
    });

    ExitCode::SUCCESS
}
