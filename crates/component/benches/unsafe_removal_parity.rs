//! Cost of each safe replacement candidate for the descriptor open and close in the component
//! crate, measured against the syscalls those sites perform today.
//!
//! What is removable is the descriptor open and close around three ioctl paths: the Linux and
//! Android ioctl opener, the Darwin ioctl opener, and the Android netlink opener. Each pairs a
//! raw socket syscall with an fd guard whose drop runs a raw close. The replacement, the socket2
//! socket constructor already used elsewhere in this crate, performs the same kernel call and
//! closes through its own owned-descriptor drop, so both sites become one safe call and the
//! unsafe count falls without a syscall being added or removed.
//!
//! The current implementations cannot appear here: the workspace denies unsafe code, and a
//! benchmark target inherits that lint. Every figure below is therefore a socket2 formulation,
//! which still bounds what the rewrite costs, because both the baseline syscall and the
//! replacement reach the kernel through the same constructor.
//!
//! The ioctl, sendto and recv calls around those descriptors stay unsafe: they take raw pointers
//! or fill out-parameters that safe Rust cannot express. Neither std nor socket2 wraps them.
//!
//! The two TCP fastopen socket-option sites in the dialer are not among socket2's option names,
//! so they have no safe formulation and no before/after pair exists to measure; they are
//! reported as not removable rather than given a fabricated ratio.
//!
//! Each case is measured twice in the same process and both runs are printed, so a single noisy
//! run cannot carry a parity claim. A test mode lists the cases without measuring them.

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
use std::process::ExitCode;
use std::time::Instant;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

const LOOPS: u64 = 20_000;
const WARMUP: u64 = 2_000;

/// The netlink domain and protocol the Android netlink opener passes to the kernel.
const AF_NETLINK: i32 = 16;
const NETLINK_ROUTE: i32 = 0;

fn cases() -> [(&'static str, fn()); 6] {
    [
        ("socket_open_tcp_stream", socket_open_tcp_stream),
        ("socket_open_dgram", socket_open_dgram),
        ("socket_open_netlink_raw", socket_open_netlink_raw),
        ("socket_close_owned", socket_close_owned),
        ("socket_open_then_close", socket_open_then_close),
        ("socket_bind_listen", socket_bind_listen),
    ]
}

/// The TCP stream open this crate already performs through socket2 everywhere: one socket open
/// with the close-on-exec flag folded into the type argument on Linux.
fn socket_open_tcp_stream() {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).expect("a socket opens");
    black_box(&socket);
    drop(socket);
}

/// The datagram path.
fn socket_open_dgram() {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, None).expect("a socket opens");
    black_box(&socket);
    drop(socket);
}

/// The raw netlink path.
fn socket_open_netlink_raw() {
    let socket =
        Socket::new(Domain::from(AF_NETLINK), Type::RAW, Some(Protocol::from(NETLINK_ROUTE))).expect("a socket opens");
    black_box(&socket);
    drop(socket);
}

/// The guard drop, which closes the descriptor today. One descriptor open plus one close per
/// timed iteration; the close is what the timed region wraps.
fn socket_close_owned() {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, None).expect("a socket opens");
    let start = Instant::now();
    black_box(&socket);
    drop(socket);
    black_box(start.elapsed());
}

/// Open and close together, which is the whole of what the ioctl opener plus its guard costs
/// today and the whole of what the replacement costs.
fn socket_open_then_close() {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, None).expect("a socket opens");
    black_box(&socket);
    drop(socket);
}

/// The bind and listen the listener path already performs per socket, as the scale the open and
/// close sit against.
fn socket_bind_listen() {
    let listener = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).expect("a socket opens");
    listener.bind(&SockAddr::from(std::net::SocketAddr::from(([127, 0, 0, 1], 0)))).expect("a bind succeeds");
    listener.listen(1).expect("a listen succeeds");
    black_box(&listener);
    drop(listener);
}

fn run_case(name: &str, f: fn()) -> f64 {
    for _ in 0..WARMUP {
        f();
    }
    let start = Instant::now();
    for _ in 0..LOOPS {
        f();
    }
    let ns = start.elapsed().as_nanos() as f64 / LOOPS as f64;
    println!("{name:<26} {ns:>9.1} ns/op");
    ns
}

fn main() -> ExitCode {
    if std::env::args().any(|arg| arg == "--test") {
        for (name, _) in cases() {
            println!("{name}");
        }
        return ExitCode::SUCCESS;
    }

    println!("component unsafe-removal parity, {LOOPS} iterations per case, two runs each\n");

    let mut first = Vec::new();
    for (name, f) in cases() {
        println!("run 1");
        first.push(run_case(name, f));
    }
    println!();

    let mut second = Vec::new();
    for ((name, f), before) in cases().into_iter().zip(&first) {
        println!("run 2");
        let after = run_case(name, f);
        let delta = (after - before) / before;
        println!("  change vs run 1 {:+.2}%\n", delta * 100.0);
        second.push(after);
    }

    let baseline = first[0];
    println!("each case as a ratio of the tcp-stream socket open (run 1 / run 2):");
    for ((name, _), one) in cases().into_iter().zip(first.iter().zip(&second)) {
        println!("{name:<26} {:.3} / {:.3}  (baseline {:.1} ns)", one.0 / baseline, one.1 / baseline, baseline);
    }

    ExitCode::SUCCESS
}
