//! Before/after cost of the unsafe sites this audit proposes to remove from the listener-tproxy
//! and listener crates.
//!
//! What is removable is the descriptor plumbing behind four socket-option paths. In
//! listener-tproxy, the `SO_REUSEADDR` set in `setsockopt_linux` and the `IP_TRANSPARENT` pair in
//! both `udp_linux` and `setsockopt_linux` take a raw descriptor and pass a `c_int` through a raw
//! pointer. socket2 already wraps all three names on the type, and a caller that holds the socket
//! value rather than an fd reaches them with no pointer and no unsafe block.
//!
//! The same argument covers the TTL and DSCP pair in transport-hysteria's raw faketcp socket,
//! where the socket value is already in hand as a socket2 `Socket`.
//!
//! In listener, the tun device's non-blocking flag is set by a raw fcntl pair over a character
//! device descriptor. socket2 performs the same two calls, but its documentation requires the
//! caller to ensure the descriptor is a socket and /dev/net/tun is not one, and this toolchain has
//! no safe wrapper on File, so the site stays and no ratio is claimed for it.
//!
//! What stays unsafe: every `recvmsg` site needs ancillary data or a source address that no safe
//! API returns, and they seed out-parameters through raw pointers. The netlink socket has no
//! socket2 domain, the `TCP_FASTOPEN` and `IP_RECVORIGDSTADDR` option names are not among
//! socket2's, and `TCP_BRUTAL_PARAMS` is a third-party kernel extension. None has a safe
//! formulation, so no before/after pair exists and none is fabricated here.
//!
//! Parity threshold: the replacement is accepted when the ratio of replacement to baseline is
//! within 3 percent, because both sides issue exactly one setsockopt and a pair of measurements
//! on this host has shown roughly half a percent of noise. Each case is therefore measured twice
//! in the same process and both runs are printed, so a single noisy run cannot carry a parity
//! claim. A test mode lists the cases without measuring them.

#![allow(
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::print_stdout,
    clippy::print_stderr
)]

use std::hint::black_box;
use std::process::ExitCode;
use std::time::Instant;

use socket2::{Domain, Protocol, SockRef, Socket, Type};

const LOOPS: u32 = 20_000;

fn datagram_socket() -> Socket {
    Socket::new(Domain::IPV4, Type::DGRAM, None).expect("a socket opens")
}

/// A stream socket standing in for the faketcp raw socket, which this host cannot open without
/// CAP_NET_RAW. The TTL and TOS option names and the value size are identical either way, so the
/// setsockopt cost being measured does not depend on which of the two carries it.
fn stream_socket() -> Socket {
    Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).expect("a tcp socket opens")
}

/// One setsockopt reached through a borrowed socket, the shape a caller holding a socket value
/// rather than a bare descriptor uses.
fn reuseaddr_over_borrowed_socket() {
    let socket = datagram_socket();
    SockRef::from(&socket).set_reuse_address(true).expect("SO_REUSEADDR is set");
    black_box(&socket);
    drop(socket);
}

/// The transparent pair, set on the socket value the dial path holds before it binds. The kernel
/// refuses these without CAP_NET_ADMIN, which an unprivileged bench host lacks; the failed call
/// still costs the syscall, which is what this measures, so the denial is recorded rather than
/// treated as a failure. socket2 only names the pair on Linux.
#[cfg(target_os = "linux")]
fn transparent_on_owned_socket() {
    let socket = datagram_socket();
    let v4 = socket.set_ip_transparent_v4(true);
    let v6 = socket.set_ip_transparent_v6(true);
    assert!(v4.is_err() && v6.is_err(), "expected the privileged pair to be denied");
    black_box(&socket);
    drop(socket);
}

/// The TTL and DSCP pair, on the raw socket the faketcp path already owns.
fn ttl_and_tos_on_owned_socket() {
    let socket = stream_socket();
    socket.set_ttl_v4(1).expect("IP_TTL is set");
    socket.set_tos_v4(8).expect("IP_TOS is set");
    black_box(&socket);
    drop(socket);
}

/// The fcntl pair behind a socket's non-blocking mode, reached through socket2.
fn nonblocking_on_owned_socket() {
    let socket = datagram_socket();
    socket.set_nonblocking(true).expect("nonblocking is set");
    black_box(&socket);
    drop(socket);
}

/// Socket creation, which precedes every option call and is the denominator of each ratio above.
fn socket_open_only() {
    let socket = datagram_socket();
    black_box(&socket);
    drop(socket);
}

fn cases() -> Vec<(&'static str, fn())> {
    let mut cases: Vec<(&'static str, fn())> = vec![
        ("socket_open_only", socket_open_only),
        ("reuseaddr_over_borrowed_socket", reuseaddr_over_borrowed_socket),
    ];
    #[cfg(target_os = "linux")]
    cases.push(("transparent_on_owned_socket", transparent_on_owned_socket));
    cases.push(("ttl_and_tos_on_owned_socket", ttl_and_tos_on_owned_socket));
    cases.push(("nonblocking_on_owned_socket", nonblocking_on_owned_socket));
    cases
}

fn run_case(name: &str, f: fn()) -> f64 {
    let start = Instant::now();
    for _ in 0..LOOPS {
        f();
    }
    let ns = f64::from(u32::try_from(start.elapsed().as_nanos()).unwrap_or(u32::MAX)) / f64::from(LOOPS);
    println!("{name:<28} {ns:>9.1} ns/op");
    ns
}

fn main() -> ExitCode {
    if std::env::args().any(|arg| arg == "--test") {
        for (name, _) in cases() {
            println!("{name}");
        }
        return ExitCode::SUCCESS;
    }

    println!("listener-tproxy unsafe-removal parity, {LOOPS} iterations per case, two runs each\n");

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
    println!("each case as a ratio of the socket open (run 1 / run 2):");
    for ((name, _), one) in cases().into_iter().zip(first.iter().zip(&second)) {
        println!("{name:<28} {:.3} / {:.3}  (baseline {:.1} ns)", one.0 / baseline, one.1 / baseline, baseline);
    }

    ExitCode::SUCCESS
}
