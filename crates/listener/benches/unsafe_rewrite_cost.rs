//! Cost of each safe candidate, measured against the syscall that dominates its path.
//!
//! The current implementations cannot appear here: the workspace denies unsafe code, and a
//! benchmark target inherits that lint. Each ratio below therefore compares safe formulations with
//! one another, which still bounds what a rewrite can cost.
//!
//! The `ifreq` layout mirror and the `sockaddr` literals describe Linux structures, so only the
//! socket baseline runs elsewhere.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::unreachable,
    clippy::todo,
    clippy::unimplemented,
    clippy::pedantic,
    clippy::nursery
)]

use std::hint::black_box;
#[cfg(target_os = "linux")]
use std::mem::{size_of, size_of_val};

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use socket2::{Domain, Socket, Type};

#[cfg(target_os = "linux")]
const IF_NAMESIZE: usize = libc::IF_NAMESIZE;

/// Layout mirror of the kernel interface request structure on Linux: a NUL-padded sixteen-byte name
/// field first, then the fixed-width payload the ioctls read and write.
#[cfg(target_os = "linux")]
#[repr(C)]
struct KernelIfreq {
    ifr_name: [libc::c_char; IF_NAMESIZE],
    ifr_payload: [u8; 24],
}

#[cfg(target_os = "linux")]
fn filled_ifreq() -> KernelIfreq {
    let mut ifr = KernelIfreq { ifr_name: [0; IF_NAMESIZE], ifr_payload: [0; 24] };
    ifr.ifr_name.iter_mut().zip(b"murmur0").for_each(|(dst, &src)| *dst = src.cast_signed());
    ifr
}

#[cfg(target_os = "linux")]
fn name_from_bytes(bytes: &[u8]) -> Result<String, std::str::Utf8Error> {
    let name = bytes.split(|b| *b == 0).next().unwrap_or(&[]);
    std::str::from_utf8(name).map(str::to_owned)
}

/// The proposed name read: mapping the signed chars lifts the field into an owned byte array, so
/// the NUL scan and the UTF-8 check then run over memory Rust already owns.
#[cfg(target_os = "linux")]
fn read_name_map(ifr: &KernelIfreq) -> Result<String, std::str::Utf8Error> {
    let bytes = ifr.ifr_name.map(|c| c.cast_unsigned());
    name_from_bytes(&bytes)
}

/// The same read assembled by copying into a fresh array, the control against the mapping form.
#[cfg(target_os = "linux")]
fn read_name_copy(ifr: &KernelIfreq) -> Result<String, std::str::Utf8Error> {
    let mut bytes = [0u8; IF_NAMESIZE];
    bytes.copy_from_slice(ifr.ifr_name.map(|c| c.cast_unsigned()).as_slice());
    name_from_bytes(&bytes)
}

/// The proposed name write: the length check the callers already perform bounds the zip, so every
/// element assignment lands inside the sixteen-byte name field.
#[cfg(target_os = "linux")]
fn write_name_zip(ifr: &mut KernelIfreq, name: &str) {
    if name.len() >= IF_NAMESIZE {
        return;
    }
    ifr.ifr_name.iter_mut().zip(name.as_bytes()).for_each(|(dst, &src)| *dst = src.cast_signed());
}

/// The same write driven by the source iterator and a NUL pad rather than by the destination
/// field, the control against the zip form.
#[cfg(target_os = "linux")]
fn write_name_padded(ifr: &mut KernelIfreq, name: &str) {
    if name.len() >= IF_NAMESIZE {
        return;
    }
    let padded = name.as_bytes().iter().copied().chain(std::iter::repeat(0)).take(IF_NAMESIZE);
    ifr.ifr_name.iter_mut().zip(padded).for_each(|(dst, src)| *dst = src.cast_signed());
}

#[cfg(target_os = "linux")]
fn sockaddr_in_literal() -> libc::sockaddr_in {
    libc::sockaddr_in { sin_family: 0, sin_port: 0, sin_addr: libc::in_addr { s_addr: 0 }, sin_zero: [0; 8] }
}

#[cfg(target_os = "linux")]
fn sockaddr_in6_literal() -> libc::sockaddr_in6 {
    libc::sockaddr_in6 {
        sin6_family: 0,
        sin6_port: 0,
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr { s6_addr: [0; 16] },
        sin6_scope_id: 0,
    }
}

/// Zeroing the same address struct through a byte view, the control against the struct literal.
#[cfg(target_os = "linux")]
fn sockaddr_in_bytewise(buf: &mut [u8]) {
    buf.fill(0);
}

#[cfg(target_os = "linux")]
fn bench_read_name(c: &mut Criterion) {
    let ifr = filled_ifreq();
    assert_eq!(read_name_map(&ifr).as_deref(), Ok("murmur0"));
    assert_eq!(read_name_copy(&ifr).as_deref(), Ok("murmur0"));
    assert_eq!(read_name_map(&ifr).as_deref(), read_name_copy(&ifr).as_deref());

    let mut group = c.benchmark_group("ifreq_name_read");
    group.throughput(Throughput::Elements(1));
    group.bench_function("array_map", |b| b.iter(|| black_box(read_name_map(black_box(&ifr)))));
    group.bench_function("copy_into_fresh", |b| b.iter(|| black_box(read_name_copy(black_box(&ifr)))));
    group.finish();
}

#[cfg(target_os = "linux")]
fn bench_write_name(c: &mut Criterion) {
    let mut expected = filled_ifreq();
    write_name_zip(&mut expected, "murmur0");
    let mut control = filled_ifreq();
    write_name_padded(&mut control, "murmur0");
    assert_eq!(expected.ifr_name, control.ifr_name);
    assert_eq!(expected.ifr_name[7], 0);

    let mut group = c.benchmark_group("ifreq_name_write");
    group.throughput(Throughput::Elements(1));
    group.bench_function("zip_assign", |b| {
        b.iter(|| {
            let mut ifr = filled_ifreq();
            write_name_zip(black_box(&mut ifr), "murmur0");
            black_box(ifr.ifr_name[0])
        })
    });
    group.bench_function("padded_source", |b| {
        b.iter(|| {
            let mut ifr = filled_ifreq();
            write_name_padded(black_box(&mut ifr), "murmur0");
            black_box(ifr.ifr_name[0])
        })
    });
    group.finish();
}

#[cfg(target_os = "linux")]
fn bench_sockaddr_init(c: &mut Criterion) {
    assert_eq!(size_of::<KernelIfreq>(), IF_NAMESIZE + 24, "layout mirror must match the kernel struct");
    assert_eq!(size_of_val(&sockaddr_in_literal()), size_of::<libc::sockaddr_in>());
    assert_eq!(size_of_val(&sockaddr_in6_literal()), size_of::<libc::sockaddr_in6>());

    let mut group = c.benchmark_group("sockaddr_init");
    group.throughput(Throughput::Elements(1));
    group.bench_function("struct_literal_v4", |b| {
        b.iter(|| black_box(sockaddr_in_literal()).sin_port);
    });
    group.bench_function("struct_literal_v6", |b| {
        b.iter(|| black_box(sockaddr_in6_literal()).sin6_port);
    });
    group.bench_function("bytewise_zero_v4", |b| {
        b.iter(|| {
            let mut buf = [1u8; size_of::<libc::sockaddr_in>()];
            sockaddr_in_bytewise(black_box(buf.as_mut_slice()));
            black_box(buf[2])
        })
    });
    group.finish();
}

/// Socket creation, which precedes the interface ioctls and is the denominator of every ratio
/// above.
fn bench_socket_baseline(c: &mut Criterion) {
    let mut group = c.benchmark_group("socket_baseline");
    group.throughput(Throughput::Elements(1));
    group.bench_function("socket2_create_and_query", |b| {
        b.iter(|| {
            let socket = Socket::new(Domain::IPV4, Type::DGRAM, None).expect("socket(AF_INET, SOCK_DGRAM)");
            black_box(
                socket.local_addr().ok().and_then(|addr| addr.as_socket()).map(|addr| addr.port()).unwrap_or_default(),
            )
        })
    });
    group.finish();
}

#[cfg(target_os = "linux")]
criterion_group!(benches, bench_read_name, bench_write_name, bench_sockaddr_init, bench_socket_baseline);
#[cfg(not(target_os = "linux"))]
criterion_group!(benches, bench_socket_baseline);
criterion_main!(benches);
