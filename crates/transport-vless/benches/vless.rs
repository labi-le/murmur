//! In-memory microbenchmarks that drive the real VLESS framing, Vision padding and AEAD code over a memory conn; no TCP/TLS/REALITY handshake is timed and none of this is a network claim.
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
use std::sync::Arc;

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use parking_lot::Mutex;
use tokio::io::AsyncWriteExt;

use murmur_common_net::deadline::pipe_sing::{pipe, PipeConn};
use murmur_common_net::io::{ExtendedStream, OldConnAsStream};
use murmur_transport_vless::encryption::common::{encode_header, AEAD};
use murmur_transport_vless::vision::conn::Conn as VisionConn;
use murmur_transport_vless::vision::vision::TlsConnCheck;
use murmur_transport_vless::vless::{new_client, DstAddr, ATYP_DOMAIN_NAME, ATYP_IPV4, ATYP_IPV6};

#[path = "support/fixture.rs"]
mod fixture;

use fixture::{
    assert_vision_wire, drain_exact, one_first_write, read_payload, runtime, vision_decode_once, vision_encode_once,
    vision_new_conn, vless_header_len, MemoryStream, UUID_STR,
};

fn bench_vless_request_framing(c: &mut Criterion) {
    let rt = runtime();
    let client = new_client(UUID_STR, None).expect("vless client");
    let payload: &[u8] = b"hi";

    let ipv4 = DstAddr { udp: false, addr_type: ATYP_IPV4, addr: vec![192, 0, 2, 1], port: 443, mux: false };
    let mut domain_addr = vec![u8::try_from(b"example.com".len()).expect("domain fits a byte")];
    domain_addr.extend_from_slice(b"example.com");
    let domain = DstAddr { udp: false, addr_type: ATYP_DOMAIN_NAME, addr: domain_addr, port: 80, mux: false };
    let ipv6_addr = "2001:db8::1".parse::<std::net::Ipv6Addr>().expect("ipv6").octets().to_vec();
    let ipv6 = DstAddr { udp: false, addr_type: ATYP_IPV6, addr: ipv6_addr, port: 8443, mux: false };
    let udp = DstAddr { udp: true, addr_type: ATYP_IPV4, addr: vec![192, 0, 2, 1], port: 443, mux: false };
    let mux = DstAddr { udp: false, addr_type: ATYP_IPV4, addr: Vec::new(), port: 0, mux: true };

    let cases: [(&str, DstAddr, &str); 5] = [
        ("ipv4", ipv4, "0011111111111111111111111111111111000101bb01c00002016869"),
        ("domain", domain, "001111111111111111111111111111111100010050020b6578616d706c652e636f6d6869"),
        ("ipv6", ipv6, "0011111111111111111111111111111111000120fb0320010db80000000000000000000000016869"),
        ("udp", udp, "0011111111111111111111111111111111000201bb01c00002016869"),
        ("mux", mux, "001111111111111111111111111111111100036869"),
    ];

    let mut group = c.benchmark_group("vless_request_framing");
    group.throughput(Throughput::Elements(1));
    for (name, dst, expected_hex) in cases {
        let expected = hex::decode(expected_hex).expect("pinned wire vector");
        let frame_len = expected.len();
        assert_eq!(
            one_first_write(&rt, &client, &dst, payload, frame_len),
            expected,
            "{name}: first write diverges from the VLESS request wire format"
        );

        group.bench_function(name, |b| {
            b.iter_batched(
                || -> (Box<dyn ExtendedStream>, PipeConn, Vec<u8>) {
                    let (inner, peer) = pipe();
                    let conn = client
                        .stream_conn(Box::new(OldConnAsStream(inner)), TlsConnCheck::Unsupported, None, None, &dst)
                        .expect("vless stream conn");
                    (conn, peer, vec![0u8; frame_len])
                },
                |(mut conn, mut peer, mut frame): (Box<dyn ExtendedStream>, PipeConn, Vec<u8>)| {
                    rt.block_on(async {
                        let (write, _) =
                            tokio::join!(conn.write_all(black_box(payload)), drain_exact(&mut peer, &mut frame));
                        write.expect("vless first write");
                    });
                },
                BatchSize::LargeInput,
            );
        });
    }
    group.finish();
}

fn bench_vless_established_write(c: &mut Criterion) {
    let rt = runtime();
    let client = new_client(UUID_STR, None).expect("vless client");
    let dst = DstAddr { udp: false, addr_type: ATYP_IPV4, addr: vec![192, 0, 2, 1], port: 443, mux: false };
    let header_len = vless_header_len(&dst);

    let mut group = c.benchmark_group("vless_established_write");
    for size in [1024usize, 16384] {
        let payload = vec![0x41u8; size];
        let handshake_len = header_len + size;
        group.throughput(Throughput::Bytes(u64::try_from(size).expect("size fits u64")));
        group.bench_function(BenchmarkId::from_parameter(size), |b| {
            b.iter_batched(
                || -> (Box<dyn ExtendedStream>, PipeConn, Vec<u8>) {
                    let (inner, mut peer) = pipe();
                    let mut conn = client
                        .stream_conn(Box::new(OldConnAsStream(inner)), TlsConnCheck::Unsupported, None, None, &dst)
                        .expect("vless stream conn");
                    let mut first = vec![0u8; handshake_len];
                    rt.block_on(async {
                        let (write, _) = tokio::join!(conn.write_all(&payload), drain_exact(&mut peer, &mut first));
                        write.expect("vless request write");
                    });
                    (conn, peer, vec![0u8; size])
                },
                |(mut conn, mut peer, mut frame): (Box<dyn ExtendedStream>, PipeConn, Vec<u8>)| {
                    rt.block_on(async {
                        let (write, _) =
                            tokio::join!(conn.write_all(black_box(&payload)), drain_exact(&mut peer, &mut frame));
                        write.expect("established write");
                    });
                },
                BatchSize::LargeInput,
            );
        });
    }
    group.finish();
}

fn bench_vision_encode(c: &mut Criterion) {
    let rt = runtime();
    let mut group = c.benchmark_group("vision_padding_encode");
    for size in [64usize, 1024, 16384] {
        let payload = vec![0x41u8; size];
        let frame = vision_encode_once(&rt, &payload);
        assert_vision_wire(&frame, size);

        group.throughput(Throughput::Bytes(u64::try_from(size).expect("size fits u64")));
        group.bench_function(BenchmarkId::from_parameter(size), |b| {
            b.iter_batched(
                || -> VisionConn { vision_new_conn(MemoryStream::sink()) },
                |mut conn: VisionConn| {
                    rt.block_on(conn.write_all(black_box(&payload))).expect("vision write");
                },
                BatchSize::LargeInput,
            );
        });
    }
    group.finish();
}

fn bench_vision_decode(c: &mut Criterion) {
    let rt = runtime();
    let mut group = c.benchmark_group("vision_padding_decode");
    for size in [64usize, 1024, 16384] {
        let payload = vec![0x41u8; size];
        let frame = Arc::new(Mutex::new(vision_encode_once(&rt, &payload)));
        let encoded = frame.lock().clone();
        assert_eq!(vision_decode_once(&rt, encoded, size), payload, "vision decode roundtrip");

        group.throughput(Throughput::Bytes(u64::try_from(size).expect("size fits u64")));
        group.bench_function(BenchmarkId::from_parameter(size), |b| {
            b.iter_batched(
                || -> (VisionConn, Vec<u8>) {
                    let conn = vision_new_conn(MemoryStream::shared_reader(Arc::clone(&frame)));
                    (conn, vec![0u8; size])
                },
                |(mut conn, mut out): (VisionConn, Vec<u8>)| {
                    rt.block_on(read_payload(&mut conn, &mut out));
                    black_box(out);
                },
                BatchSize::LargeInput,
            );
        });
    }
    group.finish();
}

fn bench_vision_roundtrip(c: &mut Criterion) {
    let rt = runtime();
    let mut group = c.benchmark_group("vision_padding_roundtrip");
    for size in [64usize, 1024, 16384] {
        let payload = vec![0x41u8; size];
        {
            let (writer_stream, shared) = MemoryStream::capture();
            let mut writer = vision_new_conn(writer_stream);
            let mut reader = vision_new_conn(MemoryStream::shared_reader(shared));
            let mut out = vec![0u8; size];
            rt.block_on(async {
                writer.write_all(&payload).await.expect("vision encode");
                read_payload(&mut reader, &mut out).await;
            });
            assert_eq!(out, payload, "vision encode/decode roundtrip");
        }

        group.throughput(Throughput::Bytes(u64::try_from(size).expect("size fits u64")));
        group.bench_function(BenchmarkId::from_parameter(size), |b| {
            b.iter_batched(
                || -> (VisionConn, VisionConn, Vec<u8>) {
                    let (writer_stream, shared) = MemoryStream::capture();
                    let writer = vision_new_conn(writer_stream);
                    let reader = vision_new_conn(MemoryStream::shared_reader(shared));
                    (writer, reader, vec![0u8; size])
                },
                |(mut writer, mut reader, mut out): (VisionConn, VisionConn, Vec<u8>)| {
                    rt.block_on(async {
                        writer.write_all(black_box(&payload)).await.expect("vision encode");
                        read_payload(&mut reader, &mut out).await;
                    });
                    black_box(out);
                },
                BatchSize::LargeInput,
            );
        });
    }
    group.finish();
}

fn bench_aead(c: &mut Criterion) {
    const CONTEXT: [u8; 32] = [0x5a; 32];
    const KEY: [u8; 32] = [0x3c; 32];
    const FIXED_NONCE: [u8; 12] = [0x2a; 12];

    {
        let mut group = c.benchmark_group("aead_seal");
        for (cipher, use_aes) in [("aes256gcm", true), ("chacha20poly1305", false)] {
            for size in [1024usize, 16384] {
                let payload = vec![0x41u8; size];
                let mut aad = [0u8; 5];
                encode_header(&mut aad, size);
                let mut sealer = AEAD::new(&CONTEXT, &KEY, use_aes);
                let mut sealed = vec![0u8; size + 16];
                {
                    let mut opener = AEAD::new(&CONTEXT, &KEY, use_aes);
                    sealer.seal(&mut sealed, None, &payload, &aad).expect("seal");
                    opener.open_in_place(&mut sealed, None, size + 16, &aad).expect("open");
                    assert_eq!(&sealed[..size], payload.as_slice(), "aead seal roundtrip");
                }
                group.throughput(Throughput::Bytes(u64::try_from(size).expect("size fits u64")));
                group.bench_function(BenchmarkId::new(cipher, size), |b| {
                    b.iter(|| {
                        sealer.seal(black_box(&mut sealed), None, black_box(payload.as_slice()), &aad).expect("seal");
                    });
                });
            }
        }
        group.finish();
    }

    {
        let mut group = c.benchmark_group("aead_open");
        for (cipher, use_aes) in [("aes256gcm", true), ("chacha20poly1305", false)] {
            for size in [1024usize, 16384] {
                let payload = vec![0x41u8; size];
                let mut aad = [0u8; 5];
                encode_header(&mut aad, size);
                let mut ciphertext = vec![0u8; size + 16];
                AEAD::new(&CONTEXT, &KEY, use_aes)
                    .seal(&mut ciphertext, Some(&FIXED_NONCE), &payload, &aad)
                    .expect("seal fixture");
                let mut opened = vec![0u8; size];
                let mut opener = AEAD::new(&CONTEXT, &KEY, use_aes);
                opener.open_into(&mut opened, Some(&FIXED_NONCE), &ciphertext, &aad).expect("open");
                assert_eq!(opened, payload, "aead open roundtrip");
                group.throughput(Throughput::Bytes(u64::try_from(size).expect("size fits u64")));
                group.bench_function(BenchmarkId::new(cipher, size), |b| {
                    b.iter(|| {
                        opener
                            .open_into(
                                black_box(&mut opened),
                                Some(&FIXED_NONCE),
                                black_box(ciphertext.as_slice()),
                                &aad,
                            )
                            .expect("open");
                    });
                });
            }
        }
        group.finish();
    }

    {
        let mut group = c.benchmark_group("aead_roundtrip");
        for (cipher, use_aes) in [("aes256gcm", true), ("chacha20poly1305", false)] {
            for size in [1024usize, 16384] {
                let payload = vec![0x41u8; size];
                let mut aad = [0u8; 5];
                encode_header(&mut aad, size);
                let mut sealer = AEAD::new(&CONTEXT, &KEY, use_aes);
                let mut opener = AEAD::new(&CONTEXT, &KEY, use_aes);
                let mut buf = vec![0u8; size + 16];
                {
                    sealer.seal(&mut buf, None, &payload, &aad).expect("seal");
                    opener.open_in_place(&mut buf, None, size + 16, &aad).expect("open");
                    assert_eq!(&buf[..size], payload.as_slice(), "aead roundtrip");
                }
                group.throughput(Throughput::Bytes(u64::try_from(size).expect("size fits u64")));
                group.bench_function(BenchmarkId::new(cipher, size), |b| {
                    b.iter(|| {
                        sealer.seal(black_box(&mut buf), None, black_box(payload.as_slice()), &aad).expect("seal");
                        opener.open_in_place(black_box(&mut buf), None, size + 16, &aad).expect("open");
                    });
                });
            }
        }
        group.finish();
    }
}

criterion_group!(
    benches,
    bench_vless_request_framing,
    bench_vless_established_write,
    bench_vision_encode,
    bench_vision_decode,
    bench_vision_roundtrip,
    bench_aead
);
criterion_main!(benches);
