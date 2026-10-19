//! The case registry shared by `metrics_heap` and `metrics_cpu`. Each `setup` builds every fixture
//! the operation needs (so its allocations land before the heap snapshot) and returns a closure
//! that performs exactly one operation and returns a cheap checksum.

use std::hint::black_box;
use std::net::IpAddr;
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::io::AsyncWriteExt;

use murmur_common_net::deadline::pipe_sing::pipe;
use murmur_common_net::io::OldConnAsStream;
use murmur_common_pool::{get as pool_get, put as pool_put};
use murmur_constant::metadata::Metadata;
use murmur_constant::rule::{Rule, RuleMatchHelper};
use murmur_transport_vless::encryption::common::{encode_header, AEAD};
use murmur_transport_vless::vision::vision::TlsConnCheck;
use murmur_transport_vless::vless::{new_client, DstAddr};

use super::fixture::{
    assert_vision_wire, drain_exact, one_first_write, read_payload, runtime, vision_decode_once, vision_encode_once,
    vision_new_conn, vless_header_len, MemoryStream, UUID_STR,
};
use super::metric_fixture::{
    checksum_bytes, checksum_ip, domain_map_10k, dst_domain, dst_ipv4, dst_mux, fakeip_cold_hosts, fakeip_hit_hosts,
    fakeip_pool, ip_cidr_trie_256, rule_chain_256, rule_helper_populated, rule_metadata_miss, DOMAIN_EXACT_KEY,
    DOMAIN_VALUE, FAKEIP_MISS_POOL_SIZE,
};

/// One operation; the argument is the iteration index. The return value is folded into the run
/// checksum.
pub type Step = Box<dyn FnMut(usize) -> u64>;

/// A whole batch; `(iterations, start_index)` returns the folded checksum. A persistent stream
/// keeps one runtime entry for the batch instead of re-entering `block_on` per operation.
pub type Batch = Box<dyn FnMut(usize, usize) -> u64>;

pub enum Runner {
    Step(Step),
    Batch(Batch),
}

#[derive(Debug)]
pub struct Case {
    pub name: &'static str,
    pub operation_scope: &'static str,
    pub bytes_per_operation: u64,
    pub setup: fn() -> Runner,
}

/// Drive a whole batch. `Step` runners call the closure once per iteration; `Batch` runners run
/// every iteration inside a single runtime entry.
pub fn run_batch(runner: &mut Runner, iterations: usize, start_index: usize) -> u64 {
    match runner {
        Runner::Step(step) => {
            let mut checksum = 0u64;
            for offset in 0..iterations {
                let iteration = start_index.checked_add(offset).expect("iteration index fits usize");
                checksum = checksum.wrapping_add(step(iteration));
            }
            checksum
        }
        Runner::Batch(batch) => batch(iterations, start_index),
    }
}

fn run_step(op: impl FnMut(usize) -> u64 + 'static) -> Runner {
    Runner::Step(Box::new(op))
}

const AEAD_CONTEXT: [u8; 32] = [0x5a; 32];
const AEAD_KEY: [u8; 32] = [0x3c; 32];
const AEAD_FIXED_NONCE: [u8; 12] = [0x2a; 12];

fn setup_control_noop() -> Runner {
    run_step(|iteration| black_box(u64::try_from(iteration).expect("iteration index fits u64")))
}

fn vless_first_step(dst: DstAddr, expected_hex: &str) -> Runner {
    let rt = runtime();
    let client = new_client(UUID_STR, None).expect("vless client");
    let payload: Vec<u8> = b"hi".to_vec();
    let frame_len = vless_header_len(&dst) + payload.len();
    let expected = hex::decode(expected_hex).expect("pinned wire vector");
    assert_eq!(frame_len, expected.len(), "computed first-write frame length");
    assert_eq!(
        one_first_write(&rt, &client, &dst, &payload, frame_len),
        expected,
        "first write diverges from the VLESS request wire format"
    );
    let mut frame = vec![0u8; frame_len];
    run_step(move |_iteration| {
        let (inner, mut peer) = pipe();
        let mut conn = client
            .stream_conn(Box::new(OldConnAsStream(inner)), TlsConnCheck::Unsupported, None, None, &dst)
            .expect("vless stream conn");
        rt.block_on(async {
            let (write, _) = tokio::join!(conn.write_all(&payload), drain_exact(&mut peer, &mut frame));
            write.expect("vless first write");
        });
        black_box(checksum_bytes(&frame))
    })
}

fn setup_vless_first_ipv4() -> Runner {
    vless_first_step(dst_ipv4(), "0011111111111111111111111111111111000101bb01c00002016869")
}

fn setup_vless_first_domain() -> Runner {
    vless_first_step(dst_domain(), "001111111111111111111111111111111100010050020b6578616d706c652e636f6d6869")
}

fn setup_vless_first_mux() -> Runner {
    vless_first_step(dst_mux(), "001111111111111111111111111111111100036869")
}

fn setup_vless_established_pipe_16384() -> Runner {
    let rt = runtime();
    let client = new_client(UUID_STR, None).expect("vless client");
    let dst = dst_ipv4();
    let payload = vec![0x41u8; 16 * 1024];
    let handshake_len = vless_header_len(&dst) + payload.len();
    let (inner, mut peer) = pipe();
    let mut conn = client
        .stream_conn(Box::new(OldConnAsStream(inner)), TlsConnCheck::Unsupported, None, None, &dst)
        .expect("vless stream conn");
    let mut first = vec![0u8; handshake_len];
    rt.block_on(async {
        let (write, _) = tokio::join!(conn.write_all(&payload), drain_exact(&mut peer, &mut first));
        write.expect("vless request write");
    });
    assert_eq!(first.first().copied(), Some(murmur_transport_vless::vless::VERSION), "handshake version byte");
    assert_eq!(&first[vless_header_len(&dst)..], payload.as_slice(), "handshake must frame the exact payload body");
    let mut frame = vec![0u8; payload.len()];
    rt.block_on(async {
        let (write, _) = tokio::join!(conn.write_all(&payload), drain_exact(&mut peer, &mut frame));
        write.expect("vless established write");
    });
    assert_eq!(frame, payload, "established write must forward the exact payload body");
    Runner::Batch(Box::new(move |iterations, _start_index| {
        rt.block_on(async {
            let mut checksum = 0u64;
            for _ in 0..iterations {
                let (write, _) = tokio::join!(conn.write_all(&payload), drain_exact(&mut peer, &mut frame));
                write.expect("established write");
                checksum = checksum.wrapping_add(checksum_bytes(&frame));
            }
            checksum
        })
    }))
}

fn setup_vless_established_16384() -> Runner {
    let rt = runtime();
    let client = new_client(UUID_STR, None).expect("vless client");
    let dst = dst_ipv4();
    let payload = vec![0x41u8; 16 * 1024];
    let handshake_len = vless_header_len(&dst) + payload.len();

    let (capture, captured) = MemoryStream::capture();
    let mut validate = client
        .stream_conn(Box::new(OldConnAsStream(capture)), TlsConnCheck::Unsupported, None, None, &dst)
        .expect("vless stream conn");
    rt.block_on(async {
        validate.write_all(&payload).await.expect("vless request write");
        validate.write_all(&payload).await.expect("vless established write");
    });
    let wire = captured.lock().clone();
    assert_eq!(wire.len(), handshake_len + payload.len(), "captured first frame plus established body");
    assert_eq!(wire.first().copied(), Some(murmur_transport_vless::vless::VERSION), "handshake version byte");
    assert_eq!(
        &wire[vless_header_len(&dst)..handshake_len],
        payload.as_slice(),
        "handshake must frame the exact payload body"
    );
    assert_eq!(&wire[handshake_len..], payload.as_slice(), "established write must forward the exact payload body");

    let mut conn = client
        .stream_conn(Box::new(OldConnAsStream(MemoryStream::sink())), TlsConnCheck::Unsupported, None, None, &dst)
        .expect("vless stream conn");
    rt.block_on(conn.write_all(&payload)).expect("vless request write");
    Runner::Batch(Box::new(move |iterations, _start_index| {
        rt.block_on(async {
            let mut checksum = 0u64;
            for _ in 0..iterations {
                conn.write_all(&payload).await.expect("established write");
                checksum = checksum.wrapping_add(checksum_bytes(&payload));
            }
            checksum
        })
    }))
}

fn setup_vision_encode(size: usize) -> Runner {
    let rt = runtime();
    let payload = vec![0x41u8; size];
    assert_vision_wire(&vision_encode_once(&rt, &payload), size);
    run_step(move |_iteration| {
        let mut conn = vision_new_conn(MemoryStream::sink());
        rt.block_on(conn.write_all(&payload)).expect("vision write");
        black_box(checksum_bytes(&payload))
    })
}

fn setup_vision_encode_1024() -> Runner {
    setup_vision_encode(1024)
}

fn setup_vision_encode_16384() -> Runner {
    setup_vision_encode(16 * 1024)
}

fn setup_vision_decode_1024() -> Runner {
    let rt = runtime();
    let payload = vec![0x41u8; 1024];
    let frame = Arc::new(Mutex::new(vision_encode_once(&rt, &payload)));
    let encoded = frame.lock().clone();
    assert_eq!(vision_decode_once(&rt, encoded, 1024), payload, "vision decode roundtrip");
    let mut out = vec![0u8; 1024];
    run_step(move |_iteration| {
        let mut conn = vision_new_conn(MemoryStream::shared_reader(Arc::clone(&frame)));
        rt.block_on(read_payload(&mut conn, &mut out));
        black_box(checksum_bytes(&out))
    })
}

fn setup_aead_seal(use_aes: bool, size: usize) -> Runner {
    let payload = vec![0x41u8; size];
    let mut aad = [0u8; 5];
    encode_header(&mut aad, size);
    let mut sealer = AEAD::new(&AEAD_CONTEXT, &AEAD_KEY, use_aes);
    let mut sealed = vec![0u8; size + 16];
    sealer.seal(&mut sealed, Some(&AEAD_FIXED_NONCE), &payload, &aad).expect("seal fixture");
    {
        let mut opener = AEAD::new(&AEAD_CONTEXT, &AEAD_KEY, use_aes);
        opener.open_in_place(&mut sealed, Some(&AEAD_FIXED_NONCE), size + 16, &aad).expect("open fixture");
        assert_eq!(&sealed[..size], payload.as_slice(), "aead seal roundtrip");
    }
    run_step(move |_iteration| {
        sealer.seal(&mut sealed, None, &payload, &aad).expect("aead seal");
        black_box(checksum_bytes(&sealed))
    })
}

fn setup_aead_seal_aes256gcm_1024() -> Runner {
    setup_aead_seal(true, 1024)
}

fn setup_aead_seal_chacha20poly1305_16384() -> Runner {
    setup_aead_seal(false, 16 * 1024)
}

fn setup_aead_open_aes256gcm_1024() -> Runner {
    let size = 1024usize;
    let payload = vec![0x41u8; size];
    let mut aad = [0u8; 5];
    encode_header(&mut aad, size);
    let mut ciphertext = vec![0u8; size + 16];
    AEAD::new(&AEAD_CONTEXT, &AEAD_KEY, true)
        .seal(&mut ciphertext, Some(&AEAD_FIXED_NONCE), &payload, &aad)
        .expect("seal fixture");
    let mut opened = vec![0u8; size];
    let mut opener = AEAD::new(&AEAD_CONTEXT, &AEAD_KEY, true);
    opener.open_into(&mut opened, Some(&AEAD_FIXED_NONCE), &ciphertext, &aad).expect("open fixture");
    assert_eq!(opened, payload, "aead open roundtrip");
    run_step(move |_iteration| {
        opener.open_into(&mut opened, Some(&AEAD_FIXED_NONCE), &ciphertext, &aad).expect("aead open");
        black_box(checksum_bytes(&opened))
    })
}

fn setup_domain_map_lookup_exact() -> Runner {
    let map = domain_map_10k();
    assert_eq!(map.lookup(DOMAIN_EXACT_KEY).copied(), Some(DOMAIN_VALUE), "exact lookup must hit");
    run_step(move |_iteration| black_box(u64::from(*map.lookup(DOMAIN_EXACT_KEY).expect("exact hit"))))
}

fn setup_ip_cidr_is_contain_v4_hit() -> Runner {
    let trie = ip_cidr_trie_256();
    let ip: IpAddr = "10.0.42.7".parse().expect("valid ipv4");
    assert!(trie.is_contain(&ip), "v4 hit must match");
    run_step(move |_iteration| black_box(u64::from(trie.is_contain(&ip))))
}

fn setup_fakeip_lookup_hit() -> Runner {
    let pool = fakeip_pool(65_536);
    let hosts = fakeip_hit_hosts();
    let ips: Vec<IpAddr> = hosts.iter().map(|host| pool.lookup(host)).collect();
    for (host, ip) in hosts.iter().zip(&ips) {
        assert_eq!(pool.lookup(host), *ip, "{host} is not a stable hit");
    }
    let mut index = 0usize;
    run_step(move |_iteration| {
        let host = &hosts[index % hosts.len()];
        index = index.wrapping_add(1);
        black_box(checksum_ip(pool.lookup(host.as_str())))
    })
}

fn setup_fakeip_lookup_miss() -> Runner {
    let pool = fakeip_pool(FAKEIP_MISS_POOL_SIZE);
    let hosts = fakeip_cold_hosts();
    let window = usize::try_from(FAKEIP_MISS_POOL_SIZE).expect("positive pool size");
    let first = pool.lookup(&hosts[0]);
    for host in &hosts[1..=window] {
        pool.lookup(host);
    }
    assert!(!pool.exist(first), "the bounded pool must have evicted the oldest mapping");
    let mut index = window + 1;
    run_step(move |_iteration| {
        let host = &hosts[index % hosts.len()];
        index = index.wrapping_add(1);
        black_box(checksum_ip(pool.lookup(host.as_str())))
    })
}

fn scan(chain: &[Arc<dyn Rule>], metadata: &mut Metadata, helper: &RuleMatchHelper) -> (usize, Option<String>) {
    for (index, rule) in chain.iter().enumerate() {
        let (matched, adapter) = rule.match_(metadata, helper);
        if matched {
            return (index + 1, Some(adapter.into_owned()));
        }
    }
    (chain.len(), None)
}

fn setup_rule_chain_256_miss() -> Runner {
    let chain = rule_chain_256();
    let helper = RuleMatchHelper::default();
    let mut metadata = rule_metadata_miss();
    let (visited, adapter) = scan(&chain, &mut metadata, &helper);
    assert_eq!(visited, chain.len(), "the miss probe must scan the whole chain");
    assert_eq!(adapter, None, "the miss probe must not match any rule");
    run_step(move |_iteration| {
        let (visited, _) = scan(&chain, &mut metadata, &helper);
        black_box(u64::try_from(visited).expect("scan length fits u64"))
    })
}

fn setup_rule_chain_256_miss_populated() -> Runner {
    let chain = rule_chain_256();
    let helper = rule_helper_populated();
    let mut metadata = rule_metadata_miss();
    let (visited, adapter) = scan(&chain, &mut metadata, &helper);
    assert_eq!(visited, chain.len(), "the miss probe must scan the whole chain");
    assert_eq!(adapter, None, "the miss probe must not match any rule");
    run_step(move |_iteration| {
        let (visited, _) = scan(&chain, &mut metadata, &helper);
        black_box(u64::try_from(visited).expect("scan length fits u64"))
    })
}

fn setup_pool_get_put_16384() -> Runner {
    const SIZE: usize = 16 * 1024;
    let probe = pool_get(SIZE);
    assert_eq!(probe.len(), SIZE, "get({SIZE}) length");
    pool_put(probe).expect("allocator-owned buffers can be returned");
    run_step(move |_iteration| {
        let buf = pool_get(SIZE);
        let len = u64::try_from(buf.len()).expect("length fits u64");
        pool_put(buf).expect("allocator-owned buffers can be returned");
        black_box(len)
    })
}

pub static CASES: &[Case] = &[
    Case {
        name: "control_noop",
        operation_scope: "black_box(iteration index); no fixture, no production code",
        bytes_per_operation: 0,
        setup: setup_control_noop,
    },
    Case {
        name: "vless_first_ipv4",
        operation_scope: "pipe() + stream_conn + first write_all(header+2 B) + peer drain; client/DstAddr prepared outside",
        bytes_per_operation: 2,
        setup: setup_vless_first_ipv4,
    },
    Case {
        name: "vless_first_domain",
        operation_scope: "pipe() + stream_conn + first write_all(header+2 B) + peer drain; client/DstAddr prepared outside",
        bytes_per_operation: 2,
        setup: setup_vless_first_domain,
    },
    Case {
        name: "vless_first_mux",
        operation_scope: "pipe() + stream_conn + first write_all(header+2 B) + peer drain; client/DstAddr prepared outside",
        bytes_per_operation: 2,
        setup: setup_vless_first_mux,
    },
    Case {
        name: "vless_established_pipe_16384",
        operation_scope: "stateful pipe/CloseSignal retention diagnostic, includes peer drain; not steady-state VLESS codec timing",
        bytes_per_operation: 16 * 1024,
        setup: setup_vless_established_pipe_16384,
    },
    Case {
        name: "vless_established_16384",
        operation_scope: "established VLESS write_all(16 KiB) into a persistent in-memory sink through the existing connection, single runtime entry per batch; handshake, peer queue and frame checks outside",
        bytes_per_operation: 16 * 1024,
        setup: setup_vless_established_16384,
    },
    Case {
        name: "vision_encode_1024",
        operation_scope: "fresh Vision framing state per op (construction + write_all(1 KiB) + teardown); payload prepared outside",
        bytes_per_operation: 1024,
        setup: setup_vision_encode_1024,
    },
    Case {
        name: "vision_encode_16384",
        operation_scope: "fresh Vision framing state per op (construction + write_all(16 KiB) + teardown); payload prepared outside",
        bytes_per_operation: 16 * 1024,
        setup: setup_vision_encode_16384,
    },
    Case {
        name: "vision_decode_1024",
        operation_scope: "fresh Vision conn per op + read of a pre-encoded 1 KiB frame; output buffer reused",
        bytes_per_operation: 1024,
        setup: setup_vision_decode_1024,
    },
    Case {
        name: "aead_seal_aes256gcm_1024",
        operation_scope: "AEAD::seal AES-256-GCM 1 KiB into a reused buffer; AAD and context prepared outside",
        bytes_per_operation: 1024,
        setup: setup_aead_seal_aes256gcm_1024,
    },
    Case {
        name: "aead_open_aes256gcm_1024",
        operation_scope: "AEAD::open_into AES-256-GCM 1 KiB; ciphertext and output buffer prepared outside",
        bytes_per_operation: 1024,
        setup: setup_aead_open_aes256gcm_1024,
    },
    Case {
        name: "aead_seal_chacha20poly1305_16384",
        operation_scope: "AEAD::seal ChaCha20-Poly1305 16 KiB into a reused buffer; AAD and context prepared outside",
        bytes_per_operation: 16 * 1024,
        setup: setup_aead_seal_chacha20poly1305_16384,
    },
    Case {
        name: "domain_map_lookup_exact",
        operation_scope: "DomainMap<u32> with 10000 patterns built outside; exact-hit lookup",
        bytes_per_operation: 0,
        setup: setup_domain_map_lookup_exact,
    },
    Case {
        name: "ip_cidr_is_contain_v4_hit",
        operation_scope: "IpCidrTrie with 256 IPv4 + 256 IPv6 prefixes built outside; IPv4 hit is_contain",
        bytes_per_operation: 0,
        setup: setup_ip_cidr_is_contain_v4_hit,
    },
    Case {
        name: "fakeip_lookup_hit",
        operation_scope: "fake-IP Pool (size 65536, persistence off) with 64 warm hosts; repeat hit lookup",
        bytes_per_operation: 0,
        setup: setup_fakeip_lookup_hit,
    },
    Case {
        name: "fakeip_lookup_miss",
        operation_scope: "bounded fake-IP Pool (size 256) over 8192 rotating hosts; cold miss inserts and evicts",
        bytes_per_operation: 0,
        setup: setup_fakeip_lookup_miss,
    },
    Case {
        name: "rule_chain_256_miss",
        operation_scope: "256-rule chain (DomainSuffix/Keyword/IPCIDR/Domain/Port) built outside; full scan, no match",
        bytes_per_operation: 0,
        setup: setup_rule_chain_256_miss,
    },
    Case {
        name: "rule_chain_256_miss_populated",
        operation_scope: "256-rule chain (DomainSuffix/Keyword/IPCIDR/Domain/Port) with all three RuleMatchHelper hooks populated; full scan, no match",
        bytes_per_operation: 0,
        setup: setup_rule_chain_256_miss_populated,
    },
    Case {
        name: "pool_get_put_16384",
        operation_scope: "murmur-common-pool get(16 KiB) + put through the global buffer pool; no payload fill",
        bytes_per_operation: 0,
        setup: setup_pool_get_put_16384,
    },
];

pub fn find(name: &str) -> Option<&'static Case> {
    CASES.iter().find(|case| case.name == name)
}

pub fn names() -> Vec<&'static str> {
    CASES.iter().map(|case| case.name).collect()
}
