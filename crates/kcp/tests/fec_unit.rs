//! Narrower unit test directly on the FEC encoder/decoder pair (rather than a full session-level
//! test): proves absent data shards are reconstructed from the surviving data + parity shards.
//!
//! Feeding data shard 0, then both parity shards, yields `recovered` of length 2 — not 1. Once
//! the heap for a shard id holds all its data-shard entries it is drained wholesale, and *every* data
//! shard absent from it is reconstructed, including one that has not arrived yet rather than one
//! that was genuinely lost. A later real copy of such a shard is therefore redundant, not a
//! duplicate; the decoder has already moved on to the next shard id.
// Test code is exempt from the production panic posture: the bans on `unwrap`,
// `expect`, `panic`, indexing and casts exist to keep a long-lived server process
// alive, and a failing test is supposed to abort. Style tiers are exempt for the
// same reason -- the scaffolding around an assertion is not product code.
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

use murmur_kcp::fec::{FecDecoder, FecEncoder, FEC_HEADER_SIZE_PLUS2};

fn make_packet(payload: &[u8]) -> Vec<u8> {
    let mut buf = vec![0u8; FEC_HEADER_SIZE_PLUS2 + payload.len()];
    buf[FEC_HEADER_SIZE_PLUS2..].copy_from_slice(payload);
    buf
}

/// The `SIZE`-prefixed frame a FEC shard carries: the 2-byte length plus payload, which is what
/// `FecEncoder::encode` writes into the shard cache and what a peer feeds back into kcp.
fn frame_of(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&((payload.len() + 2) as u16).to_le_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// Reconstruction pads every shard out to the group's longest shard, so a short shard comes back
/// with a zero tail past its own `SIZE` field. Only the `SIZE`-prefixed frame is meaningful.
fn frame_prefix(shard: &[u8]) -> Vec<u8> {
    let sz = u16::from_le_bytes([shard[0], shard[1]]) as usize;
    shard[..sz].to_vec()
}

#[test]
fn fec_reconstructs_the_absent_data_shards() {
    let mut enc = FecEncoder::new(3, 2, 0).expect("encoder");
    let mut dec = FecDecoder::new(3, 2).expect("decoder");

    let payloads: [&[u8]; 3] = [b"first-data-shard-payload", b"second-data-shard-payload", b"third-shard!"];

    let mut data_packets = Vec::new();
    let mut parity_packets = Vec::new();
    for payload in payloads {
        let mut pkt = make_packet(payload);
        let ecc = enc.encode(&mut pkt, 500);
        data_packets.push(pkt);
        parity_packets.extend(ecc);
    }
    assert_eq!(parity_packets.len(), 2, "3 data shards should trigger one parity generation of 2 shards");

    // Withhold data shard 1. Three packets (shard 0 + both parities) reach the drain threshold.
    let mut recovered = Vec::new();
    assert!(dec.decode(&data_packets[0]).is_empty());
    assert!(dec.decode(&parity_packets[0]).is_empty());
    recovered.extend(dec.decode(&parity_packets[1]));

    assert_eq!(recovered.len(), 2, "both absent data shards are reconstructed");
    assert_eq!(frame_prefix(&recovered[0]), frame_of(payloads[1]), "the lost shard must reconstruct byte-for-byte");
    assert_eq!(frame_prefix(&recovered[1]), frame_of(payloads[2]), "the not-yet-arrived shard is reconstructed too");

    // The real copy of shard 2 lands in a fresh shard set and is not mistaken for a duplicate.
    assert!(dec.decode(&data_packets[2]).is_empty());
    assert_eq!(recovered.len(), 2);
}
