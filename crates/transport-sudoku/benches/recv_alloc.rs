//! Heap-allocation census for the sudoku receive paths.
//!
//! Every received frame used to allocate a fresh body buffer and copy the decrypted plaintext
//! into a second buffer. Both `RecordConn` and `AEADConn` now keep one frame buffer per
//! connection and serve plaintext in place, so after the first frame a steady read must not
//! allocate. `dhat` is the global allocator: the steady-state delta is taken inside the async
//! loop after a warm-up frame, and the retained figure is the live heap growth caused by
//! constructing the reader and decrypting that first frame, which is the receive buffer the
//! connection keeps.
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
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::process::ExitCode;
use std::sync::Arc;
use std::task::{Context, Poll};

use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use murmur_common_net::io::Stream;
use murmur_transport_sudoku::crypto::aead::new_aead_conn;
use murmur_transport_sudoku::crypto::record_conn::new_record_conn;

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

const METHOD: &str = "chacha20-poly1305";
const SEND_KEY: [u8; 32] = [0x11; 32];
const RECV_KEY: [u8; 32] = [0x22; 32];
/// `MAX_FRAME_BODY_SIZE` minus the record header or nonce and the ChaCha20-Poly1305 tag.
const MAX_RECORD_PLAIN: usize = 65_535 - 12 - 16;
const MAX_AEAD_PLAIN: usize = 65_535 - 12 - 16;

fn test_addr() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
}

#[derive(Clone)]
struct CaptureSink {
    written: Arc<Mutex<Vec<u8>>>,
}

impl CaptureSink {
    fn new() -> Self {
        Self { written: Arc::new(Mutex::new(Vec::new())) }
    }
}

impl AsyncRead for CaptureSink {
    fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for CaptureSink {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.written.lock().extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl Stream for CaptureSink {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(test_addr())
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok(test_addr())
    }
}

struct ReplayConn {
    cursor: io::Cursor<Vec<u8>>,
}

impl ReplayConn {
    fn new(data: Vec<u8>) -> Self {
        Self { cursor: io::Cursor::new(data) }
    }
}

impl AsyncRead for ReplayConn {
    fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let n = io::Read::read(&mut self.get_mut().cursor, buf.initialize_unfilled())?;
        buf.advance(n);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ReplayConn {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl Stream for ReplayConn {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(test_addr())
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok(test_addr())
    }
}

#[derive(Clone, Copy)]
enum Sizes {
    Stable(usize),
    Alternating(usize, usize),
}

impl Sizes {
    fn payloads(self, records: usize) -> Vec<usize> {
        (0..records)
            .map(|index| match self {
                Self::Stable(len) => len,
                Self::Alternating(first, second) => {
                    let (larger, smaller) = if first >= second { (first, second) } else { (second, first) };
                    if index % 2 == 0 {
                        larger
                    } else {
                        smaller
                    }
                }
            })
            .collect()
    }
}

fn build_record_wire(rt: &tokio::runtime::Runtime, lens: &[usize]) -> Vec<u8> {
    let sink = CaptureSink::new();
    let written = Arc::clone(&sink.written);
    let mut writer = new_record_conn(Box::new(sink), METHOD, &SEND_KEY, &RECV_KEY).expect("record writer");
    let payload = vec![0x5a; lens.iter().copied().max().expect("nonempty frame list")];
    rt.block_on(async {
        for &len in lens {
            writer.write_all(&payload[..len]).await.expect("write record");
        }
    });
    let mut guard = written.lock();
    std::mem::take(&mut *guard)
}

fn build_aead_wire(rt: &tokio::runtime::Runtime, lens: &[usize]) -> Vec<u8> {
    let sink = CaptureSink::new();
    let written = Arc::clone(&sink.written);
    let mut writer = new_aead_conn(Box::new(sink), "shared-secret", METHOD).expect("aead writer");
    let payload = vec![0x5a; lens.iter().copied().max().expect("nonempty frame list")];
    rt.block_on(async {
        for &len in lens {
            writer.write_all(&payload[..len]).await.expect("write frame");
        }
    });
    let mut guard = written.lock();
    std::mem::take(&mut *guard)
}

fn run_case(
    rt: &tokio::runtime::Runtime,
    label: &str,
    lens: &[usize],
    wire: Vec<u8>,
    make_reader: impl FnOnce(Vec<u8>) -> Box<dyn AsyncRead + Unpin>,
) {
    let mut buf = vec![0u8; lens.iter().copied().max().expect("nonempty frame list")];
    let before = dhat::HeapStats::get();
    let mut reader = make_reader(wire);
    rt.block_on(async {
        reader.read_exact(&mut buf[..lens[0]]).await.expect("warm frame");
    });
    let retained = dhat::HeapStats::get().curr_bytes as i64 - before.curr_bytes as i64;

    let (blocks, bytes) = rt.block_on(async {
        let before = dhat::HeapStats::get();
        for &len in &lens[1..] {
            reader.read_exact(&mut buf[..len]).await.expect("frame");
            black_box(&buf[..len]);
        }
        let after = dhat::HeapStats::get();
        (after.total_blocks - before.total_blocks, after.total_bytes - before.total_bytes)
    });
    let operations = (lens.len() - 1) as f64;
    println!(
        "{label:<34} {:>6} {:>12.3} {:>12.1} {:>14}",
        lens.len(),
        blocks as f64 / operations,
        bytes as f64 / operations,
        retained
    );
}

fn main() -> ExitCode {
    let _profiler = dhat::Profiler::builder().testing().trim_backtraces(Some(0)).build();
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("current-thread runtime");
    rt.block_on(async {});

    println!("recv_alloc: heap allocations per decrypted frame, after one warm-up frame");
    println!("{:<34} {:>6} {:>12} {:>12} {:>14}", "case", "frames", "blocks/op", "bytes/op", "retained bytes");

    let cases = [
        ("record stable 1 KiB", Sizes::Stable(1_024), 2_048),
        ("record stable 16 KiB", Sizes::Stable(16 * 1_024), 512),
        ("record alternating 1/16 KiB", Sizes::Alternating(1_024, 16 * 1_024), 512),
        ("record stable max", Sizes::Stable(MAX_RECORD_PLAIN), 128),
        ("aead stable 1 KiB", Sizes::Stable(1_024), 2_048),
        ("aead stable 16 KiB", Sizes::Stable(16 * 1_024), 512),
        ("aead alternating 1/16 KiB", Sizes::Alternating(1_024, 16 * 1_024), 512),
        ("aead stable max", Sizes::Stable(MAX_AEAD_PLAIN), 128),
    ];
    for (label, sizes, records) in cases {
        let lens = sizes.payloads(records);
        if label.starts_with("record ") {
            let wire = build_record_wire(&rt, &lens);
            run_case(&rt, label, &lens, wire, |wire| {
                Box::new(
                    new_record_conn(Box::new(ReplayConn::new(wire)), METHOD, &RECV_KEY, &SEND_KEY)
                        .expect("record reader"),
                )
            });
        } else {
            let wire = build_aead_wire(&rt, &lens);
            run_case(&rt, label, &lens, wire, |wire| {
                Box::new(new_aead_conn(Box::new(ReplayConn::new(wire)), "shared-secret", METHOD).expect("aead reader"))
            });
        }
    }
    ExitCode::SUCCESS
}
