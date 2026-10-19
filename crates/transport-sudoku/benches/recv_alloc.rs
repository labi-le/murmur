//! Heap-allocation census for the sudoku record reader.
//!
//! Every received record used to allocate a fresh body buffer and copy the decrypted plaintext
//! into a second buffer. The reader now keeps one frame buffer per connection and decrypts in
//! place, so after the first record a read must not allocate. `dhat` is the global allocator and
//! the delta is taken inside the async loop, after a warm-up record installs the AEAD and sizes
//! the buffer.
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
use murmur_transport_sudoku::crypto::record_conn::new_record_conn;

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

const METHOD: &str = "chacha20-poly1305";
const SEND_KEY: [u8; 32] = [0x11; 32];
const RECV_KEY: [u8; 32] = [0x22; 32];
/// `MAX_FRAME_BODY_SIZE` minus the record header and the ChaCha20-Poly1305 tag.
const MAX_PLAIN: usize = 65_535 - 12 - 16;

fn test_addr() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
}

#[derive(Clone)]
struct CaptureSink {
    written: Arc<Mutex<Vec<u8>>>,
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

fn build_wire(rt: &tokio::runtime::Runtime, plain_len: usize, records: usize) -> Vec<u8> {
    let written = Arc::new(Mutex::new(Vec::new()));
    let mut writer =
        new_record_conn(Box::new(CaptureSink { written: Arc::clone(&written) }), METHOD, &SEND_KEY, &RECV_KEY)
            .expect("record writer");
    let payload = vec![0x5a; plain_len];
    rt.block_on(async {
        for _ in 0..records {
            writer.write_all(&payload).await.expect("write record");
        }
    });
    let mut guard = written.lock();
    std::mem::take(&mut *guard)
}

fn main() -> ExitCode {
    let cases = [(64usize, 4_096usize), (1_024, 2_048), (16 * 1_024, 256), (MAX_PLAIN, 64)];
    let _profiler = dhat::Profiler::builder().testing().trim_backtraces(Some(0)).build();
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("current-thread runtime");

    println!("recv_alloc: heap allocations per decrypted record, after one warm-up record");
    println!("{:<10} {:>8} {:>12} {:>12}", "plain", "records", "blocks/op", "bytes/op");
    for (plain_len, records) in cases {
        let wire = build_wire(&rt, plain_len, records);
        let mut reader =
            new_record_conn(Box::new(ReplayConn::new(wire)), METHOD, &RECV_KEY, &SEND_KEY).expect("record reader");
        let mut buf = vec![0u8; plain_len];
        let (blocks, bytes) = rt.block_on(async {
            reader.read_exact(&mut buf).await.expect("warm record");
            let before = dhat::HeapStats::get();
            for _ in 1..records {
                reader.read_exact(&mut buf).await.expect("record");
                black_box(&buf);
            }
            let after = dhat::HeapStats::get();
            (after.total_blocks - before.total_blocks, after.total_bytes - before.total_bytes)
        });
        let operations = (records - 1) as f64;
        println!(
            "{:<10} {:>8} {:>12.3} {:>12.1}",
            plain_len,
            records,
            blocks as f64 / operations,
            bytes as f64 / operations
        );
    }
    ExitCode::SUCCESS
}
