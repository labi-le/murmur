//! In-memory microbenchmarks for the v4 read path: decode pre-encoded maximum-length records
//! through the production `AsyncRead` implementation at consumer buffer widths from 1 byte to one
//! whole record. Encoding, the salt exchange and the AEAD key derivation happen outside the timed
//! region, and no socket is involved, so the numbers cover demultiplexing the plaintext only.
//!
//! The workload shapes are the ones the issue asks for: a full-record consumer as the control, and
//! small windows over the same wire bytes. `bytes` reports the plaintext decoded per iteration.
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
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::runtime::Runtime;

use murmur_std_compat::net::{Addr, Conn as NetConn};
use murmur_transport_snell::snell::{server_stream_conn, stream_conn, PacketFrameWriter, Snell, VERSION4};

const PSK: &[u8] = b"bench-password";
/// The largest payload a v4 frame carries; `MAX_LENGTH` in the crate is `pub(crate)`.
const RECORD: usize = 0x3FFF;
const FILL: u8 = 0xA5;

#[derive(Debug)]
struct MemAddr(&'static str);

impl Addr for MemAddr {
    fn network(&self) -> &str {
        self.0
    }

    fn string(&self) -> String {
        self.0.to_owned()
    }
}

fn mem_addr() -> Box<dyn Addr> {
    Box::new(MemAddr("mem"))
}

/// A write sink for the one-time fixture encoding.
struct Sink(Arc<Mutex<Vec<u8>>>);

impl AsyncRead for Sink {
    fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Sink {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.0.lock().extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl NetConn for Sink {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        Ok(mem_addr())
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        Ok(mem_addr())
    }

    fn close(&self) -> io::Result<()> {
        Ok(())
    }
}

/// A cursor over pre-encoded wire bytes for the timed decode.
struct Source {
    data: Arc<[u8]>,
    pos: usize,
}

impl Source {
    fn new(data: Arc<[u8]>) -> Self {
        Self { data, pos: 0 }
    }
}

impl AsyncRead for Source {
    fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let n = buf.remaining().min(this.data.len() - this.pos);
        buf.put_slice(&this.data[this.pos..this.pos + n]);
        this.pos += n;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Source {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::Error::from(io::ErrorKind::Unsupported)))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl NetConn for Source {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        Ok(mem_addr())
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        Ok(mem_addr())
    }

    fn close(&self) -> io::Result<()> {
        Ok(())
    }
}

fn runtime() -> Runtime {
    tokio::runtime::Builder::new_current_thread().build().expect("tokio runtime")
}

/// Encode `records` maximum-length frames once; the salt and every nonce belong to this buffer.
fn encode(rt: &Runtime, records: usize) -> Arc<[u8]> {
    let sink = Arc::new(Mutex::new(Vec::new()));
    let mut conn = stream_conn(Box::new(Sink(Arc::clone(&sink))), PSK, VERSION4);
    let payload = vec![FILL; RECORD];
    rt.block_on(async {
        for _ in 0..records {
            conn.write_packet_frame(&payload).await.expect("encode a v4 record");
        }
    });
    let bytes = sink.lock().clone();
    Arc::from(bytes)
}

fn decode_conn(data: &Arc<[u8]>) -> Snell {
    // `server_stream_conn` sets `reply`, so reads are the raw record stream: this is the side
    // that downloads through the v4 reader.
    server_stream_conn(Box::new(Source::new(Arc::clone(data))), PSK, VERSION4)
}

/// Decode every record at `window` bytes per read; used once per case to pin output equality
/// before the timed region, with the first frame's key derivation and decrypt included.
fn decode_once(rt: &Runtime, data: &Arc<[u8]>, window: usize, records: usize) -> Vec<u8> {
    let mut conn = decode_conn(data);
    let mut out = Vec::with_capacity(records * RECORD);
    let mut buf = vec![0u8; window];
    rt.block_on(async {
        let mut left = records * RECORD;
        while left > 0 {
            let n = left.min(window);
            conn.read_exact(&mut buf[..n]).await.expect("decode a window");
            out.extend_from_slice(&buf[..n]);
            left -= n;
        }
    });
    out
}

fn bench_decode(c: &mut Criterion) {
    let rt = runtime();
    let mut group = c.benchmark_group("v4_read");
    // (label, consumer window, records). The one-byte case uses fewer records so the quadratic
    // baseline drain stays inside a bounded bench; the others decode identical record bytes.
    let cases =
        [("window_1", 1usize, 2usize), ("window_64", 64, 32), ("window_512", 512, 32), ("window_full", RECORD, 32)];

    for (label, window, records) in cases {
        let data = encode(&rt, records);
        let expected = vec![FILL; records * RECORD];
        assert_eq!(expected, decode_once(&rt, &data, window, records), "{label}: decoded bytes diverge");

        // The warm-up read below consumes the first record outside the timed region, so the
        // measurement covers the remaining records only.
        let timed = (records - 1) * RECORD;
        group.throughput(Throughput::Bytes(u64::try_from(timed).expect("bytes fit u64")));
        group.bench_function(BenchmarkId::new("decode", label), |b| {
            b.iter_batched(
                || {
                    let mut conn = decode_conn(&data);
                    let mut first = vec![0u8; RECORD];
                    rt.block_on(conn.read_exact(&mut first)).expect("warm the reader on the first record");
                    assert_eq!(first, vec![FILL; RECORD], "{label}: first record diverges");
                    (conn, vec![0u8; window])
                },
                |(mut conn, mut buf)| {
                    rt.block_on(async {
                        let mut left = timed;
                        while left > 0 {
                            let n = left.min(window);
                            conn.read_exact(&mut buf[..n]).await.expect("decode a window");
                            left -= n;
                        }
                    });
                    black_box(timed)
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

criterion_group!(benches, bench_decode);
criterion_main!(benches);
