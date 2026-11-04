//! Fixtures shared by the Criterion `vless` target and the metrics case registry. The metric-only
//! helpers live in `metric_fixture.rs` so that neither target compiles helpers it does not use.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::runtime::Runtime;
use uuid::Uuid;

use murmur_common::shared_conn::SharedConn;
use murmur_common_net::deadline::pipe_sing::{pipe, PipeAddr, PipeConn};
use murmur_common_net::io::OldConnAsStream;
use murmur_component_tls::utls::VERSION_TLS13;
use murmur_std_compat::net::{Addr, Conn as OldConn};
use murmur_transport_vless::vision::conn::Conn as VisionConn;
use murmur_transport_vless::vision::vision::{new_conn as vision_conn, TlsConnCheck};
use murmur_transport_vless::vless::{Client, DstAddr};

pub const PADDING_HEADER_LEN: usize = 21;
pub const VISION_SPLIT: usize = 4096;
pub const UUID_STR: &str = "11111111-1111-1111-1111-111111111111";
pub const UUID: Uuid = Uuid::from_bytes([0x11; 16]);

pub fn runtime() -> Runtime {
    tokio::runtime::Builder::new_current_thread().enable_all().build().expect("tokio runtime")
}

pub fn tls13() -> TlsConnCheck {
    TlsConnCheck::Supported { handshake_complete: true, version: VERSION_TLS13 }
}

pub fn vision_new_conn(stream: impl OldConn + 'static) -> VisionConn {
    vision_conn(SharedConn::from_boxed(Box::new(stream)), tls13(), None, None, UUID).expect("vision conn")
}

pub async fn drain_exact(peer: &mut PipeConn, buf: &mut [u8]) {
    peer.read_exact(buf).await.expect("drain the in-memory peer");
}

pub async fn read_payload(conn: &mut VisionConn, out: &mut [u8]) {
    let mut total = 0;
    while total < out.len() {
        let window = out.get_mut(total..).expect("read window within the output buffer");
        let n = conn.read(window).await.expect("vision read");
        assert!(n > 0, "a vision read must make progress on a well-formed frame");
        total += n;
    }
}

/// Serves preloaded bytes or captures writes; `pipe()` would re-copy a chunk per Vision header read.
#[derive(Debug)]
pub struct MemoryStream {
    data: Arc<Mutex<Vec<u8>>>,
    read_pos: usize,
    capture_writes: bool,
}

impl MemoryStream {
    pub fn sink() -> Self {
        Self { data: Arc::new(Mutex::new(Vec::new())), read_pos: 0, capture_writes: false }
    }

    pub fn capture() -> (Self, Arc<Mutex<Vec<u8>>>) {
        let data = Arc::new(Mutex::new(Vec::new()));
        (Self { data: Arc::clone(&data), read_pos: 0, capture_writes: true }, data)
    }

    pub fn shared_reader(data: Arc<Mutex<Vec<u8>>>) -> Self {
        Self { data, read_pos: 0, capture_writes: false }
    }
}

impl AsyncRead for MemoryStream {
    fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let data = this.data.lock();
        let available = data.get(this.read_pos..).unwrap_or(&[]);
        let n = available.len().min(buf.remaining());
        let (head, _) = available.split_at(n);
        buf.put_slice(head);
        this.read_pos += n;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MemoryStream {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let buf = std::hint::black_box(buf);
        let this = self.get_mut();
        if this.capture_writes {
            this.data.lock().extend_from_slice(buf);
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl OldConn for MemoryStream {
    fn local_addr(&self) -> std::io::Result<Box<dyn Addr>> {
        Ok(Box::new(PipeAddr))
    }

    fn remote_addr(&self) -> std::io::Result<Box<dyn Addr>> {
        Ok(Box::new(PipeAddr))
    }

    fn close(&self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Replays a pre-encoded Vision stream: the UUID-bearing frame once, then whole continuation
/// frames forever. A replay exists because the warm cases read many frames from one stream, and
/// only the first frame may carry the UUID.
#[allow(dead_code, reason = "used only by the metrics case registry, which the Criterion target does not compile")]
#[derive(Debug)]
pub struct ReplayStream {
    prefix: Vec<u8>,
    repeat: Vec<u8>,
    position: usize,
}

impl ReplayStream {
    #[allow(dead_code, reason = "used only by the metrics case registry, which the Criterion target does not compile")]
    pub fn new(prefix: Vec<u8>, repeat: Vec<u8>) -> Self {
        assert!(!repeat.is_empty(), "a replay stream needs a continuation-frame segment");
        Self { prefix, repeat, position: 0 }
    }
}

impl AsyncRead for ReplayStream {
    fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let remaining = buf.remaining();
        if remaining > 0 {
            let source = if this.position < this.prefix.len() {
                this.prefix.get(this.position..).unwrap_or_default()
            } else {
                let offset = (this.position - this.prefix.len()) % this.repeat.len();
                this.repeat.get(offset..).unwrap_or_default()
            };
            let n = source.len().min(remaining);
            let (head, _) = source.split_at(n);
            buf.put_slice(head);
            this.position += n;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ReplayStream {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let buf = std::hint::black_box(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl OldConn for ReplayStream {
    fn local_addr(&self) -> std::io::Result<Box<dyn Addr>> {
        Ok(Box::new(PipeAddr))
    }

    fn remote_addr(&self) -> std::io::Result<Box<dyn Addr>> {
        Ok(Box::new(PipeAddr))
    }

    fn close(&self) -> std::io::Result<()> {
        Ok(())
    }
}

pub fn vless_header_len(dst: &DstAddr) -> usize {
    let mut len = 1 + 16 + 1;
    if dst.mux {
        len += 1;
    } else {
        len += 1 + 2 + 1 + dst.addr.len();
    }
    len
}

pub fn one_first_write(rt: &Runtime, client: &Client, dst: &DstAddr, payload: &[u8], frame_len: usize) -> Vec<u8> {
    let (inner, mut peer) = pipe();
    let mut conn = client
        .stream_conn(Box::new(OldConnAsStream(inner)), TlsConnCheck::Unsupported, None, None, dst)
        .expect("vless stream conn");
    let mut frame = vec![0u8; frame_len];
    rt.block_on(async {
        let (write, _) = tokio::join!(conn.write_all(payload), drain_exact(&mut peer, &mut frame));
        write.expect("vless first write");
    });
    frame
}

pub fn vision_encode_once(rt: &Runtime, payload: &[u8]) -> Vec<u8> {
    let (stream, captured) = MemoryStream::capture();
    let mut conn = vision_new_conn(stream);
    rt.block_on(conn.write_all(payload)).expect("vision write");
    let frame = captured.lock().clone();
    frame
}

/// Encodes several payloads through one Vision connection. Each payload becomes its own frame and
/// only the first carries the UUID, so this is a valid stream; separate first frames would repeat
/// the UUID and could not be concatenated.
#[allow(dead_code, reason = "used only by the metrics case registry, which the Criterion target does not compile")]
pub fn vision_encode_frames(rt: &Runtime, payloads: &[Vec<u8>]) -> Vec<u8> {
    let (stream, captured) = MemoryStream::capture();
    let mut conn = vision_new_conn(stream);
    rt.block_on(async {
        for payload in payloads {
            conn.write_all(payload.as_slice()).await.expect("vision write");
        }
    });
    let frame = captured.lock().clone();
    frame
}

pub fn assert_vision_wire(frame: &[u8], size: usize) {
    let mut pos = 0;
    let mut total = 0;
    let mut first = true;
    while pos < frame.len() {
        let header = if first { PADDING_HEADER_LEN } else { PADDING_HEADER_LEN - 16 };
        let head = frame.get(pos..pos + header).expect("vision frame header fits the wire");
        let command_off = if first { 16 } else { 0 };
        if first {
            assert_eq!(&head[..16], UUID.as_bytes(), "first vision frame must carry the user UUID");
        }
        assert_eq!(head[command_off], 0x00, "vision must emit padding-continue, not passthrough");
        let co = command_off + 1;
        let content = usize::from(u16::from_be_bytes([head[co], head[co + 1]]));
        let padding = usize::from(u16::from_be_bytes([head[co + 2], head[co + 3]]));
        assert_eq!(content, size.min(VISION_SPLIT), "vision frame content length");
        let end = pos + header + content + padding;
        assert!(end <= frame.len(), "vision frame body fits the wire");
        total += content;
        pos = end;
        first = false;
    }
    assert_eq!(total, size, "vision wire carries the whole payload");
}

/// Splits an encoded stream into the UUID-bearing first frame and the continuation frames that can
/// follow it any number of times. The encoder ends padding once its filter allowance runs out, so a
/// stream that reaches that point has no replayable tail and is rejected here.
#[allow(dead_code, reason = "used only by the metrics case registry, which the Criterion target does not compile")]
pub fn vision_replay_segments(frame: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let (command, content, padding) = vision_frame_header(frame, 0, true);
    assert_eq!(command, 0x00, "the first vision frame must continue padding");
    let split = PADDING_HEADER_LEN + content + padding;
    let mut pos = split;
    while pos < frame.len() {
        let (command, content, padding) = vision_frame_header(frame, pos, false);
        assert_eq!(command, 0x00, "a replayed vision stream carries continuation frames only");
        pos += (PADDING_HEADER_LEN - 16) + content + padding;
    }
    assert_eq!(pos, frame.len(), "the replayed vision stream must end on a frame boundary");
    let (prefix, repeat) = frame.split_at(split);
    assert!(!repeat.is_empty(), "a replay needs at least one continuation frame");
    (prefix.to_vec(), repeat.to_vec())
}

/// `(command, content length, padding length)` of the frame at `pos`.
fn vision_frame_header(frame: &[u8], pos: usize, first: bool) -> (u8, usize, usize) {
    let header = if first { PADDING_HEADER_LEN } else { PADDING_HEADER_LEN - 16 };
    let head = frame.get(pos..pos + header).expect("vision frame header");
    let command_off = if first { 16 } else { 0 };
    if first {
        assert_eq!(&head[..16], UUID.as_bytes(), "the first vision frame must carry the user UUID");
    }
    let command = head[command_off];
    let content = usize::from(u16::from_be_bytes([head[command_off + 1], head[command_off + 2]]));
    let padding = usize::from(u16::from_be_bytes([head[command_off + 3], head[command_off + 4]]));
    (command, content, padding)
}

pub fn vision_decode_once(rt: &Runtime, frame: Vec<u8>, size: usize) -> Vec<u8> {
    let mut conn = vision_new_conn(MemoryStream::shared_reader(Arc::new(Mutex::new(frame))));
    let mut out = vec![0u8; size];
    rt.block_on(read_payload(&mut conn, &mut out));
    out
}
