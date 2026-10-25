use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{anyhow, Result};
use parking_lot::Mutex as SyncMutex;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf};

use super::address::decode_address;
use super::config::ProtocolConfig;
use super::handshake_kip::{kip_handshake_client, KIP_HANDSHAKE_SKEW};
use super::init::{client_aead_seed, server_aead_seed};
use super::kip::{
    decode_kip_client_hello_payload, kip_user_hash_from_key, read_kip_message, resolve_client_hello_table,
    write_kip_message, KipMessage, KipServerHello, KIP_FEAT_ALL, KIP_HELLO_PUB_SIZE, KIP_TYPE_CLIENT_HELLO,
    KIP_TYPE_KEEP_ALIVE, KIP_TYPE_OPEN_TCP, KIP_TYPE_SERVER_HELLO, KIP_TYPE_START_MUX, KIP_TYPE_START_UOT,
};
use super::replay::GLOBAL_HANDSHAKE_REPLAY;
use super::session_keys::{
    derive_psk_directional_bases, derive_session_directional_bases, generate_x25519_ephemeral, x25519_shared_secret,
};
use super::table_probe::{pick_client_table, select_table_by_probe};
use crate::crypto::record_conn::new_record_conn;
use crate::obfs::httpmask;
use crate::obfs::sudoku::conn::{new_conn, Conn as SudokuConn};
use crate::obfs::sudoku::downlink::{new_server_downlink_writer, Closer, DownlinkWriter};
use crate::obfs::sudoku::packed::{new_packed_conn, PackedConn};
use crate::obfs::sudoku::table::Table;
use murmur_common_net::io::{close_stream, CancellableStream, OldConnAsStream, Stream};
use x25519_dalek::PublicKey;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionType {
    Tcp,
    UoT,
    Multiplex,
}

pub struct ServerSession {
    pub conn: Box<dyn Stream>,
    pub typ: SessionType,
    pub target: String,
}

impl core::fmt::Debug for ServerSession {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ServerSession").field("typ", &self.typ).field("target", &self.target).finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct HandshakeMeta {
    #[allow(
        dead_code,
        reason = "exercised only by #[cfg(test)] tests since read_server_session stopped threading it through"
    )]
    pub(crate) user_hash: String,
}

/// The runtime type assertion, promoted to a
/// local trait since the boxed stream type deliberately carries no `Any` support.
///
/// Every conn `SuspiciousError` ever carries implements it directly.
pub trait BufferedRecorderConn: Stream {
    fn get_buffered_and_recorded(&mut self) -> Vec<u8>;

    /// The fallback relay relays the raw conn, not the wrapper returned. Unwraps to the
    /// underlying raw transport conn so a post-rejection fallback
    /// relay stops running bytes back through this wrapper's own decode/recording state.
    ///
    /// DEVIATION: the handler relays the listener-accepted socket (`conn`, captured before
    /// the tunnel wrapper) to the fallback, not the conn passed to `server_handshake`. On the
    /// plain and legacy-mask paths those are the same socket, so this is equivalent. In
    /// httpmask tunnel modes (stream/poll/ws), `handle_conn` has already moved the listener conn
    /// into `wrap_conn` and keeps no handle to it, so `into_raw` returns the tunnel virtual
    /// conn. The fallback receives the de-framed tunnel payload (chunk bodies / ws payloads),
    /// whereas the documented behaviour relays the raw bytes of the listener TCP socket (HTTP
    /// chunk framing / ws frames) that remain after its tunnel reader's buffering.
    fn into_raw(self: Box<Self>) -> Box<dyn Stream>;
}

/// `SuspiciousError`: indicates a potential probing attempt or protocol violation.
///
/// When returned, `conn` (if `Some`) contains all bytes already consumed/buffered so the caller
/// can perform a best-effort fallback relay (e.g. to a local web server) without losing the
/// request.
pub struct SuspiciousError {
    pub err: anyhow::Error,
    pub conn: Option<Box<dyn BufferedRecorderConn>>,
}

impl std::fmt::Debug for SuspiciousError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SuspiciousError").field("err", &self.err).field("conn", &self.conn.is_some()).finish()
    }
}

impl std::fmt::Display for SuspiciousError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.err)
    }
}

impl std::error::Error for SuspiciousError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.err.source()
    }
}

fn suspicious(err: anyhow::Error, conn: Option<Box<dyn BufferedRecorderConn>>) -> anyhow::Error {
    anyhow::Error::new(SuspiciousError { err, conn })
}

struct RecordedConn {
    conn: Box<dyn Stream>,
    recorded: Vec<u8>,
}

impl AsyncRead for RecordedConn {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.conn).poll_read(cx, buf)
    }
}
impl AsyncWrite for RecordedConn {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.conn).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.conn).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.conn).poll_shutdown(cx)
    }
}
impl Stream for RecordedConn {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.conn.local_addr()
    }
    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.conn.peer_addr()
    }
    fn shutdown_read(&self) -> io::Result<()> {
        self.conn.shutdown_read()
    }
    fn shutdown_write(&self) -> io::Result<()> {
        self.conn.shutdown_write()
    }
    fn old_conn(&self) -> Option<&dyn murmur_std_compat::net::Conn> {
        self.conn.old_conn()
    }
}
impl BufferedRecorderConn for RecordedConn {
    fn get_buffered_and_recorded(&mut self) -> Vec<u8> {
        self.recorded.clone()
    }

    fn into_raw(self: Box<Self>) -> Box<dyn Stream> {
        self.conn
    }
}

/// Wraps a `SudokuConnHandle` (which needs `&mut self` for `get_buffered_and_recorded`) so it can
/// be shared between the value the server obfs conn wraps and the reader half of the
/// [`DirectionalConn`] it also builds — mirrors the `PackedConnHandle` convention already used by
/// `obfs::sudoku::packed`.
#[derive(Clone)]
pub(crate) struct SudokuConnHandle {
    conn: Arc<SyncMutex<SudokuConn>>,
    close_view: SudokuConnCloseView,
}

impl SudokuConnHandle {
    fn new(conn: SudokuConn) -> Self {
        let conn = Arc::new(SyncMutex::new(conn));
        let close_view = SudokuConnCloseView(Arc::clone(&conn));
        Self { conn, close_view }
    }

    fn stop_recording(&self) {
        self.conn.lock().stop_recording();
    }
}

impl AsyncRead for SudokuConnHandle {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut guard = self.conn.lock();
        Pin::new(&mut *guard).poll_read(cx, buf)
    }
}
impl AsyncWrite for SudokuConnHandle {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let mut guard = self.conn.lock();
        Pin::new(&mut *guard).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut guard = self.conn.lock();
        Pin::new(&mut *guard).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut guard = self.conn.lock();
        Pin::new(&mut *guard).poll_shutdown(cx)
    }
}
impl Stream for SudokuConnHandle {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.conn.lock().local_addr()
    }
    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.conn.lock().peer_addr()
    }
    fn shutdown_read(&self) -> io::Result<()> {
        self.conn.lock().shutdown_read()
    }
    fn shutdown_write(&self) -> io::Result<()> {
        self.conn.lock().shutdown_write()
    }
    /// A full close (unlike the half-closes above) must reach whatever real inner conn the
    /// wrapped [`SudokuConn`] itself answers `old_conn` with; a `MutexGuard` can't be returned
    /// as a `&'self` reference, so this goes through a view holding its own clone of the same
    /// `Arc` instead (see [`SudokuConnCloseView`]).
    fn old_conn(&self) -> Option<&dyn murmur_std_compat::net::Conn> {
        Some(&self.close_view)
    }
}
impl BufferedRecorderConn for SudokuConnHandle {
    fn get_buffered_and_recorded(&mut self) -> Vec<u8> {
        self.conn.lock().get_buffered_and_recorded()
    }

    fn into_raw(self: Box<Self>) -> Box<dyn Stream> {
        self
    }
}

/// See [`SudokuConnHandle::old_conn`].
#[derive(Clone)]
struct SudokuConnCloseView(Arc<SyncMutex<SudokuConn>>);

/// Never actually polled — reached only through [`Stream::old_conn`] — but
/// [`murmur_std_compat::net::Conn`] requires `AsyncRead + AsyncWrite`, so this forwards to the same
/// mutex-guarded conn `SudokuConnHandle` itself reads and writes through.
impl AsyncRead for SudokuConnCloseView {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut guard = self.get_mut().0.lock();
        Pin::new(&mut *guard).poll_read(cx, buf)
    }
}
impl AsyncWrite for SudokuConnCloseView {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let mut guard = self.get_mut().0.lock();
        Pin::new(&mut *guard).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut guard = self.get_mut().0.lock();
        Pin::new(&mut *guard).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut guard = self.get_mut().0.lock();
        Pin::new(&mut *guard).poll_shutdown(cx)
    }
}
impl murmur_std_compat::net::Conn for SudokuConnCloseView {
    fn local_addr(&self) -> io::Result<Box<dyn murmur_std_compat::net::Addr>> {
        Ok(Box::new(murmur_std_compat::net::TcpAddr::from(self.0.lock().local_addr()?)))
    }
    fn remote_addr(&self) -> io::Result<Box<dyn murmur_std_compat::net::Addr>> {
        Ok(Box::new(murmur_std_compat::net::TcpAddr::from(self.0.lock().peer_addr()?)))
    }
    fn close(&self) -> io::Result<()> {
        close_stream(&*self.0.lock())
    }
    fn close_read(&self) -> io::Result<()> {
        self.0.lock().shutdown_read()
    }
    fn close_write(&self) -> io::Result<()> {
        self.0.lock().shutdown_write()
    }
}

struct PrefixedRecorderConn {
    conn: SudokuConnHandle,
    prefix: Vec<u8>,
    shared: murmur_common::shared_conn::SharedConn,
}
impl AsyncRead for PrefixedRecorderConn {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.conn).poll_read(cx, buf)
    }
}
impl AsyncWrite for PrefixedRecorderConn {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.conn).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.conn).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.conn).poll_shutdown(cx)
    }
}
impl Stream for PrefixedRecorderConn {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.conn.local_addr()
    }
    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.conn.peer_addr()
    }
    fn shutdown_read(&self) -> io::Result<()> {
        self.conn.shutdown_read()
    }
    fn shutdown_write(&self) -> io::Result<()> {
        self.conn.shutdown_write()
    }
    fn old_conn(&self) -> Option<&dyn murmur_std_compat::net::Conn> {
        self.conn.old_conn()
    }
}
impl BufferedRecorderConn for PrefixedRecorderConn {
    fn get_buffered_and_recorded(&mut self) -> Vec<u8> {
        let mut rest = self.conn.get_buffered_and_recorded();
        let mut out = Vec::with_capacity(self.prefix.len() + rest.len());
        out.extend_from_slice(&self.prefix);
        out.append(&mut rest);
        out
    }

    fn into_raw(self: Box<Self>) -> Box<dyn Stream> {
        Box::new(OldConnAsStream(self.shared))
    }
}

/// The buffered recorder conn: wraps a connection and a shared buffered reader so we can expose
/// buffered bytes. This is used for legacy HTTP mask parsing errors so callers can fall back to a
/// real HTTP server.
struct BufferedRecorderConnImpl {
    reader: BufReader<Box<dyn Stream>>,
    recorder: Vec<u8>,
}
impl AsyncRead for BufferedRecorderConnImpl {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.reader).poll_read(cx, buf);
        if matches!(&poll, Poll::Ready(Ok(()))) {
            let n = buf.filled().len() - before;
            if n > 0 {
                let filled = buf.filled().get(before..).unwrap_or_default().to_vec();
                self.recorder.extend_from_slice(&filled);
            }
        }
        poll
    }
}
impl AsyncWrite for BufferedRecorderConnImpl {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.reader).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.reader).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.reader).poll_shutdown(cx)
    }
}
impl Stream for BufferedRecorderConnImpl {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.reader.get_ref().local_addr()
    }
    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.reader.get_ref().peer_addr()
    }
    fn shutdown_read(&self) -> io::Result<()> {
        self.reader.get_ref().shutdown_read()
    }
    fn shutdown_write(&self) -> io::Result<()> {
        self.reader.get_ref().shutdown_write()
    }
    fn old_conn(&self) -> Option<&dyn murmur_std_compat::net::Conn> {
        self.reader.get_ref().old_conn()
    }
}
impl BufferedRecorderConn for BufferedRecorderConnImpl {
    fn get_buffered_and_recorded(&mut self) -> Vec<u8> {
        let mut out = self.recorder.clone();
        out.extend_from_slice(self.reader.buffer());
        out
    }

    fn into_raw(self: Box<Self>) -> Box<dyn Stream> {
        self.reader.into_inner()
    }
}

struct PreBufferedConn {
    conn: Box<dyn Stream>,
    buf: Vec<u8>,
}
impl AsyncRead for PreBufferedConn {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        if !self.buf.is_empty() {
            let n = self.buf.len().min(buf.remaining());
            let chunk = self.buf.split_at(n).0.to_vec();
            buf.put_slice(&chunk);
            self.buf.drain(..n);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut *self.conn).poll_read(cx, buf)
    }
}
impl AsyncWrite for PreBufferedConn {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.conn).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.conn).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.conn).poll_shutdown(cx)
    }
}
impl Stream for PreBufferedConn {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.conn.local_addr()
    }
    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.conn.peer_addr()
    }
    fn shutdown_read(&self) -> io::Result<()> {
        self.conn.shutdown_read()
    }
    fn shutdown_write(&self) -> io::Result<()> {
        self.conn.shutdown_write()
    }
    fn old_conn(&self) -> Option<&dyn murmur_std_compat::net::Conn> {
        self.conn.old_conn()
    }
}

/// the runtime downlink reader union (`AsyncRead` holding either a `PackedConn` or a
/// `SudokuConnHandle`).
#[allow(
    clippy::large_enum_variant,
    reason = "Packed holds the full PackedConn state machine by value (buffers, bit accumulators, padding rng) while Sudoku is a thin Arc handle, so the size gap is the actual difference in what each variant owns"
)]
pub(crate) enum DownlinkReader {
    Packed(PackedConn),
    Sudoku(SudokuConnHandle),
}
impl AsyncRead for DownlinkReader {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Packed(c) => Pin::new(c).poll_read(cx, buf),
            Self::Sudoku(c) => Pin::new(c).poll_read(cx, buf),
        }
    }
}
impl DownlinkReader {
    fn shutdown_read(&self) -> io::Result<()> {
        match self {
            Self::Packed(c) => c.close_read(),
            Self::Sudoku(c) => c.shutdown_read(),
        }
    }
}

/// the runtime uplink/downlink writer union (`AsyncWrite` holding either a `SudokuConnHandle` or the
/// bandwidth-optimized downlink writer).
pub(crate) enum UplinkOrDownlinkWriter {
    Sudoku(SudokuConnHandle),
    Downlink(DownlinkWriter),
}
impl AsyncWrite for UplinkOrDownlinkWriter {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Self::Sudoku(c) => Pin::new(c).poll_write(cx, buf),
            Self::Downlink(c) => Pin::new(c).poll_write(cx, buf),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Sudoku(c) => Pin::new(c).poll_flush(cx),
            Self::Downlink(c) => Pin::new(c).poll_flush(cx),
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Self::Sudoku(c) => Pin::new(c).poll_shutdown(cx),
            Self::Downlink(c) => Pin::new(c).poll_shutdown(cx),
        }
    }
}
impl UplinkOrDownlinkWriter {
    fn shutdown_write(&self) -> io::Result<()> {
        match self {
            Self::Sudoku(c) => c.shutdown_write(),
            Self::Downlink(_) => Ok(()),
        }
    }
}

/// The directional conn. The writer/closers live behind `Arc<Mutex<_>>` (not just `Mutex<_>`) so
/// the pointer-holder pattern the writer replacement uses (downcasting to it)
/// survives boxing this conn into the crypto layer: `build_server_obfs_conn` keeps a clone of the
/// same `Arc`s to call [`replace_server_downlink_writer`] later without any downcast.
pub(crate) struct DirectionalConn {
    base: murmur_common::shared_conn::SharedConn,
    reader: DownlinkReader,
    writer: Arc<SyncMutex<UplinkOrDownlinkWriter>>,
    closers: Arc<SyncMutex<Vec<Closer>>>,
    close_view: DirectionalCloseView,
}

impl DirectionalConn {
    fn new(
        base: murmur_common::shared_conn::SharedConn,
        reader: DownlinkReader,
        writer: Arc<SyncMutex<UplinkOrDownlinkWriter>>,
        closers: Arc<SyncMutex<Vec<Closer>>>,
    ) -> Self {
        let close_view = DirectionalCloseView { base: base.clone(), closers: Arc::clone(&closers) };
        Self { base, reader, writer, closers, close_view }
    }

    /// Closers are async (see `obfs::sudoku::downlink`) while
    /// `Conn::close`/`close_write` are sync `&self` methods; closers are dispatched onto a
    /// background task, best-effort, mirroring `TunnelServer`'s own `BodyConn` deviation for the
    /// same mismatch.
    fn run_closers(&self) {
        run_closers_on(&self.closers);
    }
}

fn run_closers_on(closers: &Arc<SyncMutex<Vec<Closer>>>) {
    let closers = std::mem::take(&mut *closers.lock());
    for closer in closers {
        tokio::spawn(async move {
            let _ = closer().await;
        });
    }
}

impl AsyncRead for DirectionalConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.reader).poll_read(cx, buf)
    }
}
impl AsyncWrite for DirectionalConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let mut guard = self.writer.lock();
        Pin::new(&mut *guard).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut guard = self.writer.lock();
        Pin::new(&mut *guard).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut guard = self.writer.lock();
        Pin::new(&mut *guard).poll_shutdown(cx)
    }
}
impl Stream for DirectionalConn {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        OldConnAsStream(self.base.clone()).local_addr()
    }
    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        OldConnAsStream(self.base.clone()).peer_addr()
    }
    fn shutdown_read(&self) -> io::Result<()> {
        self.reader.shutdown_read()?;
        OldConnAsStream(self.base.clone()).shutdown_read()
    }
    fn shutdown_write(&self) -> io::Result<()> {
        self.run_closers();
        let writer_err = self.writer.lock().shutdown_write();
        let base_err = OldConnAsStream(self.base.clone()).shutdown_write();
        writer_err.and(base_err)
    }
    /// Unlike the read and write half-closes, a full close also runs the
    /// closers and reaches `base`'s real inner close (dial-cancel, socket close) rather than the
    /// `shutdown_read`/`shutdown_write` composition `close_stream` falls back to when this is
    /// `None`. Exposed through `old_conn` since `Stream` itself has no `close()`.
    fn old_conn(&self) -> Option<&dyn murmur_std_compat::net::Conn> {
        Some(&self.close_view)
    }
}

/// See [`DirectionalConn::old_conn`]. Holds its own clone of the same `SharedConn` `base` wraps
/// (rather than borrowing through `DirectionalConn`'s fields) so it can be a plain struct field
/// with a `'self`-scoped reference, matching `transport-vmess`'s `H2Transport`.
struct DirectionalCloseView {
    base: murmur_common::shared_conn::SharedConn,
    closers: Arc<SyncMutex<Vec<Closer>>>,
}

/// Never actually polled — reached only through [`Stream::old_conn`], whose callers only use the
/// [`murmur_std_compat::net::Conn`] capability methods below — but that trait requires
/// `AsyncRead + AsyncWrite`, so this forwards to the same `SharedConn` `DirectionalConn` itself
/// reads and writes through.
impl AsyncRead for DirectionalCloseView {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().base).poll_read(cx, buf)
    }
}
impl AsyncWrite for DirectionalCloseView {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().base).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().base).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().base).poll_shutdown(cx)
    }
}
impl murmur_std_compat::net::Conn for DirectionalCloseView {
    fn local_addr(&self) -> io::Result<Box<dyn murmur_std_compat::net::Addr>> {
        self.base.local_addr()
    }
    fn remote_addr(&self) -> io::Result<Box<dyn murmur_std_compat::net::Addr>> {
        self.base.remote_addr()
    }
    fn close(&self) -> io::Result<()> {
        run_closers_on(&self.closers);
        self.base.close()
    }
    fn close_read(&self) -> io::Result<()> {
        self.base.close_read()
    }
    fn close_write(&self) -> io::Result<()> {
        run_closers_on(&self.closers);
        self.base.close_write()
    }
}

fn opposite_direction_table(table: &Arc<Table>) -> Arc<Table> {
    table.opposite_direction()
}

fn new_client_downlink_reader(
    raw: Box<dyn Stream>,
    table: &Arc<Table>,
    padding_min: i32,
    padding_max: i32,
    pure_downlink: bool,
) -> Option<DownlinkReader> {
    let downlink_table = opposite_direction_table(table);
    if pure_downlink {
        if Arc::ptr_eq(&downlink_table, table) {
            return None;
        }
        return Some(DownlinkReader::Sudoku(SudokuConnHandle::new(new_conn(
            raw,
            Some(downlink_table),
            padding_min,
            padding_max,
            false,
        ))));
    }
    Some(DownlinkReader::Packed(new_packed_conn(raw, Some(downlink_table), padding_min, padding_max)))
}

fn new_server_downlink_writer_for(
    raw: Box<dyn Stream>,
    table: &Arc<Table>,
    padding_min: i32,
    padding_max: i32,
    pure_downlink: bool,
) -> (UplinkOrDownlinkWriter, Vec<Closer>) {
    let downlink_table = opposite_direction_table(table);
    let (writer, closers) =
        new_server_downlink_writer(raw, Some(downlink_table), padding_min, padding_max, pure_downlink);
    (UplinkOrDownlinkWriter::Downlink(writer), closers)
}

pub(crate) fn build_client_obfs_conn(
    raw: Box<dyn Stream>,
    table: &Arc<Table>,
    padding_min: i32,
    padding_max: i32,
    enable_pure_downlink: bool,
) -> Box<dyn Stream> {
    let shared = murmur_common::shared_conn::SharedConn::new(CancellableStream::new(raw));
    let base_sudoku = SudokuConnHandle::new(new_conn(
        Box::new(OldConnAsStream(shared.clone())),
        Some(Arc::clone(table)),
        padding_min,
        padding_max,
        false,
    ));
    let downlink_reader = new_client_downlink_reader(
        Box::new(OldConnAsStream(shared.clone())),
        table,
        padding_min,
        padding_max,
        enable_pure_downlink,
    );
    match downlink_reader {
        None => Box::new(base_sudoku),
        Some(reader) => Box::new(DirectionalConn::new(
            shared,
            reader,
            Arc::new(SyncMutex::new(UplinkOrDownlinkWriter::Sudoku(base_sudoku))),
            Arc::new(SyncMutex::new(Vec::new())),
        )),
    }
}

/// Handle returned by `build_server_obfs_conn` alongside the boxed conn, so the caller can still
/// swap the downlink writer after the conn has already been boxed and moved into the crypto layer
/// (via a downcast to the directional conn). `shared` is a clone of the
/// same [`murmur_common::shared_conn::SharedConn`] handle the writer/reader were built over, so a
/// replacement writer keeps writing to the same underlying raw conn.
pub(crate) struct ServerObfsHandles {
    pub(crate) shared: murmur_common::shared_conn::SharedConn,
    pub(crate) writer: Arc<SyncMutex<UplinkOrDownlinkWriter>>,
    pub(crate) closers: Arc<SyncMutex<Vec<Closer>>>,
}

pub(crate) fn build_server_obfs_conn(
    raw: Box<dyn Stream>,
    table: &Arc<Table>,
    padding_min: i32,
    padding_max: i32,
    enable_pure_downlink: bool,
    record: bool,
) -> (SudokuConnHandle, DirectionalConn, ServerObfsHandles) {
    let shared = murmur_common::shared_conn::SharedConn::new(CancellableStream::new(raw));
    let uplink_sudoku = SudokuConnHandle::new(new_conn(
        Box::new(OldConnAsStream(shared.clone())),
        Some(Arc::clone(table)),
        padding_min,
        padding_max,
        record,
    ));
    let (downlink_writer, closers) = new_server_downlink_writer_for(
        Box::new(OldConnAsStream(shared.clone())),
        table,
        padding_min,
        padding_max,
        enable_pure_downlink,
    );
    let writer_handle = Arc::new(SyncMutex::new(downlink_writer));
    let closers_handle = Arc::new(SyncMutex::new(closers));
    let directional = DirectionalConn::new(
        shared.clone(),
        DownlinkReader::Sudoku(uplink_sudoku.clone()),
        Arc::clone(&writer_handle),
        Arc::clone(&closers_handle),
    );
    (uplink_sudoku, directional, ServerObfsHandles { shared, writer: writer_handle, closers: closers_handle })
}

fn is_legacy_http_mask_mode(mode: &str) -> bool {
    matches!(mode.trim().to_lowercase().as_str(), "" | "legacy")
}

/// `ClientHandshake`: performs the client-side Sudoku handshake (no target request).
// NOT cancel-safe: the handshake writes its preamble and messages to the socket before it completes, so a dropped call leaves the connection mid-exchange; the arms that await it drop it only when the connection is being torn down.
pub async fn client_handshake(mut raw_conn: Box<dyn Stream>, cfg: &ProtocolConfig) -> Result<Box<dyn Stream>> {
    cfg.validate().map_err(|err| anyhow!("invalid config: {err}"))?;

    if !cfg.disable_http_mask && is_legacy_http_mask_mode(&cfg.http_mask_mode) {
        httpmask::masker::write_random_request_header_with_path_root(
            &mut raw_conn,
            &cfg.server_address,
            &cfg.http_mask_path_root,
        )
        .await
        .map_err(|err| anyhow!("write http mask failed: {err}"))?;
    }

    let choice = pick_client_table(cfg)?;

    let seed = client_aead_seed(&cfg.key);
    let obfs_conn =
        build_client_obfs_conn(raw_conn, &choice.table, cfg.padding_min, cfg.padding_max, cfg.enable_pure_downlink);
    let (psk_c2s, psk_s2c) = derive_psk_directional_bases(&seed);
    let mut rc = new_record_conn(obfs_conn, &cfg.aead_method, &psk_c2s, &psk_s2c)
        .map_err(|err| anyhow!("setup crypto failed: {err}"))?;

    if let Err(err) = kip_handshake_client(
        &mut rc,
        &seed,
        kip_user_hash_from_key(&cfg.key),
        KIP_FEAT_ALL,
        choice.hint,
        choice.has_hint,
    )
    .await
    {
        let _ = close_stream(&rc);
        return Err(err);
    }

    Ok(Box::new(rc))
}

async fn read_first_session_message<C: Stream + ?Sized>(conn: &mut C) -> Result<KipMessage> {
    loop {
        let msg = read_kip_message(conn).await?;
        if msg.typ == KIP_TYPE_KEEP_ALIVE {
            continue;
        }
        return Ok(msg);
    }
}

/// Consumes the legacy HTTP mask. Takes and returns ownership of the shared buffered-reader-like
/// buffer (`r`) rather than borrowing it, since the error path moves it whole into the returned
/// [`BufferedRecorderConnImpl`].
async fn maybe_consume_legacy_http_mask(
    r: BufReader<Box<dyn Stream>>,
    cfg: &ProtocolConfig,
) -> std::result::Result<(BufReader<Box<dyn Stream>>, Vec<u8>), anyhow::Error> {
    if cfg.disable_http_mask || !is_legacy_http_mask_mode(&cfg.http_mask_mode) {
        return Ok((r, Vec::new()));
    }
    let mut r = r;

    let peek = r.fill_buf().await.unwrap_or(&[]);
    let peek_bytes = peek.get(..4.min(peek.len())).unwrap_or_default().to_vec();
    if !httpmask::masker::looks_like_http_request_start(&peek_bytes) {
        return Ok((r, Vec::new()));
    }

    let (consumed, result) = httpmask::masker::consume_header(&mut r).await;
    let Err(err) = result else {
        return Ok((r, consumed));
    };

    let bad_conn = BufferedRecorderConnImpl { reader: r, recorder: consumed };
    Err(suspicious(anyhow!("invalid http header: {err}"), Some(Box::new(bad_conn))))
}

/// Performs the server-side KIP handshake.
///
/// `early_handshake_user_hash` mirrors the early-handshake user-hash check: it
/// is recovered via a runtime type assertion on the raw conn itself, which the boxed stream type
/// deliberately does not support. The equivalent
/// downcast-based recovery function in the httpmask early-handshake port was removed as dead code
/// (its wrapper conn was constructed but the recovery side was never reachable through the boxed
/// `Conn`); skipping this check here is not safely a no-op, though — it is what makes the wrapped
/// conn's caller-side application handshake terminate. The caller (`HttpMaskTunnelServer::wrap_conn`'s
/// `session_authorize`/`handle_ws` paths) already knows the hash at the point the conn is wrapped,
/// so it is threaded through explicitly instead.
pub async fn server_handshake(
    raw_conn: Box<dyn Stream>,
    cfg: &ProtocolConfig,
    early_handshake_user_hash: Option<&str>,
) -> Result<(Box<dyn Stream>, HandshakeMeta)> {
    cfg.validate().map_err(|err| anyhow!("invalid config: {err}"))?;

    if let Some(user_hash) = early_handshake_user_hash {
        return Ok((raw_conn, HandshakeMeta { user_hash: user_hash.to_owned() }));
    }

    let timeout_seconds = u64::try_from(cfg.handshake_timeout_seconds).unwrap_or(0);
    let handshake_timeout = if timeout_seconds == 0 {
        std::time::Duration::from_secs(5)
    } else {
        std::time::Duration::from_secs(timeout_seconds)
    };

    match tokio::time::timeout(handshake_timeout, server_handshake_body(raw_conn, cfg)).await {
        Ok(result) => result,
        Err(_elapsed) => Err(anyhow!(io::Error::from(io::ErrorKind::TimedOut))),
    }
}

/// The server-handshake body once past the early-handshake short-circuit, run under one
/// deadline for the whole exchange (§3 class 4: several sequential reads within one task share a
/// single handshake deadline) instead of a per-conn read-deadline set/clear pair
/// spanning the same calls.
async fn server_handshake_body(
    raw_conn: Box<dyn Stream>,
    cfg: &ProtocolConfig,
) -> Result<(Box<dyn Stream>, HandshakeMeta)> {
    let buf_reader = BufReader::new(raw_conn);

    let (buf_reader, http_header_data) = maybe_consume_legacy_http_mask(buf_reader, cfg).await?;

    let (selected_table, base_conn) = match select_table_by_probe(buf_reader, cfg, &cfg.table_candidates()).await {
        Ok((r, table, pre_read)) => {
            let raw_conn = r.into_inner();
            let base_conn: Box<dyn Stream> = Box::new(PreBufferedConn { conn: raw_conn, buf: pre_read });
            (table, base_conn)
        }
        Err((r, err, probe)) => {
            let raw_conn = r.into_inner();
            let mut combined = http_header_data;
            combined.extend_from_slice(&probe);
            return Err(suspicious(err, Some(Box::new(RecordedConn { conn: raw_conn, recorded: combined }))));
        }
    };

    let (s_conn, obfs_conn, handles) = build_server_obfs_conn(
        base_conn,
        &selected_table,
        cfg.padding_min,
        cfg.padding_max,
        cfg.enable_pure_downlink,
        true,
    );

    let seed = server_aead_seed(&cfg.key);
    let (psk_c2s, psk_s2c) = derive_psk_directional_bases(&seed);
    let mut rc = new_record_conn(Box::new(obfs_conn), &cfg.aead_method, &psk_s2c, &psk_c2s)
        .map_err(|err| anyhow!("setup crypto failed: {err}"))?;

    let suspicious_prefixed = |err: anyhow::Error| {
        suspicious(
            err,
            Some(Box::new(PrefixedRecorderConn {
                conn: s_conn.clone(),
                prefix: http_header_data.clone(),
                shared: handles.shared.clone(),
            })),
        )
    };

    let msg = match read_kip_message(&mut rc).await {
        Ok(msg) => msg,
        Err(err) => return Err(suspicious_prefixed(anyhow!("handshake read failed: {err}"))),
    };
    if msg.typ != KIP_TYPE_CLIENT_HELLO {
        return Err(suspicious_prefixed(anyhow!("unexpected handshake message: {}", msg.typ)));
    }
    let ch = match decode_kip_client_hello_payload(&msg.payload) {
        Ok(ch) => ch,
        Err(err) => return Err(suspicious_prefixed(anyhow!("decode client hello failed: {err}"))),
    };
    if (chrono::Utc::now().timestamp() - ch.timestamp.timestamp()).abs() > KIP_HANDSHAKE_SKEW.num_seconds() {
        return Err(suspicious_prefixed(anyhow!("time skew/replay")));
    }

    let user_hash_hex = hex::encode(ch.user_hash);
    if !GLOBAL_HANDSHAKE_REPLAY.allow(&user_hash_hex, ch.nonce, chrono::Utc::now()) {
        return Err(suspicious_prefixed(anyhow!("replay")));
    }
    let resolved_table = match resolve_client_hello_table(&selected_table, &cfg.table_candidates(), &ch) {
        Ok(t) => t,
        Err(err) => return Err(suspicious_prefixed(anyhow!("resolve table hint failed: {err}"))),
    };
    if !Arc::ptr_eq(&resolved_table, &selected_table) {
        // The downlink writer is rebuilt against the opposite-direction table over the
        // same raw conn. `handles.shared` is a clone of the exact `SharedConn` handle the
        // original writer was built over, so a fresh writer over another clone of it stays
        // byte-identical to the replacement.
        let (new_writer, new_closers) = new_server_downlink_writer_for(
            Box::new(OldConnAsStream(handles.shared.clone())),
            &resolved_table,
            cfg.padding_min,
            cfg.padding_max,
            cfg.enable_pure_downlink,
        );
        *handles.writer.lock() = new_writer;
        *handles.closers.lock() = new_closers;
    }

    let server_ephemeral = match generate_x25519_ephemeral() {
        Ok(k) => k,
        Err(err) => return Err(suspicious_prefixed(anyhow!("ecdh generate failed: {err}"))),
    };
    let shared = match x25519_shared_secret(&server_ephemeral, &ch.client_pub) {
        Ok(s) => s,
        Err(err) => return Err(suspicious_prefixed(anyhow!("ecdh failed: {err}"))),
    };
    let (sess_c2s, sess_s2c) = match derive_session_directional_bases(&seed, &shared, &ch.nonce) {
        Ok(v) => v,
        Err(err) => return Err(suspicious_prefixed(anyhow!("derive session keys failed: {err}"))),
    };

    let mut server_pub = [0u8; KIP_HELLO_PUB_SIZE];
    server_pub.copy_from_slice(PublicKey::from(&server_ephemeral).as_bytes());
    let sh = KipServerHello { nonce: ch.nonce, server_pub, selected_feats: ch.features & KIP_FEAT_ALL };
    if let Err(err) = write_kip_message(&mut rc, KIP_TYPE_SERVER_HELLO, &sh.encode_payload()).await {
        return Err(suspicious_prefixed(anyhow!("write server hello failed: {err}")));
    }
    if let Err(err) = rc.flush().await {
        return Err(suspicious_prefixed(anyhow!("flush server hello failed: {err}")));
    }
    if let Err(err) = rc.rekey(&sess_s2c, &sess_c2s) {
        return Err(suspicious_prefixed(anyhow!("rekey failed: {err}")));
    }

    s_conn.stop_recording();
    let rc: Box<dyn Stream> = Box::new(rc);
    Ok((rc, HandshakeMeta { user_hash: user_hash_hex }))
}

/// `ReadServerSession`: consumes the first post-handshake KIP control message and returns the
/// session intent.
pub async fn read_server_session(mut conn: Box<dyn Stream>, _meta: Option<&HandshakeMeta>) -> Result<ServerSession> {
    let first = read_first_session_message(&mut *conn).await?;

    match first.typ {
        KIP_TYPE_START_UOT => Ok(ServerSession { conn, typ: SessionType::UoT, target: String::new() }),
        KIP_TYPE_START_MUX => Ok(ServerSession { conn, typ: SessionType::Multiplex, target: String::new() }),
        KIP_TYPE_OPEN_TCP => {
            let target = decode_address(&mut &first.payload[..])
                .await
                .map_err(|err| anyhow!("decode target address failed: {err}"))?;
            Ok(ServerSession { conn, typ: SessionType::Tcp, target })
        }
        other => Err(anyhow!("unknown kip message: {other}")),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::mpsc;

    use super::*;
    use crate::address::encode_address;
    use crate::config::default_config;
    use crate::obfs::sudoku::table::{new_table, new_table_with_custom};
    use crate::uot::{read_datagram, write_datagram};
    use murmur_common_net::io::Stream;

    /// In-memory pipe stand-in: a bidirectional in-memory conn.
    struct PipeConn(DuplexStream);

    impl AsyncRead for PipeConn {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for PipeConn {
        fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
        }
    }

    impl Stream for PipeConn {
        fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
            Ok(std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0))
        }

        fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
            Ok(std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0))
        }
    }

    fn new_packed_config(table: Arc<Table>) -> ProtocolConfig {
        let mut cfg = default_config();
        cfg.key = "sudoku-test-key".to_owned();
        cfg.table = Some(table);
        cfg.padding_min = 10;
        cfg.padding_max = 30;
        cfg.enable_pure_downlink = false;
        cfg.server_address = "example.com:443".to_owned();
        cfg.disable_http_mask = true;
        cfg
    }

    async fn packed_conn_round_trip_with_padding(table_type: &str) {
        let payload: [u8; 7] = [0x3a, 0x1f, 0x71, 0x00, 0xff, 0x10, 0x22];
        let (server_end, client_end) = tokio::io::duplex(64 * 1024);
        let table = new_table("roundtrip-seed", table_type);
        let mut writer = new_packed_conn(Box::new(PipeConn(server_end)), Some(Arc::clone(&table)), 30, 80);
        let mut reader = new_packed_conn(Box::new(PipeConn(client_end)), Some(table), 30, 80);

        let write_task = tokio::spawn(async move {
            writer.write_all(&payload).await?;
            writer.flush().await?;
            drop(writer);
            Ok::<(), io::Error>(())
        });

        let read_task = tokio::spawn(async move {
            let mut got = Vec::new();
            reader.read_to_end(&mut got).await?;
            Ok::<Vec<u8>, io::Error>(got)
        });

        let got = tokio::time::timeout(Duration::from_secs(5), read_task)
            .await
            .expect("read timeout")
            .expect("read task")
            .expect("read side error");
        write_task.await.expect("write task").expect("write side error");
        assert_eq!(got, payload, "payload mismatch");
    }

    #[tokio::test]
    async fn packed_conn_round_trip_with_padding_prefer_ascii() {
        packed_conn_round_trip_with_padding("prefer_ascii").await;
    }

    #[tokio::test]
    async fn packed_conn_round_trip_with_padding_prefer_entropy() {
        packed_conn_round_trip_with_padding("prefer_entropy").await;
    }

    /// Reports a packed server error: a non-blocking check.
    async fn report_packed_server_err(
        mut server_err_rx: tokio::sync::oneshot::Receiver<Result<()>>,
        err_tx: &mpsc::Sender<anyhow::Error>,
    ) {
        if let Ok(Err(err)) = server_err_rx.try_recv() {
            let _ = err_tx.send(err).await;
        }
    }

    async fn run_packed_tcp_session(id: usize, cfg: &ProtocolConfig, err_tx: &mpsc::Sender<anyhow::Error>) {
        let (server_conn, client_conn) = tokio::io::duplex(64 * 1024);
        let target = format!("1.1.1.{}:80", (id % 200) + 1);
        let payload = [0x42u8, id as u8];

        let (server_err_tx, server_err_rx) = tokio::sync::oneshot::channel::<Result<()>>();
        let cfg_server = cfg.clone();
        let target_server = target.clone();
        tokio::spawn(async move {
            let result: Result<()> = async {
                let (c, meta) = server_handshake(Box::new(PipeConn(server_conn)), &cfg_server, None)
                    .await
                    .map_err(|err| anyhow!("server handshake tcp: {err}"))?;
                let session = read_server_session(c, Some(&meta))
                    .await
                    .map_err(|err| anyhow!("server read session tcp: {err}"))?;
                if session.typ != SessionType::Tcp {
                    return Err(anyhow!("unexpected session type: {:?}", session.typ));
                }
                if session.target != target_server {
                    return Err(anyhow!("target mismatch want {target_server} got {}", session.target));
                }
                let mut conn = session.conn;
                conn.write_all(&payload).await.map_err(|err| anyhow!("server write: {err}"))?;
                Ok(())
            }
            .await;
            let _ = server_err_tx.send(result);
        });

        let client_cfg = cfg.clone();
        let mut c_conn = match client_handshake(Box::new(PipeConn(client_conn)), &client_cfg).await {
            Ok(c) => c,
            Err(err) => {
                let _ = err_tx.send(anyhow!("client handshake tcp: {err}")).await;
                return;
            }
        };

        let addr_buf = match encode_address(&target) {
            Ok(b) => b,
            Err(err) => {
                let _ = err_tx.send(anyhow!("encode address: {err}")).await;
                return;
            }
        };
        if let Err(err) = write_kip_message(&mut c_conn, KIP_TYPE_OPEN_TCP, &addr_buf).await {
            let _ = err_tx.send(anyhow!("client send open tcp: {err}")).await;
            return;
        }

        let mut buf = vec![0u8; payload.len()];
        if let Err(err) = c_conn.read_exact(&mut buf).await {
            let _ = err_tx.send(anyhow!("client read: {err}")).await;
            return;
        }
        if buf != payload {
            let _ = err_tx.send(anyhow!("payload mismatch want {payload:x?} got {buf:x?}")).await;
            return;
        }

        report_packed_server_err(server_err_rx, err_tx).await;
    }

    async fn run_packed_uot_session(id: usize, cfg: &ProtocolConfig, err_tx: &mpsc::Sender<anyhow::Error>) {
        let (server_conn, client_conn) = tokio::io::duplex(64 * 1024);
        let target = "8.8.8.8:53";
        let payload = [0xaau8, id as u8];

        let (server_err_tx, server_err_rx) = tokio::sync::oneshot::channel::<Result<()>>();
        let cfg_server = cfg.clone();
        tokio::spawn(async move {
            let result: Result<()> = async {
                let (c, meta) = server_handshake(Box::new(PipeConn(server_conn)), &cfg_server, None)
                    .await
                    .map_err(|err| anyhow!("server handshake uot: {err}"))?;
                let session = read_server_session(c, Some(&meta))
                    .await
                    .map_err(|err| anyhow!("server read session uot: {err}"))?;
                if session.typ != SessionType::UoT {
                    return Err(anyhow!("unexpected session type: {:?}", session.typ));
                }
                let mut conn = session.conn;
                write_datagram(&mut conn, target, &payload)
                    .await
                    .map_err(|err| anyhow!("server write datagram: {err}"))?;
                Ok(())
            }
            .await;
            let _ = server_err_tx.send(result);
        });

        let client_cfg = cfg.clone();
        let mut c_conn = match client_handshake(Box::new(PipeConn(client_conn)), &client_cfg).await {
            Ok(c) => c,
            Err(err) => {
                let _ = err_tx.send(anyhow!("client handshake uot: {err}")).await;
                return;
            }
        };

        if let Err(err) = write_kip_message(&mut c_conn, KIP_TYPE_START_UOT, &[]).await {
            let _ = err_tx.send(anyhow!("client start uot: {err}")).await;
            return;
        }

        let (addr, data) = match read_datagram(&mut c_conn).await {
            Ok(v) => v,
            Err(err) => {
                let _ = err_tx.send(anyhow!("client read datagram: {err}")).await;
                return;
            }
        };
        if addr != target {
            let _ = err_tx.send(anyhow!("uot target mismatch want {target} got {addr}")).await;
            return;
        }
        if data != payload {
            let _ = err_tx.send(anyhow!("uot payload mismatch want {payload:x?} got {data:x?}")).await;
            return;
        }

        report_packed_server_err(server_err_rx, err_tx).await;
    }

    #[tokio::test]
    async fn packed_downlink_soak() {
        const SESSIONS: usize = 16;
        let table = new_table("soak-seed", "prefer_ascii");
        let cfg = new_packed_config(table);

        let (err_tx, mut err_rx) = mpsc::channel::<anyhow::Error>(SESSIONS * 2);

        let mut tasks = Vec::with_capacity(SESSIONS * 2);
        for id in 0..SESSIONS {
            let cfg_tcp = cfg.clone();
            let err_tx_tcp = err_tx.clone();
            tasks.push(tokio::spawn(async move {
                run_packed_tcp_session(id, &cfg_tcp, &err_tx_tcp).await;
            }));
            let cfg_uot = cfg.clone();
            let err_tx_uot = err_tx.clone();
            tasks.push(tokio::spawn(async move {
                run_packed_uot_session(id, &cfg_uot, &err_tx_uot).await;
            }));
        }
        drop(err_tx);

        let results = tokio::time::timeout(Duration::from_secs(10), futures::future::join_all(tasks))
            .await
            .expect("soak test timeout");
        for result in results {
            result.expect("session task");
        }

        if let Ok(err) = err_rx.try_recv() {
            panic!("soak error: {err}");
        }
    }

    #[tokio::test]
    async fn custom_table_handshake() {
        let table = new_table_with_custom("custom-seed", "prefer_entropy", "xpxvvpvv").expect("build custom table");
        let cfg = new_packed_config(table);
        let (err_tx, mut err_rx) = mpsc::channel::<anyhow::Error>(2);

        run_packed_tcp_session(42, &cfg, &err_tx).await;
        run_packed_uot_session(43, &cfg, &err_tx).await;
        drop(err_tx);

        if let Ok(err) = err_rx.try_recv() {
            panic!("custom table handshake failed: {err}");
        }
    }

    #[tokio::test]
    async fn user_hash_stable_across_table_rotation() {
        let tables = vec![new_table("seed-a", "prefer_ascii"), new_table("seed-b", "prefer_ascii")];
        let key = "userhash-stability-key";

        let mut server_cfg = default_config();
        server_cfg.key = key.to_owned();
        server_cfg.aead_method = "chacha20-poly1305".to_owned();
        server_cfg.tables = tables;
        server_cfg.padding_min = 0;
        server_cfg.padding_max = 0;
        server_cfg.enable_pure_downlink = true;
        server_cfg.handshake_timeout_seconds = 5;
        server_cfg.disable_http_mask = true;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listen");
        let addr = listener.local_addr().expect("listener addr").to_string();

        const ATTEMPTS: usize = 32;
        let (hash_tx, mut hash_rx) = mpsc::channel::<String>(ATTEMPTS);
        let (err_tx, mut err_rx) = mpsc::channel::<anyhow::Error>(ATTEMPTS);

        let server_cfg_accept = server_cfg.clone();
        tokio::spawn(async move {
            loop {
                let conn = match listener.accept().await {
                    Ok((conn, _)) => conn,
                    Err(_) => return,
                };
                let cfg = server_cfg_accept.clone();
                let hash_tx = hash_tx.clone();
                let err_tx = err_tx.clone();
                tokio::spawn(async move {
                    match server_handshake(Box::new(conn), &cfg, None).await {
                        Ok((_, meta)) => {
                            if meta.user_hash.is_empty() {
                                let _ = err_tx.send(anyhow!("unexpected EOF")).await;
                                return;
                            }
                            let _ = hash_tx.send(meta.user_hash).await;
                        }
                        Err(err) => {
                            let _ = err_tx.send(err).await;
                        }
                    }
                });
            }
        });

        let mut client_cfg = server_cfg.clone();
        client_cfg.server_address = addr.clone();

        for i in 0..ATTEMPTS {
            let raw = match TcpStream::connect(&addr).await {
                Ok(raw) => raw,
                Err(err) => panic!("dial {i}: {err}"),
            };
            let c_conn = match client_handshake(Box::new(raw), &client_cfg).await {
                Ok(c) => c,
                Err(err) => panic!("handshake {i}: {err}"),
            };
            drop(c_conn);
        }

        let mut unique = HashSet::new();
        for _ in 0..ATTEMPTS {
            tokio::select! {
                Some(err) = err_rx.recv() => panic!("server handshake error: {err}"),
                Some(h) = hash_rx.recv() => {
                    assert!(!h.is_empty(), "empty user hash");
                    assert_eq!(h.len(), 16, "unexpected user hash length: {}", h.len());
                    unique.insert(h);
                }
                () = tokio::time::sleep(Duration::from_secs(10)) => panic!("timeout waiting for server handshakes"),
            }
        }
        assert_eq!(
            unique.len(),
            1,
            "user hash should be stable across table rotation; got {} distinct values",
            unique.len()
        );
    }

    /// Hang detection, not a latency budget: high enough that only a task that stopped making
    /// progress trips it, even on an oversubscribed host. Trips here first mean check
    /// `--test-threads` against `available_parallelism`, not the code under test.
    const HANG_DEADLINE: Duration = Duration::from_secs(60);

    /// Concurrent connection count scaled to the host: enough over `available_parallelism` to
    /// force real queueing, with a floor so a low-core host still exercises genuine concurrency.
    fn concurrency_width() -> usize {
        std::thread::available_parallelism().map(std::num::NonZeroUsize::get).unwrap_or(1).saturating_mul(8).max(16)
    }

    /// Reproduces the TLS-write-buffering deadlock class fixed by the `rc.flush()` calls in
    /// `kip_handshake_client` and `server_handshake`: with rustls's `AsyncWrite` buffering
    /// ciphertext internally, a KIP hello write followed by an unflushed await-for-reply can
    /// leave the peer's request sitting in the TLS write buffer forever under contention.
    #[tokio::test]
    async fn concurrent_kip_handshake_over_tls_never_hangs() {
        use murmur_component_ca::keypair::{new_random_tls_key_pair, new_tls_key_pair_loader, KeyPairType};
        use murmur_component_tls::utls::{client as tls_client, server as tls_server, Config as TlsConfig};

        let (cert_pem, key_pem, _fp) = new_random_tls_key_pair(KeyPairType::P256).expect("key generation");
        let loader = new_tls_key_pair_loader(&cert_pem, &key_pem).expect("valid cert");
        let cert_for_server = loader().expect("cert loads");

        let server_tls_config = Arc::new(TlsConfig { certificates: vec![cert_for_server], ..Default::default() });
        let client_tls_config = Arc::new(TlsConfig { insecure_skip_verify: true, ..Default::default() });

        let table = new_table("kip-tls-repro-seed", "prefer_ascii");
        let mut cfg = new_packed_config(table);
        // `n` concurrent handshakes on one runtime share the default 5s wall-clock budget
        // (`config::default_config`'s `handshake_timeout_seconds`); under host load that budget
        // alone can be exceeded even though every handshake keeps making progress (a timing
        // flake, not the hang class this test targets - see `HANG_DEADLINE` below for that).
        cfg.handshake_timeout_seconds = i32::try_from(HANG_DEADLINE.as_secs()).expect("HANG_DEADLINE fits i32 seconds");

        let n = concurrency_width();
        let mut tasks = Vec::with_capacity(n * 2);

        for _ in 0..n {
            let (server_end, client_end) = tokio::io::duplex(64 * 1024);
            let server_tls_config = Arc::clone(&server_tls_config);
            let client_tls_config = Arc::clone(&client_tls_config);
            let cfg_server = cfg.clone();
            let cfg_client = cfg.clone();

            tasks.push(tokio::spawn(async move {
                let tls_conn = tls_server(Box::new(PipeConn(server_end)), server_tls_config);
                let (_, meta) =
                    tokio::time::timeout(HANG_DEADLINE, server_handshake(Box::new(tls_conn), &cfg_server, None))
                        .await
                        .expect("server handshake timed out: hello stuck in TLS write buffer")
                        .expect("server handshake failed");
                assert!(!meta.user_hash.is_empty(), "empty user hash");
            }));

            tasks.push(tokio::spawn(async move {
                let tls_conn = tls_client(Box::new(PipeConn(client_end)), client_tls_config);
                tokio::time::timeout(HANG_DEADLINE, client_handshake(Box::new(tls_conn), &cfg_client))
                    .await
                    .expect("client handshake timed out: hello stuck in TLS write buffer")
                    .expect("client handshake failed");
            }));
        }

        for task in tasks {
            task.await.expect("handshake task panicked");
        }
    }
    /// Regression test for the P0 finding this replaces the read-deadline-observing version
    /// of: with a single table candidate (the default config shape), `select_table_by_probe` used
    /// to return without ever reading from the wire, and `server_handshake` cleared the read
    /// deadline right there — before the unauthenticated client hello read (`read_kip_message`)
    /// even started, so a client that sent nothing hung the handshake forever. The Stream
    /// migration replaced the per-conn read-deadline set/clear pair with one
    /// `tokio::time::timeout` wrapping the whole handshake body (§3 class 4), which cannot be
    /// cleared early because there is no separate clear step at all; this test observes the same
    /// regression class by asserting the handshake actually times out instead of hanging when no
    /// client hello ever arrives.
    #[tokio::test]
    async fn server_handshake_times_out_while_awaiting_client_hello() {
        let table = new_table("deadline-seed", "prefer_ascii");
        let mut cfg = new_packed_config(table);
        cfg.handshake_timeout_seconds = 1;
        let (server_end, client_end) = tokio::io::duplex(4096);

        let handshake_task =
            tokio::spawn(async move { server_handshake(Box::new(PipeConn(server_end)), &cfg, None).await });

        let result = tokio::time::timeout(Duration::from_secs(5), handshake_task)
            .await
            .expect("server_handshake must time out on its own instead of hanging forever")
            .expect("handshake task panicked");
        assert!(result.is_err(), "expected a timeout error since the client never sent a hello");
        drop(client_end);
    }

    /// A connection stand-in that only captures written bytes; used to observe the exact wire
    /// bytes a real client-side obfs+AEAD stack produces for one KIP message, without needing a
    /// live peer.
    struct CaptureConn {
        buf: Arc<SyncMutex<Vec<u8>>>,
    }
    impl AsyncRead for CaptureConn {
        fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    impl AsyncWrite for CaptureConn {
        fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            self.buf.lock().extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    impl Stream for CaptureConn {
        fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
            Ok(std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0))
        }
        fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
            Ok(std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0))
        }
    }

    /// Regression test for the recorder-duplication finding: the legacy-mask consumer seeded the
    /// recorder with the consumed bytes plus the reader's buffer, and the buffered-and-recorded
    /// accessor then appended the buffer a second time, so a malformed request whose first line
    /// fails method validation but whose
    /// remaining header lines were already pulled into the `BufReader`'s internal buffer (e.g.
    /// `HEADX / HTTP/1.1\r\nHost: a\r\n\r\n` sent as one write) reached a fallback with
    /// `Host: a\r\n\r\n` duplicated. This also proves the buffered-and-recorded accessor followed
    /// by `into_raw` reconstructs the exact client byte stream in order with nothing lost or
    /// duplicated: bytes sent only after the rejection (`tail`) must still arrive, unrepeated,
    /// through the conn `into_raw` returns.
    #[tokio::test]
    async fn suspicious_error_preserves_exact_byte_stream_legacy_mask_path() {
        let table = new_table("suspicious-legacy-seed", "prefer_ascii");
        let mut cfg = new_packed_config(table);
        cfg.disable_http_mask = false;

        let (server_end, mut client_end) = tokio::io::duplex(4096);
        let header = b"HEADX / HTTP/1.1\r\nHost: a\r\n\r\n".to_vec();
        let tail = b"EXTRA-TAIL-BYTES-AFTER-ERROR".to_vec();
        let tail_len = tail.len();

        let (recorded_tx, recorded_rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
        let (raw_tx, raw_rx) = tokio::sync::oneshot::channel::<Vec<u8>>();

        let handshake_task = tokio::spawn(async move {
            let err = match server_handshake(Box::new(PipeConn(server_end)), &cfg, None).await {
                Ok(_) => panic!("a malformed legacy-mask request must be rejected"),
                Err(err) => err,
            };
            let suspicious = err.downcast::<SuspiciousError>().expect("expected a SuspiciousError");
            let mut conn = suspicious.conn.expect("suspicious error must carry the recorder conn");
            let recorded = conn.get_buffered_and_recorded();
            recorded_tx.send(recorded).expect("send recorded bytes");

            let mut raw = conn.into_raw();
            let mut tail_buf = vec![0u8; tail_len];
            raw.read_exact(&mut tail_buf).await.expect("read tail bytes from raw conn");
            raw_tx.send(tail_buf).expect("send raw tail bytes");
        });

        client_end.write_all(&header).await.expect("write malformed header");

        let recorded = recorded_rx.await.expect("recorded channel closed");
        assert_eq!(recorded, header, "get_buffered_and_recorded must return exactly the client's header bytes once");

        client_end.write_all(&tail).await.expect("write tail bytes");
        let raw_tail = raw_rx.await.expect("raw channel closed");
        assert_eq!(raw_tail, tail, "into_raw must expose the live raw conn for bytes sent after the error");

        handshake_task.await.expect("handshake task panicked");
    }

    /// Same property as above, exercised via a garbage first message at the KIP phase (past the
    /// obfs/AEAD layer) instead of the legacy HTTP mask parser, over `PrefixedRecorderConn`. Uses
    /// a real client-side obfs+AEAD encoder so the server decodes successfully and rejects on
    /// message type, not on framing — deterministic, no raw-garbage timing/hang risk.
    #[tokio::test]
    async fn suspicious_error_preserves_exact_byte_stream_kip_phase() {
        let table = new_table("suspicious-kip-seed", "prefer_ascii");
        let mut cfg = new_packed_config(Arc::clone(&table));
        cfg.disable_http_mask = true;

        let capture = Arc::new(SyncMutex::new(Vec::new()));
        let seed = client_aead_seed(&cfg.key);
        let obfs_conn = build_client_obfs_conn(
            Box::new(CaptureConn { buf: Arc::clone(&capture) }),
            &table,
            cfg.padding_min,
            cfg.padding_max,
            cfg.enable_pure_downlink,
        );
        let (psk_c2s, psk_s2c) = derive_psk_directional_bases(&seed);
        let mut rc_client =
            new_record_conn(obfs_conn, &cfg.aead_method, &psk_c2s, &psk_s2c).expect("client record conn");
        write_kip_message(&mut rc_client, KIP_TYPE_KEEP_ALIVE, &[]).await.expect("write keep-alive message");
        rc_client.flush().await.expect("flush keep-alive message");
        drop(rc_client);
        let encoded_message = capture.lock().clone();
        assert!(!encoded_message.is_empty(), "the client stack must have produced wire bytes");

        let (server_end, mut client_end) = tokio::io::duplex(4096);
        let tail = b"KIP-PHASE-TAIL-BYTES".to_vec();
        let tail_len = tail.len();

        let (recorded_tx, recorded_rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
        let (raw_tx, raw_rx) = tokio::sync::oneshot::channel::<Vec<u8>>();

        let handshake_task = tokio::spawn(async move {
            let err = match server_handshake(Box::new(PipeConn(server_end)), &cfg, None).await {
                Ok(_) => panic!("a non-client-hello first KIP message must be rejected"),
                Err(err) => err,
            };
            let suspicious = err.downcast::<SuspiciousError>().expect("expected a SuspiciousError");
            let mut conn = suspicious.conn.expect("suspicious error must carry the recorder conn");
            let recorded = conn.get_buffered_and_recorded();
            recorded_tx.send(recorded).expect("send recorded bytes");

            let mut raw = conn.into_raw();
            let mut tail_buf = vec![0u8; tail_len];
            raw.read_exact(&mut tail_buf).await.expect("read tail bytes from raw conn");
            raw_tx.send(tail_buf).expect("send raw tail bytes");
        });

        client_end.write_all(&encoded_message).await.expect("write encoded keep-alive message");

        let recorded = recorded_rx.await.expect("recorded channel closed");
        assert_eq!(
            recorded, encoded_message,
            "get_buffered_and_recorded must return exactly the raw bytes read for the rejected message, no duplicates"
        );

        client_end.write_all(&tail).await.expect("write tail bytes");
        let raw_tail = raw_rx.await.expect("raw channel closed");
        assert_eq!(raw_tail, tail, "into_raw must expose the live raw conn for bytes sent after the error");

        handshake_task.await.expect("handshake task panicked");
    }
}
