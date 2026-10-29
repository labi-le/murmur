use std::any::Any;
use std::fmt;
use std::future::{poll_fn, Future};
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio_util::sync::CancellationToken;

use murmur_compat::sing_buf::get;
use murmur_compat::sing_buf::{new_size, Buffer, BUFFER_SIZE};
use murmur_sing::network::ReadWaitOptions;
use murmur_std_compat::net::Conn;

use crate::io::{close_stream, ExtendedStream, Stream};

use super::deadline::conn::{is_conn, new_conn};
use super::deadline::pipe_sing::is_pipe;

pub use super::deadline::pipe_sing::pipe;

pub use crate::packet::packet::{ReaderWithUpstream, WithUpstream, WriterWithUpstream};

pub trait EarlyConn: Send + Sync {
    fn need_handshake(&self) -> bool;
}

/// Blanket `as_any` for every `UpstreamNode` implementor, so each impl block stops repeating
/// the identical `fn as_any(&self) -> &dyn Any { self }` override.
pub trait AsAny: Any {
    fn as_any(&self) -> &dyn Any;
}

/// Bound on `UpstreamNode` itself, not on a broader always-satisfied bound like `Any`:
/// `common/net/io.rs` forwards `Conn`/`PacketConn`/etc. through `Box`, but never `UpstreamNode`,
/// so `Box<dyn UpstreamNode>` (or any `Box<dyn X: UpstreamNode>`) never satisfies this blanket
/// merely by boxing something that already does. `as_any` on a boxed value therefore always
/// dispatches through the box to the real conn's own vtable instead of answering for the box.
impl<T: UpstreamNode + 'static> AsAny for T {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// The wrapper-chain assertions gathered into one vocabulary. An erased value cannot be
/// tested for a trait it does not carry, so a node reports its links here instead.
pub trait UpstreamNode: AsAny + Send + Sync {
    fn upstream_node(&self) -> Option<&dyn UpstreamNode> {
        None
    }

    fn net_conn_node(&self) -> Option<&dyn UpstreamNode> {
        None
    }

    fn upstream_reader_node(&self) -> Option<&dyn UpstreamNode> {
        None
    }

    fn upstream_writer_node(&self) -> Option<&dyn UpstreamNode> {
        None
    }

    /// The reader-replaceable flag; `None` is the missing method, where the walk
    /// stops instead of descending.
    fn reader_replaceable(&self) -> Option<bool> {
        None
    }

    /// The writer-replaceable flag; `None` as above.
    fn writer_replaceable(&self) -> Option<bool> {
        None
    }

    fn reader_possibly_replaceable(&self) -> bool {
        false
    }

    fn writer_possibly_replaceable(&self) -> bool {
        false
    }

    /// A type test of the early-conn capability.
    fn early_conn(&self) -> Option<&dyn EarlyConn> {
        None
    }

    fn front_headroom(&self) -> Option<i32> {
        None
    }

    fn rear_headroom(&self) -> Option<i32> {
        None
    }

    fn lazy_headroom(&self) -> bool {
        false
    }

    fn reader_mtu(&self) -> Option<i32> {
        None
    }

    fn writer_mtu(&self) -> Option<i32> {
        None
    }
}

#[async_trait]
pub trait ExtendedReader: AsyncRead + Unpin + UpstreamNode {
    async fn read_buffer(&mut self, buffer: &mut Buffer) -> io::Result<()>;
}

#[async_trait]
pub trait ExtendedWriter: AsyncWrite + Unpin + UpstreamNode {
    async fn write_buffer(&mut self, buffer: &mut Buffer) -> io::Result<()>;
}

/// `ExtendedReader` + `ExtendedWriter` + a net conn.
///
/// Built on [`crate::io::ExtendedStream`] rather than the old `ExtendedConn`: the old
/// supertrait's raw-conn capability had no real consumer anywhere in the workspace — every
/// call site was itself another forwarding definition, never a downcast — so it is gone, not
/// carried forward as a dead method.
#[async_trait]
pub trait ExtendedConn: ExtendedStream + UpstreamNode {
    async fn read_buffer(&mut self, buffer: &mut Buffer) -> io::Result<()>;

    async fn write_buffer(&mut self, buffer: &mut Buffer) -> io::Result<()>;
}

// S11: remove in U8, when the final old-`Conn` bridge is deleted.
impl<C: Conn + UpstreamNode> UpstreamNode for crate::io::OldConnAsStream<C> {
    fn upstream_node(&self) -> Option<&dyn UpstreamNode> {
        Some(&self.0)
    }
}

pub trait CachedReader: Send + Sync {
    fn read_cached(&mut self) -> Option<Buffer>;
}

pub type CountFunc = Box<dyn Fn(i64) + Send + Sync>;

pub const DEFAULT_HEADROOM: i32 = 1024;

pub fn calculate_front_headroom(writer: &dyn UpstreamNode) -> i32 {
    let mut headroom = 0;
    let mut current = Some(writer);
    while let Some(node) = current {
        if node.lazy_headroom() {
            return DEFAULT_HEADROOM;
        }
        headroom += node.front_headroom().unwrap_or(0);
        current = node.upstream_writer_node().or_else(|| node.upstream_node());
    }
    headroom
}

fn calculate_reader_front_headroom(reader: &dyn UpstreamNode) -> i32 {
    let mut headroom = 0;
    let mut current = Some(reader);
    while let Some(node) = current {
        if node.lazy_headroom() {
            return DEFAULT_HEADROOM;
        }
        headroom += node.front_headroom().unwrap_or(0);
        current = node.upstream_reader_node().or_else(|| node.upstream_node());
    }
    headroom
}

pub fn calculate_rear_headroom(writer: &dyn UpstreamNode) -> i32 {
    let mut headroom = 0;
    let mut current = Some(writer);
    while let Some(node) = current {
        if node.lazy_headroom() {
            return DEFAULT_HEADROOM;
        }
        headroom += node.rear_headroom().unwrap_or(0);
        current = node.upstream_writer_node().or_else(|| node.upstream_node());
    }
    headroom
}

fn calculate_reader_mtu(reader: &dyn UpstreamNode) -> i32 {
    let mut mtu = 0;
    let mut current = Some(reader);
    while let Some(node) = current {
        if node.lazy_headroom() {
            return 0;
        }
        if let Some(node_mtu) = node.reader_mtu() {
            if node_mtu > mtu {
                mtu = node_mtu;
            }
        }
        current = node.upstream_reader_node().or_else(|| node.upstream_node());
    }
    mtu
}

fn calculate_writer_mtu(writer: &dyn UpstreamNode) -> i32 {
    let mut mtu = 0;
    let mut current = Some(writer);
    while let Some(node) = current {
        if node.lazy_headroom() {
            return 0;
        }
        if let Some(node_mtu) = node.writer_mtu() {
            if mtu == 0 || node_mtu > 0 && node_mtu < mtu {
                mtu = node_mtu;
            }
        }
        current = node.upstream_writer_node().or_else(|| node.upstream_node());
    }
    mtu
}

pub fn calculate_mtu(reader: &dyn UpstreamNode, writer: &dyn UpstreamNode) -> i32 {
    let reader_mtu = calculate_reader_mtu(reader);
    let writer_mtu = calculate_writer_mtu(writer);
    if reader_mtu == 0 && writer_mtu == 0 || reader_mtu > BUFFER_SIZE || writer_mtu > BUFFER_SIZE {
        return 0;
    }
    let reader_headroom = calculate_reader_front_headroom(reader);
    if reader_mtu > writer_mtu {
        reader_mtu + reader_headroom
    } else {
        writer_mtu + reader_headroom
    }
}

pub fn new_read_wait_options(source: &dyn UpstreamNode, destination: &dyn UpstreamNode) -> ReadWaitOptions {
    ReadWaitOptions {
        front_headroom: headroom_as_usize(calculate_front_headroom(destination)),
        rear_headroom: headroom_as_usize(calculate_rear_headroom(destination)),
        mtu: headroom_as_usize(calculate_mtu(source, destination)),
    }
}

/// Headroom/mtu values travel as `i32`; a negative one clamps to zero, and `i32` always fits the
/// target's `usize`.
fn headroom_as_usize(value: i32) -> usize {
    usize::try_from(value.max(0)).unwrap_or_default()
}

pub fn unwrap_reader(reader: &dyn UpstreamNode) -> &dyn UpstreamNode {
    if !reader.reader_replaceable().unwrap_or(false) {
        return reader;
    }
    if let Some(upstream) = reader.upstream_reader_node() {
        return unwrap_reader(upstream);
    }
    if let Some(upstream) = reader.upstream_node() {
        return unwrap_reader(upstream);
    }
    reader
}

pub fn unwrap_writer(writer: &dyn UpstreamNode) -> &dyn UpstreamNode {
    if !writer.writer_replaceable().unwrap_or(false) {
        return writer;
    }
    if let Some(upstream) = writer.upstream_writer_node() {
        return unwrap_writer(upstream);
    }
    if let Some(upstream) = writer.upstream_node() {
        return unwrap_writer(upstream);
    }
    writer
}

pub async fn write_buffer(writer: &mut dyn ExtendedWriter, buffer: &mut Buffer) -> io::Result<usize> {
    let front_headroom = calculate_front_headroom(&*writer);
    let rear_headroom = calculate_rear_headroom(&*writer);
    let mut resized;
    let buffer =
        if headroom_as_usize(front_headroom) > buffer.start() || headroom_as_usize(rear_headroom) > buffer.free_len() {
            #[expect(
                clippy::cast_possible_truncation,
                clippy::cast_possible_wrap,
                reason = "a sing buffer is allocated from an i32 size, so its length always fits"
            )]
            let buffer_len = buffer.len() as i32;
            let mut new_buffer = new_size(buffer_len + front_headroom + rear_headroom);
            new_buffer.resize(headroom_as_usize(front_headroom), 0);
            new_buffer.write_bytes(buffer.bytes())?;
            buffer.release();
            resized = new_buffer;
            &mut resized
        } else {
            buffer
        };
    let data_len = buffer.len();
    writer.write_buffer(buffer).await?;
    Ok(data_len)
}

#[derive(Debug)]
pub struct ExtendedReaderWrapper<R> {
    reader: R,
}

#[derive(Debug)]
pub struct ExtendedWriterWrapper<W> {
    writer: W,
}

/// An extended conn that keeps deadlines and close reachable.
///
/// Holds a [`crate::io::CancellableStream`] rather than a bare `Box<dyn Stream>` so deadlines and
/// close still reach a wrapped `TcpStream` (whose [`Stream::old_conn`] is `None`) instead of
/// silently no-op'ing.
pub struct ExtendedConnWrapper {
    conn: crate::io::CancellableStream<Box<dyn Stream>>,
}

impl fmt::Debug for ExtendedConnWrapper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExtendedConnWrapper").finish_non_exhaustive()
    }
}

impl<R> UpstreamNode for ExtendedReaderWrapper<R> where R: AsyncRead + Unpin + Send + Sync + 'static {}

impl<W> UpstreamNode for ExtendedWriterWrapper<W> where W: AsyncWrite + Unpin + Send + Sync + 'static {}

impl UpstreamNode for ExtendedConnWrapper {}

impl<R> AsyncRead for ExtendedReaderWrapper<R>
where
    R: AsyncRead + Unpin,
{
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().reader).poll_read(cx, buf)
    }
}

impl<W> AsyncWrite for ExtendedWriterWrapper<W>
where
    W: AsyncWrite + Unpin,
{
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().writer).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_shutdown(cx)
    }
}

#[async_trait]
impl<R> ExtendedReader for ExtendedReaderWrapper<R>
where
    R: AsyncRead + Unpin + Send + Sync + 'static,
{
    async fn read_buffer(&mut self, buffer: &mut Buffer) -> io::Result<()> {
        match self.reader.read(buffer.free_bytes()).await {
            Ok(n) => {
                buffer.truncate(n);
                Ok(())
            }
            Err(err) => {
                buffer.truncate(0);
                Err(err)
            }
        }
    }
}

#[async_trait]
impl<W> ExtendedWriter for ExtendedWriterWrapper<W>
where
    W: AsyncWrite + Unpin + Send + Sync + 'static,
{
    async fn write_buffer(&mut self, buffer: &mut Buffer) -> io::Result<()> {
        let result = self.writer.write_all(buffer.bytes()).await;
        buffer.release();
        result
    }
}

impl AsyncRead for ExtendedConnWrapper {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().conn).poll_read(cx, buf)
    }
}

impl AsyncWrite for ExtendedConnWrapper {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().conn).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().conn).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().conn).poll_shutdown(cx)
    }
}

impl Stream for ExtendedConnWrapper {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.conn.local_addr()
    }
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.conn.peer_addr()
    }
    fn shutdown_read(&self) -> io::Result<()> {
        self.conn.shutdown_read()
    }
    fn shutdown_write(&self) -> io::Result<()> {
        self.conn.shutdown_write()
    }
    fn old_conn(&self) -> Option<&dyn Conn> {
        Some(self)
    }
}

// S11: remove in U8, when the final old-`Conn` bridge is deleted.
impl Conn for ExtendedConnWrapper {
    fn local_addr(&self) -> io::Result<Box<dyn murmur_std_compat::net::Addr>> {
        self.conn.old_local_addr()
    }
    fn remote_addr(&self) -> io::Result<Box<dyn murmur_std_compat::net::Addr>> {
        self.conn.old_remote_addr()
    }
    fn close(&self) -> io::Result<()> {
        self.conn.old_close()
    }
    fn close_read(&self) -> io::Result<()> {
        self.conn.old_close_read()
    }
    fn close_write(&self) -> io::Result<()> {
        self.conn.old_close_write()
    }
    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.conn.old_set_deadline(deadline)
    }
    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.conn.old_set_read_deadline(deadline)
    }
    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.conn.old_set_write_deadline(deadline)
    }
}

impl ExtendedStream for ExtendedConnWrapper {
    /// Both replaceable flags are hardcoded `true`.
    fn reader_replaceable(&self) -> bool {
        true
    }
    fn writer_replaceable(&self) -> bool {
        true
    }
}

#[async_trait]
impl ExtendedConn for ExtendedConnWrapper {
    async fn read_buffer(&mut self, buffer: &mut Buffer) -> io::Result<()> {
        match self.conn.read(buffer.free_bytes()).await {
            Ok(n) => {
                buffer.truncate(n);
                Ok(())
            }
            Err(err) => {
                buffer.truncate(0);
                Err(err)
            }
        }
    }

    async fn write_buffer(&mut self, buffer: &mut Buffer) -> io::Result<()> {
        let result = self.conn.write_all(buffer.bytes()).await;
        buffer.release();
        result
    }
}

/// Wraps an `AsyncRead` as an extended reader. An erased `dyn AsyncRead` cannot be re-tested for
/// already being extended, so a caller holding one uses it directly.
pub fn new_extended_reader<R>(reader: R) -> Box<dyn ExtendedReader>
where
    R: AsyncRead + Unpin + Send + Sync + 'static,
{
    Box::new(ExtendedReaderWrapper { reader })
}

/// The pass-through case is in [`new_extended_reader`].
pub fn new_extended_writer<W>(writer: W) -> Box<dyn ExtendedWriter>
where
    W: AsyncWrite + Unpin + Send + Sync + 'static,
{
    Box::new(ExtendedWriterWrapper { writer })
}

/// The pass-through case is in [`new_extended_reader`].
pub fn new_extended_conn<C: Stream + 'static>(conn: C) -> Box<dyn ExtendedConn> {
    Box::new(ExtendedConnWrapper { conn: crate::io::CancellableStream::new(Box::new(conn)) })
}

/// Like `ExtendedConnWrapper`, but generic over a caller's own [`UpstreamNode`] so its
/// node link can forward to the wrapped value instead of losing it behind `Box<dyn Stream>`.
struct ExtendedConnNodeWrapper<C> {
    conn: C,
}

impl<C> fmt::Debug for ExtendedConnNodeWrapper<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExtendedConnNodeWrapper").finish_non_exhaustive()
    }
}

impl<C: Stream> AsyncRead for ExtendedConnNodeWrapper<C> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().conn).poll_read(cx, buf)
    }
}

impl<C: Stream> AsyncWrite for ExtendedConnNodeWrapper<C> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().conn).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().conn).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().conn).poll_shutdown(cx)
    }
}

impl<C: UpstreamNode> UpstreamNode for ExtendedConnNodeWrapper<C> {
    fn upstream_node(&self) -> Option<&dyn UpstreamNode> {
        Some(&self.conn)
    }
}

impl<C: Stream> Stream for ExtendedConnNodeWrapper<C> {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.conn.local_addr()
    }
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.conn.peer_addr()
    }
    fn shutdown_read(&self) -> io::Result<()> {
        self.conn.shutdown_read()
    }
    fn shutdown_write(&self) -> io::Result<()> {
        self.conn.shutdown_write()
    }
    fn old_conn(&self) -> Option<&dyn Conn> {
        self.conn.old_conn()
    }
}

impl<C: Stream> ExtendedStream for ExtendedConnNodeWrapper<C> {
    fn reader_replaceable(&self) -> bool {
        true
    }
    fn writer_replaceable(&self) -> bool {
        true
    }
}

#[async_trait]
impl<C: Stream + UpstreamNode> ExtendedConn for ExtendedConnNodeWrapper<C> {
    async fn read_buffer(&mut self, buffer: &mut Buffer) -> io::Result<()> {
        match self.conn.read(buffer.free_bytes()).await {
            Ok(n) => {
                buffer.truncate(n);
                Ok(())
            }
            Err(err) => {
                buffer.truncate(0);
                Err(err)
            }
        }
    }

    async fn write_buffer(&mut self, buffer: &mut Buffer) -> io::Result<()> {
        let result = self.conn.write_all(buffer.bytes()).await;
        buffer.release();
        result
    }
}

/// Like [`new_extended_conn`], for a caller holding a value that is also a [`UpstreamNode`]: the
/// wrap keeps it discoverable through the node walk instead of erasing it behind `Box<dyn Stream>`.
pub fn new_extended_conn_from_node<C: Stream + UpstreamNode + 'static>(conn: C) -> Box<dyn ExtendedConn> {
    Box::new(ExtendedConnNodeWrapper { conn })
}

/// Wraps a stream in the deadline layer; a pipe is returned unchanged.
pub fn new_deadline_conn<C: Stream + 'static>(conn: C) -> Box<dyn ExtendedConn> {
    let conn = new_extended_conn(conn);
    if is_pipe(AsAny::as_any(&*conn)) || is_pipe(unwrap_reader(&*conn).as_any()) {
        return conn;
    }
    if is_conn(AsAny::as_any(&*conn)) || is_conn(unwrap_reader(&*conn).as_any()) {
        return conn;
    }
    Box::new(DeadlineConn { conn: new_conn(conn) })
}

/// [`new_conn`]'s conn, whose buffer half is declared here rather than in the deadline module.
pub struct DeadlineConn {
    conn: super::deadline::conn::Conn,
}

impl fmt::Debug for DeadlineConn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeadlineConn").finish_non_exhaustive()
    }
}

impl AsyncRead for DeadlineConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().conn).poll_read(cx, buf)
    }
}

impl AsyncWrite for DeadlineConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().conn).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().conn).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().conn).poll_shutdown(cx)
    }
}

impl UpstreamNode for DeadlineConn {
    fn upstream_node(&self) -> Option<&dyn UpstreamNode> {
        None
    }

    /// The reader-replaceable flag, which the walk honours.
    fn reader_replaceable(&self) -> Option<bool> {
        Some(self.conn.reader_replaceable())
    }

    fn writer_replaceable(&self) -> Option<bool> {
        Some(self.conn.writer_replaceable())
    }
}

impl Stream for DeadlineConn {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Stream::local_addr(&self.conn)
    }
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Stream::peer_addr(&self.conn)
    }
    fn shutdown_read(&self) -> io::Result<()> {
        Stream::shutdown_read(&self.conn)
    }
    fn shutdown_write(&self) -> io::Result<()> {
        Stream::shutdown_write(&self.conn)
    }
    /// The wrapped `deadline::conn::Conn` still implements the old `Conn` (kept for
    /// `component-tls`'s not-yet-converted `server`), with real deadline/close behaviour beyond
    /// this bridge's own defaults, so it is exposed here too.
    fn old_conn(&self) -> Option<&dyn Conn> {
        Some(&self.conn)
    }
}

impl ExtendedStream for DeadlineConn {
    fn reader_replaceable(&self) -> bool {
        self.conn.reader_replaceable()
    }
    fn writer_replaceable(&self) -> bool {
        self.conn.writer_replaceable()
    }
}

#[async_trait]
impl ExtendedConn for DeadlineConn {
    /// Reads the buffer half, which the deadline layer declares as its local
    /// `BufferConn`.
    async fn read_buffer(&mut self, buffer: &mut Buffer) -> io::Result<()> {
        super::deadline::conn::BufferConn::read_buffer(&mut self.conn, buffer).await
    }

    async fn write_buffer(&mut self, buffer: &mut Buffer) -> io::Result<()> {
        super::deadline::conn::BufferConn::write_buffer(&mut self.conn, buffer).await
    }
}

pub fn need_handshake(conn: &dyn UpstreamNode) -> bool {
    let mut current = Some(conn);
    while let Some(node) = current {
        if let Some(early_conn) = node.early_conn() {
            return early_conn.need_handshake();
        }
        current = node.upstream_node();
    }
    false
}

/// One direction of [`relay_streams`].
struct RelayDirection {
    buffer: Vec<u8>,
    filled: usize,
    written: usize,
    need_flush: bool,
    /// Bytes read from `src`, used to tell a half-closed direction's peer that is still active
    /// from one that has gone silent.
    progress: u64,
}

impl RelayDirection {
    fn new() -> Self {
        let buffer = get(BUFFER_SIZE);
        Self { buffer, filled: 0, written: 0, need_flush: false, progress: 0 }
    }

    /// One copy step; `Ok(())` marks a clean end of stream. Flushes `dst` whenever
    /// `src` has no more data ready right now, mirroring `tokio::io::copy`:
    /// a TLS `dst` can report a write as consumed while the ciphertext still sits in its
    /// internal buffer, and only `poll_flush` guarantees it reaches the peer.
    fn poll(&mut self, cx: &mut Context<'_>, src: &mut dyn Stream, dst: &mut dyn Stream) -> Poll<io::Result<()>> {
        loop {
            if self.written < self.filled {
                let pending = self.buffer.get(self.written..self.filled).unwrap_or_default();
                match Pin::new(&mut *dst).poll_write(cx, pending) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                    Poll::Ready(Ok(n)) => {
                        self.written += n;
                        self.need_flush = true;
                        continue;
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                }
            }
            self.filled = 0;
            self.written = 0;
            let mut read_buf = ReadBuf::new(&mut self.buffer);
            match Pin::new(&mut *src).poll_read(cx, &mut read_buf) {
                Poll::Pending => {
                    if self.need_flush {
                        match Pin::new(&mut *dst).poll_flush(cx) {
                            Poll::Pending => return Poll::Pending,
                            Poll::Ready(Ok(())) => self.need_flush = false,
                            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                        }
                    }
                    return Poll::Pending;
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        if self.need_flush {
                            match Pin::new(&mut *dst).poll_flush(cx) {
                                Poll::Pending => return Poll::Pending,
                                Poll::Ready(Ok(())) => self.need_flush = false,
                                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                            }
                        }
                        return Poll::Ready(Ok(()));
                    }
                    self.filled = n;
                    self.progress = self.progress.saturating_add(n as u64);
                }
            }
        }
    }
}

impl Drop for RelayDirection {
    fn drop(&mut self) {
        let buffer = std::mem::take(&mut self.buffer);
        if !buffer.is_empty() {
            let _ = murmur_compat::sing_buf::put(buffer);
        }
    }
}

/// Relays both directions of `left`/`right` and reports whether `ctx` cancelled the relay. Both
/// directions are polled in one future, copying through the plain `AsyncRead`/`AsyncWrite` halves.
/// `ctx` is the cancellation interrupter, folded into the loop. Full close and half-close go
/// through [`close_stream`]/[`Stream::shutdown_write`], which reach the wrapped old
/// `Conn::close`/`close_write` exactly as before when `src`/`dst` are [`ConnAsStreamRef`]s (see
/// [`relay_inner`]).
async fn relay_streams_inner(ctx: Option<&CancellationToken>, left: &mut dyn Stream, right: &mut dyn Stream) -> bool {
    relay_streams_with_drain_timeout(ctx, left, right, HALF_CLOSE_IDLE_TIMEOUT).await
}

/// Idle grace after one direction ends before the still-open direction is considered abandoned.
/// A peer that half-closes and keeps reading stays connected while it makes progress; one that
/// only sent a CONNECT and vanished is reaped instead of pinning a socket until the upstream
/// server decides to close.
///
/// The reference relay (`mihomo`'s `Relay`) waits for the second copy without a bound. This idle
/// cap is a deliberate, documented deviation: it changes only the abandoned half-close case, and
/// bounds the accepted sockets an aborted `CONNECT` can pin.
const HALF_CLOSE_IDLE_TIMEOUT: Duration = Duration::from_secs(15);

async fn relay_streams_with_drain_timeout(
    ctx: Option<&CancellationToken>,
    left: &mut dyn Stream,
    right: &mut dyn Stream,
    drain_timeout: Duration,
) -> bool {
    let mut right_to_left = RelayDirection::new();
    let mut left_to_right = RelayDirection::new();
    let mut cancel: Option<Pin<Box<dyn Future<Output = ()> + Send + '_>>> = match ctx {
        Some(ctx) => Some(Box::pin(ctx.cancelled())),
        None => None,
    };
    let mut cancelled = false;
    let mut right_to_left_done = false;
    let mut left_to_right_done = false;
    let mut drain: Option<(Pin<Box<tokio::time::Sleep>>, u64, u64)> = None;

    poll_fn(|cx| {
        if let Some(cancel) = cancel.as_mut() {
            if !cancelled && cancel.as_mut().poll(cx).is_ready() {
                cancelled = true;
                let _ = close_stream(&*left);
                let _ = close_stream(&*right);
            }
        }

        // Evaluate both directions before acting on either: closing `left` the moment
        // `right_to_left` fails would otherwise poison `left_to_right`'s read before it gets a
        // chance, this same cycle, to drain bytes the peer already delivered (and symmetrically
        // for `right`), silently dropping data a caller already confirmed as written (review
        // finding: `review_full_duplex_relay_with_stalled_download_still_reads_upload` under load).
        let right_to_left_result = (!right_to_left_done).then(|| right_to_left.poll(cx, right, left));
        let left_to_right_result = (!left_to_right_done).then(|| left_to_right.poll(cx, left, right));

        if let Some(result) = right_to_left_result {
            match result {
                Poll::Pending => {}
                Poll::Ready(Ok(())) => {
                    right_to_left_done = true;
                    let _ = left.shutdown_write();
                }
                Poll::Ready(Err(_)) => {
                    right_to_left_done = true;
                    let _ = close_stream(&*left);
                }
            }
        }
        if let Some(result) = left_to_right_result {
            match result {
                Poll::Pending => {}
                Poll::Ready(Ok(())) => {
                    left_to_right_done = true;
                    let _ = right.shutdown_write();
                }
                Poll::Ready(Err(_)) => {
                    left_to_right_done = true;
                    let _ = close_stream(&*right);
                }
            }
        }

        if right_to_left_done && left_to_right_done {
            return Poll::Ready(());
        }
        if right_to_left_done || left_to_right_done {
            let progress = (left_to_right.progress, right_to_left.progress);
            let (sleep, left_progress, right_progress) =
                drain.get_or_insert_with(|| (Box::pin(tokio::time::sleep(drain_timeout)), progress.0, progress.1));
            if *left_progress != progress.0 || *right_progress != progress.1 {
                *left_progress = progress.0;
                *right_progress = progress.1;
                sleep.as_mut().reset(tokio::time::Instant::now() + drain_timeout);
            }
            if sleep.as_mut().poll(cx).is_ready() {
                let _ = close_stream(&*left);
                let _ = close_stream(&*right);
                return Poll::Ready(());
            }
        }
        Poll::Pending
    })
    .await;

    let _ = close_stream(&*left);
    let _ = close_stream(&*right);
    cancelled
}

/// `Relay`, over a [`Stream`] pair.
pub async fn relay_streams(left: &mut dyn Stream, right: &mut dyn Stream) {
    relay_streams_inner(None, left, right).await;
}

/// Bridges a borrowed old `Conn` into [`Stream`], for [`relay_inner`]'s two old-`Conn`
/// entry points below. `local_addr`/`peer_addr` are never called by the relay loop, so they
/// report `Unsupported` instead of duplicating `io.rs`'s private old-`Addr`-to-`SocketAddr`
/// conversion. `old_conn` answers `Some`, so [`close_stream`] reaches the wrapped `Conn::close`.
struct ConnAsStreamRef<'a>(&'a mut dyn Conn);

impl AsyncRead for ConnAsStreamRef<'_> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().0).poll_read(cx, buf)
    }
}

impl AsyncWrite for ConnAsStreamRef<'_> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.get_mut().0).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().0).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().0).poll_shutdown(cx)
    }
}

impl Stream for ConnAsStreamRef<'_> {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "ConnAsStreamRef::local_addr: relay never calls this"))
    }
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "ConnAsStreamRef::peer_addr: relay never calls this"))
    }
    fn shutdown_read(&self) -> io::Result<()> {
        self.0.close_read()
    }
    fn shutdown_write(&self) -> io::Result<()> {
        self.0.close_write()
    }
    fn old_conn(&self) -> Option<&dyn Conn> {
        Some(&*self.0)
    }
}

/// `Relay`. Bridges the crate's two remaining old-`Conn` relay entry points — [`relay`],
/// called by `murmur-tunnel`'s `connection::handle_socket`, `murmur-listener`'s
/// `inbound::vmess_interop_support` and `snell::server` tests, plus
/// `super::context::relay_context`, called by `murmur-transport-shadowtls`'s `server` — onto
/// [`relay_streams_inner`] via [`ConnAsStreamRef`], so there is exactly one relay loop instead of
/// a duplicated old/new pair.
pub(crate) async fn relay_inner(
    ctx: Option<&CancellationToken>,
    left_conn: &mut dyn Conn,
    right_conn: &mut dyn Conn,
) -> bool {
    relay_streams_inner(ctx, &mut ConnAsStreamRef(left_conn), &mut ConnAsStreamRef(right_conn)).await
}

pub async fn relay(left_conn: &mut dyn Conn, right_conn: &mut dyn Conn) {
    relay_inner(None, left_conn, right_conn).await;
}

#[cfg(test)]
mod tests {
    struct Stutter {
        inner: tokio::net::TcpStream,
        armed: std::sync::Arc<std::sync::atomic::AtomicBool>,
        skip: bool,
    }

    impl tokio::io::AsyncRead for Stutter {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
        }
    }

    impl tokio::io::AsyncWrite for Stutter {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            let this = self.get_mut();
            if this.armed.load(std::sync::atomic::Ordering::SeqCst) && !this.skip {
                this.skip = true;
                cx.waker().wake_by_ref();
                return std::task::Poll::Pending;
            }
            this.skip = false;
            std::pin::Pin::new(&mut this.inner).poll_write(cx, buf)
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }

    impl murmur_std_compat::net::Conn for Stutter {
        fn local_addr(&self) -> std::io::Result<Box<dyn murmur_std_compat::net::Addr>> {
            murmur_std_compat::net::Conn::local_addr(&self.inner)
        }
        fn remote_addr(&self) -> std::io::Result<Box<dyn murmur_std_compat::net::Addr>> {
            murmur_std_compat::net::Conn::remote_addr(&self.inner)
        }
        fn close(&self) -> std::io::Result<()> {
            murmur_std_compat::net::Conn::close(&self.inner)
        }
    }

    /// A minimal same-process PEM section reader: (label, decoded DER) pairs, good enough for the
    /// one self-signed test certificate below. Kept local instead of depending on `component::ca`
    /// or `component::tls` (crate split: this module already sits in the crate those two
    /// transitively depend on, so a dev-dependency the other way would cycle).
    fn pem_sections(pem: &str) -> Vec<(String, Vec<u8>)> {
        let mut sections = Vec::new();
        let mut label = None;
        let mut body = String::new();
        for line in pem.lines() {
            if let Some(rest) = line.strip_prefix("-----BEGIN ") {
                label = rest.strip_suffix("-----").map(str::to_owned);
                body.clear();
                continue;
            }
            if line.starts_with("-----END ") {
                if let Some(l) = label.take() {
                    use base64::Engine as _;
                    if let Ok(der) = base64::engine::general_purpose::STANDARD.decode(&body) {
                        sections.push((l, der));
                    }
                }
                continue;
            }
            if label.is_some() {
                body.push_str(line.trim());
            }
        }
        sections
    }

    struct StutterTlsClientConn(tokio_rustls::client::TlsStream<Box<dyn murmur_std_compat::net::Conn>>);

    impl tokio::io::AsyncRead for StutterTlsClientConn {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }

    impl tokio::io::AsyncWrite for StutterTlsClientConn {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::pin::Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().0).poll_flush(cx)
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
        }
    }

    impl murmur_std_compat::net::Conn for StutterTlsClientConn {
        fn local_addr(&self) -> std::io::Result<Box<dyn murmur_std_compat::net::Addr>> {
            self.0.get_ref().0.local_addr()
        }
        fn remote_addr(&self) -> std::io::Result<Box<dyn murmur_std_compat::net::Addr>> {
            self.0.get_ref().0.remote_addr()
        }
        fn close(&self) -> std::io::Result<()> {
            self.0.get_ref().0.close()
        }
    }

    #[derive(Debug)]
    struct NoVerify;

    impl rustls::client::danger::ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms.supported_schemes()
        }
    }

    async fn stutter_tls_pair() -> (
        StutterTlsClientConn,
        tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
        std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};

        let cert_pem = include_str!("testdata/stutter_tls_cert.pem");
        let key_pem = include_str!("testdata/stutter_tls_key.pem");
        let cert_der = pem_sections(cert_pem)
            .into_iter()
            .find(|(label, _)| label == "CERTIFICATE")
            .map(|(_, der)| CertificateDer::from(der))
            .expect("parse test certificate");
        let key_der = pem_sections(key_pem)
            .into_iter()
            .find(|(label, _)| label == "PRIVATE KEY")
            .map(|(_, der)| PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der)))
            .expect("parse test private key");

        let server_config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("rustls default protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .expect("build test tls server config");
        let client_config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("rustls default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(NoVerify))
        .with_no_client_auth();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (client_raw, (server_raw, _)) =
            tokio::try_join!(tokio::net::TcpStream::connect(addr), listener.accept()).expect("pair");
        let armed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stutter: Box<dyn murmur_std_compat::net::Conn> =
            Box::new(Stutter { inner: client_raw, armed: std::sync::Arc::clone(&armed), skip: false });

        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(client_config));
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_config));
        let server_name = ServerName::try_from("localhost").unwrap();
        let (client_tls, server_tls) =
            tokio::try_join!(connector.connect(server_name, stutter), acceptor.accept(server_raw)).expect("handshake");
        (StutterTlsClientConn(client_tls), server_tls, armed)
    }

    /// Regression test for the flush defect fixed above: `RelayDirection::poll` used to never
    /// call `poll_flush` on `dst`. `tokio_rustls`'s `poll_write` already drains its ciphertext to
    /// the underlying socket as long as that socket accepts it, so on an idle loopback pair the
    /// bytes reach the peer even without a flush; the defect only strands ciphertext when the
    /// underlying `poll_write` returns `Pending` partway through draining — real backpressure, or
    /// (here) a conn that stutters once on purpose. `Stutter` forces exactly that partial write
    /// once, after the handshake, so this test fails on the pre-fix parent and passes post-fix.
    #[tokio::test]
    async fn relay_flushes_tls_after_partial_socket_write() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (client_tls, mut server_tls, armed) = stutter_tls_pair().await;
        armed.store(true, std::sync::atomic::Ordering::SeqCst);

        let app_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind app");
        let app_addr = app_listener.local_addr().expect("app addr");
        let (mut app_peer, (app_conn, _)) =
            tokio::try_join!(tokio::net::TcpStream::connect(app_addr), app_listener.accept()).expect("app pair");
        let mut left: Box<dyn murmur_std_compat::net::Conn> = Box::new(app_conn);
        let mut right: Box<dyn murmur_std_compat::net::Conn> = Box::new(client_tls);
        tokio::spawn(async move {
            super::relay_inner(None, &mut *left, &mut *right).await;
        });

        let message = b"first-flight";
        app_peer.write_all(message).await.expect("write");
        let mut received = vec![0u8; message.len()];
        tokio::time::timeout(std::time::Duration::from_secs(5), server_tls.read_exact(&mut received))
            .await
            .expect("relay must flush TLS ciphertext stranded by a partial socket write")
            .expect("read");
        assert_eq!(&received, message);
    }

    /// Regression for `agent://ReviewNetS1`'s P2, exercised through the live constructor every
    /// outbound conn goes through (`adapter/outbound/base.rs:512 new_deadline_conn`): a read
    /// dropped while `Pending`, then the deadline cleared and re-armed, must not leave the next
    /// read racing an abandoned cancel future.
    #[tokio::test]
    async fn new_deadline_conn_survives_a_dropped_read_then_clear_rearm() {
        use std::io;
        use std::net::SocketAddr;
        use std::pin::Pin;
        use std::task::{Context, Poll};
        use std::time::Duration;

        use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
        use tokio::time::Instant;

        use crate::io::{ExtendedStream, Stream};

        struct Dx(DuplexStream);
        impl AsyncRead for Dx {
            fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
                Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
            }
        }
        impl AsyncWrite for Dx {
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
        impl Stream for Dx {
            fn local_addr(&self) -> io::Result<SocketAddr> {
                Ok("127.0.0.1:1".parse().unwrap())
            }
            fn peer_addr(&self) -> io::Result<SocketAddr> {
                Ok("127.0.0.1:2".parse().unwrap())
            }
        }
        impl ExtendedStream for Dx {}

        let (mut writer, reader) = tokio::io::duplex(64);
        let mut conn = super::new_deadline_conn(Dx(reader));

        conn.old_conn().unwrap().set_read_deadline(Some(Instant::now() + Duration::from_millis(30))).unwrap();
        let mut buf = [0u8; 1];
        let dropped = tokio::time::timeout(Duration::from_millis(5), conn.read(&mut buf)).await;
        assert!(dropped.is_err(), "the read must still be Pending when it is dropped");

        tokio::time::sleep(Duration::from_millis(60)).await;
        conn.old_conn().unwrap().set_read_deadline(None).unwrap();
        conn.old_conn().unwrap().set_read_deadline(Some(Instant::now() + Duration::from_secs(60))).unwrap();

        writer.write_all(b"z").await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), conn.read_exact(&mut buf))
            .await
            .expect("must not hang")
            .expect("read through new_deadline_conn after a dropped read + clear/rearm must succeed");
        assert_eq!(buf[0], b'z');
    }

    struct MarkerNode;

    impl super::UpstreamNode for MarkerNode {}

    #[test]
    fn as_any_reaches_the_boxed_node_not_the_box() {
        let boxed: Box<dyn super::UpstreamNode> = Box::new(MarkerNode);
        assert!(boxed.as_any().downcast_ref::<MarkerNode>().is_some(), "expected the boxed MarkerNode, got the box");
    }

    async fn tcp_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (client, (server, _)) =
            tokio::try_join!(tokio::net::TcpStream::connect(addr), listener.accept()).expect("pair");
        (client, server)
    }

    /// The right side finishing (EOF) must half-close only the left side's write half — the peer
    /// on the left sees EOF, but the still-open right-to-left... left-to-right direction (the
    /// left peer writing, the right peer reading) must keep working until it finishes on its own.
    #[tokio::test]
    async fn relay_streams_forwards_half_close_from_the_right_and_keeps_the_left_to_right_direction_open() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut left, mut left_peer) = tcp_pair().await;
        let (mut right, mut right_peer) = tcp_pair().await;

        let relay_task = tokio::spawn(async move {
            super::relay_streams(&mut left, &mut right).await;
            (left, right)
        });

        right_peer.shutdown().await.expect("right peer half-closes its write side");
        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), left_peer.read(&mut buf))
            .await
            .expect("left peer must see EOF once the right side finishes")
            .expect("read");
        assert_eq!(n, 0, "left peer must observe EOF, not an error, from the half-close");

        let message = b"left-to-right still open";
        left_peer.write_all(message).await.expect("left peer can still write");
        let mut received = vec![0u8; message.len()];
        tokio::time::timeout(std::time::Duration::from_secs(5), right_peer.read_exact(&mut received))
            .await
            .expect("the direction that has not finished must still relay data")
            .expect("read");
        assert_eq!(&received, message);

        drop(left_peer);
        drop(right_peer);
        let (mut left, mut right) = tokio::time::timeout(std::time::Duration::from_secs(5), relay_task)
            .await
            .expect("relay must finish once both peers are gone")
            .expect("relay task must not panic");

        // Full close on both sides: a read attempted directly on the conns relay just finished
        // with must fail or return EOF immediately, not hang.
        let mut buf = [0u8; 1];
        let left_read = tokio::time::timeout(std::time::Duration::from_secs(2), left.read(&mut buf)).await;
        assert!(left_read.is_ok(), "left must be fully closed, not hung, after relay finishes");
        let right_read = tokio::time::timeout(std::time::Duration::from_secs(2), right.read(&mut buf)).await;
        assert!(right_read.is_ok(), "right must be fully closed, not hung, after relay finishes");
    }

    /// The mirror of the test above: the left side finishing first must half-close only the
    /// right side's write half, leaving right-to-left open.
    #[tokio::test]
    async fn relay_streams_forwards_half_close_from_the_left_and_keeps_the_right_to_left_direction_open() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut left, mut left_peer) = tcp_pair().await;
        let (mut right, mut right_peer) = tcp_pair().await;

        tokio::spawn(async move {
            super::relay_streams(&mut left, &mut right).await;
        });

        left_peer.shutdown().await.expect("left peer half-closes its write side");
        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), right_peer.read(&mut buf))
            .await
            .expect("right peer must see EOF once the left side finishes")
            .expect("read");
        assert_eq!(n, 0, "right peer must observe EOF, not an error, from the half-close");

        let message = b"right-to-left still open";
        right_peer.write_all(message).await.expect("right peer can still write");
        let mut received = vec![0u8; message.len()];
        tokio::time::timeout(std::time::Duration::from_secs(5), left_peer.read_exact(&mut received))
            .await
            .expect("the direction that has not finished must still relay data")
            .expect("read");
        assert_eq!(&received, message);
    }

    /// A peer that half-closes and then goes silent must not pin the relay, and so the accepted
    /// socket, until the upstream server decides to close: the idle drain closes both sides.
    #[tokio::test]
    async fn a_half_closed_relay_reaps_a_silent_peer_after_the_drain_timeout() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut left, mut left_peer) = tcp_pair().await;
        let (mut right, mut right_peer) = tcp_pair().await;

        let relay_task = tokio::spawn(async move {
            super::relay_streams_with_drain_timeout(None, &mut left, &mut right, std::time::Duration::from_millis(100))
                .await;
        });

        left_peer.shutdown().await.expect("left peer half-closes its write side");
        tokio::time::timeout(std::time::Duration::from_secs(2), relay_task)
            .await
            .expect("a silent half-closed peer must be reaped")
            .expect("relay task must not panic");

        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(std::time::Duration::from_secs(2), right_peer.read(&mut buf))
            .await
            .expect("right peer read must not hang after the relay closed");
        assert!(matches!(read, Ok(0) | Err(_)), "right peer must observe the closed relay, got {read:?}");
    }

    /// The drain deadline is idle-based: a peer that keeps sending after the other side
    /// half-closed must stay connected past the timeout.
    #[tokio::test]
    async fn an_active_peer_after_half_close_survives_past_the_drain_timeout() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (mut left, mut left_peer) = tcp_pair().await;
        let (mut right, mut right_peer) = tcp_pair().await;

        let relay_task = tokio::spawn(async move {
            super::relay_streams_with_drain_timeout(None, &mut left, &mut right, std::time::Duration::from_millis(200))
                .await;
        });

        left_peer.shutdown().await.expect("left peer half-closes its write side");
        for _ in 0..8 {
            right_peer.write_all(b"x").await.expect("right peer write");
            let mut byte = [0u8; 1];
            tokio::time::timeout(std::time::Duration::from_secs(1), left_peer.read_exact(&mut byte))
                .await
                .expect("the active direction must keep flowing")
                .expect("read");
            tokio::time::sleep(std::time::Duration::from_millis(60)).await;
        }
        assert!(!relay_task.is_finished(), "an active half-closed relay must not be reaped");

        drop(left_peer);
        drop(right_peer);
        tokio::time::timeout(std::time::Duration::from_secs(2), relay_task)
            .await
            .expect("relay must finish once both peers are gone")
            .expect("relay task must not panic");
    }

    /// [`relay`]'s old-`Conn` entry point must forward the same half-close behaviour through
    /// [`ConnAsStreamRef`], proving the bridge, not just [`relay_streams`] directly.
    #[tokio::test]
    async fn relay_bridges_half_close_through_conn_as_stream_ref() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (left, mut left_peer) = tcp_pair().await;
        let (right, mut right_peer) = tcp_pair().await;
        let mut left: Box<dyn murmur_std_compat::net::Conn> = Box::new(left);
        let mut right: Box<dyn murmur_std_compat::net::Conn> = Box::new(right);

        tokio::spawn(async move {
            super::relay(&mut *left, &mut *right).await;
        });

        right_peer.shutdown().await.expect("right peer half-closes its write side");
        let mut buf = [0u8; 1];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), left_peer.read(&mut buf))
            .await
            .expect("left peer must see EOF once the right side finishes")
            .expect("read");
        assert_eq!(n, 0);

        let message = b"bridged relay still forwards";
        left_peer.write_all(message).await.expect("left peer can still write");
        let mut received = vec![0u8; message.len()];
        tokio::time::timeout(std::time::Duration::from_secs(5), right_peer.read_exact(&mut received))
            .await
            .expect("the direction that has not finished must still relay data")
            .expect("read");
        assert_eq!(&received, message);
    }
}
