//! Adapts [`crate::record`]'s async-fn record API onto `poll`-based `AsyncRead`/`AsyncWrite`,
//! for the application-data phase once the handshake has switched to traffic keys. One in-flight
//! record operation per direction is kept alive across polls (moving the owned reader/writer half
//! into the future and back out on completion) rather than re-issued from scratch, since
//! reissuing would redecrypt/resend.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, ReadHalf, WriteHalf};

use crate::handshake::CONTENT_TYPE_APPLICATION_DATA;
use crate::record::{RecordLayer, RecordReader, RecordWriter};

type ReadResult<R> = (RecordReader<R>, anyhow::Result<(u8, Vec<u8>)>);
type WriteResult<W> = (RecordWriter<W>, anyhow::Result<()>);

enum ReadState<R> {
    Idle(RecordReader<R>),
    Reading(Pin<Box<dyn Future<Output = ReadResult<R>> + Send + Sync>>),
    Poisoned,
}

enum WriteState<W> {
    Idle(RecordWriter<W>),
    Writing(Pin<Box<dyn Future<Output = WriteResult<W>> + Send + Sync>>),
    Poisoned,
}

/// How many records carrying no plaintext may go unread before the peer counts as stuck.
const MAX_EMPTY_RECORDS: u32 = 32;
const MAX_WRITE_PLAINTEXT: usize = 16 * 1024 - 1;

pub struct RealityStream<S> {
    read_state: ReadState<ReadHalf<S>>,
    write_state: WriteState<WriteHalf<S>>,
    write_waiter: Option<Waker>,
    leftover: Vec<u8>,
    leftover_pos: usize,
    empty_records: u32,
    cipher_suite: u16,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static> RealityStream<S> {
    pub fn new(record_layer: RecordLayer<S>) -> Self {
        let (reader, writer) = record_layer.split();
        Self {
            read_state: ReadState::Idle(reader),
            write_state: WriteState::Idle(writer),
            write_waiter: None,
            leftover: Vec::new(),
            leftover_pos: 0,
            empty_records: 0,
            cipher_suite: 0,
        }
    }

    /// Records the negotiated TLS 1.3 cipher suite, which the record layer does not otherwise
    /// expose to a caller that only holds the stream.
    #[must_use]
    pub fn with_cipher_suite(mut self, cipher_suite: u16) -> Self {
        self.cipher_suite = cipher_suite;
        self
    }

    #[must_use]
    pub const fn cipher_suite(&self) -> u16 {
        self.cipher_suite
    }

    /// The application-data plaintext already decrypted but not yet handed to the reader.
    pub fn take_buffered_incoming(&mut self) -> Vec<u8> {
        let buffered = if self.leftover_pos < self.leftover.len() {
            self.leftover.split_off(self.leftover_pos)
        } else {
            Vec::new()
        };
        self.leftover.clear();
        self.leftover_pos = 0;
        buffered
    }

    fn poll_pending_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match std::mem::replace(&mut self.write_state, WriteState::Poisoned) {
            WriteState::Idle(writer) => {
                self.write_state = WriteState::Idle(writer);
                Poll::Ready(Ok(()))
            }
            WriteState::Writing(mut fut) => match fut.as_mut().poll(cx) {
                Poll::Pending => {
                    self.write_state = WriteState::Writing(fut);
                    Poll::Pending
                }
                Poll::Ready((writer, Ok(()))) => {
                    self.write_state = WriteState::Idle(writer);
                    Poll::Ready(Ok(()))
                }
                Poll::Ready((_, Err(err))) => Poll::Ready(Err(io_err(err))),
            },
            WriteState::Poisoned => Poll::Ready(Err(io::Error::other("REALITY: write state poisoned"))),
        }
    }

    fn poll_write_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let result = self.poll_pending_write(cx);
        if result.is_pending() {
            if let Some(waiter) = &mut self.write_waiter {
                waiter.clone_from(cx.waker());
            } else {
                self.write_waiter = Some(cx.waker().clone());
            }
        } else {
            self.write_waiter = None;
        }
        result
    }
}

/// Omits the in-flight record futures, whose state is not printable.
impl<S> core::fmt::Debug for RealityStream<S> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RealityStream")
            .field("leftover_pos", &self.leftover_pos)
            .field("empty_records", &self.empty_records)
            .finish_non_exhaustive()
    }
}

fn io_err(err: anyhow::Error) -> io::Error {
    io::Error::other(err)
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static> AsyncRead for RealityStream<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        // A write-then-read caller may not flush; backpressure must not block full-duplex reads.
        let write_result = self.poll_pending_write(cx);
        // Driving the record with the reader's waker must not strand a separate write task.
        if let Some(waiter) = self.write_waiter.take() {
            if !waiter.will_wake(cx.waker()) {
                waiter.wake();
            }
        }
        if let Poll::Ready(Err(err)) = write_result {
            return Poll::Ready(Err(err));
        }
        if self.leftover_pos < self.leftover.len() {
            let n = (self.leftover.len() - self.leftover_pos).min(buf.remaining());
            let (_, pending) = self.leftover.split_at(self.leftover_pos);
            let (chunk, _) = pending.split_at(n);
            buf.put_slice(chunk);
            self.leftover_pos += n;
            if self.leftover_pos == self.leftover.len() {
                self.leftover.clear();
                self.leftover_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        loop {
            match std::mem::replace(&mut self.read_state, ReadState::Poisoned) {
                ReadState::Idle(mut reader) => {
                    self.read_state = ReadState::Reading(Box::pin(async move {
                        let result = reader.read_record().await;
                        (reader, result)
                    }));
                }
                ReadState::Reading(mut fut) => match fut.as_mut().poll(cx) {
                    Poll::Pending => {
                        self.read_state = ReadState::Reading(fut);
                        return Poll::Pending;
                    }
                    Poll::Ready((reader, result)) => {
                        self.read_state = ReadState::Idle(reader);
                        match result {
                            Err(err) => return Poll::Ready(Err(io_err(err))),
                            Ok((content_type, payload)) => {
                                if content_type != CONTENT_TYPE_APPLICATION_DATA {
                                    // Post-handshake NewSessionTicket or a stray alert: not
                                    // application data, discard and read the next record.
                                    continue;
                                }
                                if payload.is_empty() {
                                    // A record may hold no plaintext, and a zero-byte read
                                    // would end a tunnel that is still live: the
                                    // These are skipped too, bounded the same way.
                                    self.empty_records += 1;
                                    if self.empty_records > MAX_EMPTY_RECORDS {
                                        return Poll::Ready(Err(io::Error::other("REALITY: too many empty records")));
                                    }
                                    continue;
                                }
                                self.empty_records = 0;
                                let n = payload.len().min(buf.remaining());
                                let (chunk, _) = payload.split_at(n);
                                buf.put_slice(chunk);
                                if n < payload.len() {
                                    self.leftover = payload;
                                    self.leftover_pos = n;
                                }
                                return Poll::Ready(Ok(()));
                            }
                        }
                    }
                },
                ReadState::Poisoned => return Poll::Ready(Err(io::Error::other("REALITY: read state poisoned"))),
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static> AsyncWrite for RealityStream<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        std::task::ready!(self.poll_write_ready(cx))?;
        let WriteState::Idle(mut writer) = std::mem::replace(&mut self.write_state, WriteState::Poisoned) else {
            return Poll::Ready(Err(io::Error::other("REALITY: write state poisoned")));
        };
        let n = buf.len().min(MAX_WRITE_PLAINTEXT);
        let chunk = buf.split_at(n).0.to_vec();
        self.write_state = WriteState::Writing(Box::pin(async move {
            let result = writer.write_encrypted(CONTENT_TYPE_APPLICATION_DATA, &chunk).await;
            (writer, result)
        }));
        // Ownership accepts this prefix now; a later caller may grow or replace its buffer.
        if let Poll::Ready(Err(err)) = self.poll_pending_write(cx) {
            return Poll::Ready(Err(err));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        std::task::ready!(self.poll_write_ready(cx))?;
        match &mut self.write_state {
            WriteState::Idle(writer) => Pin::new(writer.inner_mut()).poll_flush(cx),
            WriteState::Writing(_) | WriteState::Poisoned => {
                Poll::Ready(Err(io::Error::other("REALITY: write state poisoned")))
            }
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        std::task::ready!(self.poll_write_ready(cx))?;
        match &mut self.write_state {
            WriteState::Idle(writer) => Pin::new(writer.inner_mut()).poll_shutdown(cx),
            WriteState::Writing(_) | WriteState::Poisoned => {
                Poll::Ready(Err(io::Error::other("REALITY: write state poisoned")))
            }
        }
    }
}

/// The REALITY conn wrapper, reduced to what a split conn can still do.
///
/// The handshake consumes the transport and [`RealityStream::new`] splits it into a read and a
/// write half, so nothing downstream can reach the socket itself. The callers that need a real
/// `close` capture the OS socket first and hand it back with [`RealityConnAddrs::with_closer`].
#[derive(Debug)]
pub struct RealityCloser {
    socket: Arc<socket2::Socket>,
}

impl RealityCloser {
    /// `None` when the pre-handshake conn exposes no OS socket to clone, in which case the
    /// stream keeps the trait defaults and close stays a no-op.
    pub fn capture<S: murmur_common_net::io::Stream + ?Sized>(stream: &S) -> Option<Self> {
        let socket = stream.as_socket()?.try_clone().ok()?;
        Some(Self { socket: Arc::new(socket) })
    }

    fn shutdown(&self, how: std::net::Shutdown) -> io::Result<()> {
        self.socket.shutdown(how)
    }
}

/// The I/O arms exist only because [`murmur_std_compat::net::Conn`] requires them. Nothing in this
/// workspace reads or writes through a `Stream::old_conn` value -- [`murmur_common_net::io::CancellableStream`] and
/// [`murmur_common_net::io::StreamAsOldConn`] both forward their `AsyncRead`/`AsyncWrite` to the wrapped `Stream` and
/// use `old_conn` only for `close`/deadlines -- so the arms report `Unsupported` instead of
/// pretending to be a stream.
impl AsyncRead for RealityCloser {
    fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::new(io::ErrorKind::Unsupported, "reality close view carries no read side")))
    }
}

impl AsyncWrite for RealityCloser {
    fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, _buf: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::Error::new(io::ErrorKind::Unsupported, "reality close view carries no write side")))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl murmur_std_compat::net::Conn for RealityCloser {
    fn local_addr(&self) -> io::Result<Box<dyn murmur_std_compat::net::Addr>> {
        let addr = self
            .socket
            .local_addr()?
            .as_socket()
            .ok_or_else(|| io::Error::other("reality close view: the socket reported no address family"))?;
        Ok(Box::new(murmur_std_compat::net::TcpAddr::from(addr)))
    }

    fn remote_addr(&self) -> io::Result<Box<dyn murmur_std_compat::net::Addr>> {
        let addr = self
            .socket
            .peer_addr()?
            .as_socket()
            .ok_or_else(|| io::Error::other("reality close view: the socket reported no address family"))?;
        Ok(Box::new(murmur_std_compat::net::TcpAddr::from(addr)))
    }

    fn close(&self) -> io::Result<()> {
        self.shutdown(std::net::Shutdown::Both)
    }

    fn close_read(&self) -> io::Result<()> {
        self.shutdown(std::net::Shutdown::Read)
    }

    /// A write half-close closes the whole connection: a half-close was observed to be
    /// intercepted and leak memory, so the connection is closed outright.
    fn close_write(&self) -> io::Result<()> {
        self.shutdown(std::net::Shutdown::Both)
    }

    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        Some(socket2::SockRef::from(&*self.socket))
    }
}

/// A [`common_net::io::Stream`](murmur_common_net::io::Stream) view over a [`RealityStream`].
///
/// The trait needs synchronous `local_addr`/`peer_addr`, which [`RealityStream`] cannot answer
/// once its handshake-phase [`RecordLayer`] has been split and consumed -- so callers that need a
/// `Stream` (every listener/outbound integration site) capture both addresses from the
/// pre-handshake connection and attach them here instead.
#[derive(Debug)]
pub struct RealityConnAddrs<S> {
    inner: RealityStream<S>,
    local: std::net::SocketAddr,
    peer: std::net::SocketAddr,
    closer: Option<RealityCloser>,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static> RealityStream<S> {
    #[must_use]
    pub fn with_addrs(self, local: std::net::SocketAddr, peer: std::net::SocketAddr) -> RealityConnAddrs<S> {
        RealityConnAddrs { inner: self, local, peer, closer: None }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static> RealityConnAddrs<S> {
    /// Attaches the transport's close handle, captured with [`RealityCloser::capture`] before the
    /// handshake split the conn.
    #[must_use]
    pub fn with_closer(mut self, closer: RealityCloser) -> Self {
        self.closer = Some(closer);
        self
    }

    #[must_use]
    pub const fn cipher_suite(&self) -> u16 {
        self.inner.cipher_suite()
    }

    /// The application-data plaintext already decrypted but not yet handed to the reader.
    pub fn take_buffered_incoming(&mut self) -> Vec<u8> {
        self.inner.take_buffered_incoming()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static> AsyncRead for RealityConnAddrs<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static> AsyncWrite for RealityConnAddrs<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static> murmur_common_net::io::Stream for RealityConnAddrs<S> {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        Ok(self.local)
    }

    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        Ok(self.peer)
    }

    fn shutdown_read(&self) -> io::Result<()> {
        match &self.closer {
            Some(closer) => closer.shutdown(std::net::Shutdown::Read),
            None => Ok(()),
        }
    }

    /// A write half-close closes the whole connection.
    fn shutdown_write(&self) -> io::Result<()> {
        match &self.closer {
            Some(closer) => closer.shutdown(std::net::Shutdown::Both),
            None => Ok(()),
        }
    }

    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        self.closer.as_ref().and_then(murmur_std_compat::net::Conn::as_socket)
    }

    fn old_conn(&self) -> Option<&dyn murmur_std_compat::net::Conn> {
        self.closer.as_ref().map(|closer| {
            let closer: &dyn murmur_std_compat::net::Conn = closer;
            closer
        })
    }
}
