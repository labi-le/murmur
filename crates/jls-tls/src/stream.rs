//! The post-handshake connection type returned to callers: an
//! `AsyncRead`/`AsyncWrite` stream backed by the TLS 1.3 application-data
//! record layer, plus the JLS authentication outcome.
//!
//! Read and write are implemented as plain poll-based state machines (no
//! `unsafe`, no boxed self-referential futures): the read half and write half
//! of the underlying transport (via `tokio::io::split`) are independent
//! fields, so both directions can make progress concurrently, e.g. under
//! `tokio::io::copy_bidirectional`.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use socket2::SockRef;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, ReadHalf, WriteHalf};

use crate::record::{self, DirectionKeys, MAX_PLAINTEXT_RECORD};
use crate::JlsConnectionState;

/// RFC 8446 §6.1: the only alert a peer may send outside of an error
/// condition. It is surfaced as an EOF on the next read, which is
/// indistinguishable from a socket half-close, so callers can tell a graceful
/// shutdown apart from a teardown.
pub(crate) const ALERT_CLOSE_NOTIFY: [u8; 2] = [1, 0];

fn other_error(err: impl std::fmt::Display) -> io::Error {
    io::Error::other(err.to_string())
}

fn poll_fill<R: AsyncRead + Unpin>(
    read_half: &mut R,
    cx: &mut Context<'_>,
    buf: &mut [u8],
    pos: &mut usize,
) -> Poll<io::Result<()>> {
    while *pos < buf.len() {
        let (_, tail) = buf.split_at_mut(*pos);
        let mut rb = ReadBuf::new(tail);
        match Pin::new(&mut *read_half).poll_read(cx, &mut rb) {
            Poll::Ready(Ok(())) => {
                let n = rb.filled().len();
                if n == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "jls: peer closed connection",
                    )));
                }
                *pos += n;
            }
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        }
    }
    Poll::Ready(Ok(()))
}

enum ReadPhase {
    Header,
    Payload,
}

struct ReadState<S> {
    read_half: ReadHalf<S>,
    keys: DirectionKeys,
    phase: ReadPhase,
    header: [u8; 5],
    header_pos: usize,
    payload: Vec<u8>,
    payload_pos: usize,
    ready: Vec<u8>,
    ready_pos: usize,
    /// A decrypted `close_notify` was read; every later poll is the same
    /// zero-byte EOF, never another read from the transport.
    closed: bool,
}

impl<S> ReadState<S> {
    fn new(read_half: ReadHalf<S>, keys: DirectionKeys) -> Self {
        Self {
            read_half,
            keys,
            phase: ReadPhase::Header,
            header: [0u8; 5],
            header_pos: 0,
            payload: Vec::new(),
            payload_pos: 0,
            ready: Vec::new(),
            ready_pos: 0,
            closed: false,
        }
    }
}

impl<S: AsyncRead + Unpin> ReadState<S> {
    fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.closed {
            return Poll::Ready(Ok(()));
        }
        loop {
            if self.ready_pos < self.ready.len() {
                return Poll::Ready(Ok(()));
            }
            match self.phase {
                ReadPhase::Header => match poll_fill(&mut self.read_half, cx, &mut self.header, &mut self.header_pos) {
                    Poll::Ready(Ok(())) => {
                        let len = u16::from_be_bytes([self.header[3], self.header[4]]) as usize;
                        self.payload = vec![0u8; len];
                        self.payload_pos = 0;
                        self.phase = ReadPhase::Payload;
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => return Poll::Pending,
                },
                ReadPhase::Payload => {
                    match poll_fill(&mut self.read_half, cx, &mut self.payload, &mut self.payload_pos) {
                        Poll::Ready(Ok(())) => {
                            let content_type = self.header[0];
                            self.header_pos = 0;
                            self.phase = ReadPhase::Header;
                            if content_type == record::CONTENT_CHANGE_CIPHER_SPEC {
                                continue;
                            }
                            if content_type != record::CONTENT_APPLICATION_DATA {
                                return Poll::Ready(Err(other_error(
                                    "record: unexpected outer content type in application phase",
                                )));
                            }
                            let header = self.header;
                            let (inner_type, inner) = match record::open(&mut self.keys, &header, &self.payload) {
                                Ok(v) => v,
                                Err(err) => return Poll::Ready(Err(other_error(err))),
                            };
                            match inner_type {
                                record::CONTENT_APPLICATION_DATA => {
                                    self.ready = inner;
                                    self.ready_pos = 0;
                                }
                                record::CONTENT_ALERT => {
                                    if inner == ALERT_CLOSE_NOTIFY {
                                        self.closed = true;
                                        return Poll::Ready(Ok(()));
                                    }
                                    return Poll::Ready(Err(other_error("record: peer sent a fatal alert")));
                                }
                                record::CONTENT_HANDSHAKE => {
                                    return Poll::Ready(Err(other_error(
                                        "record: post-handshake key update is not supported by this engine",
                                    )));
                                }
                                _ => return Poll::Ready(Err(other_error("record: unexpected inner content type"))),
                            }
                        }
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
        }
    }
}

struct WriteState<S> {
    write_half: WriteHalf<S>,
    keys: DirectionKeys,
    out: Vec<u8>,
    out_pos: usize,
}

impl<S> WriteState<S> {
    fn new(write_half: WriteHalf<S>, keys: DirectionKeys) -> Self {
        Self { write_half, keys, out: Vec::new(), out_pos: 0 }
    }
}

impl<S: AsyncWrite + Unpin> WriteState<S> {
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.out_pos < self.out.len() {
            let pending = self.out.get(self.out_pos..).unwrap_or_default();
            match Pin::new(&mut self.write_half).poll_write(cx, pending) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "jls: write returned zero")))
                }
                Poll::Ready(Ok(n)) => self.out_pos += n,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.out.clear();
        self.out_pos = 0;
        Poll::Ready(Ok(()))
    }
}

/// A finished TLS 1.3 + JLS connection.
///
/// Reads/writes are relayed through the AEAD application-data record layer
/// (RFC 8446 §5.2); [`JlsStream::state`] reports the JLS authentication
/// outcome negotiated during the handshake.
pub struct JlsStream<S> {
    read: ReadState<S>,
    write: WriteState<S>,
    state: JlsConnectionState,
    local_addr: Option<std::net::SocketAddr>,
    peer_addr: Option<std::net::SocketAddr>,
}

impl<S> std::fmt::Debug for JlsStream<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JlsStream")
            .field("state", &self.state)
            .field("local_addr", &self.local_addr)
            .field("peer_addr", &self.peer_addr)
            .finish_non_exhaustive()
    }
}

impl<S> JlsStream<S> {
    /// `local_addr`/`peer_addr` are captured from the original, unsplit
    /// transport before the handshake driver split it into independent
    /// read/write halves (`tokio::io::split`); a socket's local/peer address
    /// is constant for the connection's lifetime, so a one-time snapshot is
    /// equivalent to querying it live.
    pub(crate) fn new(
        read_half: ReadHalf<S>,
        read_keys: DirectionKeys,
        write_half: WriteHalf<S>,
        write_keys: DirectionKeys,
        state: JlsConnectionState,
        local_addr: Option<std::net::SocketAddr>,
        peer_addr: Option<std::net::SocketAddr>,
    ) -> Self {
        Self {
            read: ReadState::new(read_half, read_keys),
            write: WriteState::new(write_half, write_keys),
            state,
            local_addr,
            peer_addr,
        }
    }

    /// The JLS authentication outcome negotiated during the handshake.
    #[must_use]
    pub fn state(&self) -> &JlsConnectionState {
        &self.state
    }
}

impl<S: AsyncWrite + Unpin> JlsStream<S> {
    /// Seals `payload` as an encrypted alert and writes the record out. The
    /// engine has no shutdown path of its own, so this exists only to let a
    /// test push a peer's alert through the real record layer.
    #[cfg(test)]
    pub(crate) async fn write_alert(&mut self, payload: &[u8]) -> io::Result<()> {
        let sealed = record::seal(&mut self.write.keys, record::CONTENT_ALERT, payload).map_err(other_error)?;
        tokio::io::AsyncWriteExt::write_all(&mut self.write.write_half, &sealed).await
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for JlsStream<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // A `ReadBuf` with no room is already satisfied; pulling a record off
        // the transport for it would block on data nothing can accept.
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        match this.read.poll_next(cx) {
            Poll::Ready(Ok(())) => {
                let read = &mut this.read;
                let (_, pending) = read.ready.split_at(read.ready_pos);
                let n = pending.len().min(out.remaining());
                let (head, _) = pending.split_at(n);
                out.put_slice(head);
                read.ready_pos += n;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for JlsStream<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match this.write.poll_drain(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let chunk_len = buf.len().min(MAX_PLAINTEXT_RECORD);
        let (chunk, _) = buf.split_at(chunk_len);
        let record =
            record::seal(&mut this.write.keys, record::CONTENT_APPLICATION_DATA, chunk).map_err(other_error)?;
        this.write.out = record;
        this.write.out_pos = 0;
        match this.write.poll_drain(cx) {
            Poll::Ready(Ok(())) | Poll::Pending => Poll::Ready(Ok(chunk_len)),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.write.poll_drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.write.write_half).poll_flush(cx),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.write.poll_drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.write.write_half).poll_shutdown(cx),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// `local_addr`/`peer_addr` are a one-time snapshot taken by
/// [`crate::client_handshake`] / [`crate::server_handshake`] from the
/// original transport before it is split into independent read/write
/// halves (`tokio::io::split`); a socket's local/peer address is constant
/// for the connection's lifetime, so this is equivalent to querying it live.
impl<S: murmur_common_net::io::Stream> murmur_common_net::io::Stream for JlsStream<S> {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.local_addr.ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "jls: local_addr unavailable"))
    }

    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.peer_addr.ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "jls: peer_addr unavailable"))
    }

    fn as_socket(&self) -> Option<SockRef<'_>> {
        None
    }
}
