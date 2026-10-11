//! The `h3` QUIC transport the Hysteria2 server needs.
//!
//! `h3` has no hook for a stream whose first frame is not an HTTP/3 frame, and Hysteria2 opens
//! exactly those (`0x401`) beside its HTTP/3 authentication request on the same connection. The
//! separation comes from [`DispatchConnection`], which implements `h3`'s QUIC traits over `quinn`
//! and classifies each accepted bidirectional stream by its first QUIC varint, routing `0x401` to
//! the proxy receiver and replaying the sniffed bytes in front of every other stream.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes, BytesMut};
use futures::StreamExt as _;
use quinn::VarInt;

use crate::protocol::FRAME_TYPE_TCP_REQUEST;

/// `quinn`'s send half behind `h3`'s trait. The wrapper is required by the orphan rule: `h3` and
/// `quinn` are both foreign here, so the impl needs a local type.
#[derive(Debug)]
pub struct H3Send {
    inner: quinn::SendStream,
    /// `h3` hands data over without a waker; the next `poll_ready` flushes it.
    writing: Option<Bytes>,
}

impl H3Send {
    fn new(inner: quinn::SendStream) -> Self {
        Self { inner, writing: None }
    }

    /// The wrapped stream, back out unchanged.
    fn into_inner(self) -> quinn::SendStream {
        self.inner
    }
}

/// The h3 request stream [`crate::service`] answers the authentication exchange on.
pub type H3RequestStream = h3::server::RequestStream<H3Stream, Bytes>;

/// `quinn`'s receive half behind `h3`'s trait, replaying whatever the classifier read.
#[derive(Debug)]
pub struct H3Recv {
    inner: quinn::RecvStream,
    prefix: Bytes,
}

impl H3Recv {
    fn new(inner: quinn::RecvStream) -> Self {
        Self { inner, prefix: Bytes::new() }
    }

    /// Appends a freshly read chunk *before* the bytes already held.
    fn push(&mut self, chunk: &[u8]) {
        let mut bytes = BytesMut::with_capacity(chunk.len() + self.prefix.len());
        bytes.extend_from_slice(chunk);
        bytes.extend_from_slice(&self.prefix);
        self.prefix = bytes.freeze();
    }
}

impl h3::quic::RecvStream for H3Recv {
    type Buf = Bytes;

    fn poll_data(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Self::Buf>, h3::quic::StreamErrorIncoming>> {
        if !self.prefix.is_empty() {
            return Poll::Ready(Ok(Some(std::mem::take(&mut self.prefix))));
        }
        let mut scratch = vec![0u8; 2048];
        let mut read_buf = tokio::io::ReadBuf::new(&mut scratch);
        match tokio::io::AsyncRead::poll_read(Pin::new(&mut self.inner), cx, &mut read_buf) {
            Poll::Ready(Ok(())) if read_buf.filled().is_empty() => Poll::Ready(Ok(None)),
            Poll::Ready(Ok(())) => Poll::Ready(Ok(Some(Bytes::copy_from_slice(read_buf.filled())))),
            Poll::Ready(Err(err)) => Poll::Ready(Err(h3::quic::StreamErrorIncoming::ConnectionErrorIncoming {
                connection_error: h3::quic::ConnectionErrorIncoming::Undefined(Arc::new(err)),
            })),
            Poll::Pending => Poll::Pending,
        }
    }

    fn stop_sending(&mut self, error_code: u64) {
        let _ = self.inner.stop(VarInt::from_u64(error_code).unwrap_or(VarInt::from_u32(0)));
    }

    fn recv_id(&self) -> h3::quic::StreamId {
        stream_id(self.inner.id())
    }
}

impl h3::quic::SendStream<Bytes> for H3Send {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), h3::quic::StreamErrorIncoming>> {
        let Some(mut pending) = self.writing.take() else {
            return Poll::Ready(Ok(()));
        };
        while pending.has_remaining() {
            match <quinn::SendStream as tokio::io::AsyncWrite>::poll_write(Pin::new(&mut self.inner), cx, &pending) {
                Poll::Ready(Ok(0)) => {
                    self.writing = Some(pending);
                    return Poll::Ready(Err(h3::quic::StreamErrorIncoming::Unknown(Box::new(io::Error::other(
                        "hysteria2: the stream accepted no bytes",
                    )))));
                }
                Poll::Ready(Ok(written)) => pending.advance(written),
                Poll::Ready(Err(err)) => {
                    self.writing = Some(pending);
                    return Poll::Ready(Err(write_error(err)));
                }
                Poll::Pending => {
                    self.writing = Some(pending);
                    return Poll::Pending;
                }
            }
        }
        Poll::Ready(Ok(()))
    }

    fn send_data<T: Into<h3::quic::WriteBuf<Bytes>>>(&mut self, data: T) -> Result<(), h3::quic::StreamErrorIncoming> {
        if self.writing.is_some() {
            return Err(h3::quic::StreamErrorIncoming::ConnectionErrorIncoming {
                connection_error: h3::quic::ConnectionErrorIncoming::InternalError(
                    "hysteria2: send_data before the previous frame was flushed".to_owned(),
                ),
            });
        }
        // The buffer is multi-segment (frame header, then payload); taking only the first chunk
        // would truncate the frame on the wire.
        let mut data = data.into();
        let len = data.remaining();
        self.writing = Some(data.copy_to_bytes(len));
        Ok(())
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), h3::quic::StreamErrorIncoming>> {
        match self.poll_ready(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        }
        self.inner.finish().map_err(closed_error)?;
        Poll::Ready(Ok(()))
    }

    fn reset(&mut self, reset_code: u64) {
        self.writing = None;
        let _ = self.inner.reset(VarInt::from_u64(reset_code).unwrap_or(VarInt::from_u32(0)));
    }

    fn send_id(&self) -> h3::quic::StreamId {
        stream_id(self.inner.id())
    }
}

/// A bidirectional stream as `h3` sees it.
#[derive(Debug)]
pub struct H3Stream {
    send: H3Send,
    recv: H3Recv,
}

impl H3Stream {
    fn into_parts(self) -> (quinn::SendStream, quinn::RecvStream, Bytes) {
        (self.send.into_inner(), self.recv.inner, self.recv.prefix)
    }
}

impl h3::quic::RecvStream for H3Stream {
    type Buf = Bytes;

    fn poll_data(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Self::Buf>, h3::quic::StreamErrorIncoming>> {
        self.recv.poll_data(cx)
    }

    fn stop_sending(&mut self, error_code: u64) {
        self.recv.stop_sending(error_code);
    }

    fn recv_id(&self) -> h3::quic::StreamId {
        self.recv.recv_id()
    }
}

impl h3::quic::SendStream<Bytes> for H3Stream {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), h3::quic::StreamErrorIncoming>> {
        h3::quic::SendStream::poll_ready(&mut self.send, cx)
    }

    fn send_data<T: Into<h3::quic::WriteBuf<Bytes>>>(&mut self, data: T) -> Result<(), h3::quic::StreamErrorIncoming> {
        h3::quic::SendStream::send_data(&mut self.send, data)
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), h3::quic::StreamErrorIncoming>> {
        h3::quic::SendStream::poll_finish(&mut self.send, cx)
    }

    fn reset(&mut self, reset_code: u64) {
        h3::quic::SendStream::reset(&mut self.send, reset_code);
    }

    fn send_id(&self) -> h3::quic::StreamId {
        h3::quic::SendStream::send_id(&self.send)
    }
}

impl h3::quic::BidiStream<Bytes> for H3Stream {
    type SendStream = H3Send;
    type RecvStream = H3Recv;

    fn split(self) -> (Self::SendStream, Self::RecvStream) {
        (self.send, self.recv)
    }
}

/// A stream diverted out of `h3` because it opened with `0x401`.
#[derive(Debug)]
pub struct ProxyStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    prefix: Vec<u8>,
}

impl ProxyStream {
    /// The sniffed frame type plus the rest of the stream, for [`crate::quic::QuicStream`].
    #[must_use]
    pub fn into_parts(self) -> (quinn::SendStream, quinn::RecvStream, Vec<u8>) {
        (self.send, self.recv, self.prefix)
    }

    /// Refuses a stream that arrived before authentication.
    pub fn stop(mut self) {
        let _ = self.send.reset(VarInt::from_u32(0));
        let _ = self.recv.stop(VarInt::from_u32(0));
    }
}

impl tokio::io::AsyncRead for ProxyStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.prefix.is_empty() {
            let len = self.prefix.len().min(buf.remaining());
            let (head, _) = self.prefix.split_at(len);
            buf.put_slice(head);
            self.prefix.drain(..len);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

/// quinn and h3 both encode a QUIC stream id as the same 62-bit varint.
#[expect(
    clippy::unreachable,
    reason = "a quinn `StreamId` is itself a 62-bit varint, so h3's `try_from` cannot reject one"
)]
fn stream_id(id: quinn::StreamId) -> h3::quic::StreamId {
    h3::quic::StreamId::try_from(u64::from(id)).unwrap_or_else(|_| unreachable!("a quinn stream id fits the h3 varint"))
}

/// Reads whatever the peer has sent so far, for the frame-type sniff.
fn poll_chunk(recv: &mut quinn::RecvStream, cx: &mut Context<'_>) -> Poll<io::Result<Option<Vec<u8>>>> {
    let mut scratch = vec![0u8; 2048];
    let mut read_buf = tokio::io::ReadBuf::new(&mut scratch);
    match tokio::io::AsyncRead::poll_read(Pin::new(recv), cx, &mut read_buf) {
        Poll::Ready(Ok(())) if read_buf.filled().is_empty() => Poll::Ready(Ok(None)),
        Poll::Ready(Ok(())) => Poll::Ready(Ok(Some(read_buf.filled().to_vec()))),
        Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
        Poll::Pending => Poll::Pending,
    }
}

fn write_error(err: io::Error) -> h3::quic::StreamErrorIncoming {
    h3::quic::StreamErrorIncoming::Unknown(Box::new(err))
}

fn closed_error(_err: quinn::ClosedStream) -> h3::quic::StreamErrorIncoming {
    h3::quic::StreamErrorIncoming::StreamTerminated { error_code: 0 }
}

fn stream_error(err: quinn::ConnectionError) -> h3::quic::StreamErrorIncoming {
    h3::quic::StreamErrorIncoming::ConnectionErrorIncoming { connection_error: conn_error(err) }
}

fn conn_error(err: quinn::ConnectionError) -> h3::quic::ConnectionErrorIncoming {
    match err {
        quinn::ConnectionError::ApplicationClosed(closed) => {
            h3::quic::ConnectionErrorIncoming::ApplicationClose { error_code: closed.error_code.into_inner() }
        }
        quinn::ConnectionError::TimedOut => h3::quic::ConnectionErrorIncoming::Timeout,
        err @ (quinn::ConnectionError::VersionMismatch
        | quinn::ConnectionError::TransportError(_)
        | quinn::ConnectionError::ConnectionClosed(_)
        | quinn::ConnectionError::Reset
        | quinn::ConnectionError::LocallyClosed
        | quinn::ConnectionError::CidsExhausted) => h3::quic::ConnectionErrorIncoming::Undefined(Arc::new(err)),
    }
}

fn unsupported(reason: &str) -> h3::quic::ConnectionErrorIncoming {
    h3::quic::ConnectionErrorIncoming::Undefined(Arc::new(io::Error::other(reason.to_owned())))
}

/// A `quinn` stream of accepted or opened streams. It has to outlive the poll that first
/// registered its waker: a fresh `accept_bi()`/`accept_uni()` future dropped on `Pending` leaves
/// `quinn`'s `Notify` with no waiter, so the next stream stores a permit nobody is woken for.
type BoxStreamSync<T> = Pin<Box<dyn futures::Stream<Item = T> + Sync + Send>>;

type BiStream = Result<(quinn::SendStream, quinn::RecvStream), quinn::ConnectionError>;
type UniRecvStream = Result<quinn::RecvStream, quinn::ConnectionError>;
type UniSendStream = Result<quinn::SendStream, quinn::ConnectionError>;

fn accept_bi_stream(connection: quinn::Connection) -> BoxStreamSync<BiStream> {
    Box::pin(futures::stream::unfold(connection, |connection| async move {
        Some((connection.accept_bi().await, connection))
    }))
}

fn accept_uni_stream(connection: quinn::Connection) -> BoxStreamSync<UniRecvStream> {
    Box::pin(futures::stream::unfold(connection, |connection| async move {
        Some((connection.accept_uni().await, connection))
    }))
}

fn open_bi_stream(connection: quinn::Connection) -> BoxStreamSync<BiStream> {
    Box::pin(futures::stream::unfold(
        connection,
        |connection| async move { Some((connection.open_bi().await, connection)) },
    ))
}

fn open_uni_stream(connection: quinn::Connection) -> BoxStreamSync<UniSendStream> {
    Box::pin(futures::stream::unfold(connection, |connection| async move {
        Some((connection.open_uni().await, connection))
    }))
}

/// An `h3` QUIC connection with `0x401` streams diverted.
pub struct DispatchConnection {
    connection: quinn::Connection,
    pending: Option<H3Stream>,
    proxy_streams: tokio::sync::mpsc::Sender<ProxyStream>,
    incoming_bi: BoxStreamSync<BiStream>,
    incoming_uni: BoxStreamSync<UniRecvStream>,
    opening_bi: Option<BoxStreamSync<BiStream>>,
    opening_uni: Option<BoxStreamSync<UniSendStream>>,
}

impl std::fmt::Debug for DispatchConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DispatchConnection")
            .field("connection", &self.connection)
            .field("pending", &self.pending)
            .finish_non_exhaustive()
    }
}

impl DispatchConnection {
    /// Returns the connection and the receiver carrying the proxy streams it diverts.
    #[must_use]
    pub fn new(connection: quinn::Connection) -> (Self, tokio::sync::mpsc::Receiver<ProxyStream>) {
        let (proxy_streams, receiver) = tokio::sync::mpsc::channel(64);
        let this = Self::with_proxy_streams(connection, proxy_streams);
        (this, receiver)
    }

    /// Shares `proxy_streams` so an [`Self::opener`] clone routes into the same receiver.
    fn with_proxy_streams(
        connection: quinn::Connection,
        proxy_streams: tokio::sync::mpsc::Sender<ProxyStream>,
    ) -> Self {
        let incoming_bi = accept_bi_stream(connection.clone());
        let incoming_uni = accept_uni_stream(connection.clone());
        Self {
            connection,
            pending: None,
            proxy_streams,
            incoming_bi,
            incoming_uni,
            opening_bi: None,
            opening_uni: None,
        }
    }

    /// Takes the stream the classifier settled on, leaving `pending` empty for the next accept.
    fn take_pending(&mut self) -> Option<H3Stream> {
        self.pending.take()
    }
}

impl h3::quic::OpenStreams<Bytes> for DispatchConnection {
    type BidiStream = H3Stream;
    type SendStream = H3Send;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, h3::quic::StreamErrorIncoming>> {
        let connection = self.connection.clone();
        let opening = self.opening_bi.get_or_insert_with(|| open_bi_stream(connection));
        match opening.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok((send, recv)))) => {
                Poll::Ready(Ok(H3Stream { send: H3Send::new(send), recv: H3Recv::new(recv) }))
            }
            Poll::Ready(Some(Err(err))) => Poll::Ready(Err(stream_error(err))),
            Poll::Ready(None) => Poll::Ready(Err(stream_error(quinn::ConnectionError::LocallyClosed))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, h3::quic::StreamErrorIncoming>> {
        let connection = self.connection.clone();
        let opening = self.opening_uni.get_or_insert_with(|| open_uni_stream(connection));
        match opening.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok(send))) => Poll::Ready(Ok(H3Send::new(send))),
            Poll::Ready(Some(Err(err))) => Poll::Ready(Err(stream_error(err))),
            Poll::Ready(None) => Poll::Ready(Err(stream_error(quinn::ConnectionError::LocallyClosed))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        self.connection.close(VarInt::from_u64(code.value()).unwrap_or(VarInt::from_u32(0)), reason);
    }
}

impl h3::quic::Connection<Bytes> for DispatchConnection {
    type RecvStream = H3Recv;
    type OpenStreams = Self;

    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::RecvStream, h3::quic::ConnectionErrorIncoming>> {
        match self.incoming_uni.poll_next_unpin(cx) {
            Poll::Ready(Some(Ok(recv))) => Poll::Ready(Ok(H3Recv::new(recv))),
            Poll::Ready(Some(Err(err))) => Poll::Ready(Err(conn_error(err))),
            Poll::Ready(None) => Poll::Ready(Err(unsupported("hysteria2: the stream of incoming streams ended"))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, h3::quic::ConnectionErrorIncoming>> {
        loop {
            if self.pending.is_none() {
                match self.incoming_bi.poll_next_unpin(cx) {
                    Poll::Ready(Some(Ok((send, recv)))) => {
                        self.pending = Some(H3Stream { send: H3Send::new(send), recv: H3Recv::new(recv) });
                    }
                    Poll::Ready(Some(Err(err))) => return Poll::Ready(Err(conn_error(err))),
                    Poll::Ready(None) => {
                        return Poll::Ready(Err(unsupported("hysteria2: the stream of incoming streams ended")));
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
            // The varint width is only known once the first byte has arrived.
            let Some(pending) = self.pending.as_mut() else {
                continue;
            };
            if pending.recv.prefix.is_empty() {
                match poll_chunk(&mut pending.recv.inner, cx) {
                    Poll::Ready(Ok(Some(chunk))) => pending.recv.push(&chunk),
                    Poll::Ready(Ok(None)) => {
                        let Some(stream) = self.take_pending() else {
                            continue;
                        };
                        return Poll::Ready(Ok(stream));
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(unsupported(&err.to_string()))),
                    Poll::Pending => return Poll::Pending,
                }
            }

            let Some(pending) = self.pending.as_mut() else {
                continue;
            };
            let Some(&frame_head) = pending.recv.prefix.first() else {
                continue;
            };
            let needed = crate::quic::frame_type_len(frame_head);
            while pending.recv.prefix.len() < needed {
                match poll_chunk(&mut pending.recv.inner, cx) {
                    Poll::Ready(Ok(Some(chunk))) => pending.recv.push(&chunk),
                    Poll::Ready(Ok(None)) => {
                        let Some(stream) = self.take_pending() else {
                            break;
                        };
                        return Poll::Ready(Ok(stream));
                    }
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(unsupported(&err.to_string()))),
                    Poll::Pending => return Poll::Pending,
                }
            }

            let Some(pending) = self.pending.as_mut() else {
                continue;
            };
            let Some((&head, header)) = pending.recv.prefix.split_first() else {
                continue;
            };
            let Some(type_bytes) = header.get(..needed - 1) else {
                continue;
            };
            let frame_type = crate::quic::decode_frame_type(head, type_bytes);
            if frame_type != FRAME_TYPE_TCP_REQUEST {
                let Some(stream) = self.take_pending() else {
                    continue;
                };
                return Poll::Ready(Ok(stream));
            }
            let Some(pending) = self.take_pending() else {
                continue;
            };
            let (send, recv, prefix) = pending.into_parts();
            // The sniff may have read past the frame type (the address and payload can share the
            // first chunk); every sniffed byte belongs to the proxy stream, not just the varint.
            let stream = ProxyStream { send, recv, prefix: prefix.to_vec() };
            if self.proxy_streams.try_send(stream).is_err() {
                return Poll::Ready(Err(unsupported("hysteria2: proxy stream receiver is gone")));
            }
        }
    }

    fn opener(&self) -> Self::OpenStreams {
        let connection = self.connection.clone();
        Self::with_proxy_streams(connection, self.proxy_streams.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_quinn_stream_id_round_trips_through_the_h3_encoding() {
        let id: quinn::StreamId = VarInt::from_u32(4).into();
        assert_eq!(stream_id(id).into_inner(), 4);
    }

    #[test]
    fn the_maximum_quic_stream_id_is_still_a_valid_h3_id() {
        let raw: u64 = VarInt::MAX.into_inner();
        assert_eq!(stream_id(VarInt::MAX.into()).into_inner(), raw);
    }

    #[test]
    fn only_the_tcp_request_frame_type_is_diverted() {
        let mut frame = [0u8; 8];
        crate::protocol::var_int_put(&mut frame, FRAME_TYPE_TCP_REQUEST);
        assert_eq!(crate::quic::decode_frame_type(frame[0], &frame[1..2]), FRAME_TYPE_TCP_REQUEST);

        let mut head = [0u8; 8];
        crate::protocol::var_int_put(&mut head, 0x01);
        assert_eq!(crate::quic::decode_frame_type(head[0], &[]), 0x01);
    }
}
