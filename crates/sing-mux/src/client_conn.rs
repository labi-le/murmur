//! The client-side conns each hold one already-open mux stream.
//!
//! They lazily write their handshake header on the first write call,
//! then lazily read the handshake response on the first `Read`. The stream is split (see
//! `rule://wave-rules` #3), so the write-side request-written state and read-side response-read
//! state never contend for one lock; per rule #8, the in-flight handshake read and the in-flight
//! handshake write each keep their own state across `Pending` polls instead of restarting and
//! losing already-consumed bytes.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf};

use crate::protocol::{
    encode_stream_request, read_addr_port, read_stream_response, StreamNetwork, StreamRequest, STATUS_ERROR,
};
use crate::session::MuxStream;
use murmur_compat::sing_buf::Buffer;
use murmur_sing::metadata::{Socksaddr, SOCKSADDR_SERIALIZER};
use murmur_sing::network::{PacketConn as SingPacketConn, PacketReader, PacketWriter};
use murmur_std_compat::net::Addr;

type BoxedRead = ReadHalf<Box<dyn MuxStream>>;
type BoxedWrite = WriteHalf<Box<dyn MuxStream>>;
type ResponseFuture = Pin<Box<dyn Future<Output = (BoxedRead, io::Result<()>)> + Send>>;
type RequestFuture = Pin<Box<dyn Future<Output = (BoxedWrite, io::Result<()>)> + Send>>;

fn read_state_error() -> io::Error {
    io::Error::other("sing-mux: client conn read half is not in its handshake state")
}

fn write_state_error() -> io::Error {
    io::Error::other("sing-mux: client conn write half is not in its handshake state")
}

fn packet_state_error() -> io::Error {
    io::Error::other("sing-mux: client packet conn in-flight state is missing")
}

async fn drive_response_read(mut inner: BoxedRead) -> (BoxedRead, io::Result<()>) {
    let result = match read_stream_response(&mut inner).await {
        Ok(response) if response.status == STATUS_ERROR => {
            Err(io::Error::other(format!("remote error: {}", response.message)))
        }
        Ok(_) => Ok(()),
        Err(err) => Err(err),
    };
    (inner, result)
}

struct ReadState {
    inner: Option<BoxedRead>,
    pending: Option<ResponseFuture>,
    response_read: bool,
}

impl ReadState {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<&mut BoxedRead>> {
        if self.response_read {
            return Poll::Ready(Ok(self.inner.as_mut().ok_or_else(read_state_error)?));
        }
        if self.pending.is_none() {
            let inner = self.inner.take().ok_or_else(read_state_error)?;
            self.pending = Some(Box::pin(drive_response_read(inner)));
        }
        let fut = self.pending.as_mut().ok_or_else(read_state_error)?;
        match fut.as_mut().poll(cx) {
            Poll::Ready((inner, result)) => {
                self.inner = Some(inner);
                self.pending = None;
                match result {
                    Ok(()) => {
                        self.response_read = true;
                        Poll::Ready(Ok(self.inner.as_mut().ok_or_else(read_state_error)?))
                    }
                    Err(err) => Poll::Ready(Err(err)),
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

async fn drive_request_write(mut inner: BoxedWrite, frame: Vec<u8>) -> (BoxedWrite, io::Result<()>) {
    let result = inner.write_all(&frame).await;
    (inner, result)
}

struct WriteState {
    inner: Option<BoxedWrite>,
    pending: Option<RequestFuture>,
    request_written: bool,
}

impl WriteState {
    fn poll_ready(
        &mut self,
        cx: &mut Context<'_>,
        frame: impl FnOnce() -> io::Result<Vec<u8>>,
    ) -> Poll<io::Result<&mut BoxedWrite>> {
        if self.request_written {
            return Poll::Ready(Ok(self.inner.as_mut().ok_or_else(write_state_error)?));
        }
        if self.pending.is_none() {
            let frame = match frame() {
                Ok(frame) => frame,
                Err(err) => return Poll::Ready(Err(err)),
            };
            let inner = self.inner.take().ok_or_else(write_state_error)?;
            self.pending = Some(Box::pin(drive_request_write(inner, frame)));
        }
        let fut = self.pending.as_mut().ok_or_else(write_state_error)?;
        match fut.as_mut().poll(cx) {
            Poll::Ready((inner, result)) => {
                self.inner = Some(inner);
                self.pending = None;
                match result {
                    Ok(()) => {
                        self.request_written = true;
                        Poll::Ready(Ok(self.inner.as_mut().ok_or_else(write_state_error)?))
                    }
                    Err(err) => Poll::Ready(Err(err)),
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

pub struct ClientConn {
    read: Mutex<ReadState>,
    write: Mutex<WriteState>,
    destination: Socksaddr,
}

impl core::fmt::Debug for ClientConn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClientConn").field("destination", &self.destination).finish_non_exhaustive()
    }
}

fn stream_request_frame(
    network: StreamNetwork,
    destination: &Socksaddr,
    packet_addr: bool,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    let request = StreamRequest { network, destination: destination.clone(), packet_addr };
    let mut frame = Vec::new();
    encode_stream_request(&request, &mut frame)?;
    frame.extend_from_slice(payload);
    Ok(frame)
}

/// Builds the stream-backed client conn.
#[must_use]
pub fn new_client_conn(stream: Box<dyn MuxStream>, destination: Socksaddr) -> ClientConn {
    let (read, write) = tokio::io::split(stream);
    ClientConn {
        read: Mutex::new(ReadState { inner: Some(read), pending: None, response_read: false }),
        write: Mutex::new(WriteState { inner: Some(write), pending: None, request_written: false }),
        destination,
    }
}

impl AsyncRead for ClientConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut read = self.read.lock();
        match read.poll_ready(cx) {
            Poll::Ready(Ok(inner)) => Pin::new(inner).poll_read(cx, buf),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for ClientConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let mut write = self.write.lock();
        let already_written = write.request_written;
        let destination = self.destination.clone();
        match write.poll_ready(cx, move || stream_request_frame(StreamNetwork::Tcp, &destination, false, buf)) {
            Poll::Ready(Ok(inner)) => {
                if already_written {
                    Pin::new(inner).poll_write(cx, buf)
                } else {
                    // The handshake write just completed and it already carried this exact
                    // payload as its tail, so the whole buffer is accepted without writing it
                    // twice.
                    Poll::Ready(Ok(buf.len()))
                }
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut write = self.write.lock();
        match write.poll_ready(cx, || Ok(Vec::new())) {
            Poll::Ready(Ok(inner)) => Pin::new(inner).poll_flush(cx),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut write = self.write.lock();
        match write.poll_ready(cx, || Ok(Vec::new())) {
            Poll::Ready(Ok(inner)) => Pin::new(inner).poll_shutdown(cx),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// The packet conn and the packet-addr conn, folded into one type parameterised by
/// `packet_addr` (the two differ only in whether a per-packet [`Socksaddr`] precedes the
/// length-prefixed payload; every framing/handshake detail otherwise matches byte for byte). The
/// packet-conn core additionally supports plain `Read`/`Write` (used by the UDP dial case);
/// the core is `Arc`-shared so [`ClientPacketConn`]'s
/// `AsyncRead`/`AsyncWrite` impl can hold an owned, `'static` in-flight future across `Pending`
/// polls (rule://wave-rules #8) without borrowing `self`.
struct ClientPacketConnCore {
    read: tokio::sync::Mutex<(BoxedRead, bool)>,
    write: tokio::sync::Mutex<(BoxedWrite, bool)>,
    destination: Socksaddr,
    packet_addr: bool,
}

type PacketReadFuture = Pin<Box<dyn Future<Output = (Vec<u8>, io::Result<(usize, Socksaddr)>)> + Send>>;
type PacketWriteFuture = Pin<Box<dyn Future<Output = io::Result<usize>> + Send>>;

pub struct ClientPacketConn {
    core: Arc<ClientPacketConnCore>,
    in_flight: Mutex<(Option<PacketReadFuture>, Option<PacketWriteFuture>)>,
}

impl core::fmt::Debug for ClientPacketConn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ClientPacketConn").finish_non_exhaustive()
    }
}

/// The UDP branch of the client constructor, alongside the packet-address
/// conn it returns.
#[must_use]
pub fn new_client_packet_conn(
    stream: Box<dyn MuxStream>,
    destination: Socksaddr,
    packet_addr: bool,
) -> ClientPacketConn {
    let (read, write) = tokio::io::split(stream);
    let core = Arc::new(ClientPacketConnCore {
        read: tokio::sync::Mutex::new((read, false)),
        write: tokio::sync::Mutex::new((write, false)),
        destination,
        packet_addr,
    });
    ClientPacketConn { core, in_flight: Mutex::new((None, None)) }
}

impl ClientPacketConnCore {
    /// Writes one packet to the destination.
    #[expect(
        clippy::significant_drop_tightening,
        reason = "the write half is borrowed out of the guard and written through across the awaited write, so the guard has to span the whole frame"
    )]
    async fn write_payload(&self, payload: &[u8], destination: Option<&Socksaddr>) -> io::Result<usize> {
        let mut guard = self.write.lock().await;
        let (inner, request_written) = &mut *guard;
        if !*request_written {
            let mut frame = stream_request_frame(StreamNetwork::Udp, &self.destination, self.packet_addr, &[])?;
            append_packet_payload(&mut frame, payload, self.packet_addr, destination);
            inner.write_all(&frame).await?;
            *request_written = true;
            return Ok(payload.len());
        }
        let mut frame = Vec::new();
        append_packet_payload(&mut frame, payload, self.packet_addr, destination);
        inner.write_all(&frame).await?;
        Ok(payload.len())
    }

    /// Reads one packet and reports its source.
    #[expect(
        clippy::significant_drop_tightening,
        reason = "the read half is borrowed out of the guard and read through across the awaited reads, so the guard has to span the whole packet"
    )]
    async fn read_payload(&self, buf: &mut [u8]) -> io::Result<(usize, Socksaddr)> {
        let mut guard = self.read.lock().await;
        let (inner, response_read) = &mut *guard;
        if !*response_read {
            let response = read_stream_response(inner).await?;
            if response.status == STATUS_ERROR {
                return Err(io::Error::other(format!("remote error: {}", response.message)));
            }
            *response_read = true;
        }
        let destination = if self.packet_addr { read_addr_port(inner).await? } else { Socksaddr::default() };
        let mut length = [0u8; 2];
        inner.read_exact(&mut length).await?;
        let length = u16::from_be_bytes(length) as usize;
        if buf.len() < length {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "sing-mux packet read: short buffer"));
        }
        inner.read_exact(buf.split_at_mut(length).0).await?;
        Ok((length, destination))
    }
}

fn append_packet_payload(frame: &mut Vec<u8>, payload: &[u8], packet_addr: bool, destination: Option<&Socksaddr>) {
    if packet_addr {
        let destination = destination.cloned().unwrap_or_default();
        let _ = SOCKSADDR_SERIALIZER.write_addr_port(frame, &destination);
    }
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the per-packet length is the 16-bit prefix the wire format defines, and a UDP payload never exceeds it"
    )]
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
}

impl AsyncRead for ClientPacketConn {
    #[expect(
        clippy::significant_drop_tightening,
        reason = "the in-flight read future is borrowed out of the guard, polled and cleared through it, so the guard has to span the whole poll"
    )]
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut in_flight = self.in_flight.lock();
        if in_flight.0.is_none() {
            let core = Arc::clone(&self.core);
            let mut scratch = vec![0u8; buf.remaining()];
            in_flight.0 = Some(Box::pin(async move {
                let result = core.read_payload(&mut scratch).await;
                (scratch, result)
            }));
        }
        let fut = in_flight.0.as_mut().ok_or_else(packet_state_error)?;
        match fut.as_mut().poll(cx) {
            Poll::Ready((scratch, result)) => {
                in_flight.0 = None;
                match result {
                    Ok((n, _destination)) => {
                        buf.put_slice(scratch.split_at(n).0);
                        Poll::Ready(Ok(()))
                    }
                    Err(err) => Poll::Ready(Err(err)),
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for ClientPacketConn {
    #[expect(
        clippy::significant_drop_tightening,
        reason = "the in-flight write future is borrowed out of the guard, polled and cleared through it, so the guard has to span the whole poll"
    )]
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let mut in_flight = self.in_flight.lock();
        if in_flight.1.is_none() {
            let core = Arc::clone(&self.core);
            let data = buf.to_vec();
            in_flight.1 = Some(Box::pin(async move { core.write_payload(&data, None).await }));
        }
        let fut = in_flight.1.as_mut().ok_or_else(packet_state_error)?;
        match fut.as_mut().poll(cx) {
            Poll::Ready(result) => {
                in_flight.1 = None;
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let core = Arc::clone(&this.core);
        let mut fut = Box::pin(async move { core.write.lock().await.0.shutdown().await });
        fut.as_mut().poll(cx)
    }
}

#[async_trait]
impl SingPacketConn for ClientPacketConn {
    async fn close(&self) -> io::Result<()> {
        self.core.write.lock().await.0.shutdown().await
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "sing-mux client packet conn has no local addr"))
    }
}

#[async_trait]
impl PacketReader for ClientPacketConn {
    async fn read_packet(&self, buffer: &mut Buffer) -> io::Result<Socksaddr> {
        let free = buffer.free_len();
        let mut scratch = vec![0u8; free];
        let (n, destination) = self.core.read_payload(&mut scratch).await?;
        buffer.write_bytes(scratch.split_at(n).0)?;
        Ok(destination)
    }
}

#[async_trait]
impl PacketWriter for ClientPacketConn {
    async fn write_packet(&self, buffer: &Buffer, destination: &Socksaddr) -> io::Result<()> {
        self.core.write_payload(buffer.bytes(), Some(destination)).await.map(|_| ())
    }
}
