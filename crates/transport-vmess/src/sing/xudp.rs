//! Client-only XUDP framing.
//!
//! The server side of the mux command (`COMMAND_MUX`) would dispatch the mux/XUDP multiplexing (distinct
//! from this crate's generic `murmur_sing_mux`), which is not implemented — see
//! `transport::vmess::sing`'s module doc — so nothing routes it through XUDP framing.
//!
//! VMess uses the fixed-destination stream interface; VLESS uses the per-packet address interface.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

use super::addr;
use murmur_common::shared_conn::SharedConn as VmessSharedConn;
use murmur_common_net::io::{old_addr_to_socket_addr, OldConnAsStream, StreamAsOldConn};
use murmur_sing::metadata::Socksaddr;
use murmur_std_compat::net::{Addr, Conn as NetConn, PacketConn as NetPacketConn, UdpAddr};

const STATUS_NEW: u8 = 1;
const STATUS_KEEP: u8 = 2;
const STATUS_END: u8 = 3;
const STATUS_KEEP_ALIVE: u8 = 4;
const OPTION_DATA: u8 = 1;
const OPTION_ERROR: u8 = 2;
const NETWORK_UDP: u8 = 2;

struct ReadState {
    conn: super::conn_driver::ConnHandle,
}

struct WriteState {
    conn: super::conn_driver::ConnHandle,
    destination: Socksaddr,
    global_id: [u8; 8],
    request_written: bool,
}

impl WriteState {
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the XUDP header length and payload length are 16-bit wire fields, so the narrowing casts are the wire format"
    )]
    async fn write_packet(&mut self, payload: &[u8], destination: Option<&Socksaddr>) -> io::Result<usize> {
        let destination = destination.unwrap_or(&self.destination);
        let addr_len = addr::addr_port_len(destination);
        let mut frame = Vec::new();
        if self.request_written {
            let header_len = 5 + addr_len;
            frame.extend_from_slice(&(header_len as u16).to_be_bytes());
            frame.extend_from_slice(&[0, 0, STATUS_KEEP, OPTION_DATA, NETWORK_UDP]);
            addr::write_addr_port(&mut frame, destination).map_err(io::Error::other)?;
            frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        } else {
            let header_len = 2 + 5 + addr_len + if self.global_id == [0u8; 8] { 0 } else { 8 } + 2;
            frame.extend_from_slice(&((header_len - 4) as u16).to_be_bytes());
            frame.extend_from_slice(&[0, 0, STATUS_NEW, OPTION_DATA, NETWORK_UDP]);
            addr::write_addr_port(&mut frame, destination).map_err(io::Error::other)?;
            if self.global_id != [0u8; 8] {
                frame.extend_from_slice(&self.global_id);
            }
            frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
            self.request_written = true;
        }
        frame.extend_from_slice(payload);
        self.conn.write_all(&frame).await?;
        Ok(payload.len())
    }
}

impl ReadState {
    async fn read_packet(&mut self, out: &mut [u8]) -> io::Result<(usize, Option<Socksaddr>)> {
        loop {
            let mut head = [0u8; 6];
            self.conn.read_exact(&mut head).await?;
            let length = u16::from_be_bytes([head[0], head[1]]);
            let frame_type = head[4];
            let option = head[5];

            let mut keep_payload_len = None;
            let mut destination = None;
            match frame_type {
                STATUS_NEW => return Err(io::Error::other("unexpected frame new")),
                STATUS_KEEP => {
                    if length == 4 {
                        let mut discard = [0u8; 2];
                        self.conn.read_exact(&mut discard).await?;
                        keep_payload_len = Some(discard);
                    } else {
                        let remaining = (length as usize).checked_sub(2).ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidData, "xudp keep frame length too short")
                        })?;
                        let mut rest = vec![0u8; remaining];
                        self.conn.read_exact(&mut rest).await?;
                        let Some((_, network)) = rest.split_first() else {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "xudp keep frame missing network byte",
                            ));
                        };
                        let mut cursor: &[u8] = network;
                        destination = Some(addr::read_addr_port(&mut cursor).map_err(io::Error::other)?);
                        let [hi, lo] = cursor else {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "xudp keep frame missing payload length",
                            ));
                        };
                        keep_payload_len = Some([*hi, *lo]);
                    }
                }
                STATUS_END => {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "xudp session ended"));
                }
                STATUS_KEEP_ALIVE => {}
                other => return Err(io::Error::other(format!("unexpected frame: {other}"))),
            }

            if option & OPTION_ERROR == OPTION_ERROR {
                return Err(io::Error::new(io::ErrorKind::ConnectionReset, "remote closed"));
            }
            if option & OPTION_DATA != OPTION_DATA {
                continue;
            }
            let payload_len = if let Some(bytes) = keep_payload_len {
                u16::from_be_bytes(bytes) as usize
            } else {
                let mut len_buf = [0u8; 2];
                self.conn.read_exact(&mut len_buf).await?;
                u16::from_be_bytes(len_buf) as usize
            };
            let Some(packet) = out.get_mut(..payload_len) else {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "buffer is shorter than an xudp packet"));
            };
            self.conn.read_exact(packet).await?;
            return Ok((payload_len, destination));
        }
    }
}

impl super::conn_driver::DriveRead for ReadState {
    fn read<'a>(&'a mut self, b: &'a mut [u8]) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>> {
        Box::pin(async move { self.read_packet(b).await.map(|(len, _)| len) })
    }
}

impl super::conn_driver::DriveWrite for WriteState {
    fn write<'a>(&'a mut self, b: &'a [u8]) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>> {
        Box::pin(self.write_packet(b, None))
    }
}

/// Builds a `XudpPacketConn` over `conn`, a [`super::client::Conn`] already dialed with
/// `COMMAND_MUX`.
#[must_use]
pub fn new_xudp_conn(conn: Box<dyn NetConn>, global_id: [u8; 8], destination: Socksaddr) -> Box<dyn NetConn> {
    let close_handle = VmessSharedConn::from_boxed(conn);
    let shared = super::conn_driver::SharedConn::new(Box::new(OldConnAsStream(close_handle.clone())));
    let read_state = ReadState { conn: Arc::clone(&shared).into() };
    let write_state = WriteState { conn: Arc::clone(&shared).into(), destination, global_id, request_written: false };
    Box::new(StreamAsOldConn::new(super::conn_driver::Driven::new(shared, close_handle, read_state, write_state)))
}

struct XudpPacketConn {
    read: Mutex<ReadState>,
    write: Mutex<WriteState>,
    close_handle: VmessSharedConn,
    destination: Socksaddr,
}

#[async_trait]
impl NetPacketConn for XudpPacketConn {
    async fn read_from(&self, out: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        let mut read = self.read.lock().await;
        let (len, address) = read.read_packet(out).await?;
        drop(read);
        let destination = address.as_ref().unwrap_or(&self.destination);
        let ip = destination.addr.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "xudp reply has no IP"))?;
        Ok((len, Box::new(UdpAddr::new(ip, destination.port))))
    }

    async fn write_to(&self, payload: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        let socket = old_addr_to_socket_addr(addr)?;
        let destination = Socksaddr::from_ip(socket.ip(), socket.port());
        let mut write = self.write.lock().await;
        let len = write.write_packet(payload, Some(&destination)).await?;
        write.conn.flush().await?;
        drop(write);
        Ok(len)
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.close_handle.local_addr()
    }

    fn close(&self) -> io::Result<()> {
        self.close_handle.close()
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.close_handle.set_deadline(deadline)
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.close_handle.set_read_deadline(deadline)
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.close_handle.set_write_deadline(deadline)
    }
}

#[must_use]
pub fn new_xudp_packet_conn(
    conn: Box<dyn NetConn>,
    global_id: [u8; 8],
    destination: Socksaddr,
) -> Box<dyn NetPacketConn> {
    let close_handle = VmessSharedConn::from_boxed(conn);
    let shared = super::conn_driver::SharedConn::new(Box::new(OldConnAsStream(close_handle.clone())));
    let read = Mutex::new(ReadState { conn: Arc::clone(&shared).into() });
    let write = Mutex::new(WriteState {
        conn: shared.into(),
        destination: destination.clone(),
        global_id,
        request_written: false,
    });
    Box::new(XudpPacketConn { read, write, close_handle, destination })
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};

    use super::*;
    use murmur_std_compat::net::{Addr, TcpAddr};

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex")).collect()
    }

    fn seq(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 256) as u8).collect()
    }

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

    impl NetConn for PipeConn {
        fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(TcpAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)))
        }
        fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(TcpAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)))
        }
        fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    fn pipe_pair() -> (Box<dyn NetConn>, Box<dyn NetConn>) {
        let (a, b) = tokio::io::duplex(64 * 1024);
        (Box::new(PipeConn(a)), Box::new(PipeConn(b)))
    }

    fn dst() -> Socksaddr {
        Socksaddr::from_ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 53)
    }

    /// Known-answer vectors from the XUDP set: two consecutive writes on a fresh
    /// conn produce a `STATUS_NEW` frame
    /// (`000c0000010102003501010203040003000102`) then a `STATUS_KEEP` frame whose length prefix is
    /// `5+addrLen` (`000c...`, not `000e...`).
    #[tokio::test]
    async fn xudp_write_new_then_keep_frame_matches_known_answer() {
        let (client, mut server) = pipe_pair();
        let mut conn = new_xudp_conn(client, [0u8; 8], dst());

        conn.write_all(&seq(3)).await.unwrap();
        let want_new = hex("000c0000010102003501010203040003000102");
        let mut new_frame = vec![0u8; want_new.len()];
        server.read_exact(&mut new_frame).await.unwrap();
        assert_eq!(new_frame, want_new);

        conn.write_all(&seq(5)).await.unwrap();
        let want_keep = hex("000c00000201020035010102030400050001020304");
        let mut keep_frame = vec![0u8; want_keep.len()];
        server.read_exact(&mut keep_frame).await.unwrap();
        assert_eq!(keep_frame, want_keep);
    }

    /// Known-answer vectors from the same set: two consecutive `STATUS_KEEP` frames as a peer would
    /// send them, read back through a fresh XUDP conn, followed by a `STATUS_END` frame.
    /// `STATUS_END` is a clean end of stream, which the packet-conn read propagates as an
    /// error rather than an empty datagram; this build does the same.
    #[tokio::test]
    async fn xudp_read_two_keep_frames_then_end_matches_known_answer() {
        let (client, mut server) = pipe_pair();
        let frame0 = hex("000c0000020102003501010203040003000102");
        let frame1 = hex("000c00000201020035010102030400050001020304");
        let end_frame = hex("000000000300");
        tokio::spawn(async move {
            server.write_all(&frame0).await.unwrap();
            server.write_all(&frame1).await.unwrap();
            server.write_all(&end_frame).await.unwrap();
        });

        let mut conn = new_xudp_conn(client, [0u8; 8], dst());
        let mut buf = vec![0u8; 64];
        let n0 = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n0], seq(3).as_slice());
        let n1 = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n1], seq(5).as_slice());
        conn.read(&mut buf).await.expect_err("STATUS_END must end the read, not return Ok(0)");
    }

    /// A `STATUS_KEEP` frame whose declared payload length is 0 is a legitimate empty datagram
    /// (the peer sent an empty UDP packet) and must still be delivered as `Ok(0)`, distinct from
    /// `STATUS_END` ending the session with an error.
    #[tokio::test]
    async fn xudp_read_empty_keep_payload_then_end_ends_relay() {
        let (client, mut server) = pipe_pair();
        let empty_keep_frame = hex("000c0000020102003501010203040000");
        let end_frame = hex("000000000300");
        tokio::spawn(async move {
            server.write_all(&empty_keep_frame).await.unwrap();
            server.write_all(&end_frame).await.unwrap();
        });

        let mut conn = new_xudp_conn(client, [0u8; 8], dst());
        let mut buf = vec![0u8; 64];
        let n0 = conn.read(&mut buf).await.unwrap();
        assert_eq!(n0, 0, "an empty KEEP payload is a real zero-length datagram, delivered as Ok(0)");
        conn.read(&mut buf).await.expect_err("STATUS_END must end the read, not return Ok(0)");
    }

    /// A stand-in for the sing client `Conn` `new_xudp_conn`/`wrap_bind_conn` actually wrap in
    /// production: `close` really shuts the socket down, but `close_read`/`close_write` are left
    /// at their inherited no-op defaults, exactly like `sing::client::Conn`'s own `impl NetConn`
    /// (which never overrides them). A raw `TcpStream` wrapped in `StreamAsOldConn` does *not*
    /// reproduce this: its `shutdown_read`/`shutdown_write` are real socket shutdowns, which would
    /// make the regression below pass even on the buggy code.
    struct NoHalfCloseConn(tokio::net::TcpStream);

    impl AsyncRead for NoHalfCloseConn {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for NoHalfCloseConn {
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

    impl NetConn for NoHalfCloseConn {
        fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(TcpAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)))
        }
        fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(TcpAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)))
        }
        fn close(&self) -> io::Result<()> {
            socket2::SockRef::from(&self.0).shutdown(std::net::Shutdown::Both)
        }
    }

    /// Regression for the review of `152f46e2`: `Driven`'s `Stream` impl had no `old_conn`, so
    /// `StreamAsOldConn::close` fell back to `close_stream`'s shutdown-both-halves default, which
    /// reaches `OldConnAsStream(inner).shutdown_read`/`shutdown_write` — the sing client `Conn`'s
    /// own shutdown pair, both no-ops it never overrides. The real vmess TCP
    /// connection was never closed, on a direct `close()` and on a tracker kill through the API.
    /// This test fails on `152f46e2` (times out waiting for the peer to see EOF) and passes once
    /// `Driven` carries a `close_handle` for `old_conn` to answer with.
    #[tokio::test]
    async fn close_reaches_the_real_tcp_connection() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");

        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let mut buf = [0u8; 16];
            loop {
                match AsyncReadExt::read(&mut sock, &mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => continue,
                }
            }
        });

        let client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let client: Box<dyn NetConn> = Box::new(NoHalfCloseConn(client));
        let conn = new_xudp_conn(client, [0u8; 8], dst());
        conn.close().expect("close");

        tokio::time::timeout(std::time::Duration::from_secs(2), server)
            .await
            .expect("close() must reach the real TCP connection")
            .expect("server task");
    }
}
