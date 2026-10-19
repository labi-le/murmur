//! Packet-address serialization for both VLESS datagrams and VMess's fixed-target bind stream.

use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use murmur_common::shared_conn::SharedConn as VmessSharedConn;
use murmur_common_net::io::{old_addr_to_socket_addr, OldConnAsStream, StreamAsOldConn};
use murmur_sing::metadata::Socksaddr;
use murmur_std_compat::net::{Addr, Conn as NetConn, PacketConn as NetPacketConn, UdpAddr};

const FAMILY_IPV4: u8 = 0x01;
const FAMILY_IPV6: u8 = 0x02;

/// The address serializer, with an IPv4 and an IPv6 family byte: address then port (the default
/// serializer order, unlike `super::addr`'s port-then-address VMess header layout), and no FQDN
/// family byte is registered.
fn address_len(addr: &Socksaddr) -> io::Result<usize> {
    if addr.is_ipv4() {
        Ok(5)
    } else if addr.is_ipv6() {
        Ok(17)
    } else if addr.is_valid() {
        Err(fqdn_unsupported(&addr.fqdn))
    } else {
        Err(io::Error::new(io::ErrorKind::InvalidInput, "unsupported address"))
    }
}

fn fqdn_unsupported(fqdn: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, format!("packetaddr: fqdn unsupported: {fqdn}"))
}

fn addr_port_len(dst: &Socksaddr) -> io::Result<usize> {
    Ok(address_len(dst)? + 2)
}

fn write_addr_port(buffer: &mut Vec<u8>, dst: &Socksaddr) -> io::Result<()> {
    if dst.is_fqdn() {
        return Err(fqdn_unsupported(&dst.fqdn));
    }
    match dst.addr {
        Some(IpAddr::V4(v4)) => {
            buffer.push(FAMILY_IPV4);
            buffer.extend_from_slice(&v4.octets());
        }
        Some(IpAddr::V6(v6)) => {
            buffer.push(FAMILY_IPV6);
            buffer.extend_from_slice(&v6.octets());
        }
        None => return Err(io::Error::new(io::ErrorKind::InvalidInput, "unsupported address")),
    }
    buffer.extend_from_slice(&dst.port.to_be_bytes());
    Ok(())
}

/// Splits exactly `N` leading bytes off `input`, or reports `UnexpectedEof` when it is shorter.
fn split_array<const N: usize>(input: &[u8]) -> io::Result<([u8; N], &[u8])> {
    let (head, rest) = input.split_at_checked(N).ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
    let mut array = [0u8; N];
    array.copy_from_slice(head);
    Ok((array, rest))
}

fn read_addr_port(cursor: &[u8]) -> io::Result<(Socksaddr, &[u8])> {
    let ([family], rest) = split_array::<1>(cursor)?;
    let (mut addr, rest) = match family {
        FAMILY_IPV4 => {
            let (octets, rest) = split_array::<4>(rest)?;
            (Socksaddr::from_ip(IpAddr::from(octets), 0), rest)
        }
        FAMILY_IPV6 => {
            let (octets, rest) = split_array::<16>(rest)?;
            (Socksaddr::from_ip(IpAddr::from(octets), 0), rest)
        }
        other => return Err(io::Error::new(io::ErrorKind::InvalidData, format!("unknown address family: {other}"))),
    };
    let (port, rest) = split_array::<2>(rest)?;
    addr.port = u16::from_be_bytes(port);
    Ok((addr.unwrap(), rest))
}

pub const SEQ_PACKET_MAGIC_ADDRESS: &str = "sp.packet-addr.v2fly.arpa";

struct ReadState {
    conn: super::conn_driver::ConnHandle,
}

struct WriteState {
    conn: super::conn_driver::ConnHandle,
    target: Socksaddr,
}

impl WriteState {
    /// Writes one packet (`addr` fixed to the real target — see the module doc).
    async fn write_packet(&mut self, payload: &[u8]) -> io::Result<usize> {
        let mut frame = Vec::with_capacity(addr_port_len(&self.target)? + payload.len());
        write_addr_port(&mut frame, &self.target)?;
        frame.extend_from_slice(payload);
        self.conn.write_all(&frame).await?;
        Ok(payload.len())
    }
}

impl ReadState {
    async fn read_packet(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let mut raw = vec![0u8; out.len() + 32];
        let n = self.conn.read(&mut raw).await?;
        let (frame, _) = raw.split_at(n);
        let (_destination, packet) = read_addr_port(frame)?;
        if packet.len() > out.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "buffer is shorter than a packetaddr packet"));
        }
        let (dst, _) = out.split_at_mut(packet.len());
        dst.copy_from_slice(packet);
        Ok(packet.len())
    }
}

impl super::conn_driver::DriveRead for ReadState {
    fn read<'a>(&'a mut self, b: &'a mut [u8]) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>> {
        Box::pin(self.read_packet(b))
    }
}

impl super::conn_driver::DriveWrite for WriteState {
    fn write<'a>(&'a mut self, b: &'a [u8]) -> Pin<Box<dyn Future<Output = io::Result<usize>> + Send + 'a>> {
        Box::pin(self.write_packet(b))
    }
}

#[must_use]
pub fn wrap_bind_conn(conn: Box<dyn NetConn>, target: Socksaddr) -> Box<dyn NetConn> {
    let close_handle = VmessSharedConn::from_boxed(conn);
    let shared = super::conn_driver::SharedConn::new(Box::new(OldConnAsStream(close_handle.clone())));
    let read_state = ReadState { conn: Arc::clone(&shared).into() };
    let write_state = WriteState { conn: Arc::clone(&shared).into(), target };
    Box::new(StreamAsOldConn::new(super::conn_driver::Driven::new(shared, close_handle, read_state, write_state)))
}

struct PacketAddrPacketConn {
    inner: Box<dyn NetPacketConn>,
}

#[async_trait]
impl NetPacketConn for PacketAddrPacketConn {
    async fn read_from(&self, out: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        let mut raw = vec![0u8; out.len() + 19];
        let (n, _) = self.inner.read_from(&mut raw).await?;
        let (frame, _) = raw.split_at(n);
        let (destination, packet) = read_addr_port(frame)?;
        if packet.len() > out.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "buffer is shorter than a packetaddr packet"));
        }
        let (dst, _) = out.split_at_mut(packet.len());
        dst.copy_from_slice(packet);
        let ip = destination.addr.ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "packetaddr has no IP"))?;
        Ok((packet.len(), Box::new(UdpAddr::new(ip, destination.port))))
    }

    async fn write_to(&self, payload: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        let socket = old_addr_to_socket_addr(addr)?;
        let target = Socksaddr::from_ip(socket.ip(), socket.port());
        let mut packet = Vec::with_capacity(addr_port_len(&target)? + payload.len());
        write_addr_port(&mut packet, &target)?;
        packet.extend_from_slice(payload);
        self.inner.write_to(&packet, addr).await?;
        Ok(payload.len())
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.inner.local_addr()
    }

    fn close(&self) -> io::Result<()> {
        self.inner.close()
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.inner.set_deadline(deadline)
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.inner.set_read_deadline(deadline)
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.inner.set_write_deadline(deadline)
    }
}

#[must_use]
pub fn wrap_packet_conn(conn: Box<dyn NetPacketConn>) -> Box<dyn NetPacketConn> {
    Box::new(PacketAddrPacketConn { inner: conn })
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
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

    /// Known-answer vectors from the XUDP set:
    /// address-then-port with family byte `0x01` for IPv4, two consecutive writes to the one fixed
    /// target this build binds at construction.
    #[tokio::test]
    async fn packetaddr_write_ipv4_matches_known_answer() {
        let (client, mut server) = pipe_pair();
        let target = Socksaddr::from_ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 53);
        let mut conn = wrap_bind_conn(client, target);

        conn.write_all(&seq(3)).await.unwrap();
        let mut frame0 = vec![0u8; 10];
        server.read_exact(&mut frame0).await.unwrap();
        assert_eq!(frame0, hex("01010203040035000102"));

        conn.write_all(&seq(4)).await.unwrap();
        let mut frame1 = vec![0u8; 11];
        server.read_exact(&mut frame1).await.unwrap();
        assert_eq!(frame1, hex("0101020304003500010203"));
    }

    /// Same known-answer set, family byte `0x02` for IPv6.
    #[tokio::test]
    async fn packetaddr_write_ipv6_matches_known_answer() {
        let (client, mut server) = pipe_pair();
        let target = Socksaddr::from_ip(IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()), 443);
        let mut conn = wrap_bind_conn(client, target);

        conn.write_all(&seq(3)).await.unwrap();
        let mut frame0 = vec![0u8; 22];
        server.read_exact(&mut frame0).await.unwrap();
        assert_eq!(frame0, hex("0220010db800000000000000000000000101bb000102"));

        conn.write_all(&seq(6)).await.unwrap();
        let mut frame1 = vec![0u8; 25];
        server.read_exact(&mut frame1).await.unwrap();
        assert_eq!(frame1, hex("0220010db800000000000000000000000101bb000102030405"));
    }

    /// Round trip: the frames above, fed in as two consecutive incoming packets,
    /// decode back to the original payloads (strips the address-then-port header, keeps the
    /// fixed bind-reply semantics `wrap_bind_conn` implements).
    #[tokio::test]
    async fn packetaddr_read_two_packets_matches_known_answer() {
        let (client, mut server) = pipe_pair();
        let target = Socksaddr::from_ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 53);
        let mut conn = wrap_bind_conn(client, target);
        let mut buf = vec![0u8; 64];

        server.write_all(&hex("01010203040035000102")).await.unwrap();
        let n0 = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n0], seq(3).as_slice());

        server.write_all(&hex("0101020304003500010203")).await.unwrap();
        let n1 = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n1], seq(4).as_slice());
    }

    #[test]
    fn packetaddr_write_fqdn_rejected() {
        let mut buffer = Vec::new();
        let err = write_addr_port(&mut buffer, &Socksaddr::fqdn("example.com", 80)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("fqdn unsupported"));
    }

    /// A stand-in for the sing client `Conn` `wrap_bind_conn`/`new_xudp_conn` actually wrap in
    /// production: `close` really shuts the socket down, but `close_read`/`close_write` are left
    /// at their inherited no-op defaults, exactly like `sing::client::Conn`'s own `impl NetConn`.
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

    /// Regression for the review of `152f46e2`: see `sing::xudp::tests::
    /// close_reaches_the_real_tcp_connection` for the identical `Driven`/`old_conn` bug — this is
    /// the `packetaddr` side of the same probe.
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
        let target = Socksaddr::from_ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 53);
        let conn = wrap_bind_conn(client, target);
        conn.close().expect("close");

        tokio::time::timeout(std::time::Duration::from_secs(2), server)
            .await
            .expect("close() must reach the real TCP connection")
            .expect("server task");
    }
}
