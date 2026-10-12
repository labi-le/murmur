use std::io;
use std::sync::Arc;

use async_trait::async_trait;
use tokio::io::AsyncWriteExt as _;

use murmur_common::shared_conn::SharedConn;
use murmur_common_net::WaitReadFrom;
use murmur_common_pool as pool;
use murmur_std_compat::net::{Addr, Conn as NetConn, PacketConn as NetPacketConn};

/// The read-full contract: returns the count read against the error, as the packet-conn read reports it.
async fn read_full(conn: &SharedConn, dst: &mut [u8]) -> (usize, io::Result<()>) {
    let mut filled = 0;
    let mut rest: &mut [u8] = dst;
    while !rest.is_empty() {
        match conn.read(rest).await {
            Ok(0) => {
                let err = if filled == 0 {
                    io::Error::new(io::ErrorKind::UnexpectedEof, "EOF")
                } else {
                    io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF")
                };
                return (filled, Err(err));
            }
            Ok(n) => {
                let (_, tail) = rest.split_at_mut(n);
                rest = tail;
                filled += n;
            }
            Err(err) => return (filled, Err(err)),
        }
    }
    (filled, Ok(()))
}

/// Reads and drops `len` bytes the caller's slice could not hold. The length prefix is already off
/// the stream when a read rejects a datagram, so the payload has to leave it too; otherwise the
/// next read decodes payload bytes as a length prefix and every later datagram is corrupt. A conn
/// that breaks mid-drain reports its own error rather than the short-buffer one, which would look
/// recoverable on a stream that is gone.
// NOT cancel-safe: a dropped drain has already consumed part of the rejected datagram, so a later
// read would start mid-frame; `read_from` is awaited inside the deadline layer's `select!`
// (`NetPacketConn::with_read_deadline`), where a cancellation tears the connection down instead of
// permitting another read.
async fn discard_payload(conn: &SharedConn, len: usize) -> io::Result<()> {
    let mut scratch = [0u8; 512];
    let mut remaining = len;
    while remaining > 0 {
        let chunk = remaining.min(scratch.len());
        let Some(dst) = scratch.get_mut(..chunk) else {
            return Err(io::Error::other("vless: discard window exceeds the scratch block"));
        };
        let (n, err) = read_full(conn, dst).await;
        err?;
        remaining -= n;
    }
    Ok(())
}

/// The address value handed back on every read; a `Box<dyn Addr>` alone cannot be shared, so it is
/// held behind an `Arc`.
#[derive(Debug, Clone)]
struct AddrRef(Arc<dyn Addr>);

impl Addr for AddrRef {
    fn network(&self) -> &str {
        self.0.network()
    }

    fn string(&self) -> String {
        self.0.string()
    }

    fn addr_port(&self) -> Option<murmur_std_compat::net::AddrPort> {
        self.0.addr_port()
    }

    fn raw_addr(&self) -> Option<&dyn Addr> {
        self.0.raw_addr()
    }

    fn as_iface_prefix(&self) -> Option<ipnet::IpNet> {
        self.0.as_iface_prefix()
    }

    fn as_sock_addr(&self) -> Option<murmur_std_compat::net::SockAddr> {
        self.0.as_sock_addr()
    }
}

#[derive(Debug)]
pub struct PacketConn {
    conn: SharedConn,
    r_addr: Arc<dyn Addr>,
}

impl PacketConn {
    pub(crate) fn new(conn: Box<dyn NetConn>, r_addr: Box<dyn Addr>) -> Self {
        Self { conn: SharedConn::from_boxed(conn), r_addr: Arc::from(r_addr) }
    }
}

#[async_trait]
impl NetPacketConn for PacketConn {
    async fn write_to(&self, b: &[u8], _addr: &dyn Addr) -> io::Result<usize> {
        let mut conn = self.conn.clone();
        let length = u16::try_from(b.len()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        conn.write_all(&length.to_be_bytes()).await?;

        conn.write_all(b).await?;
        conn.flush().await?;
        Ok(b.len())
    }

    async fn read_from(&self, b: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        let mut length_bytes = [0u8; 2];
        let (_, err) = read_full(&self.conn, &mut length_bytes).await;
        err?;
        let length = usize::from(u16::from_be_bytes(length_bytes));
        if b.len() < length {
            discard_payload(&self.conn, length).await?;
            return Err(io::Error::other("short buffer"));
        }
        let (dst, _tail) = b.split_at_mut(length);
        let (n, err) = read_full(&self.conn, dst).await;
        err?;
        Ok((n, Box::new(AddrRef(Arc::clone(&self.r_addr)))))
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.conn.local_addr()
    }

    fn close(&self) -> io::Result<()> {
        self.conn.close()
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.conn.set_deadline(deadline)
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.conn.set_read_deadline(deadline)
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.conn.set_write_deadline(deadline)
    }
}

#[async_trait]
impl WaitReadFrom for PacketConn {
    // NOT cancel-safe: a dropped call has already consumed datagram framing from the socket, so a later read would start mid-frame; every `select!` arm that awaits it drops it only while the connection is being torn down.
    async fn wait_read_from(
        &self,
    ) -> (Vec<u8>, Option<Box<dyn FnOnce() + Send>>, Option<Box<dyn Addr>>, io::Result<()>) {
        let mut length_bytes = [0u8; 2];
        let (_, err) = read_full(&self.conn, &mut length_bytes).await;
        if let Err(err) = err {
            return (Vec::new(), None, None, Err(err));
        }
        let length = usize::from(u16::from_be_bytes(length_bytes));

        let mut read_buf = pool::get(length);
        let (n, err) = read_full(&self.conn, &mut read_buf).await;
        if let Err(err) = err {
            let _ = pool::put(read_buf);
            return (Vec::new(), None, None, Err(err));
        }

        // Copy the filled prefix out of the pooled block so the block itself can move into the
        // `put` closure that returns it to the pool.
        let (data, _tail) = read_buf.split_at(n);
        let data = data.to_vec();
        let put: Box<dyn FnOnce() + Send> = Box::new(move || {
            let _ = pool::put(read_buf);
        });
        (data, Some(put), Some(Box::new(AddrRef(Arc::clone(&self.r_addr)))), Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use tokio::net::{TcpListener, TcpStream};

    use super::*;

    /// A conn carrying `frame` on an accepted loopback socket, plus the writing peer that keeps
    /// the connection open for the duration of the test.
    async fn conn_carrying(frame: &[u8]) -> (PacketConn, TcpStream) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.expect("an ephemeral port is free");
        let addr = listener.local_addr().expect("the probe is bound");
        let mut peer = TcpStream::connect(addr).await.expect("the peer connects");
        let (server, _) = listener.accept().await.expect("the probe accepts");
        peer.write_all(frame).await.expect("the frame is written");
        let pc = PacketConn::new(Box::new(server), Box::new(murmur_std_compat::net::UdpAddr::from(addr)));
        (pc, peer)
    }

    /// The stream from the report: `00 04 | 00 01 41 42` then `00 02 | 43 44`. A two-byte read
    /// rejects the first datagram; the read after it must start at the second length prefix
    /// instead of decoding `00 01` as a header.
    #[tokio::test]
    async fn a_short_buffer_does_not_leave_the_read_between_packet_boundaries() {
        let (pc, _peer) = conn_carrying(&[0x00, 0x04, 0x00, 0x01, 0x41, 0x42, 0x00, 0x02, 0x43, 0x44]).await;

        let mut small = [0u8; 2];
        let err = NetPacketConn::read_from(&pc, &mut small)
            .await
            .expect_err("four payload bytes do not fit a two-byte slice");
        assert_eq!(err.to_string(), "short buffer");

        let mut larger = [0u8; 8];
        let (n, _addr) = NetPacketConn::read_from(&pc, &mut larger)
            .await
            .expect("the read after a short buffer must start at the second length prefix");
        assert_eq!(&larger[..n], b"CD", "the second datagram must survive the rejected first one");
    }

    /// The drain spans more than one read, so a payload larger than a single drain chunk must
    /// still leave the stream aligned on the next datagram.
    #[tokio::test]
    async fn a_short_buffer_drains_a_payload_larger_than_one_chunk() {
        let payload = [0xABu8; 4096];
        let mut frame = Vec::new();
        frame.extend_from_slice(&u16::try_from(payload.len()).expect("4096 fits a u16").to_be_bytes());
        frame.extend_from_slice(&payload);
        frame.extend_from_slice(&[0x00, 0x02, 0x43, 0x44]);
        let (pc, _peer) = conn_carrying(&frame).await;

        let mut small = [0u8; 16];
        NetPacketConn::read_from(&pc, &mut small).await.expect_err("4096 payload bytes do not fit a 16-byte slice");

        let mut larger = [0u8; 8];
        let (n, _addr) = NetPacketConn::read_from(&pc, &mut larger)
            .await
            .expect("the datagram behind the drained one must be readable");
        assert_eq!(&larger[..n], b"CD");
    }

    /// A slice that holds the payload exactly is a fit, not a short buffer, and the read after it
    /// must still find the next length prefix.
    #[tokio::test]
    async fn a_payload_exactly_filling_the_slice_is_returned_intact() {
        let (pc, _peer) = conn_carrying(&[0x00, 0x02, 0x43, 0x44, 0x00, 0x02, 0x45, 0x46]).await;

        let mut exact = [0u8; 2];
        let (n, _addr) = NetPacketConn::read_from(&pc, &mut exact).await.expect("an exact fit is not a short buffer");
        assert_eq!(&exact[..n], b"CD");

        let (n, _addr) = NetPacketConn::read_from(&pc, &mut exact).await.expect("the second exact fit reads too");
        assert_eq!(&exact[..n], b"EF");
    }
}
