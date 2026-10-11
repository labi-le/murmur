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
