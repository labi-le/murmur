use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::Mutex as AsyncMutex;

use murmur_common::shared_conn::SharedConn;
use murmur_std_compat::net::{Addr, Conn as NetConn};

pub type SessionStatus = u8;

pub const SESSION_STATUS_NEW: SessionStatus = 0x01;
pub const SESSION_STATUS_KEEP: SessionStatus = 0x02;
pub const SESSION_STATUS_END: SessionStatus = 0x03;
pub const SESSION_STATUS_KEEP_ALIVE: SessionStatus = 0x04;

pub const OPTION_NONE: u8 = 0x00;
pub const OPTION_DATA: u8 = 0x01;
pub const OPTION_ERROR: u8 = 0x02;

#[derive(Clone, Debug, Default)]
pub struct MuxOption {
    pub id: [u8; 2],
    pub port: u16,
    pub host: String,
    pub type_: String,
}

/// reads and writes touch the embedded conn directly with no lock, relying on
/// the conn's concurrent-read/concurrent-write guarantee; `common::net::relay` polls the read
/// side first, so a client-speaks-first exchange leaves a read pending while the peer waits on a
/// write, and sharing one lock between read and write state here serialized that write behind the
/// pending read's guard — either a hang, bounded only by the caller's own timeout, or at best full
/// serialization of a duplex stream. This mirrors `transport/vmess/websocket.rs`'s
/// `ReadInner`/`WriteInner` split: read state and write state live behind separate locks, and
/// both sides reach the wire through a [`SharedConn`], whose lock is held only across one poll,
/// never across a suspension.
struct ReadInner {
    conn: Box<dyn NetConn>,
    length: [u8; 2],
    id: [u8; 2],
    id_shared: Arc<AtomicU16>,
    status: [u8; 2],
    remain: usize,
}

impl ReadInner {
    async fn do_read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        if self.remain != 0 {
            let length = self.remain.min(b.len());
            let (head, _) = b.split_at_mut(length);
            let n = self.conn.read(head).await?;
            self.remain -= n;
            return Ok(n);
        }

        loop {
            self.conn.read_exact(&mut self.length).await?;
            let length = u16::from_be_bytes(self.length);
            if length > 512 {
                return Err(io::Error::other("invalid metalen"));
            }

            self.conn.read_exact(&mut self.id).await?;
            self.id_shared.store(u16::from_be_bytes(self.id), Ordering::SeqCst);

            // The status read also ignores the read amount here.
            #[expect(
                clippy::unused_io_amount,
                reason = "the status read deliberately ignores how many bytes arrived"
            )]
            self.conn.read(&mut self.status).await?;

            let opcode = self.status[0];
            if opcode == SESSION_STATUS_KEEP_ALIVE {
                continue;
            }

            let opts = self.status[1];

            if opts != OPTION_DATA {
                continue;
            }

            self.conn.read_exact(&mut self.length).await?;
            let data_len = u16::from_be_bytes(self.length) as usize;
            self.remain = data_len;
            let data_len = data_len.min(b.len());

            let (head, _) = b.split_at_mut(data_len);
            let n = self.conn.read(head).await;
            return match n {
                Ok(n) => {
                    self.remain -= n;
                    Ok(n)
                }
                Err(err) => {
                    // The failed read never advanced `remain`, so it stays at the declared data length.
                    Err(err)
                }
            };
        }
    }
}

struct WriteInner {
    conn: Box<dyn NetConn>,
    id_shared: Arc<AtomicU16>,
    /// The pending metadata prefix, pre-filled with the session's new-session metadata frame: the
    /// next write prepends it to its own frame, in the same underlying write call, then the buffer
    /// resets to empty before every following write.
    pending_prefix: Vec<u8>,
}

impl WriteInner {
    /// A write reports the framed byte count (header + optional metadata prefix + payload), never
    /// the caller's buffer length. Returning the raw underlying write count instead can report
    /// more bytes than the buffer holds, which panics inside
    /// `tokio::io::AsyncWriteExt::write_all` (review finding 0 on dbe00639). A single
    /// underlying write could also accept only part of the frame and silently drop the
    /// rest, where a full write succeeds or errors; `write_all` fixes both:
    /// every frame byte reaches the wire (or an error is returned) and the reported count is
    /// `b.len()`.
    async fn do_write(&mut self, b: &[u8]) -> io::Result<usize> {
        // Rejected before the prefix is taken, so a rejected frame leaves the metadata pending.
        let payload_len = u16::try_from(b.len()).map_err(|_| io::Error::other("mux payload exceeds 65535 bytes"))?;
        let mut frame = std::mem::take(&mut self.pending_prefix);
        frame.extend_from_slice(&4u16.to_be_bytes());
        frame.extend_from_slice(&self.id_shared.load(Ordering::SeqCst).to_be_bytes());
        frame.push(SESSION_STATUS_KEEP);
        frame.push(OPTION_DATA);
        frame.extend_from_slice(&payload_len.to_be_bytes());
        frame.extend_from_slice(b);
        self.conn.write_all(&frame).await?;
        self.conn.flush().await?;
        Ok(b.len())
    }
}

type ReadFuture = Pin<Box<dyn Future<Output = (Vec<u8>, io::Result<usize>)> + Send + 'static>>;
type WriteFuture = Pin<Box<dyn Future<Output = (Vec<u8>, io::Result<usize>)> + Send + 'static>>;

/// `Mux`: a mux-compatible client for v2ray-plugin, not a complete implementation.
pub struct Mux {
    read_inner: Arc<AsyncMutex<ReadInner>>,
    write_inner: Arc<AsyncMutex<WriteInner>>,
    conn: SharedConn,
    read: parking_lot::Mutex<Option<ReadFuture>>,
    write: parking_lot::Mutex<Option<WriteFuture>>,
    read_buf: parking_lot::Mutex<Vec<u8>>,
    write_buf: parking_lot::Mutex<Vec<u8>>,
    local_addr: io::Result<Box<dyn Addr>>,
    remote_addr: io::Result<Box<dyn Addr>>,
}

fn clone_addr_result(result: &io::Result<Box<dyn Addr>>) -> io::Result<Box<dyn Addr>> {
    match result {
        Ok(addr) => Ok(addr.clone_addr()),
        Err(err) => Err(io::Error::new(err.kind(), err.to_string())),
    }
}

trait CloneAddr {
    fn clone_addr(&self) -> Box<dyn Addr>;
}

impl CloneAddr for Box<dyn Addr> {
    fn clone_addr(&self) -> Box<dyn Addr> {
        match self.as_sock_addr() {
            Some(murmur_std_compat::net::SockAddr::Tcp(tcp)) => Box::new(tcp),
            Some(murmur_std_compat::net::SockAddr::Udp(udp)) => Box::new(udp),
            None => Box::new(murmur_std_compat::net::TcpAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)),
        }
    }
}

impl AsyncRead for Mux {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut read = this.read.lock();
        if read.is_none() {
            let inner = Arc::clone(&this.read_inner);
            let mut tmp = std::mem::take(&mut *this.read_buf.lock());
            tmp.clear();
            tmp.resize(buf.remaining(), 0);
            *read = Some(Box::pin(async move {
                let mut guard = inner.lock().await;
                let result = guard.do_read(&mut tmp).await;
                drop(guard);
                (tmp, result)
            }));
        }
        let Some(future) = read.as_mut() else {
            return Poll::Ready(Err(io::Error::other("read future was just installed")));
        };
        match future.as_mut().poll(cx) {
            Poll::Ready((tmp, result)) => {
                *read = None;
                drop(read);
                match result {
                    Ok(n) => {
                        let Some(filled) = tmp.get(..n) else {
                            return Poll::Ready(Err(io::Error::other("read filled more than the buffer holds")));
                        };
                        buf.put_slice(filled);
                        *this.read_buf.lock() = tmp;
                        Poll::Ready(Ok(()))
                    }
                    Err(err) => {
                        *this.read_buf.lock() = tmp;
                        Poll::Ready(Err(err))
                    }
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for Mux {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let mut write = this.write.lock();
        if write.is_none() {
            let inner = Arc::clone(&this.write_inner);
            let mut data = std::mem::take(&mut *this.write_buf.lock());
            data.clear();
            data.extend_from_slice(buf);
            *write = Some(Box::pin(async move {
                let mut guard = inner.lock().await;
                let result = guard.do_write(&data).await;
                drop(guard);
                (data, result)
            }));
        }
        let Some(future) = write.as_mut() else {
            return Poll::Ready(Err(io::Error::other("write future was just installed")));
        };
        match future.as_mut().poll(cx) {
            Poll::Ready((data, result)) => {
                *write = None;
                drop(write);
                *this.write_buf.lock() = data;
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().conn).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl NetConn for Mux {
    /// The underlying conn is forced closed after one second in case the
    /// session-end frame write blocks: the write is raced against a one-second sleep.
    /// Sent through `write_inner`'s lock, like `WriteInner::do_write`, so the End frame cannot
    /// interleave with an in-flight data frame on a conn whose `poll_write` has only one
    /// in-flight slot (review finding 1 on 0a6d0631).
    fn close(&self) -> io::Result<()> {
        let write_inner = Arc::clone(&self.write_inner);
        let conn = self.conn.clone();
        tokio::spawn(async move {
            let send = async {
                let mut guard = write_inner.lock().await;
                let id = guard.id_shared.load(Ordering::SeqCst).to_be_bytes();
                let frame = [0x0, 0x4, id[0], id[1], SESSION_STATUS_END, OPTION_NONE];
                guard.conn.write_all(&frame).await?;
                guard.conn.flush().await
            };
            tokio::select! {
                () = tokio::time::sleep(std::time::Duration::from_secs(1)) => {
                    let _ = conn.close();
                }
                _ = send => {
                    let _ = conn.close();
                }
            }
        });
        Ok(())
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        clone_addr_result(&self.local_addr)
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        clone_addr_result(&self.remote_addr)
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.conn.set_deadline(deadline)
    }
}

impl std::fmt::Debug for Mux {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mux").finish_non_exhaustive()
    }
}

#[must_use]
#[expect(
    clippy::needless_pass_by_value,
    reason = "public constructor: the option is taken by value, and callers hand it a freshly built value"
)]
pub fn new_mux(conn: Box<dyn NetConn>, option: MuxOption) -> Mux {
    let local_addr = conn.local_addr();
    let remote_addr = conn.remote_addr();

    let mut buf = Vec::new();
    // Fill an empty length placeholder, fixed up once the metadata frame is complete.
    buf.extend_from_slice(&[0x0, 0x0]);
    buf.extend_from_slice(&option.id);
    buf.push(SESSION_STATUS_NEW);
    buf.push(OPTION_NONE);

    let net_type: u8 = if option.type_ == "udp" { 0x2 } else { 0x1 };
    buf.push(net_type);

    buf.extend_from_slice(&option.port.to_be_bytes());

    match option.host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ipv4)) => {
            buf.push(0x1);
            buf.extend_from_slice(&ipv4.octets());
        }
        Ok(IpAddr::V6(ipv6)) => {
            buf.push(0x3);
            buf.extend_from_slice(&ipv6.octets());
        }
        Err(_) => {
            buf.push(0x2);
            buf.extend_from_slice(option.host.as_bytes());
        }
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "the metadata-length prefix is the frame's 16-bit wire field, and the metadata is \
                  a fixed header plus the option host, which the config carries as a hostname or IP literal"
    )]
    let metadata_len = (buf.len() - 2) as u16;
    let (length_field, _) = buf.split_at_mut(2);
    length_field.copy_from_slice(&metadata_len.to_be_bytes());

    let shared = SharedConn::from_boxed(conn);
    let id_shared = Arc::new(AtomicU16::new(u16::from_be_bytes(option.id)));
    let read_inner = ReadInner {
        conn: Box::new(shared.clone()),
        length: [0; 2],
        id: option.id,
        id_shared: Arc::clone(&id_shared),
        status: [0; 2],
        remain: 0,
    };
    let write_inner = WriteInner { conn: Box::new(shared.clone()), id_shared, pending_prefix: buf };

    Mux {
        read_inner: Arc::new(AsyncMutex::new(read_inner)),
        write_inner: Arc::new(AsyncMutex::new(write_inner)),
        conn: shared,
        read: parking_lot::Mutex::new(None),
        write: parking_lot::Mutex::new(None),
        read_buf: parking_lot::Mutex::new(Vec::new()),
        write_buf: parking_lot::Mutex::new(Vec::new()),
        local_addr,
        remote_addr,
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use tokio::io::{split, AsyncReadExt, AsyncWriteExt};

    use super::*;
    use murmur_std_compat::net::TcpAddr;

    struct DuplexConn(tokio::io::DuplexStream);

    impl AsyncRead for DuplexConn {
        fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for DuplexConn {
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

    impl NetConn for DuplexConn {
        fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(TcpAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)))
        }

        fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(TcpAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)))
        }

        fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A `Mux` plus two writes over a captured conn.
    /// The first write prepends the `SESSION_STATUS_NEW` metadata frame (id `00 00`, host
    /// `example.com`, port 80, `tcp`) to the `SESSION_STATUS_KEEP` data frame, and the second
    /// write sends only the `SESSION_STATUS_KEEP` frame. Unlike the raw underlying
    /// conn byte count (34 then 14), `WriteInner::do_write` reports
    /// `len(b)` (review finding 0 on dbe00639) so `AsyncWrite`'s `n <= buf.len()` contract holds;
    /// the pinned frame bytes on the wire are unaffected.
    #[tokio::test]
    async fn do_write_prepends_new_metadata_frame() {
        let (client, mut server) = tokio::io::duplex(256);
        let option = MuxOption { id: [0, 0], port: 80, host: "example.com".to_owned(), type_: "tcp".to_owned() };
        let mux = new_mux(Box::new(DuplexConn(client)), option);
        let write_inner = Arc::clone(&mux.write_inner);

        {
            let mut guard = write_inner.lock().await;
            let n = guard.do_write(b"hello").await.unwrap();
            assert_eq!(n, 5);
            assert!(guard.pending_prefix.is_empty());
        }
        let mut first = vec![0u8; 34];
        server.read_exact(&mut first).await.unwrap();
        assert_eq!(hex::encode(&first), "001300000100010050026578616d706c652e636f6d000400000201000568656c6c6f");

        {
            let mut guard = write_inner.lock().await;
            let n = guard.do_write(b"world!").await.unwrap();
            assert_eq!(n, 6);
        }
        let mut second = vec![0u8; 14];
        server.read_exact(&mut second).await.unwrap();
        assert_eq!(hex::encode(&second), "0004000002010006776f726c6421");
    }

    /// Review finding 0 (P1) on dbe00639: `WriteInner::do_write` used to return the framed byte
    /// count instead of `len(b)`, breaking `AsyncWrite`'s `n <= buf.len()` contract; running
    /// `tokio::io::AsyncWriteExt::write_all` through a `Mux` panicked (`WriteAll::poll`'s
    /// `split_at`), reachable in production through the shadowsocks outbound with the
    /// v2ray-plugin obfs and `cipher: none`. This must not panic, and the frame reaching the
    /// wire is byte-identical to the known-answer test above.
    #[tokio::test]
    async fn write_all_through_mux_does_not_panic() {
        let (client, mut server) = tokio::io::duplex(256);
        let option = MuxOption { id: [0, 0], port: 80, host: "example.com".to_owned(), type_: "tcp".to_owned() };
        let mut mux = new_mux(Box::new(DuplexConn(client)), option);

        mux.write_all(b"hello").await.expect("write_all must not panic or error (review finding 0)");

        let mut first = vec![0u8; 34];
        server.read_exact(&mut first).await.unwrap();
        assert_eq!(hex::encode(&first), "001300000100010050026578616d706c652e636f6d000400000201000568656c6c6f");
    }

    /// Finding 21 regression: `common::net::relay` polls the read side first, so a
    /// client-speaks-first exchange leaves `Mux`'s read pending (the peer here never writes)
    /// while a write is ready to go out. Before the read/write lock split, both sides shared one
    /// `Arc<AsyncMutex<Inner>>` held across the pending read's `.await`, so the write below never
    /// reached the wire and this test timed out. After the split, the write completes without
    /// waiting on the unrelated pending read.
    #[tokio::test]
    async fn write_does_not_block_behind_pending_read() {
        let (client, _server) = tokio::io::duplex(256);
        let option = MuxOption { id: [1, 2], port: 80, host: "example.com".to_owned(), type_: "tcp".to_owned() };
        let mux = new_mux(Box::new(DuplexConn(client)), option);
        let (mut read_half, mut write_half) = split(mux);

        let read_task = tokio::spawn(async move {
            let mut buf = [0u8; 4];
            read_half.read(&mut buf).await
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let write_result = tokio::time::timeout(std::time::Duration::from_secs(2), write_half.write_all(b"hi")).await;
        assert!(write_result.is_ok(), "write blocked behind the pending read (finding 21 regression)");
        write_result.unwrap().unwrap();

        read_task.abort();
    }

    /// Round 2 review (agent://ReviewP3MuxMasque, finding 1 on `close`): the End frame must
    /// reach the wire through the same `write_inner` lock as `do_write`, so a `close` racing an
    /// in-flight data write cannot interleave with it or steal its bytes, and both frames must
    /// carry the mux's shared session id. This locks `write_inner` directly (bypassing `poll_write`,
    /// like `do_write_prepends_new_metadata_frame` above) to hold the write in flight on a
    /// duplex too small to accept the whole frame in one poll, calls `close` while that write is
    /// still blocked on the peer draining it, then checks the wire: the complete data frame
    /// arrives first, the End frame follows immediately after, and both carry id `09 09`.
    #[tokio::test]
    async fn close_during_an_in_flight_write_sees_the_data_frame_then_end_with_the_same_id() {
        let (client, mut server) = tokio::io::duplex(16);
        let option = MuxOption { id: [9, 9], port: 80, host: "example.com".to_owned(), type_: "tcp".to_owned() };
        let mux = new_mux(Box::new(DuplexConn(client)), option);
        let write_inner = Arc::clone(&mux.write_inner);

        let payload = vec![b'x'; 4096];
        let payload_for_task = payload.clone();
        let write_task = tokio::spawn(async move {
            let mut guard = write_inner.lock().await;
            guard.do_write(&payload_for_task).await
        });

        // Give the write a chance to start and block on the small duplex buffer, well inside
        // close()'s 1s force-close deadline.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        mux.close().expect("close must not error synchronously");

        let data_frame_len = 21 /* NEW metadata prefix for host=example.com, port=80 */
            + 8 /* data-frame header: frame length(2) + id(2) + status(1) + opt(1) + data length(2) */
            + payload.len();
        let mut got = vec![0u8; data_frame_len + 6 /* End frame */];
        tokio::time::timeout(std::time::Duration::from_secs(2), server.read_exact(&mut got))
            .await
            .expect("timed out draining the wire")
            .expect("read data frame then End frame");
        write_task.await.expect("write task panicked").expect("do_write must not fail");

        let (data_frame, end_frame) = got.split_at(data_frame_len);
        assert_eq!(&data_frame[23..25], &[9, 9], "data frame must carry the mux's session id");
        assert_eq!(&data_frame[29..], payload.as_slice(), "data frame payload must reach the wire intact");
        assert_eq!(
            end_frame,
            [0x00, 0x04, 0x09, 0x09, SESSION_STATUS_END, OPTION_NONE],
            "End frame must follow the complete data frame and carry the same session id"
        );
    }
}
