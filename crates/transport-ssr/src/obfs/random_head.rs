use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use rand::{Rng as _, RngCore as _};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use murmur_common_net::io::Stream;
use murmur_common_pool as pool;

use super::base::Base;
use super::obfs::{register, Obfs, ObfsList};

#[derive(Clone, Debug)]
pub(crate) struct RandomHead;
#[expect(
    clippy::struct_excessive_bools,
    reason = "the flags mirror the independent handshake stages of the protocol; collapsing them would change the shared shape"
)]
pub(crate) struct RandomHeadConn {
    conn: Box<dyn Stream>,
    has_sent_header: bool,
    raw_trans_sent: bool,
    raw_trans_recv: bool,
    buf: Vec<u8>,
    /// A write is reported done only once its block is fully accepted, so partially accepted
    /// blocks still go out in the order they were staged.
    queue: VecDeque<Vec<u8>>,
    queue_written: usize,
    /// A connector write failure seen while draining, kept for the caller `Write` that staged it.
    queue_error: Option<io::Error>,
    /// Set while a caller `Write` waits for its staged block, so it stages its bytes only once.
    caller_pending: bool,
    /// the first `Read` discards its connector read, and a `Pending` retry must not repeat it.
    first_read_done: bool,
}

/// `init()`, called from the registry's initializer instead of at package load.
pub(crate) fn init(list: &mut ObfsList) {
    register(list, "random_head", new_random_head, 0);
}

pub(crate) fn new_random_head(_b: &Base) -> Box<dyn Obfs> {
    Box::new(RandomHead)
}

impl RandomHeadConn {
    /// `Write`'s first block: four plus a random value below 96 bytes and the complement of their
    /// CRC32.
    fn build_header() -> Vec<u8> {
        let data_length = rand::rng().random_range(0..96) + 4;
        let mut buf = pool::get(data_length + 4);
        let (data, checksum) = buf.split_at_mut(data_length);
        rand::rng().fill_bytes(data);
        let crc32 = 0xffff_ffffu32.wrapping_sub(crc32fast::hash(data));
        checksum.copy_from_slice(&crc32.to_le_bytes());
        buf
    }

    /// The write body; `from_read` marks the empty write a read makes,
    /// whose result it discards.
    fn poll_write_body(&mut self, cx: &mut Context<'_>, b: &[u8], from_read: bool) -> Poll<io::Result<usize>> {
        if from_read {
            self.stage_write(b);
            return self.drain(cx).map(|done| done.map(|()| b.len()));
        }

        if let Some(err) = self.queue_error.take() {
            self.caller_pending = false;
            return Poll::Ready(Err(err));
        }

        if !self.caller_pending {
            if self.raw_trans_sent && self.queue.is_empty() {
                return Pin::new(&mut *self.conn).poll_write(cx, b);
            }
            self.caller_pending = true;
            self.stage_write(b);
            if self.queue.is_empty() {
                self.caller_pending = false;
                return Poll::Ready(Ok(b.len()));
            }
        }

        match self.drain(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => {
                self.caller_pending = false;
                Poll::Ready(Err(err))
            }
            Poll::Ready(Ok(())) => {
                self.caller_pending = false;
                Poll::Ready(Ok(b.len()))
            }
        }
    }

    fn stage_write(&mut self, b: &[u8]) {
        if self.raw_trans_sent {
            self.queue.push_back(b.to_vec());
            return;
        }

        self.buf.extend_from_slice(b);
        if !self.has_sent_header {
            self.has_sent_header = true;
            let header = Self::build_header();
            self.queue.push_back(header);
        } else if self.raw_trans_recv {
            self.raw_trans_sent = true;
            self.queue.push_back(std::mem::take(&mut self.buf));
        }
    }

    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            if self.queue.is_empty() {
                return Poll::Ready(Ok(()));
            }
            if self.queue_written >= self.queue.front().map_or(0, Vec::len) {
                if let Some(done) = self.queue.pop_front() {
                    pool::put(done).ok();
                }
                self.queue_written = 0;
                continue;
            }
            let written = self.queue_written;
            let poll = if let Some(pending) = self.queue.front() {
                if let Some(rest) = pending.get(written..) {
                    Pin::new(&mut *self.conn).poll_write(cx, rest)
                } else {
                    Poll::Ready(Ok(0))
                }
            } else {
                Poll::Ready(Ok(0))
            };
            match poll {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => {
                    self.queue.clear();
                    self.queue_written = 0;
                    return Poll::Ready(Err(err));
                }
                Poll::Ready(Ok(0)) => {
                    self.queue.clear();
                    self.queue_written = 0;
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                Poll::Ready(Ok(n)) => self.queue_written += n,
            }
        }
    }
}

impl Obfs for RandomHead {
    fn stream_conn(&self, c: Box<dyn Stream>) -> Box<dyn Stream> {
        Box::new(RandomHeadConn {
            conn: c,
            has_sent_header: false,
            raw_trans_sent: false,
            raw_trans_recv: false,
            buf: Vec::new(),
            queue: VecDeque::new(),
            queue_written: 0,
            queue_error: None,
            caller_pending: false,
            first_read_done: false,
        })
    }
}

impl AsyncRead for RandomHeadConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.queue.is_empty() {
                match this.drain(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(err)) => {
                        if this.caller_pending {
                            this.queue_error = Some(err);
                        }
                        continue;
                    }
                    Poll::Ready(Ok(())) => {}
                }
                continue;
            }

            if this.raw_trans_recv {
                return Pin::new(&mut *this.conn).poll_read(cx, buf);
            }

            if !this.first_read_done {
                let mut scratch = pool::get(pool::RELAY_BUFFER_SIZE);
                let is_pending = {
                    let mut read_buf = ReadBuf::new(&mut scratch);
                    matches!(Pin::new(&mut *this.conn).poll_read(cx, &mut read_buf), Poll::Pending)
                };
                pool::put(scratch).ok();
                if is_pending {
                    return Poll::Pending;
                }
                this.first_read_done = true;
                this.raw_trans_recv = true;
            }

            match this.poll_write_body(cx, &[], true) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(_) => {}
            }
        }
    }
}

impl AsyncWrite for RandomHeadConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.get_mut().poll_write_body(cx, buf, false)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.drain(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Ready(Ok(())) => Pin::new(&mut *this.conn).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().conn).poll_shutdown(cx)
    }
}

impl Stream for RandomHeadConn {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.conn.local_addr()
    }

    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.conn.peer_addr()
    }

    fn shutdown_read(&self) -> io::Result<()> {
        self.conn.shutdown_read()
    }

    fn shutdown_write(&self) -> io::Result<()> {
        self.conn.shutdown_write()
    }

    fn old_conn(&self) -> Option<&dyn murmur_std_compat::net::Conn> {
        self.conn.old_conn()
    }
}
