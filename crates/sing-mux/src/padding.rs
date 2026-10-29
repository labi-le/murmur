//! The padding conn wraps one carrier connection and reads/writes both directions concurrently
//! (`Read`/`Write` on the same fd from two tasks). This build splits the carrier with
//! `tokio::io::split` (a `BiLock`, released between polls, so the two directions never block each
//! other — see `rule://wave-rules` #3) and rejoins the two independently-stateful halves with
//! `tokio::io::join`.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, ReadHalf, WriteHalf};

use crate::session::MuxConn;

const FIRST_PADDINGS: u32 = 16;
const MAX_CHUNK: usize = 65535;
const SKIP_CHUNK: usize = 4096;

fn random_padding_len() -> u16 {
    256 + rand::rng().random_range(0..512)
}

struct PaddingRead {
    inner: ReadHalf<Box<dyn MuxConn>>,
    read_padding: u32,
    read_remaining: usize,
    padding_remaining: usize,
    header_buf: [u8; 4],
    header_filled: usize,
    scratch: Vec<u8>,
}

impl AsyncRead for PaddingRead {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        loop {
            let this = &mut *self;
            if this.read_remaining > 0 {
                let want = this.read_remaining.min(buf.remaining());
                if want == 0 {
                    return Poll::Ready(Ok(()));
                }
                if this.scratch.len() < want {
                    this.scratch.resize(want, 0);
                }
                // `ReadBuf::take` borrows the parent's *uninitialized* tail without recording
                // that the child initialized it, so `advance` on the parent afterwards would trip
                // its bounds check for any caller that hands us a `ReadBuf` over uninit memory
                // (h2's codec does). Staging through a reused buffer keeps `put_slice` doing the
                // initialization bookkeeping.
                let mut sub = ReadBuf::new(this.scratch.split_at_mut(want).0);
                return match Pin::new(&mut this.inner).poll_read(cx, &mut sub) {
                    Poll::Ready(Ok(())) => {
                        let n = sub.filled().len();
                        buf.put_slice(this.scratch.split_at(n).0);
                        this.read_remaining -= n;
                        Poll::Ready(Ok(()))
                    }
                    Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                    Poll::Pending => Poll::Pending,
                };
            }
            if this.padding_remaining > 0 {
                let mut scratch = [0u8; SKIP_CHUNK];
                loop {
                    if this.padding_remaining == 0 {
                        break;
                    }
                    let want = this.padding_remaining.min(SKIP_CHUNK);
                    let mut sub = ReadBuf::new(scratch.split_at_mut(want).0);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut sub) {
                        Poll::Ready(Ok(())) => {
                            let n = sub.filled().len();
                            if n == 0 {
                                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                            }
                            this.padding_remaining -= n;
                        }
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                continue;
            }
            if this.read_padding < FIRST_PADDINGS {
                while this.header_filled < 4 {
                    let mut sub = ReadBuf::new(this.header_buf.split_at_mut(this.header_filled).1);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut sub) {
                        Poll::Ready(Ok(())) => {
                            let n = sub.filled().len();
                            if n == 0 {
                                return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                            }
                            this.header_filled += n;
                        }
                        Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                let original_data_size = u16::from_be_bytes([this.header_buf[0], this.header_buf[1]]) as usize;
                let padding_len = u16::from_be_bytes([this.header_buf[2], this.header_buf[3]]) as usize;
                this.header_filled = 0;
                this.read_padding += 1;
                this.read_remaining = original_data_size;
                this.padding_remaining = padding_len;
                continue;
            }
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }
    }
}

struct PaddingWrite {
    inner: WriteHalf<Box<dyn MuxConn>>,
    write_padding: u32,
    pending: Vec<u8>,
    pending_written: usize,
    pending_payload_len: usize,
}

impl PaddingWrite {
    /// Drains the unwritten tail of `self.pending` into `self.inner`, reporting the accepted
    /// payload length once the whole frame (header + payload + padding) has gone out. the
    /// `Write` performs this as one blocking syscall; polling drives it to completion across
    /// however many `poll_write` calls the runtime needs.
    fn drive_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        while self.pending_written < self.pending.len() {
            match Pin::new(&mut self.inner).poll_write(cx, self.pending.split_at(self.pending_written).1) {
                Poll::Ready(Ok(n)) => {
                    if n == 0 {
                        return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                    }
                    self.pending_written += n;
                }
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.pending.clear();
        self.pending_written = 0;
        self.write_padding += 1;
        Poll::Ready(Ok(self.pending_payload_len))
    }
}

impl AsyncWrite for PaddingWrite {
    /// Writes one chunk (the helper loops for payloads over
    /// 65535 bytes; `poll_write`'s partial-write contract gives the same chunking for free).
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if !this.pending.is_empty() {
            return this.drive_pending(cx);
        }
        if this.write_padding >= FIRST_PADDINGS {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        let data_len = buf.len().min(MAX_CHUNK);
        let padding_len = random_padding_len();
        this.pending.clear();
        #[expect(
            clippy::cast_possible_truncation,
            reason = "`data_len` is capped at `MAX_CHUNK` (65535), the largest value the 16-bit length field carries"
        )]
        this.pending.extend_from_slice(&(data_len as u16).to_be_bytes());
        this.pending.extend_from_slice(&padding_len.to_be_bytes());
        this.pending.extend_from_slice(buf.split_at(data_len).0);
        this.pending.resize(this.pending.len() + padding_len as usize, 0);
        this.pending_payload_len = data_len;
        this.drive_pending(cx)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if !this.pending.is_empty() {
            match this.drive_pending(cx) {
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if !this.pending.is_empty() {
            match this.drive_pending(cx) {
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

#[must_use]
pub fn new_padding_conn(conn: Box<dyn MuxConn>) -> Box<dyn MuxConn> {
    let (read_half, write_half) = tokio::io::split(conn);
    let read = PaddingRead {
        inner: read_half,
        read_padding: 0,
        read_remaining: 0,
        padding_remaining: 0,
        header_buf: [0; 4],
        header_filled: 0,
        scratch: Vec::new(),
    };
    let write = PaddingWrite {
        inner: write_half,
        write_padding: 0,
        pending: Vec::new(),
        pending_written: 0,
        pending_payload_len: 0,
    };
    Box::new(tokio::io::join(read, write))
}

#[cfg(test)]
mod tests {
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn round_trips_padded_frames() {
        let (client_raw, server_raw) = duplex(1 << 20);
        let mut client: Box<dyn MuxConn> = new_padding_conn(Box::new(client_raw));
        let mut server: Box<dyn MuxConn> = new_padding_conn(Box::new(server_raw));

        let client_task = tokio::spawn(async move {
            for i in 0..20u8 {
                let payload = vec![i; 100 + i as usize];
                client.write_all(&payload).await.unwrap();
                client.flush().await.unwrap();
                let mut echo = vec![0u8; payload.len()];
                client.read_exact(&mut echo).await.unwrap();
                assert_eq!(echo, payload);
            }
        });

        for i in 0..20u8 {
            let len = 100 + i as usize;
            let mut buf = vec![0u8; len];
            server.read_exact(&mut buf).await.unwrap();
            assert!(buf.iter().all(|&b| b == i));
            server.write_all(&buf).await.unwrap();
            server.flush().await.unwrap();
        }
        client_task.await.unwrap();
    }
}
