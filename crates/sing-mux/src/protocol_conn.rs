//! DEVIATION: the `Write` returns `n-1` on the header-prepending first call (an off-by-one that
//! only fails to matter because both the `smux`/`yamux` client constructors that consume this
//! conn's first write discard the returned `n` and check only `err`). Rust's `AsyncWrite` contract
//! requires `n <= buf.len()`, and violating it can panic a well-behaved caller that slices
//! `buf[n..]`; this crate reports the correct `buf.len()` once the whole header+payload frame has
//! gone out, which is what every other caller of this conn already assumes.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::protocol::{encode_request, Request};
use crate::session::MuxConn;

struct ProtocolConn {
    inner: Box<dyn MuxConn>,
    request: Request,
    request_written: bool,
    pending: Vec<u8>,
    pending_written: usize,
    pending_payload_len: usize,
}

impl ProtocolConn {
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
        self.request_written = true;
        self.pending.clear();
        self.pending_written = 0;
        Poll::Ready(Ok(self.pending_payload_len))
    }
}

impl AsyncRead for ProtocolConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ProtocolConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if !this.pending.is_empty() {
            return this.drive_pending(cx);
        }
        if this.request_written {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        this.pending = encode_request(this.request, buf);
        this.pending_payload_len = buf.len();
        this.drive_pending(cx)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.pending.is_empty() {
            match this.drive_pending(cx) {
                Poll::Ready(Ok(_)) => {}
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
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
pub fn new_protocol_conn(conn: Box<dyn MuxConn>, request: Request) -> Box<dyn MuxConn> {
    Box::new(ProtocolConn {
        inner: conn,
        request,
        request_written: false,
        pending: Vec::new(),
        pending_written: 0,
        pending_payload_len: 0,
    })
}
