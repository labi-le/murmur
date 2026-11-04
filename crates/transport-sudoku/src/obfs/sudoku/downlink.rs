use std::fmt;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures::future::BoxFuture;
use tokio::io::AsyncWrite;

use murmur_common_net::io::Stream as NetConn;

use super::conn::{err_closed_pipe, WriteDrain};
use super::encode::encode_sudoku_payload;
use super::packed::{new_packed_conn, PackedConnHandle};
use super::padding_prob::pick_padding_threshold;
use super::rand::{new_seeded_rand, SudokuRand};
use super::table::Table;

/// the `[]func() error`: the closers a server-side directional conn runs when
/// it tears the downlink writer down.
pub type Closer = Box<dyn Fn() -> BoxFuture<'static, io::Result<()>> + Send + Sync>;

/// Encodes payload bytes with the selected downlink codec.
pub struct DownlinkWriter {
    data_writer: Option<Box<dyn AsyncWrite + Send + Unpin>>,
}

impl fmt::Debug for DownlinkWriter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DownlinkWriter").field("data_writer", &self.data_writer.is_some()).finish()
    }
}

#[must_use]
pub fn new_downlink_writer(
    raw: Box<dyn AsyncWrite + Send + Unpin>,
    table: Option<Arc<Table>>,
    p_min: i32,
    p_max: i32,
) -> DownlinkWriter {
    let local_rng = new_seeded_rand();
    new_downlink_writer_from(Box::new(new_sudoku_data_writer(raw, table, local_rng, p_min, p_max)))
}

#[must_use]
pub fn new_packed_downlink_writer(
    raw: Box<dyn NetConn>,
    table: Option<Arc<Table>>,
    p_min: i32,
    p_max: i32,
) -> (PackedConnHandle, DownlinkWriter) {
    let packed = PackedConnHandle::new(new_packed_conn(raw, table, p_min, p_max));
    let writer = new_downlink_writer_from(Box::new(packed.clone()));
    (packed, writer)
}

#[must_use]
pub fn new_server_downlink_writer(
    raw: Box<dyn NetConn>,
    table: Option<Arc<Table>>,
    p_min: i32,
    p_max: i32,
    pure: bool,
) -> (DownlinkWriter, Vec<Closer>) {
    if pure {
        return (new_downlink_writer(Box::new(ConnWriter(raw)), table, p_min, p_max), Vec::new());
    }

    let (packed, writer) = new_packed_downlink_writer(raw, table, p_min, p_max);
    let closer: Closer = Box::new(move || {
        let packed = packed.clone();
        Box::pin(async move { packed.flush().await })
    });
    (writer, vec![closer])
}

fn new_downlink_writer_from(data_writer: Box<dyn AsyncWrite + Send + Unpin>) -> DownlinkWriter {
    DownlinkWriter { data_writer: Some(data_writer) }
}

impl AsyncWrite for DownlinkWriter {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let Some(writer) = this.data_writer.as_mut() else {
            return Poll::Ready(Err(err_closed_pipe()));
        };
        Pin::new(&mut **writer).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        match this.data_writer.as_mut() {
            Some(writer) => Pin::new(&mut **writer).poll_flush(cx),
            None => Poll::Ready(Err(err_closed_pipe())),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        match this.data_writer.as_mut() {
            Some(writer) => Pin::new(&mut **writer).poll_shutdown(cx),
            None => Poll::Ready(Ok(())),
        }
    }
}

/// Presents a connection where the downlink writer expects only a byte sink.
struct ConnWriter(Box<dyn NetConn>);

impl fmt::Debug for ConnWriter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnWriter").finish()
    }
}

impl AsyncWrite for ConnWriter {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().0).poll_shutdown(cx)
    }
}

pub(crate) struct SudokuDataWriter {
    writer: Option<Box<dyn AsyncWrite + Send + Unpin>>,
    table: Option<Arc<Table>>,
    rng: Option<SudokuRand>,
    padding_threshold: u64,
    write_drain: WriteDrain,
}

impl fmt::Debug for SudokuDataWriter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SudokuDataWriter")
            .field("table", &self.table.as_ref().map(|table| table.hint()))
            .field("padding_threshold", &self.padding_threshold)
            .finish_non_exhaustive()
    }
}

pub(crate) fn new_sudoku_data_writer(
    writer: Box<dyn AsyncWrite + Send + Unpin>,
    table: Option<Arc<Table>>,
    mut rng: SudokuRand,
    p_min: i32,
    p_max: i32,
) -> SudokuDataWriter {
    let padding_threshold = pick_padding_threshold(Some(&mut rng), p_min, p_max);
    SudokuDataWriter {
        writer: Some(writer),
        table,
        rng: Some(rng),
        padding_threshold,
        write_drain: WriteDrain::with_capacity(4096),
    }
}

impl AsyncWrite for SudokuDataWriter {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.writer.is_none() {
            return Poll::Ready(Err(err_closed_pipe()));
        }
        if this.table.as_ref().is_none_or(|table| table.layout.is_none()) || this.rng.is_none() {
            return Poll::Ready(Err(err_closed_pipe()));
        }

        if this.write_drain.idle() {
            let Some(table) = this.table.clone() else {
                return Poll::Ready(Err(err_closed_pipe()));
            };
            let Some(rng) = this.rng.as_mut() else {
                return Poll::Ready(Err(err_closed_pipe()));
            };
            let threshold = this.padding_threshold;
            let mut out = this.write_drain.take_buf();
            encode_sudoku_payload(&mut out, &table, rng, threshold, buf);
            this.write_drain.put_buf(out);
            this.write_drain.start(buf.len());
        }

        let Some(writer) = this.writer.as_mut() else {
            return Poll::Ready(Err(err_closed_pipe()));
        };
        this.write_drain.poll_drain(cx, &mut **writer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        match this.writer.as_mut() {
            Some(writer) => Pin::new(&mut **writer).poll_flush(cx),
            None => Poll::Ready(Err(err_closed_pipe())),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        match this.writer.as_mut() {
            Some(writer) => Pin::new(&mut **writer).poll_shutdown(cx),
            None => Poll::Ready(Ok(())),
        }
    }
}
