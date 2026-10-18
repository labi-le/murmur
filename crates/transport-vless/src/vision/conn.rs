use std::any::Any;
use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use uuid::Uuid;

use murmur_common::shared_conn::SharedConn;
use murmur_common_net::io::{ExtendedStream, Stream as NetStream};
use murmur_common_net::sing::{
    calculate_front_headroom, calculate_rear_headroom, EarlyConn, ExtendedConn as CommonExtendedConn, UpstreamNode,
};
use murmur_compat::sing_buf::{as_, new_size, with, Buffer};
use murmur_component::dialer::tfo::NeedAdditionalReadDeadline;
use murmur_component_tls::utls::TlsBufferedIncoming;
use murmur_log::{debugln, errorln};
use murmur_std_compat::net::{Addr, Conn as NetConn, ExtendedConn as NetExtendedConn};

use super::filter::TLS_APPLICATION_DATA_START;
use super::padding::{
    apply_padding, COMMAND_PADDING_CONTINUE, COMMAND_PADDING_DIRECT, COMMAND_PADDING_END, PADDING_HEADER_LEN,
    UUID_SIZE, XRAY_BUF_SIZE,
};

fn short_buffer() -> io::Error {
    io::Error::new(io::ErrorKind::WriteZero, "short buffer")
}

fn eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "EOF")
}

fn unexpected_eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF")
}

fn unknown_read_command(command: u8) -> io::Error {
    io::Error::other(format!("XTLS Vision read unknown command: {command}"))
}

enum ReadOp {
    /// Reads the remaining buffer once; `nested` marks the recursive read-buffer call made after a
    /// content read.
    RemainingBuffer {
        nested: bool,
    },
    Content {
        read_size: usize,
        into_remaining: bool,
    },
    Padding {
        copied: usize,
    },
    Header {
        header: Vec<u8>,
        filled: usize,
    },
    Reader,
}

enum WriteOp {
    Write {
        index: usize,
        offset: usize,
    },
    /// The step at `index` is written; the old TLS writer must be flushed and the writer swapped
    /// to the raw transport before the next step.
    Flush {
        index: usize,
    },
}

impl std::fmt::Debug for ReadOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReadOp")
    }
}

impl std::fmt::Debug for WriteOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WriteOp")
    }
}

/// `Conn`, which wraps the conn the crate built and exposes it as a conn plus its
/// `ExtendedReader` and `ExtendedWriter` halves.
#[expect(
    clippy::struct_excessive_bools,
    reason = "the bools are the XTLS Vision state machine, one flag per state it reads"
)]
pub struct Conn {
    inner: SharedConn,
    reader: SharedConn,
    writer: SharedConn,
    user_uuid: Uuid,

    /// The conn below TLS that XTLS direct mode switches to, supplied by the caller rather
    /// than read out of the TLS conn; `None` keeps the conn in TLS mode.
    direct_net: Option<SharedConn>,

    /// The TLS conn's buffered incoming plaintext, taken live when the read direction switches so
    /// bytes decrypted before the switch are still delivered.
    buffered_incoming: Option<Arc<dyn TlsBufferedIncoming>>,

    pub(crate) packets_to_filter: i32,
    pub(crate) is_tls: bool,
    pub(crate) is_tls12orabove: bool,
    pub(crate) enable_xtls: bool,
    pub(crate) cipher: u16,
    pub(crate) remaining_server_hello: u16,
    pub(crate) read_remaining_buffer: Option<Buffer>,
    pub(crate) read_remaining_content: i32,
    pub(crate) read_remaining_padding: i32,
    pub(crate) read_process: bool,
    pub(crate) read_filter_uuid: bool,
    pub(crate) read_last_command: u8,
    pub(crate) write_filter_application_data: bool,
    pub(crate) write_direct: bool,
    pub(crate) write_once_user_uuid: Option<[u8; UUID_SIZE]>,

    read_op: Option<ReadOp>,
    read_pending_err: Option<io::Error>,
    read_scratch: Buffer,
    write_op: Option<WriteOp>,
    write_buffers: Vec<Buffer>,
    write_index: usize,
    write_apply_padding: bool,
    write_command: u8,
    /// Capacity kept for the frame after one this conn allocated itself; a caller's buffer is
    /// never parked here.
    write_scratch: Buffer,
    write_owned: bool,

    /// The last deadline the caller set for each direction. A direction's transport is replaced
    /// on a raw switch, and the deadline set before the switch would otherwise stay behind on the
    /// TLS conn the raw direction no longer polls.
    read_deadline: parking_lot::Mutex<DeadlineState>,
    write_deadline: parking_lot::Mutex<DeadlineState>,
}

#[derive(Clone, Copy, Default)]
struct DeadlineState {
    set: bool,
    value: Option<tokio::time::Instant>,
}

impl core::fmt::Debug for Conn {
    /// The conns, the buffers and the padding key material are redacted; only the flags that
    /// decide the wire shape are shown.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Conn")
            .field("read_process", &self.read_process)
            .field("read_last_command", &self.read_last_command)
            .field("write_filter_application_data", &self.write_filter_application_data)
            .field("write_direct", &self.write_direct)
            .finish_non_exhaustive()
    }
}

impl Conn {
    /// The fields the vision conn constructor fills.
    #[allow(
        clippy::too_many_arguments,
        reason = "one constructor fills the exact field set the vision conn constructor passes in"
    )]
    pub(crate) fn new(
        inner: SharedConn,
        reader: SharedConn,
        writer: SharedConn,
        user_uuid: Uuid,
        direct_net: Option<SharedConn>,
        buffered_incoming: Option<Arc<dyn TlsBufferedIncoming>>,
    ) -> Self {
        Self {
            inner,
            reader,
            writer,
            user_uuid,
            direct_net,
            buffered_incoming,
            packets_to_filter: 8,
            is_tls: false,
            is_tls12orabove: false,
            enable_xtls: false,
            cipher: 0,
            remaining_server_hello: 0,
            read_remaining_buffer: None,
            read_remaining_content: 0,
            read_remaining_padding: 0,
            read_process: true,
            read_filter_uuid: true,
            read_last_command: 0,
            write_filter_application_data: true,
            write_direct: false,
            write_once_user_uuid: Some(*user_uuid.as_bytes()),
            read_op: None,
            read_pending_err: None,
            read_scratch: Buffer::default(),
            write_op: None,
            write_buffers: Vec::new(),
            write_index: 0,
            write_apply_padding: false,
            write_command: COMMAND_PADDING_CONTINUE,
            write_scratch: Buffer::default(),
            write_owned: false,
            read_deadline: parking_lot::Mutex::new(DeadlineState::default()),
            write_deadline: parking_lot::Mutex::new(DeadlineState::default()),
        }
    }

    pub async fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        if self.read_process || self.read_remaining_buffer.is_some() {
            let mut buffer = with(b.to_vec());
            self.read_buffer(&mut buffer).await?;
            let n = buffer.len();
            let n = n.min(b.len());
            let (dst, _) = b.split_at_mut(n);
            let (src, _) = buffer.bytes().split_at(n);
            dst.copy_from_slice(src);
            return Ok(n);
        }
        tokio::io::AsyncReadExt::read(&mut self.reader, b).await
    }

    pub async fn read_buffer(&mut self, buffer: &mut Buffer) -> io::Result<()> {
        poll_fn(|cx| self.poll_read_buffer(cx, buffer)).await
    }

    pub async fn write(&mut self, p: &[u8]) -> io::Result<usize> {
        if self.write_filter_application_data {
            if self.write_op.is_some() {
                let mut empty = Buffer::default();
                self.write_owned_buffer(&mut empty).await?;
                return Ok(p.len());
            }
            let mut buffer = self.allocate_write_buffer(p)?;
            self.write_owned_buffer(&mut buffer).await?;
            return Ok(p.len());
        }
        tokio::io::AsyncWriteExt::write(&mut self.writer, p).await
    }

    pub async fn write_buffer(&mut self, buffer: &mut Buffer) -> io::Result<()> {
        poll_fn(|cx| self.poll_write_buffer(cx, buffer, false)).await
    }

    /// The `write`/`poll_write` path, where the buffer was taken from [`Conn::allocate_write_buffer`]
    /// and its capacity may be kept for the next frame.
    async fn write_owned_buffer(&mut self, buffer: &mut Buffer) -> io::Result<()> {
        poll_fn(|cx| self.poll_write_buffer(cx, buffer, true)).await
    }

    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        reason = "the padding header is a small fixed-size wire prefix"
    )]
    pub fn front_headroom(&self) -> i32 {
        let mut front_headroom = if self.read_filter_uuid || self.write_once_user_uuid.is_some() {
            PADDING_HEADER_LEN as i32
        } else {
            (PADDING_HEADER_LEN - UUID_SIZE) as i32
        };
        if self.write_filter_application_data {
            let direct_net_headroom = self.direct_net.as_ref().map_or(0, |conn| calculate_front_headroom(conn));
            let abs = direct_net_headroom - calculate_front_headroom(&self.inner);
            if abs > 0 {
                front_headroom += abs;
            }
        }
        front_headroom
    }

    pub fn rear_headroom(&self) -> i32 {
        let mut rear_headroom = 500 + 900;
        if self.write_filter_application_data {
            let direct_net_headroom = self.direct_net.as_ref().map_or(0, |conn| calculate_rear_headroom(conn));
            let abs = direct_net_headroom - calculate_rear_headroom(&self.inner);
            if abs > 0 {
                rear_headroom += abs;
            }
        }
        rear_headroom
    }

    /// Sizes a buffer with the front and rear room `apply_padding` and the raw handoff need, so a
    /// caller's slice never reaches the padding path without headroom.
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        reason = "the headroom and payload sizes are bounded by the padding reserve and the caller's buffer"
    )]
    fn allocate_write_buffer(&mut self, payload: &[u8]) -> io::Result<Buffer> {
        let front = self.front_headroom().max(0) as usize;
        let rear = self.rear_headroom().max(0) as usize;
        let needed = front + rear + payload.len();
        let mut buffer = std::mem::take(&mut self.write_scratch);
        if buffer.raw_cap() < needed {
            buffer.release();
            buffer = new_size(needed as i32);
        } else {
            buffer.reset();
        }
        buffer.resize(front, 0);
        let written = buffer.write_bytes(payload)?;
        if written != payload.len() {
            return Err(short_buffer());
        }
        Ok(buffer)
    }

    pub const fn need_handshake(&self) -> bool {
        self.write_once_user_uuid.is_some()
    }

    pub const fn need_additional_read_deadline(&self) -> bool {
        true
    }

    /// The direct conn, when one is in use. `None` means the caller's TLS layer keeps it
    /// private.
    const fn direct_conn(&self) -> Option<&SharedConn> {
        if self.write_direct || self.read_last_command == COMMAND_PADDING_DIRECT {
            self.direct_net.as_ref()
        } else {
            Some(&self.inner)
        }
    }

    pub const fn reader_possibly_replaceable(&self) -> bool {
        self.read_process
    }

    pub const fn reader_replaceable(&self) -> bool {
        !self.read_process && self.read_last_command == COMMAND_PADDING_DIRECT
    }

    pub const fn writer_possibly_replaceable(&self) -> bool {
        self.write_filter_application_data
    }

    pub const fn writer_replaceable(&self) -> bool {
        self.write_direct
    }

    pub fn close(&self) -> io::Result<()> {
        if self.reader_replaceable() || self.writer_replaceable() {
            if let Some(direct_net) = &self.direct_net {
                return direct_net.close();
            }
        }
        self.inner.close()
    }

    fn store_deadline(slot: &parking_lot::Mutex<DeadlineState>, deadline: Option<tokio::time::Instant>) {
        *slot.lock() = DeadlineState { set: true, value: deadline };
    }

    /// Carries a deadline set before the read switch onto the transport that now owns the read
    /// direction; a switch that dropped it would let a raw read outlive its deadline.
    fn reapply_read_deadline(&self) {
        let state = *self.read_deadline.lock();
        if state.set {
            let _ = self.reader.set_read_deadline(state.value);
        }
    }

    fn reapply_write_deadline(&self) {
        let state = *self.write_deadline.lock();
        if state.set {
            let _ = self.writer.set_write_deadline(state.value);
        }
    }

    fn poll_read_buffer(&mut self, cx: &mut Context<'_>, buffer: &mut Buffer) -> Poll<io::Result<()>> {
        loop {
            if let Some(op) = self.read_op.take() {
                if let Some(ready) = self.poll_read_op(cx, buffer, op) {
                    return ready;
                }
                continue;
            }
            if let Some(err) = self.select_read_op(buffer) {
                return Poll::Ready(Err(err));
            }
        }
    }

    /// Runs one step of `op`. `None` means the step did not finish its operation, so the caller has
    /// to select the operation for the next step.
    fn poll_read_op(&mut self, cx: &mut Context<'_>, buffer: &mut Buffer, op: ReadOp) -> Option<Poll<io::Result<()>>> {
        match op {
            ReadOp::RemainingBuffer { nested } => Some(self.poll_read_remaining_buffer(cx, buffer, nested)),
            ReadOp::Content { read_size, into_remaining } => {
                self.poll_read_content(cx, buffer, read_size, into_remaining)
            }
            ReadOp::Padding { copied } => self.poll_read_padding(cx, copied),
            ReadOp::Header { header, filled } => self.poll_read_header(cx, header, filled),
            ReadOp::Reader => Some(self.poll_read_reader(cx, buffer)),
        }
    }

    /// The remaining-buffer read step; `nested` marks the recursive read-buffer call made after a
    /// content read.
    fn poll_read_remaining_buffer(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut Buffer,
        nested: bool,
    ) -> Poll<io::Result<()>> {
        let Some(remaining) = self.read_remaining_buffer.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        if buffer.is_full() {
            return Poll::Ready(Err(short_buffer()));
        }
        let result = {
            let mut read_buf = ReadBuf::new(buffer.free_bytes());
            match Pin::new(&mut *remaining).poll_read(cx, &mut read_buf) {
                Poll::Pending => {
                    self.read_op = Some(ReadOp::RemainingBuffer { nested });
                    return Poll::Pending;
                }
                Poll::Ready(Ok(())) => Ok(read_buf.filled().len()),
                Poll::Ready(Err(err)) => Err(err),
            }
        };
        let n = match &result {
            Ok(n) => *n,
            Err(_) => 0,
        };
        buffer.truncate(buffer.len() + n);
        if self.read_remaining_buffer.as_ref().is_some_and(Buffer::is_empty) {
            if let Some(mut empty) = self.read_remaining_buffer.take() {
                empty.release();
            }
        }
        let result = match result {
            Ok(_) => Ok(()),
            Err(err) => Err(err),
        };
        if nested {
            // The nested read-buffer call: its result replaces an outer error
            // and is dropped when the outer read succeeded.
            return Poll::Ready(match self.read_pending_err.take() {
                Some(_) => result,
                None => Ok(()),
            });
        }
        Poll::Ready(result)
    }

    /// The `Content` step: reads `read_size` bytes from the filtered reader and filters them, into
    /// the remaining buffer when the caller's buffer cannot take them.
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        reason = "a read count is bounded by the buffer size, which the constructors size from an `i32`"
    )]
    fn poll_read_content(
        &mut self,
        cx: &mut Context<'_>,
        buffer: &mut Buffer,
        read_size: usize,
        into_remaining: bool,
    ) -> Option<Poll<io::Result<()>>> {
        let mut pending = None;
        let result = if into_remaining {
            let Some(mut remaining) = self.read_remaining_buffer.take() else {
                return Some(Poll::Ready(Err(short_buffer())));
            };
            let result = {
                let Some(free) = remaining.free_bytes().get_mut(..read_size) else {
                    return Some(Poll::Ready(Err(short_buffer())));
                };
                let mut read_buf = ReadBuf::new(free);
                match Pin::new(&mut self.reader).poll_read(cx, &mut read_buf) {
                    Poll::Pending => {
                        self.read_remaining_buffer = Some(remaining);
                        self.read_op = Some(ReadOp::Content { read_size, into_remaining });
                        return Some(Poll::Pending);
                    }
                    Poll::Ready(Ok(())) => Ok(read_buf.filled().len()),
                    Poll::Ready(Err(err)) => Err(err),
                }
            };
            let n = match &result {
                Ok(n) => *n,
                Err(_) => 0,
            };
            remaining.truncate(n);
            self.read_remaining_content -= n as i32;
            self.filter_tls(remaining.bytes());
            pending = Some(remaining);
            result.map(|_| n)
        } else {
            let result = {
                let Some(free) = buffer.free_bytes().get_mut(..read_size) else {
                    return Some(Poll::Ready(Err(short_buffer())));
                };
                let mut read_buf = ReadBuf::new(free);
                match Pin::new(&mut self.reader).poll_read(cx, &mut read_buf) {
                    Poll::Pending => {
                        self.read_op = Some(ReadOp::Content { read_size, into_remaining });
                        return Some(Poll::Pending);
                    }
                    Poll::Ready(Ok(())) => Ok(read_buf.filled().len()),
                    Poll::Ready(Err(err)) => Err(err),
                }
            };
            let n = match &result {
                Ok(n) => *n,
                Err(_) => 0,
            };
            buffer.truncate(n);
            self.read_remaining_content -= n as i32;
            self.filter_tls(buffer.bytes());
            result.map(|_| n)
        };
        self.read_pending_err = match &result {
            Ok(_) => None,
            Err(err) => Some(io::Error::new(err.kind(), err.to_string())),
        };
        let had_pending = pending.is_some();
        if self.read_remaining_buffer.is_none() {
            if let Some(remaining) = pending {
                self.read_remaining_buffer = Some(remaining);
            }
        }
        if had_pending || self.read_remaining_buffer.is_some() {
            self.read_op = Some(ReadOp::RemainingBuffer { nested: true });
            return None;
        }
        Some(Poll::Ready(match result {
            Ok(_) => Ok(()),
            Err(err) => Err(err),
        }))
    }

    /// The `Padding` step: drains `read_remaining_padding` bytes from the filtered reader.
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        reason = "the padding count is a positive `i32` wire length field"
    )]
    fn poll_read_padding(&mut self, cx: &mut Context<'_>, copied: usize) -> Option<Poll<io::Result<()>>> {
        let mut copied_total = copied;
        let mut scratch = [0u8; 4096];
        loop {
            let want = (self.read_remaining_padding as usize).saturating_sub(copied_total);
            let result = {
                let read_len = want.min(scratch.len());
                let (head, _) = scratch.split_at_mut(read_len);
                let mut read_buf = ReadBuf::new(head);
                match Pin::new(&mut self.reader).poll_read(cx, &mut read_buf) {
                    Poll::Pending => {
                        self.read_op = Some(ReadOp::Padding { copied: copied_total });
                        return Some(Poll::Pending);
                    }
                    Poll::Ready(Ok(())) => Ok(read_buf.filled().len()),
                    Poll::Ready(Err(err)) => Err(err),
                }
            };
            let n = match result {
                Ok(n) => n,
                Err(err) => return Some(Poll::Ready(Err(err))),
            };
            if n == 0 {
                return Some(Poll::Ready(Err(eof())));
            }
            copied_total += n;
            if copied_total >= self.read_remaining_padding as usize {
                break;
            }
        }
        self.read_remaining_padding -= copied_total as i32;
        None
    }

    /// The `Header` step: reads the padding header, checks the `UUID` once and records the lengths.
    fn poll_read_header(
        &mut self,
        cx: &mut Context<'_>,
        mut header: Vec<u8>,
        mut filled: usize,
    ) -> Option<Poll<io::Result<()>>> {
        let need = header.len();
        loop {
            let result = {
                let (_, pending) = header.split_at_mut(filled);
                let mut read_buf = ReadBuf::new(pending);
                match Pin::new(&mut self.reader).poll_read(cx, &mut read_buf) {
                    Poll::Pending => {
                        self.read_op = Some(ReadOp::Header { header, filled });
                        return Some(Poll::Pending);
                    }
                    Poll::Ready(Ok(())) => Ok(read_buf.filled().len()),
                    Poll::Ready(Err(err)) => Err(err),
                }
            };
            let n = match result {
                Ok(n) => n,
                Err(err) => return Some(Poll::Ready(Err(err))),
            };
            if n == 0 {
                return Some(Poll::Ready(Err(if filled == 0 { eof() } else { unexpected_eof() })));
            }
            filled += n;
            if filled >= need {
                break;
            }
        }
        let mut header = header.as_slice();
        if self.read_filter_uuid {
            self.read_filter_uuid = false;
            let Some(uuid) = header.get(..UUID_SIZE) else {
                return Some(Poll::Ready(Err(unexpected_eof())));
            };
            if self.user_uuid.as_bytes() != uuid {
                let got = Uuid::from_slice(uuid).unwrap_or_else(|_| Uuid::nil());
                let err = io::Error::other(format!("XTLS Vision server responded unknown UUID: {got}"));
                errorln!("{}", err);
                return Some(Poll::Ready(Err(err)));
            }
            header = header.get(UUID_SIZE..).unwrap_or_default();
        }
        // the wire header is `command | content length | padding length`, each field big-endian.
        let [command, content_lo, content_hi, padding_lo, padding_hi, ..] = *header else {
            return Some(Poll::Ready(Err(unexpected_eof())));
        };
        self.read_remaining_padding = i32::from(u16::from_be_bytes([padding_lo, padding_hi]));
        self.read_remaining_content = i32::from(u16::from_be_bytes([content_lo, content_hi]));
        self.read_last_command = command;
        debugln!(
            "XTLS Vision read padding: command={}, payloadLen={}, paddingLen={}",
            self.read_last_command,
            self.read_remaining_content,
            self.read_remaining_padding
        );
        None
    }

    /// The `Reader` step: hands the read straight to the filtered reader.
    fn poll_read_reader(&mut self, cx: &mut Context<'_>, buffer: &mut Buffer) -> Poll<io::Result<()>> {
        let mut read_buf = ReadBuf::new(buffer.free_bytes());
        match Pin::new(&mut self.reader).poll_read(cx, &mut read_buf) {
            Poll::Pending => {
                self.read_op = Some(ReadOp::Reader);
                Poll::Pending
            }
            Poll::Ready(Ok(())) => {
                let n = read_buf.filled().len();
                buffer.truncate(n);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => {
                buffer.truncate(0);
                Poll::Ready(Err(err))
            }
        }
    }

    /// Picks the operation for the next read step, or fails on an unknown padding command.
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        reason = "the content counters stay within the `i32` wire length fields, so a size that fits one fits the other"
    )]
    fn select_read_op(&mut self, buffer: &Buffer) -> Option<io::Error> {
        if self.read_remaining_buffer.is_some() {
            self.read_op = Some(ReadOp::RemainingBuffer { nested: false });
            return None;
        }
        if self.read_remaining_content > 0 {
            let mut read_size = XRAY_BUF_SIZE;
            if buffer.free_len() > read_size {
                read_size = buffer.free_len();
            }
            if read_size as i32 > self.read_remaining_content {
                read_size = self.read_remaining_content as usize;
            }
            let into_remaining = buffer.free_len() < read_size;
            if into_remaining {
                self.read_remaining_buffer = Some(new_size(read_size as i32));
            }
            self.read_op = Some(ReadOp::Content { read_size, into_remaining });
            return None;
        }
        if self.read_remaining_padding > 0 {
            self.read_op = Some(ReadOp::Padding { copied: 0 });
            return None;
        }
        if self.read_process {
            match self.read_last_command {
                COMMAND_PADDING_CONTINUE => {
                    let need = if self.read_filter_uuid { PADDING_HEADER_LEN } else { PADDING_HEADER_LEN - UUID_SIZE };
                    self.read_op = Some(ReadOp::Header { header: vec![0u8; need], filled: 0 });
                    return None;
                }
                COMMAND_PADDING_END => {
                    self.read_process = false;
                    return None;
                }
                COMMAND_PADDING_DIRECT => {
                    let Some(direct_net) = self.direct_net.clone() else {
                        let err = io::Error::other("XTLS Vision direct read without a raw transport");
                        errorln!("{}", err);
                        return Some(err);
                    };
                    let buffered = match &self.buffered_incoming {
                        Some(buffered_incoming) => {
                            let Some(buffered) = buffered_incoming.take_buffered_incoming() else {
                                let err = io::Error::other("XTLS Vision direct read with a stranded TLS read buffer");
                                errorln!("{}", err);
                                return Some(err);
                            };
                            buffered
                        }
                        None => Vec::new(),
                    };
                    if !buffered.is_empty() {
                        self.read_remaining_buffer = Some(as_(buffered));
                    }
                    self.read_process = false;
                    self.reader = direct_net;
                    self.reapply_read_deadline();
                    debugln!("XTLS Vision direct read start");
                    return None;
                }
                command => {
                    let err = unknown_read_command(command);
                    debugln!("{}", err);
                    return Some(err);
                }
            }
        }
        self.read_op = Some(ReadOp::Reader);
        None
    }

    fn poll_write_buffer(&mut self, cx: &mut Context<'_>, buffer: &mut Buffer, owned: bool) -> Poll<io::Result<()>> {
        loop {
            if let Some(op) = self.write_op.take() {
                let (index, mut offset) = match op {
                    WriteOp::Write { index, offset } => (index, offset),
                    WriteOp::Flush { index } => {
                        match self.poll_switch_writer(cx) {
                            Poll::Pending => {
                                self.write_op = Some(WriteOp::Flush { index });
                                return Poll::Pending;
                            }
                            Poll::Ready(Err(err)) => {
                                self.release_from(index + 1);
                                return Poll::Ready(Err(err));
                            }
                            Poll::Ready(Ok(())) => {}
                        }
                        if !self.advance_write(index) {
                            return Poll::Ready(Ok(()));
                        }
                        continue;
                    }
                };
                loop {
                    let written = {
                        let Some(bytes) = self.write_buffers.get(index).map(Buffer::bytes) else {
                            return Poll::Ready(Err(short_buffer()));
                        };
                        if offset >= bytes.len() {
                            break;
                        }
                        let Some(pending) = bytes.get(offset..) else {
                            return Poll::Ready(Err(short_buffer()));
                        };
                        match Pin::new(&mut self.writer).poll_write(cx, pending) {
                            Poll::Pending => {
                                self.write_op = Some(WriteOp::Write { index, offset });
                                return Poll::Pending;
                            }
                            Poll::Ready(Ok(0)) => Err(io::ErrorKind::WriteZero.into()),
                            Poll::Ready(Ok(n)) => {
                                offset += n;
                                Ok(())
                            }
                            Poll::Ready(Err(err)) => Err(err),
                        }
                    };
                    if let Err(err) = written {
                        for unwritten in self.write_buffers.iter_mut().skip(index) {
                            unwritten.release();
                        }
                        self.write_buffers.clear();
                        return Poll::Ready(Err(err));
                    }
                }
                let retain_owned = self.write_owned && index + 1 == self.write_buffers.len();
                let Some(step) = self.write_buffers.get_mut(index) else {
                    return Poll::Ready(Err(short_buffer()));
                };
                if !retain_owned {
                    step.release();
                }
                if self.write_command == COMMAND_PADDING_DIRECT {
                    match self.poll_switch_writer(cx) {
                        Poll::Pending => {
                            self.write_op = Some(WriteOp::Flush { index });
                            return Poll::Pending;
                        }
                        Poll::Ready(Err(err)) => {
                            self.release_from(index + 1);
                            return Poll::Ready(Err(err));
                        }
                        Poll::Ready(Ok(())) => {}
                    }
                }
                if !self.advance_write(index) {
                    return Poll::Ready(Ok(()));
                }
                continue;
            }

            self.begin_write_frame(buffer, owned);
            self.write_op = Some(WriteOp::Write { index: 0, offset: 0 });
        }
    }

    /// Queues the frame for a fresh write, padding and splitting it as the state machine needs.
    fn begin_write_frame(&mut self, buffer: &mut Buffer, owned: bool) {
        if self.write_filter_application_data {
            if buffer.is_empty() {
                apply_padding(buffer, COMMAND_PADDING_CONTINUE, &mut self.write_once_user_uuid, true);
                self.write_buffers.clear();
                self.write_buffers.push(std::mem::take(buffer));
                self.write_command = COMMAND_PADDING_CONTINUE;
                self.write_apply_padding = true;
                self.write_index = 0;
                self.write_owned = owned;
                return;
            }

            self.filter_tls(buffer.bytes());
            let mut buffers = std::mem::take(&mut self.write_buffers);
            self.reshape_buffer(std::mem::take(buffer), &mut buffers);
            self.write_buffers = buffers;
            self.write_apply_padding = true;
            self.write_index = 0;
            self.write_owned = owned;
            self.prepare_write_step();
            return;
        }

        self.write_buffers.clear();
        self.write_buffers.push(std::mem::take(buffer));
        self.write_command = COMMAND_PADDING_CONTINUE;
        self.write_index = 0;
        self.write_owned = owned;
    }

    /// Flushes the old TLS writer and swaps to the raw transport, synchronously so the swap cannot
    /// be dropped mid-flight by a cancellation.
    fn poll_switch_writer(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(direct_net) = self.direct_net.clone() else {
            return Poll::Ready(Err(io::Error::other("XTLS Vision direct write without a raw transport")));
        };
        match Pin::new(&mut self.writer).poll_flush(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Ready(Ok(())) => {
                self.writer = direct_net;
                self.reapply_write_deadline();
                debugln!("XTLS Vision direct write start");
                Poll::Ready(Ok(()))
            }
        }
    }

    /// Moves to the step after `index`; `false` means the queued write is done.
    fn advance_write(&mut self, index: usize) -> bool {
        self.write_index = index + 1;
        if self.write_index >= self.write_buffers.len() {
            if self.write_owned {
                if let Some(mut primary) = self.write_buffers.pop() {
                    // The frame's own buffer is worth keeping; a split segment, or one past the
                    // pooled size classes, goes back to the allocator instead.
                    if primary.raw_cap() <= 65535 {
                        primary.reset();
                        self.write_scratch = primary;
                    } else {
                        primary.release();
                    }
                }
                self.release_from(0);
            } else {
                self.write_buffers.clear();
            }
            return false;
        }
        self.prepare_write_step();
        self.write_op = Some(WriteOp::Write { index: self.write_index, offset: 0 });
        true
    }

    fn release_from(&mut self, index: usize) {
        for unwritten in self.write_buffers.iter_mut().skip(index) {
            unwritten.release();
        }
        self.write_buffers.clear();
    }

    /// The per-buffer step of the write-buffer loop.
    fn prepare_write_step(&mut self) {
        let index = self.write_index;
        let Some(step) = self.write_buffers.get_mut(index) else {
            return;
        };
        let mut command = COMMAND_PADDING_CONTINUE;
        if self.write_apply_padding {
            let length = step.len();
            let starts_application_data = length > 6 && step.to(3) == &TLS_APPLICATION_DATA_START[..];
            if self.is_tls && starts_application_data {
                command = COMMAND_PADDING_END;
                if self.enable_xtls && self.direct_net.is_some() {
                    command = COMMAND_PADDING_DIRECT;
                    self.write_direct = true;
                }
                self.write_filter_application_data = false;
                self.write_apply_padding = false;
            } else if !self.is_tls12orabove && self.packets_to_filter <= 1 {
                command = COMMAND_PADDING_END;
                self.write_filter_application_data = false;
                self.write_apply_padding = false;
            }
            apply_padding(step, command, &mut self.write_once_user_uuid, self.is_tls);
        }
        self.write_command = command;
    }
}

impl Drop for Conn {
    /// `Buffer` has no `Drop`; the buffers still held here would otherwise never go back to the pool.
    fn drop(&mut self) {
        self.write_scratch.release();
        self.read_scratch.release();
        if let Some(mut remaining) = self.read_remaining_buffer.take() {
            remaining.release();
        }
        self.release_from(0);
    }
}

impl AsyncRead for Conn {
    /// Reads through a buffer that stands in for the caller's
    /// slice, which the `Buffer` cannot borrow.
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.read_process && this.read_op.is_none() && this.read_remaining_buffer.is_none() {
            return Pin::new(&mut this.reader).poll_read(cx, buf);
        }
        if this.read_scratch.raw_cap() == buf.remaining() {
            this.read_scratch.reset();
        } else {
            this.read_scratch = with(vec![0u8; buf.remaining()]);
        }
        let mut scratch = std::mem::take(&mut this.read_scratch);
        let result = this.poll_read_buffer(cx, &mut scratch);
        match result {
            Poll::Ready(Ok(())) => {
                let n = scratch.len();
                if n > 0 {
                    let (fits, _) = scratch.bytes().split_at(n.min(buf.remaining()));
                    buf.put_slice(fits);
                }
                scratch.reset();
                this.read_scratch = scratch;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => {
                this.read_scratch = scratch;
                Poll::Ready(Err(err))
            }
            Poll::Pending => {
                this.read_scratch = scratch;
                Poll::Pending
            }
        }
    }
}

impl AsyncWrite for Conn {
    /// Sizes a buffer with the headroom the write buffer needs, then hands it over. A
    /// queued frame is resumed as-is, since the caller's slice is only valid for the poll that
    /// queued it.
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if !this.write_filter_application_data && this.write_op.is_none() {
            return Pin::new(&mut this.writer).poll_write(cx, buf);
        }
        if this.write_op.is_some() {
            return match this.poll_write_buffer(cx, &mut Buffer::default(), true) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(buf.len())),
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Pending => Poll::Pending,
            };
        }
        let mut buffer = match this.allocate_write_buffer(buf) {
            Ok(buffer) => buffer,
            Err(err) => return Poll::Ready(Err(err)),
        };
        let n = buffer.len();
        match this.poll_write_buffer(cx, &mut buffer, true) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(n)),
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_shutdown(cx)
    }
}

impl NetConn for Conn {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.inner.local_addr()
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.inner.remote_addr()
    }

    fn close(&self) -> io::Result<()> {
        Self::close(self)
    }

    fn close_read(&self) -> io::Result<()> {
        self.reader.close_read()
    }

    fn close_write(&self) -> io::Result<()> {
        self.writer.close_write()
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        Self::store_deadline(&self.read_deadline, deadline);
        Self::store_deadline(&self.write_deadline, deadline);
        self.reader.set_deadline(deadline)?;
        self.writer.set_deadline(deadline)
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        Self::store_deadline(&self.read_deadline, deadline);
        self.reader.set_read_deadline(deadline)
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        Self::store_deadline(&self.write_deadline, deadline);
        self.writer.set_write_deadline(deadline)
    }
}

impl NetExtendedConn for Conn {
    fn upstream(&self) -> Option<&dyn Any> {
        self.direct_conn().map(|conn: &SharedConn| -> &dyn Any { conn })
    }

    fn reader_replaceable(&self) -> bool {
        Self::reader_replaceable(self)
    }

    fn writer_replaceable(&self) -> bool {
        Self::writer_replaceable(self)
    }
}

impl UpstreamNode for Conn {
    fn upstream_node(&self) -> Option<&dyn UpstreamNode> {
        self.direct_conn().map(|conn: &SharedConn| -> &dyn UpstreamNode { conn })
    }

    fn reader_replaceable(&self) -> Option<bool> {
        Some(Self::reader_replaceable(self))
    }

    fn writer_replaceable(&self) -> Option<bool> {
        Some(Self::writer_replaceable(self))
    }

    fn reader_possibly_replaceable(&self) -> bool {
        Self::reader_possibly_replaceable(self)
    }

    fn writer_possibly_replaceable(&self) -> bool {
        Self::writer_possibly_replaceable(self)
    }

    fn early_conn(&self) -> Option<&dyn EarlyConn> {
        Some(self)
    }

    fn front_headroom(&self) -> Option<i32> {
        Some(Self::front_headroom(self))
    }

    fn rear_headroom(&self) -> Option<i32> {
        Some(Self::rear_headroom(self))
    }
}

impl EarlyConn for Conn {
    fn need_handshake(&self) -> bool {
        Self::need_handshake(self)
    }
}

impl NeedAdditionalReadDeadline for Conn {
    fn need_additional_read_deadline(&self) -> bool {
        Self::need_additional_read_deadline(self)
    }
}

#[async_trait::async_trait]
impl CommonExtendedConn for Conn {
    async fn read_buffer(&mut self, buffer: &mut Buffer) -> io::Result<()> {
        Self::read_buffer(self, buffer).await
    }

    async fn write_buffer(&mut self, buffer: &mut Buffer) -> io::Result<()> {
        Self::write_buffer(self, buffer).await
    }
}

impl NetStream for Conn {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        crate::conn::old_addr_to_socket_addr(NetConn::local_addr(self)?.as_ref())
    }

    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        crate::conn::old_addr_to_socket_addr(NetConn::remote_addr(self)?.as_ref())
    }

    fn shutdown_read(&self) -> io::Result<()> {
        NetConn::close_read(self)
    }

    fn shutdown_write(&self) -> io::Result<()> {
        NetConn::close_write(self)
    }

    fn old_conn(&self) -> Option<&dyn NetConn> {
        Some(self)
    }

    fn need_additional_read_deadline(&self) -> bool {
        Self::need_additional_read_deadline(self)
    }
}

impl ExtendedStream for Conn {
    fn reader_replaceable(&self) -> bool {
        Self::reader_replaceable(self)
    }

    fn writer_replaceable(&self) -> bool {
        Self::writer_replaceable(self)
    }
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::io;
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use uuid::Uuid;

    use murmur_common::shared_conn::SharedConn;
    use murmur_common_net::deadline::pipe_sing::{pipe, PipeConn};
    use murmur_component_tls::utls::{TlsBufferedIncoming, VERSION_TLS13};
    use murmur_std_compat::net::Conn as NetConn;

    use super::Conn;
    use crate::vision::padding::{
        COMMAND_PADDING_CONTINUE, COMMAND_PADDING_DIRECT, COMMAND_PADDING_END, PADDING_HEADER_LEN, XRAY_BUF_SIZE,
    };
    use crate::vision::vision::{new_conn, TlsConnCheck};

    const UUID: Uuid = Uuid::from_bytes([0x11; 16]);
    const CONTENT_AFTER_SPLIT: usize = XRAY_BUF_SIZE / 2;

    fn tls13() -> TlsConnCheck {
        TlsConnCheck::Supported { handshake_complete: true, version: VERSION_TLS13 }
    }

    fn shared(conn: PipeConn) -> SharedConn {
        SharedConn::from_boxed(Box::new(conn))
    }

    fn vision(inner: PipeConn, direct: Option<PipeConn>) -> Conn {
        new_conn(shared(inner), tls13(), direct.map(shared), None, UUID).expect("vision conn")
    }

    fn application_data(len: usize) -> Vec<u8> {
        let mut payload = vec![0x41u8; len];
        payload[..3].copy_from_slice(&[0x17, 0x03, 0x03]);
        payload
    }

    /// Reads one UUID-bearing frame: `uuid | command | contentLen | paddingLen | content | padding`.
    async fn read_uuid_frame(peer: &mut PipeConn) -> (u8, usize, Vec<u8>) {
        let mut head = [0u8; PADDING_HEADER_LEN];
        peer.read_exact(&mut head).await.expect("frame header");
        assert_eq!(&head[..16], UUID.as_bytes(), "first frame must carry the user UUID");
        let command = head[16];
        let content_len = usize::from(u16::from_be_bytes([head[17], head[18]]));
        let padding_len = usize::from(u16::from_be_bytes([head[19], head[20]]));
        let mut body = vec![0u8; content_len + padding_len];
        peer.read_exact(&mut body).await.expect("frame body");
        body.truncate(content_len);
        (command, content_len, body)
    }

    /// The next frame after the UUID was consumed: `command | contentLen | paddingLen | ...`.
    async fn read_continuation_frame(peer: &mut PipeConn) -> (u8, usize, Vec<u8>) {
        let mut head = [0u8; PADDING_HEADER_LEN - 16];
        peer.read_exact(&mut head).await.expect("continuation header");
        let command = head[0];
        let content_len = usize::from(u16::from_be_bytes([head[1], head[2]]));
        let padding_len = usize::from(u16::from_be_bytes([head[3], head[4]]));
        let mut body = vec![0u8; content_len + padding_len];
        peer.read_exact(&mut body).await.expect("continuation body");
        body.truncate(content_len);
        (command, content_len, body)
    }

    async fn assert_nothing_more(peer: &mut PipeConn) {
        let mut extra = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_millis(100), peer.read(&mut extra)).await;
        assert!(read.is_err(), "unexpected trailing bytes on the wire");
    }

    /// The write entry point must size its own headroom: the `as_` buffer has `start == 0` and no
    /// rear room, while `apply_padding` prepends up to 21 bytes and appends up to 900.
    #[tokio::test]
    async fn write_builds_a_padded_frame_without_a_zero_headroom_panic() {
        let (inner, mut peer) = pipe();
        let mut conn = vision(inner, None);
        let (write, (command, content_len, body)) = tokio::join!(conn.write_all(b"hello"), read_uuid_frame(&mut peer));
        write.expect("vision write");
        assert_eq!(command, COMMAND_PADDING_CONTINUE);
        assert_eq!(content_len, 5);
        assert_eq!(body, b"hello");
    }

    /// The reference accepts the VLESS encryption conn as a Vision transport even without a TLS
    /// session: the conn still frames and pads the first write.
    #[tokio::test]
    async fn no_tls_conn_frames_and_pads_the_first_write() {
        let (inner, mut peer) = pipe();
        let mut conn =
            new_conn(shared(inner), TlsConnCheck::NoTls, None, None, UUID).expect("encryption-only vision conn");
        let (write, (command, content_len, body)) = tokio::join!(conn.write_all(b"hello"), read_uuid_frame(&mut peer));
        write.expect("vision write");
        assert_eq!(command, COMMAND_PADDING_CONTINUE);
        assert_eq!(content_len, 5);
        assert_eq!(body, b"hello");
    }

    /// Without TLS and without encryption the conn shape is unknown, so Vision still fails closed.
    #[test]
    fn unsupported_conn_is_still_rejected() {
        let (inner, _peer) = pipe();
        assert!(new_conn(shared(inner), TlsConnCheck::Unsupported, None, None, UUID).is_err());
    }

    /// Padding-only Vision never switches to direct mode, so a TLS raw-transport handle is refused.
    #[test]
    fn no_tls_conn_refuses_a_tls_raw_transport() {
        let (inner, _peer) = pipe();
        let (raw, _raw_peer) = pipe();
        let err = new_conn(shared(inner), TlsConnCheck::NoTls, Some(shared(raw)), None, UUID)
            .err()
            .map(|err| err.to_string())
            .expect("rejected");
        assert_eq!(err, "vision: encryption-only conn cannot carry a TLS raw transport");
    }

    /// A Pending below the vision layer must resume the queued frame: the caller's re-poll uses
    /// the same slice, and a second wrap would duplicate the header (and the payload).
    #[tokio::test]
    async fn write_resumes_a_pending_frame_without_rewrapping_it() {
        let (inner, mut peer) = pipe();
        let mut conn = vision(inner, None);
        let payload = b"hello";
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut first = Box::pin(std::future::poll_fn(|cx| Pin::new(&mut conn).poll_write(cx, payload)));
        assert!(first.as_mut().poll(&mut cx).is_pending(), "the peer has not read the frame yet");
        drop(first);

        let frame = murmur_sing::network::ReadWaiter::wait_read_buffer(&peer).await.expect("pending frame");
        let bytes = frame.bytes();
        assert_eq!(&bytes[..16], UUID.as_bytes());
        assert_eq!(bytes[16], COMMAND_PADDING_CONTINUE);
        let content_len = usize::from(u16::from_be_bytes([bytes[17], bytes[18]]));
        let padding_len = usize::from(u16::from_be_bytes([bytes[19], bytes[20]]));
        assert_eq!(content_len, payload.len());
        assert_eq!(&bytes[PADDING_HEADER_LEN..PADDING_HEADER_LEN + content_len], payload);
        assert_eq!(bytes.len(), PADDING_HEADER_LEN + content_len + padding_len);

        let mut second = Box::pin(std::future::poll_fn(|cx| Pin::new(&mut conn).poll_write(cx, payload)));
        let Poll::Ready(Ok(written)) = second.as_mut().poll(&mut cx) else {
            panic!("the drained frame must complete on the resumed poll");
        };
        assert_eq!(written, payload.len());
        drop(second);
        assert_nothing_more(&mut peer).await;
    }

    /// A payload at the split threshold becomes two sing buffers; each one prepends its own
    /// header, and only the first carries the UUID.
    #[tokio::test]
    async fn boundary_sized_write_frames_both_split_buffers() {
        let (inner, mut peer) = pipe();
        let mut conn = vision(inner, None);
        let payload = vec![0x41u8; XRAY_BUF_SIZE - PADDING_HEADER_LEN];

        let write = async {
            conn.write_all(&payload).await.expect("vision write");
        };
        let read = async {
            let first = read_uuid_frame(&mut peer).await;
            let second = read_continuation_frame(&mut peer).await;
            (first, second)
        };
        let ((), (first, second)) = tokio::join!(write, read);
        let (command, content_len, body) = first;
        let (next_command, next_len, next_body) = second;

        assert_eq!(command, COMMAND_PADDING_CONTINUE);
        assert_eq!(content_len, CONTENT_AFTER_SPLIT);
        assert_eq!(body, payload[..CONTENT_AFTER_SPLIT]);
        assert_eq!(next_command, COMMAND_PADDING_CONTINUE);
        assert_eq!(next_len, payload.len() - CONTENT_AFTER_SPLIT);
        assert_eq!(next_body, payload[CONTENT_AFTER_SPLIT..]);
    }

    /// Once the first application-data buffer is marked DIRECT, the rest of the queued payload
    /// must leave through the raw transport, not through the outer TLS conn.
    #[tokio::test]
    async fn write_switches_queued_bytes_to_the_raw_transport_on_the_direct_command() {
        let (inner, mut tls_peer) = pipe();
        let (raw, mut raw_peer) = pipe();
        let mut conn = vision(inner, Some(raw));
        conn.enable_xtls = true;
        conn.is_tls = true;
        let payload = application_data(XRAY_BUF_SIZE - PADDING_HEADER_LEN);

        let write = async {
            conn.write_all(&payload).await.expect("vision write");
        };
        let read = async {
            let first = read_uuid_frame(&mut tls_peer).await;
            let mut rest = vec![0u8; payload.len() - CONTENT_AFTER_SPLIT];
            raw_peer.read_exact(&mut rest).await.expect("raw remainder");
            (first, rest)
        };
        let ((), ((command, content_len, body), rest)) = tokio::join!(write, read);

        assert_eq!(command, COMMAND_PADDING_DIRECT);
        assert_eq!(content_len, CONTENT_AFTER_SPLIT);
        assert_eq!(body, payload[..CONTENT_AFTER_SPLIT]);
        assert_eq!(rest, payload[CONTENT_AFTER_SPLIT..]);
        assert!(conn.write_direct, "the writer must have switched to the raw transport");
    }

    /// Without a raw transport the conn must not tell the peer to go DIRECT while it keeps
    /// sending through the outer TLS conn; it has to end the padding on the TLS side instead.
    #[tokio::test]
    async fn write_without_a_raw_transport_never_emits_direct() {
        let (inner, mut tls_peer) = pipe();
        let mut conn = vision(inner, None);
        conn.enable_xtls = true;
        conn.is_tls = true;
        let payload = application_data(XRAY_BUF_SIZE - PADDING_HEADER_LEN);

        let write = async {
            conn.write_all(&payload).await.expect("vision write");
        };
        let read = async {
            let first = read_uuid_frame(&mut tls_peer).await;
            let mut rest = vec![0u8; payload.len() - CONTENT_AFTER_SPLIT];
            tls_peer.read_exact(&mut rest).await.expect("tls remainder");
            (first, rest)
        };
        let ((), ((command, content_len, body), rest)) = tokio::join!(write, read);

        assert_eq!(command, COMMAND_PADDING_END, "DIRECT without a raw transport desyncs the peer");
        assert_eq!(content_len, CONTENT_AFTER_SPLIT);
        assert_eq!(body, payload[..CONTENT_AFTER_SPLIT]);
        assert_eq!(rest, payload[CONTENT_AFTER_SPLIT..], "the remainder stays in the outer TLS conn");
        assert!(!conn.write_direct);
    }

    /// A server DIRECT command moves the read side to the raw transport for the bytes after it.
    #[tokio::test]
    async fn read_follows_the_direct_command_to_the_raw_transport() {
        let (inner, mut tls_peer) = pipe();
        let (raw, mut raw_peer) = pipe();
        let mut conn = vision(inner, Some(raw));

        let mut header = Vec::with_capacity(PADDING_HEADER_LEN);
        header.extend_from_slice(UUID.as_bytes());
        header.push(COMMAND_PADDING_DIRECT);
        header.extend_from_slice(&0u16.to_be_bytes());
        header.extend_from_slice(&0u16.to_be_bytes());
        let send = async {
            tls_peer.write_all(&header).await.expect("server header");
            raw_peer.write_all(b"R").await.expect("raw byte");
        };
        let mut buf = [0u8; 4];
        let (_, read) = tokio::time::timeout(Duration::from_secs(2), async { tokio::join!(send, conn.read(&mut buf)) })
            .await
            .expect("read must not hang");
        let n = read.expect("read");
        assert_eq!(&buf[..n], b"R");
    }

    /// A DIRECT command the conn cannot honour must fail loudly: reading it as outer TLS would
    /// hand the caller ciphertext-shaped bytes as if they were the peer's raw stream.
    #[tokio::test]
    async fn read_direct_without_a_raw_transport_fails_instead_of_reading_outer_tls() {
        let (inner, mut tls_peer) = pipe();
        let mut conn = vision(inner, None);

        let mut header = Vec::with_capacity(PADDING_HEADER_LEN);
        header.extend_from_slice(UUID.as_bytes());
        header.push(COMMAND_PADDING_DIRECT);
        header.extend_from_slice(&0u16.to_be_bytes());
        header.extend_from_slice(&0u16.to_be_bytes());

        let mut buf = [0u8; 4];
        let (_, result) = tokio::time::timeout(Duration::from_secs(1), async {
            tokio::join!(tls_peer.write_all(&header), conn.read(&mut buf))
        })
        .await
        .expect("read must not hang");
        assert!(result.is_err(), "DIRECT without a raw transport must not silently read outer TLS");
    }

    /// The plaintext the TLS layer already decrypted must reach the caller before the raw
    /// transport's bytes, since the raw stream begins after it on the wire.
    #[tokio::test]
    async fn read_delivers_buffered_incoming_before_raw_bytes() {
        struct Buffered(Mutex<Option<Vec<u8>>>);
        impl TlsBufferedIncoming for Buffered {
            fn take_buffered_incoming(&self) -> Option<Vec<u8>> {
                self.0.lock().expect("buffered handoff").take()
            }
        }

        let (inner, mut tls_peer) = pipe();
        let (raw, mut raw_peer) = pipe();
        let buffered: Arc<dyn TlsBufferedIncoming> = Arc::new(Buffered(Mutex::new(Some(b"AB".to_vec()))));
        let mut conn = new_conn(shared(inner), tls13(), Some(shared(raw)), Some(buffered), UUID).expect("vision conn");

        let mut header = Vec::with_capacity(PADDING_HEADER_LEN);
        header.extend_from_slice(UUID.as_bytes());
        header.push(COMMAND_PADDING_DIRECT);
        header.extend_from_slice(&0u16.to_be_bytes());
        header.extend_from_slice(&0u16.to_be_bytes());
        let send = async {
            tls_peer.write_all(&header).await.expect("server header");
            raw_peer.write_all(b"CD").await.expect("raw bytes");
        };
        let mut first = [0u8; 2];
        let mut second = [0u8; 2];
        let (_, ()) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(send, async {
                conn.read_exact(&mut first).await.expect("buffered read");
                conn.read_exact(&mut second).await.expect("raw read");
            })
        })
        .await
        .expect("reads must not hang");
        assert_eq!(&first, b"AB");
        assert_eq!(&second, b"CD");
    }

    fn direct_header() -> Vec<u8> {
        let mut header = Vec::with_capacity(PADDING_HEADER_LEN);
        header.extend_from_slice(UUID.as_bytes());
        header.push(COMMAND_PADDING_DIRECT);
        header.extend_from_slice(&0u16.to_be_bytes());
        header.extend_from_slice(&0u16.to_be_bytes());
        header
    }

    #[tokio::test(start_paused = true)]
    async fn read_deadlines_expire_and_clear_after_the_raw_switch() {
        let (inner, mut tls_peer) = pipe();
        let (raw, mut raw_peer) = pipe();
        let mut conn = vision(inner, Some(raw));
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        conn.set_read_deadline(Some(deadline)).expect("set deadline before the switch");

        let header = direct_header();
        let send = async {
            tls_peer.write_all(&header).await.expect("server header");
            raw_peer.write_all(b"R").await.expect("raw byte");
        };
        let mut buf = [0u8; 1];
        let (_, read) = tokio::join!(send, conn.read(&mut buf));
        assert_eq!(read.expect("switched read"), 1);
        assert_eq!(&buf, b"R");

        tokio::time::advance(Duration::from_secs(30)).await;
        let error = tokio::time::timeout(Duration::from_secs(1), conn.read(&mut buf))
            .await
            .expect("the carried deadline must wake the raw read")
            .expect_err("the raw read must expire");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);

        conn.set_read_deadline(None).expect("clear the raw read deadline");
        let (send, read) = tokio::join!(raw_peer.write_all(b"B"), conn.read(&mut buf));
        send.expect("raw byte after clearing the deadline");
        assert_eq!(read.expect("read after clearing the deadline"), 1);
        assert_eq!(&buf, b"B");

        conn.set_read_deadline(Some(tokio::time::Instant::now())).expect("set a deadline after the switch");
        let error = tokio::time::timeout(Duration::from_secs(1), conn.read(&mut buf))
            .await
            .expect("the new deadline must govern the raw read")
            .expect_err("the new deadline must expire");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }

    #[tokio::test(start_paused = true)]
    async fn write_deadlines_expire_and_clear_after_the_raw_switch() {
        for clear_before_expiry in [false, true] {
            let (inner, mut tls_peer) = pipe();
            let (raw, mut raw_peer) = pipe();
            let mut conn = vision(inner, Some(raw));
            conn.enable_xtls = true;
            conn.is_tls = true;
            let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
            conn.set_write_deadline(Some(deadline)).expect("set deadline before the switch");
            let payload = application_data(XRAY_BUF_SIZE - PADDING_HEADER_LEN);
            let read = async {
                let (command, content_len, _) = read_uuid_frame(&mut tls_peer).await;
                assert_eq!(command, COMMAND_PADDING_DIRECT);
                let mut rest = vec![0u8; payload.len() - content_len];
                raw_peer.read_exact(&mut rest).await.expect("raw remainder");
                rest
            };
            let (write, rest) = tokio::join!(conn.write_all(&payload), read);
            write.expect("switched write");
            assert_eq!(rest, payload[CONTENT_AFTER_SPLIT..]);

            if clear_before_expiry {
                conn.set_write_deadline(None).expect("clear the raw write deadline");
            }
            tokio::time::advance(Duration::from_secs(30)).await;
            if clear_before_expiry {
                let mut buf = [0u8; 1];
                let (write, read) = tokio::join!(conn.write_all(b"B"), raw_peer.read_exact(&mut buf));
                write.expect("write after clearing the deadline");
                read.expect("raw byte after clearing the deadline");
                assert_eq!(&buf, b"B");
                conn.set_write_deadline(Some(tokio::time::Instant::now())).expect("set a raw write deadline");
            }
            let error = tokio::time::timeout(Duration::from_secs(1), conn.write_all(b"expired"))
                .await
                .expect("the active raw write deadline must wake the caller")
                .expect_err("the raw write must expire");
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        }
    }

    #[tokio::test]
    async fn closing_the_raw_write_half_leaves_the_raw_read_half_open() {
        use murmur_common_net::io::StreamAsOldConn;
        use tokio::net::{TcpListener, TcpStream};

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("raw listener");
        let mut raw_peer = TcpStream::connect(listener.local_addr().expect("raw address")).await.expect("raw peer");
        let (raw, _) = listener.accept().await.expect("raw socket");
        let raw = SharedConn::from_boxed(Box::new(StreamAsOldConn::new(raw)));
        let (inner, mut tls_peer) = pipe();
        let mut conn = new_conn(shared(inner), tls13(), Some(raw), None, UUID).expect("vision conn");
        conn.enable_xtls = true;
        conn.is_tls = true;
        let mut payload = application_data(22);
        payload[3..5].copy_from_slice(&17u16.to_be_bytes());
        let (write, (command, _, body)) = tokio::join!(conn.write_all(&payload), read_uuid_frame(&mut tls_peer));
        write.expect("switch the writer");
        assert_eq!(command, COMMAND_PADDING_DIRECT);
        assert_eq!(body, payload);

        conn.close_write().expect("close the raw write half");
        let mut byte = [0u8; 1];
        let eof = tokio::time::timeout(Duration::from_secs(2), raw_peer.read(&mut byte))
            .await
            .expect("the peer must observe the write-half close")
            .expect("peer read");
        assert_eq!(eof, 0);

        let header = direct_header();
        let send = async {
            tls_peer.write_all(&header).await.expect("read-side direct header");
            raw_peer.write_all(b"R").await.expect("the peer can still send");
        };
        let (_, read) =
            tokio::time::timeout(Duration::from_secs(2), async { tokio::join!(send, conn.read(&mut byte)) })
                .await
                .expect("the raw read half must stay open");
        assert_eq!(read.expect("raw read after write-half close"), 1);
        assert_eq!(&byte, b"R");
    }

    #[tokio::test]
    async fn consecutive_padded_writes_do_not_repeat_the_uuid_or_keep_a_previous_tail() {
        let (inner, mut peer) = pipe();
        let mut conn = vision(inner, None);
        let write = async {
            conn.write_all(b"longer payload").await.expect("first write");
            conn.write_all(b"short").await.expect("second write");
        };
        let read = async {
            let first = read_uuid_frame(&mut peer).await;
            let second = read_continuation_frame(&mut peer).await;
            (first, second)
        };
        let ((), (first, second)) = tokio::join!(write, read);
        assert_eq!(first.0, COMMAND_PADDING_CONTINUE);
        assert_eq!(first.2, b"longer payload");
        assert_eq!(second.0, COMMAND_PADDING_CONTINUE);
        assert_eq!(second.2, b"short");
    }

    /// The split point is the last TLS application-data start in the buffer when one lands past
    /// the padding header, not the fixed half-buffer cut.
    #[tokio::test]
    async fn write_splits_at_a_discovered_application_data_start() {
        let (inner, mut peer) = pipe();
        let mut conn = vision(inner, None);
        let payload_len = XRAY_BUF_SIZE - PADDING_HEADER_LEN;
        let mut payload = vec![0x41u8; payload_len];
        let cut = XRAY_BUF_SIZE / 2 + 7;
        payload[cut..cut + 3].copy_from_slice(&[0x17, 0x03, 0x03]);

        let write = async {
            conn.write_all(&payload).await.expect("vision write");
        };
        let read = async {
            let first = read_uuid_frame(&mut peer).await;
            let second = read_continuation_frame(&mut peer).await;
            (first, second)
        };
        let ((), (first, second)) = tokio::join!(write, read);

        assert_eq!(first.1, cut, "the first frame must end at the record boundary");
        assert_eq!(first.2, payload[..cut]);
        assert_eq!(second.1, payload_len - cut);
        assert_eq!(second.2, payload[cut..]);
    }

    /// A split frame that parks mid-queue must resume at the next segment, which carries its own
    /// header and no second UUID.
    #[tokio::test]
    async fn write_resumes_a_pending_split_frame_at_the_next_segment() {
        let (inner, mut peer) = pipe();
        let mut conn = vision(inner, None);
        let payload = vec![0x41u8; XRAY_BUF_SIZE - PADDING_HEADER_LEN];
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);

        let mut resume = Box::pin(std::future::poll_fn(|cx| Pin::new(&mut conn).poll_write(cx, &payload)));
        assert!(resume.as_mut().poll(&mut cx).is_pending(), "the peer has not read the first segment yet");

        let first = murmur_sing::network::ReadWaiter::wait_read_buffer(&peer).await.expect("first segment");
        let first_bytes = first.bytes();
        assert_eq!(&first_bytes[..16], UUID.as_bytes(), "only the first segment carries the user UUID");
        assert_eq!(first_bytes[16], COMMAND_PADDING_CONTINUE);
        assert_eq!(usize::from(u16::from_be_bytes([first_bytes[17], first_bytes[18]])), CONTENT_AFTER_SPLIT);

        assert!(resume.as_mut().poll(&mut cx).is_pending(), "the peer has not read the second segment yet");

        let second = murmur_sing::network::ReadWaiter::wait_read_buffer(&peer).await.expect("second segment");
        let second_bytes = second.bytes();
        assert_eq!(second_bytes[0], COMMAND_PADDING_CONTINUE);
        assert_eq!(
            usize::from(u16::from_be_bytes([second_bytes[1], second_bytes[2]])),
            payload.len() - CONTENT_AFTER_SPLIT
        );

        let Poll::Ready(Ok(written)) = resume.as_mut().poll(&mut cx) else {
            panic!("the drained frame must complete on the resumed poll");
        };
        assert_eq!(written, payload.len());
        drop(resume);
        assert_nothing_more(&mut peer).await;
    }
}
