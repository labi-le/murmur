use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use bytes::{Buf, Bytes};
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::OwnedSemaphorePermit;

use crate::error::{err_stream_closed, stream_error, ErrInfo};
use crate::frame::{Header, FLAG_ACK, FLAG_FIN, FLAG_RST, FLAG_SYN, HEADER_SIZE, TYPE_DATA, TYPE_WINDOW_UPDATE};
use crate::session::SessionCore;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Lifecycle {
    Init,
    SynSent,
    SynReceived,
    Established,
    Finished,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HalfState {
    Open,
    Closed,
    Reset,
}

#[derive(Debug)]
struct StateInner {
    lifecycle: Lifecycle,
    read_state: HalfState,
    write_state: HalfState,
    read_err: Option<ErrInfo>,
    write_err: Option<ErrInfo>,
}

#[derive(Debug)]
struct RecvState {
    buf: VecDeque<Bytes>,
    len: u32,
    cap: u32,
    target: u32,
}

impl RecvState {
    const fn grow_to(&mut self, force: bool) -> (bool, u32) {
        let current = self.cap + self.len;
        if current >= self.target {
            return (force, 0);
        }
        let delta = self.target - current;
        if delta < self.target / 2 && !force {
            return (false, 0);
        }
        self.cap += delta;
        (true, delta)
    }

    #[allow(clippy::cast_possible_truncation, reason = "byte count is bounded by the u32 receive window")]
    fn read_into(&mut self, buf: &mut ReadBuf<'_>) -> usize {
        let mut total = 0;
        while buf.remaining() > 0 {
            let Some(front) = self.buf.front_mut() else { break };
            let want = front.len().min(buf.remaining());
            let (chunk, _) = front.split_at(want);
            buf.put_slice(chunk);
            front.advance(want);
            total += want;
            if front.is_empty() {
                self.buf.pop_front();
            }
        }
        self.len -= total as u32;
        total
    }
}

#[derive(Debug)]
pub struct StreamShared {
    pub id: u32,
    core: Arc<SessionCore>,
    max_message_size: u32,
    max_stream_window_size: u32,
    state: Mutex<StateInner>,
    recv: Mutex<RecvState>,
    send_window: AtomicU32,
    recv_waker: Mutex<Option<Waker>>,
    send_waker: Mutex<Option<Waker>>,
    open_permit: Mutex<Option<OwnedSemaphorePermit>>,
}

impl StreamShared {
    pub fn new_outgoing(id: u32, core: Arc<SessionCore>, permit: OwnedSemaphorePermit) -> Arc<Self> {
        Self::new_inner(id, core, Lifecycle::Init, Some(permit))
    }

    pub fn new_incoming(id: u32, core: Arc<SessionCore>) -> Arc<Self> {
        Self::new_inner(id, core, Lifecycle::SynReceived, None)
    }

    fn new_inner(
        id: u32,
        core: Arc<SessionCore>,
        lifecycle: Lifecycle,
        permit: Option<OwnedSemaphorePermit>,
    ) -> Arc<Self> {
        let target = core.config.initial_stream_window_size;
        let max_message_size = core.config.max_message_size;
        let max_stream_window_size = core.config.max_stream_window_size;
        Arc::new(Self {
            id,
            core,
            max_message_size,
            max_stream_window_size,
            state: Mutex::new(StateInner {
                lifecycle,
                read_state: HalfState::Open,
                write_state: HalfState::Open,
                read_err: None,
                write_err: None,
            }),
            recv: Mutex::new(RecvState {
                buf: VecDeque::new(),
                len: 0,
                cap: crate::frame::INITIAL_STREAM_WINDOW,
                target,
            }),
            send_window: AtomicU32::new(crate::frame::INITIAL_STREAM_WINDOW),
            recv_waker: Mutex::new(None),
            send_waker: Mutex::new(None),
            open_permit: Mutex::new(permit),
        })
    }

    /// The waker leaves the slot before it is woken: `wake` can run the waiter on another
    /// worker, and that waiter comes straight back for the same slot.
    fn wake_recv(&self) {
        let waker = self.recv_waker.lock().take();
        if let Some(w) = waker {
            w.wake();
        }
    }

    fn wake_send(&self) {
        let waker = self.send_waker.lock().take();
        if let Some(w) = waker {
            w.wake();
        }
    }

    fn notify_waiting(&self) {
        self.wake_recv();
        self.wake_send();
    }

    fn release_permit(&self) {
        self.open_permit.lock().take();
    }

    fn send_flags(&self) -> u16 {
        let mut st = self.state.lock();
        match st.lifecycle {
            Lifecycle::Init => {
                st.lifecycle = Lifecycle::SynSent;
                FLAG_SYN
            }
            Lifecycle::SynReceived => {
                st.lifecycle = Lifecycle::Established;
                FLAG_ACK
            }
            Lifecycle::SynSent | Lifecycle::Established | Lifecycle::Finished => 0,
        }
    }

    /// Sends a window update. This never grows the target window beyond
    /// `config.initial_stream_window_size`: the RTT-adaptive doubling is a throughput
    /// accelerant, not part of the wire protocol, and is intentionally left out.
    pub fn send_window_update(&self) -> io::Result<()> {
        let flags = self.send_flags();
        let (needed, delta) = self.recv.lock().grow_to(flags != 0);
        if !needed {
            return Ok(());
        }
        let hdr = Header::encode(TYPE_WINDOW_UPDATE, flags, self.id, delta);
        self.core.send_frame(hdr.to_vec())
    }

    fn process_flags(&self, hdr: &Header, flags: u16) {
        let mut close_stream = false;
        if flags & FLAG_ACK != 0 {
            let mut st = self.state.lock();
            if st.lifecycle == Lifecycle::SynSent {
                st.lifecycle = Lifecycle::Established;
            }
            drop(st);
            self.release_permit();
        }
        if flags & FLAG_FIN != 0 {
            let mut notify = false;
            let mut st = self.state.lock();
            if st.read_state == HalfState::Open {
                st.read_state = HalfState::Closed;
                if st.write_state != HalfState::Open {
                    close_stream = true;
                    st.lifecycle = Lifecycle::Finished;
                }
                notify = true;
            }
            drop(st);
            if notify {
                self.notify_waiting();
            }
        }
        if flags & FLAG_RST != 0 {
            let err = if hdr.msg_type == TYPE_WINDOW_UPDATE {
                ErrInfo::from_io(&stream_error(hdr.length, true))
            } else {
                ErrInfo::from_io(&crate::error::err_stream_reset())
            };
            {
                let mut st = self.state.lock();
                if st.read_state == HalfState::Open {
                    st.read_state = HalfState::Reset;
                    st.read_err = Some(err.clone());
                }
                if st.write_state == HalfState::Open {
                    st.write_state = HalfState::Reset;
                    st.write_err = Some(err);
                }
                st.lifecycle = Lifecycle::Finished;
            }
            close_stream = true;
            self.notify_waiting();
        }
        if close_stream {
            self.cleanup();
        }
    }

    pub fn incr_send_window(&self, hdr: &Header, flags: u16) {
        self.process_flags(hdr, flags);
        if !self.credit_send_window(hdr.length) {
            self.reset_with_error(crate::frame::GO_AWAY_PROTO_ERR);
            return;
        }
        self.wake_send();
    }

    /// Credits a peer's window update, refusing one that would take the stream past
    /// `config.max_stream_window_size` or wrap the counter; the caller resets the stream.
    fn credit_send_window(&self, delta: u32) -> bool {
        let mut window = self.send_window.load(Ordering::Acquire);
        loop {
            let Some(credited) = window.checked_add(delta) else {
                return false;
            };
            if credited > self.max_stream_window_size {
                return false;
            }
            match self.send_window.compare_exchange_weak(window, credited, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return true,
                Err(current) => window = current,
            }
        }
    }

    /// The flag processing and overflow check that precede a data read, split out so the
    /// caller (owning the wire reader) can validate before consuming `hdr.length` bytes from
    /// the connection, checking before it reads.
    pub fn begin_data(&self, hdr: &Header, flags: u16, length: u32) -> io::Result<()> {
        self.process_flags(hdr, flags);
        if length == 0 {
            return Ok(());
        }
        let cap = self.recv.lock().cap;
        if cap < length {
            return Err(crate::error::err_recv_window_exceeded(cap, length));
        }
        Ok(())
    }

    /// The tail of a data read: called only after [`begin_data`] accepted the
    /// length, with the bytes already read off the wire.
    pub fn commit_data(&self, data: Bytes) {
        if data.is_empty() {
            return;
        }
        #[allow(clippy::cast_possible_truncation, reason = "payload length is bounded by the u32 receive window")]
        let len = data.len() as u32;
        let mut recv = self.recv.lock();
        recv.len += len;
        recv.cap -= len;
        recv.buf.push_back(data);
        drop(recv);
        self.wake_recv();
    }

    /// Removes this stream from the session's registry and releases its open permit.
    fn cleanup(&self) {
        self.core.close_stream(self.id);
        self.release_permit();
    }

    pub fn force_close(&self, err: &io::Error) {
        let info = ErrInfo::from_io(err);
        {
            let mut st = self.state.lock();
            if st.read_state == HalfState::Open {
                st.read_state = HalfState::Reset;
                st.read_err = Some(info.clone());
            }
            if st.write_state == HalfState::Open {
                st.write_state = HalfState::Reset;
                st.write_err = Some(info);
            }
            st.lifecycle = Lifecycle::Finished;
        }
        self.notify_waiting();
        self.release_permit();
    }

    fn reset_with_error(&self, err_code: u32) {
        let mut st = self.state.lock();
        if st.lifecycle == Lifecycle::Finished {
            return;
        }
        let send_reset = st.lifecycle != Lifecycle::Init;
        if st.write_state == HalfState::Open {
            st.write_state = HalfState::Reset;
            st.write_err = Some(ErrInfo::from_io(&stream_error(err_code, false)));
        }
        if st.read_state == HalfState::Open {
            st.read_state = HalfState::Reset;
            st.read_err = Some(ErrInfo::from_io(&stream_error(err_code, false)));
        }
        st.lifecycle = Lifecycle::Finished;
        drop(st);
        self.notify_waiting();
        if send_reset {
            let hdr = Header::encode(TYPE_WINDOW_UPDATE, FLAG_RST, self.id, err_code);
            let _ = self.core.send_frame(hdr.to_vec());
        }
        self.cleanup();
    }

    /// A dropped stream never emits a wire RST; the local registry slot is the only thing to
    /// release here. A RST after a half-close would tear down the peer's still-open half, which
    /// is the whole point of half-closing.
    fn abandon(&self) {
        let clean = {
            let st = self.state.lock();
            st.write_state == HalfState::Closed || st.read_state == HalfState::Closed
        };
        if clean {
            self.cleanup();
        } else {
            self.reset_with_error(0);
        }
    }

    fn close_write(&self) -> io::Result<()> {
        let mut st = self.state.lock();
        match st.write_state {
            HalfState::Open => {}
            HalfState::Closed => return Ok(()),
            HalfState::Reset => return Err(st.write_err.as_ref().map_or_else(err_stream_closed, ErrInfo::to_io)),
        }
        st.write_state = HalfState::Closed;
        let cleanup = st.read_state != HalfState::Open;
        if cleanup {
            st.lifecycle = Lifecycle::Finished;
        }
        drop(st);
        self.notify_waiting();
        let flags = self.send_flags() | FLAG_FIN;
        let hdr = Header::encode(TYPE_WINDOW_UPDATE, flags, self.id, 0);
        let result = self.core.send_frame(hdr.to_vec());
        if cleanup {
            self.cleanup();
        }
        result
    }
}

/// A single multiplexed stream.
///
/// Implements [`AsyncRead`]/[`AsyncWrite`] directly against `shared` rather than splitting into
/// two half-owned types (per `rule://wave-rules` #3): read and write here only ever touch
/// disjoint state (`recv`/`recv_waker` vs. `send_window`/`send_waker`), each behind its own
/// lock, so the two directions never block each other despite living on one `Stream`.
#[derive(Debug)]
pub struct Stream {
    shared: Arc<StreamShared>,
}

impl Stream {
    pub const fn new(shared: Arc<StreamShared>) -> Self {
        Self { shared }
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        self.shared.abandon();
    }
}

impl AsyncRead for Stream {
    /// Reads from the stream. Registers `cx.waker()` and rechecks the buffer (rather than storing
    /// an in-flight future) per `rule://wave-rules` #2: there is no sub-operation to drive here,
    /// only a condition to wait on, so a `Waker` slot is the whole state machine.
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        loop {
            let closed_empty;
            {
                let st = self.shared.state.lock();
                match st.read_state {
                    HalfState::Reset => {
                        let err = st.read_err.as_ref().map_or_else(crate::error::err_stream_reset, ErrInfo::to_io);
                        drop(st);
                        return Poll::Ready(Err(err));
                    }
                    HalfState::Closed => closed_empty = true,
                    HalfState::Open => closed_empty = false,
                }
            }

            let n = self.shared.recv.lock().read_into(buf);
            if n > 0 {
                let _ = self.shared.send_window_update();
                return Poll::Ready(Ok(()));
            }
            if closed_empty {
                return Poll::Ready(Ok(()));
            }

            *self.shared.recv_waker.lock() = Some(cx.waker().clone());
            if !self.shared.recv.lock().buf.is_empty() {
                continue;
            }
            return Poll::Pending;
        }
    }
}

impl AsyncWrite for Stream {
    /// Writes one chunk (the helper loops for buffers larger than
    /// the negotiated window/message size).
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        loop {
            {
                let st = self.shared.state.lock();
                match st.write_state {
                    HalfState::Closed => return Poll::Ready(Err(err_stream_closed())),
                    HalfState::Reset => {
                        let err = st.write_err.as_ref().map_or_else(err_stream_closed, ErrInfo::to_io);
                        drop(st);
                        return Poll::Ready(Err(err));
                    }
                    HalfState::Open => {}
                }
            }

            let window = self.shared.send_window.load(Ordering::Acquire);
            if window == 0 {
                *self.shared.send_waker.lock() = Some(cx.waker().clone());
                if self.shared.send_window.load(Ordering::Acquire) > 0 {
                    continue;
                }
                return Poll::Pending;
            }

            // `HEADER_SIZE` sizes a buffer (usize) while `max_message_size` is a wire u32; the
            // header is 12 bytes, so the conversion never saturates.
            let budget = self.shared.max_message_size.saturating_sub(u32::try_from(HEADER_SIZE).unwrap_or(u32::MAX));
            let max = window.min(budget).min(u32::try_from(data.len()).unwrap_or(u32::MAX));
            let max_len = usize::try_from(max).unwrap_or(usize::MAX);
            let flags = self.shared.send_flags();
            let hdr = Header::encode(TYPE_DATA, flags, self.shared.id, max);
            let mut frame = Vec::with_capacity(HEADER_SIZE + max_len);
            frame.extend_from_slice(&hdr);
            let (payload, _) = data.split_at(max_len);
            frame.extend_from_slice(payload);
            self.shared.core.send_frame(frame)?;
            self.shared.send_window.fetch_sub(max, Ordering::AcqRel);
            return Poll::Ready(Ok(max_len));
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    /// Half-closes the write side, invoked as tokio's half-close hook.
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(self.shared.close_write())
    }
}
