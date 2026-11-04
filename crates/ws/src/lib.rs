//! The websocket frame codec, masking, streaming reader, and control-frame (ping/pong/close)
//! responder that murmur's httpmask tunnel and websocket-based outbound transports use.
//!
//! No dependency in this crate's `Cargo.toml` provides this wire format (report `NEEDED CRATE`
//! before adding one; swapping it changes byte-for-byte framing behaviour, not just an
//! implementation detail).
//!
//! The reader and control handler would keep the source/dest reader/writer as struct fields and
//! read/write through them across many method calls without re-supplying them; a Rust async design
//! cannot hold a borrowed reader across `.await` points inside a struct like that, so every method
//! here takes the live connection as an explicit `&mut` parameter instead. Extensions, the frame-size
//! cap, UTF-8 checking and continuation/intermediate hooks are dropped: no caller in this
//! codebase sets them (report `NEEDED SHIM ITEM` if a future caller does). Buffer pooling in
//! the writer and control writer is dropped too: this crate allocates instead of pooling, which
//! changes allocation count, not wire bytes.
// Test code is exempt from the production panic posture: the bans on `unwrap`,
// `expect`, `panic`, indexing and casts exist to keep a long-lived server process
// alive, and a failing test is supposed to abort. Style tiers are exempt for the
// same reason -- the scaffolding around an assertion is not product code.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::string_slice,
        clippy::print_stdout,
        clippy::print_stderr,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::pedantic,
        clippy::nursery
    )
)]

use std::borrow::Cow;
use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct State(pub u8);

pub const STATE_SERVER_SIDE: State = State(0x1);
pub const STATE_CLIENT_SIDE: State = State(0x2);
pub const STATE_EXTENDED: State = State(0x4);
pub const STATE_FRAGMENTED: State = State(0x8);

impl State {
    #[must_use]
    pub const fn is(self, v: Self) -> bool {
        self.0 & v.0 != 0
    }

    #[must_use]
    pub const fn set(self, v: Self) -> Self {
        Self(self.0 | v.0)
    }

    #[must_use]
    pub const fn clear(self, v: Self) -> Self {
        Self(self.0 & !v.0)
    }

    #[must_use]
    pub const fn server_side(self) -> bool {
        self.is(STATE_SERVER_SIDE)
    }

    #[must_use]
    pub const fn client_side(self) -> bool {
        self.is(STATE_CLIENT_SIDE)
    }

    #[must_use]
    pub const fn extended(self) -> bool {
        self.is(STATE_EXTENDED)
    }

    #[must_use]
    pub const fn fragmented(self) -> bool {
        self.is(STATE_FRAGMENTED)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OpCode(pub u8);

pub const OP_CONTINUATION: OpCode = OpCode(0x0);
pub const OP_TEXT: OpCode = OpCode(0x1);
pub const OP_BINARY: OpCode = OpCode(0x2);
pub const OP_CLOSE: OpCode = OpCode(0x8);
pub const OP_PING: OpCode = OpCode(0x9);
pub const OP_PONG: OpCode = OpCode(0xa);

impl OpCode {
    #[must_use]
    pub const fn is_control(self) -> bool {
        self.0 & 0x8 != 0
    }

    #[must_use]
    pub const fn is_data(self) -> bool {
        self.0 & 0x8 == 0
    }

    #[must_use]
    pub fn is_reserved(self) -> bool {
        (0x3..=0x7).contains(&self.0) || (0xb..=0xf).contains(&self.0)
    }
}

impl std::ops::BitOr for OpCode {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl std::ops::BitAnd for OpCode {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StatusCode(pub u16);

pub const STATUS_NORMAL_CLOSURE: StatusCode = StatusCode(1000);
pub const STATUS_GOING_AWAY: StatusCode = StatusCode(1001);
pub const STATUS_PROTOCOL_ERROR: StatusCode = StatusCode(1002);
pub const STATUS_UNSUPPORTED_DATA: StatusCode = StatusCode(1003);
pub const STATUS_NO_MEANING_YET: StatusCode = StatusCode(1004);
pub const STATUS_INVALID_FRAME_PAYLOAD_DATA: StatusCode = StatusCode(1007);
pub const STATUS_POLICY_VIOLATION: StatusCode = StatusCode(1008);
pub const STATUS_MESSAGE_TOO_BIG: StatusCode = StatusCode(1009);
pub const STATUS_MANDATORY_EXT: StatusCode = StatusCode(1010);
pub const STATUS_INTERNAL_SERVER_ERROR: StatusCode = StatusCode(1011);
pub const STATUS_TLS_HANDSHAKE: StatusCode = StatusCode(1015);
pub const STATUS_ABNORMAL_CLOSURE: StatusCode = StatusCode(1006);
pub const STATUS_NO_STATUS_RCVD: StatusCode = StatusCode(1005);

#[derive(Debug, Clone, Copy)]
pub struct StatusCodeRange {
    pub min: StatusCode,
    pub max: StatusCode,
}

pub const STATUS_RANGE_NOT_IN_USE: StatusCodeRange = StatusCodeRange { min: StatusCode(0), max: StatusCode(999) };
pub const STATUS_RANGE_PROTOCOL: StatusCodeRange = StatusCodeRange { min: StatusCode(1000), max: StatusCode(2999) };
pub const STATUS_RANGE_APPLICATION: StatusCodeRange = StatusCodeRange { min: StatusCode(3000), max: StatusCode(3999) };
pub const STATUS_RANGE_PRIVATE: StatusCodeRange = StatusCodeRange { min: StatusCode(4000), max: StatusCode(4999) };

impl StatusCode {
    #[must_use]
    pub fn is_in(self, r: StatusCodeRange) -> bool {
        r.min <= self && self <= r.max
    }

    #[must_use]
    pub const fn empty(self) -> bool {
        self.0 == 0
    }

    #[must_use]
    pub fn is_not_used(self) -> bool {
        self.is_in(STATUS_RANGE_NOT_IN_USE)
    }

    #[must_use]
    pub fn is_application_spec(self) -> bool {
        self.is_in(STATUS_RANGE_APPLICATION)
    }

    #[must_use]
    pub fn is_private_spec(self) -> bool {
        self.is_in(STATUS_RANGE_PRIVATE)
    }

    #[must_use]
    pub fn is_protocol_spec(self) -> bool {
        self.is_in(STATUS_RANGE_PROTOCOL)
    }

    #[must_use]
    pub const fn is_protocol_defined(self) -> bool {
        matches!(
            self,
            STATUS_NORMAL_CLOSURE
                | STATUS_GOING_AWAY
                | STATUS_PROTOCOL_ERROR
                | STATUS_UNSUPPORTED_DATA
                | STATUS_INVALID_FRAME_PAYLOAD_DATA
                | STATUS_POLICY_VIOLATION
                | STATUS_MESSAGE_TOO_BIG
                | STATUS_MANDATORY_EXT
                | STATUS_INTERNAL_SERVER_ERROR
                | STATUS_NO_STATUS_RCVD
                | STATUS_ABNORMAL_CLOSURE
                | STATUS_TLS_HANDSHAKE
        )
    }

    #[must_use]
    pub const fn is_protocol_reserved(self) -> bool {
        matches!(self, STATUS_NO_STATUS_RCVD | STATUS_ABNORMAL_CLOSURE | STATUS_TLS_HANDSHAKE)
    }
}

pub const MAX_CONTROL_FRAME_PAYLOAD_SIZE: usize = 125;
pub const MAX_HEADER_SIZE: usize = 14;

/// [`MAX_CONTROL_FRAME_PAYLOAD_SIZE`] in [`Header::length`]'s signed type, so a parsed length is
/// bounded without a `usize`-to-`i64` cast at every call site.
#[allow(clippy::cast_possible_wrap, reason = "a 125-byte cap is exact in i64")]
const MAX_CONTROL_FRAME_PAYLOAD_LENGTH: i64 = MAX_CONTROL_FRAME_PAYLOAD_SIZE as i64;

const LEN7: u64 = 125;
const LEN16: u64 = 0xffff;

#[derive(Debug, Clone, Copy, Default)]
pub struct Header {
    pub fin: bool,
    pub rsv: u8,
    pub op_code: OpCode,
    pub masked: bool,
    pub mask: [u8; 4],
    pub length: i64,
}

impl Default for OpCode {
    fn default() -> Self {
        OP_CONTINUATION
    }
}

#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum ProtocolError {
    #[error("use of reserved op code")]
    OpCodeReserved,
    #[error("control frame payload limit exceeded")]
    ControlPayloadOverflow,
    #[error("control frame is not final")]
    ControlNotFinal,
    #[error("non-zero rsv bits with no extension negotiated")]
    NonZeroRsv,
    #[error("frames from client to server must be masked")]
    MaskRequired,
    #[error("frames from server to client must be not masked")]
    MaskUnexpected,
    #[error("unexpected non-continuation data frame")]
    ContinuationExpected,
    #[error("unexpected continuation data frame")]
    ContinuationUnexpected,
    #[error("header error: the most significant bit must be 0")]
    HeaderLengthMsb,
    #[error("header error: unexpected payload length bits")]
    HeaderLengthUnexpected,
    #[error("status code is not in use")]
    StatusCodeNotInUse,
    #[error("status code is only application level")]
    StatusCodeApplicationLevel,
    #[error("status code has no meaning yet")]
    StatusCodeNoMeaning,
    #[error("status code is not defined in spec")]
    StatusCodeUnknown,
    #[error("invalid utf8 sequence in close reason")]
    InvalidUtf8,
}

#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("no frame advance")]
pub struct ErrNoFrameAdvance;

#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("not a control frame")]
pub struct ErrNotControlFrame;

#[derive(Debug, Clone)]
pub struct ClosedError {
    pub code: StatusCode,
    pub reason: Vec<u8>,
}

impl std::fmt::Display for ClosedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ws closed: {} {}", self.code.0, String::from_utf8_lossy(&self.reason))
    }
}

impl std::error::Error for ClosedError {}

pub fn cipher(payload: &mut [u8], mask: [u8; 4], offset: usize) {
    // The key repeats every four bytes; `offset` is how far into that cycle this call starts.
    for (byte, key) in payload.iter_mut().zip(mask.iter().cycle().skip(offset % 4)) {
        *byte ^= *key;
    }
}

#[must_use]
pub fn new_mask() -> [u8; 4] {
    rand::random()
}

pub fn put_close_frame_body(p: &mut [u8], code: StatusCode, reason: &[u8]) {
    let (code_bytes, body) = p.split_at_mut(2);
    code_bytes.copy_from_slice(&code.0.to_be_bytes());
    let (reason_bytes, _) = body.split_at_mut(reason.len());
    reason_bytes.copy_from_slice(reason);
}

#[must_use]
pub fn new_close_frame_body(code: StatusCode, reason: &[u8]) -> Vec<u8> {
    let n = (2 + reason.len()).min(MAX_CONTROL_FRAME_PAYLOAD_SIZE);
    let crop = (MAX_CONTROL_FRAME_PAYLOAD_SIZE - 2).min(reason.len());
    let mut p = vec![0u8; n];
    let (cropped, _) = reason.split_at(crop);
    put_close_frame_body(&mut p, code, cropped);
    p
}

#[must_use]
pub fn parse_close_frame_data(payload: &[u8]) -> (StatusCode, Vec<u8>) {
    let [hi, lo, reason @ ..] = payload else {
        return (StatusCode(0), Vec::new());
    };
    (StatusCode(u16::from_be_bytes([*hi, *lo])), reason.to_vec())
}

pub fn check_close_frame_data(code: StatusCode, reason: &[u8]) -> Result<(), ProtocolError> {
    if code.is_not_used() {
        return Err(ProtocolError::StatusCodeNotInUse);
    }
    if code.is_protocol_reserved() {
        return Err(ProtocolError::StatusCodeApplicationLevel);
    }
    if code == STATUS_NO_MEANING_YET {
        return Err(ProtocolError::StatusCodeNoMeaning);
    }
    if code.is_protocol_spec() && !code.is_protocol_defined() {
        return Err(ProtocolError::StatusCodeUnknown);
    }
    if std::str::from_utf8(reason).is_err() {
        return Err(ProtocolError::InvalidUtf8);
    }
    Ok(())
}

pub fn check_header(h: &Header, s: State) -> Result<(), ProtocolError> {
    if h.op_code.is_reserved() {
        return Err(ProtocolError::OpCodeReserved);
    }
    if h.op_code.is_control() {
        if h.length > MAX_CONTROL_FRAME_PAYLOAD_LENGTH {
            return Err(ProtocolError::ControlPayloadOverflow);
        }
        if !h.fin {
            return Err(ProtocolError::ControlNotFinal);
        }
    }
    if h.rsv != 0 && !s.extended() {
        return Err(ProtocolError::NonZeroRsv);
    }
    if s.server_side() && !h.masked {
        return Err(ProtocolError::MaskRequired);
    }
    if s.client_side() && h.masked {
        return Err(ProtocolError::MaskUnexpected);
    }
    if s.fragmented() && !h.op_code.is_control() && h.op_code != OP_CONTINUATION {
        return Err(ProtocolError::ContinuationExpected);
    }
    if !s.fragmented() && h.op_code == OP_CONTINUATION {
        return Err(ProtocolError::ContinuationUnexpected);
    }
    Ok(())
}

/// A byte count as the frame's declared [`Header::length`], which RFC6455 §5.2 caps at 63 bits.
fn frame_length(len: usize) -> io::Result<i64> {
    i64::try_from(len).map_err(|_| io::Error::other(ProtocolError::HeaderLengthUnexpected))
}

/// A declared [`Header::length`] as a buffer size; the field is signed, so a negative length names
/// no bytes and is a length error rather than an empty buffer.
fn length_buffer(length: i64) -> io::Result<usize> {
    usize::try_from(length).map_err(|_| io::Error::other(ProtocolError::HeaderLengthUnexpected))
}

enum ReadFullOutcome {
    Full,
    Eof,
    UnexpectedEof,
}

async fn read_full<R: AsyncRead + Unpin + ?Sized>(r: &mut R, buf: &mut [u8]) -> io::Result<ReadFullOutcome> {
    let mut filled = 0;
    while filled < buf.len() {
        let (_, rest) = buf.split_at_mut(filled);
        let n = r.read(rest).await?;
        if n == 0 {
            return Ok(if filled == 0 { ReadFullOutcome::Eof } else { ReadFullOutcome::UnexpectedEof });
        }
        filled += n;
    }
    Ok(ReadFullOutcome::Full)
}

/// Reads a frame header. `Ok(None)` is a clean stream end (zero bytes read); a
/// partial header is `io::ErrorKind::UnexpectedEof`.
pub async fn read_header<R: AsyncRead + Unpin + ?Sized>(r: &mut R) -> io::Result<Option<Header>> {
    let mut bts = [0u8; 2];
    match read_full(r, &mut bts).await? {
        ReadFullOutcome::Eof => return Ok(None),
        ReadFullOutcome::UnexpectedEof => return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
        ReadFullOutcome::Full => {}
    }

    let [first, second] = bts;
    let fin = first & 0x80 != 0;
    let rsv = (first & 0x70) >> 4;
    let op_code = OpCode(first & 0x0f);

    let masked = second & 0x80 != 0;
    let mut extra = if masked { 4 } else { 0 };
    let length_field = second & 0x7f;
    let mut length: i64 = 0;
    match length_field {
        l if l < 126 => length = i64::from(l),
        126 => extra += 2,
        127 => extra += 8,
        _ => return Err(io::Error::other(ProtocolError::HeaderLengthUnexpected)),
    }

    let mut mask = [0u8; 4];
    if extra > 0 {
        let mut extra_buf = [0u8; 12];
        let (extra_bytes, _) = extra_buf.split_at_mut(extra);
        let ReadFullOutcome::Full = read_full(r, &mut *extra_bytes).await? else {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        };
        let mut off = 0;
        match length_field {
            126 => {
                let [hi, lo, ..] = extra_bytes else {
                    return Err(io::Error::other(ProtocolError::HeaderLengthUnexpected));
                };
                length = i64::from(u16::from_be_bytes([*hi, *lo]));
                off = 2;
            }
            127 => {
                let [msb, b1, b2, b3, b4, b5, b6, b7, ..] = extra_bytes else {
                    return Err(io::Error::other(ProtocolError::HeaderLengthUnexpected));
                };
                if *msb & 0x80 != 0 {
                    return Err(io::Error::other(ProtocolError::HeaderLengthMsb));
                }
                length = i64::from_be_bytes([*msb, *b1, *b2, *b3, *b4, *b5, *b6, *b7]);
                off = 8;
            }
            _ => {}
        }
        if masked {
            let (_, mask_region) = extra_bytes.split_at(off);
            let (mask_source, _) = mask_region.split_at(mask.len());
            mask.copy_from_slice(mask_source);
        }
    }

    Ok(Some(Header { fin, rsv, op_code, masked, mask, length }))
}

pub async fn write_header<W: AsyncWrite + Unpin + ?Sized>(w: &mut W, h: &Header) -> io::Result<()> {
    let mut bts = [0u8; MAX_HEADER_SIZE];
    if h.fin {
        bts[0] |= 0x80;
    }
    bts[0] |= h.rsv << 4;
    bts[0] |= h.op_code.0;

    // A negative length is rejected outright, so each conversion below is
    // narrowed only by the arm that holds it.
    let length = u64::try_from(h.length).map_err(|_| io::Error::other(ProtocolError::HeaderLengthUnexpected))?;
    let mut n;
    if length <= LEN7 {
        bts[1] = u8::try_from(length).map_err(io::Error::other)?;
        n = 2;
    } else if length <= LEN16 {
        bts[1] = 126;
        bts[2..4].copy_from_slice(&u16::try_from(length).map_err(io::Error::other)?.to_be_bytes());
        n = 4;
    } else {
        bts[1] = 127;
        bts[2..10].copy_from_slice(&length.to_be_bytes());
        n = 10;
    }

    if h.masked {
        bts[1] |= 0x80;
        // `n` is at most 10 here, so the four mask bytes always fit in `bts`.
        let (_, mask_region) = bts.split_at_mut(n);
        let (mask_dst, _) = mask_region.split_at_mut(h.mask.len());
        mask_dst.copy_from_slice(&h.mask);
        n += 4;
    }

    let (header, _) = bts.split_at(n);
    w.write_all(header).await
}

/// Builds a single fin frame, masking the payload when `s` is client-side.
pub async fn write_message<W: AsyncWrite + Unpin + ?Sized>(
    w: &mut W,
    s: State,
    op: OpCode,
    p: &[u8],
) -> io::Result<()> {
    // Masking rewrites the payload in place, so only a client-side frame needs its own copy.
    let (payload, mask) = if s.client_side() {
        let mut payload = p.to_vec();
        let mask = new_mask();
        cipher(&mut payload, mask, 0);
        (Cow::Owned(payload), mask)
    } else {
        (Cow::Borrowed(p), [0; 4])
    };
    let length = frame_length(payload.len())?;
    let header = Header { fin: true, rsv: 0, op_code: op, masked: s.client_side(), mask, length };
    write_header(w, &header).await?;
    w.write_all(&payload).await
}

/// Writes a message, masking `payload` in place instead of copying it into a fresh buffer.
pub async fn write_message_owned<W: AsyncWrite + Unpin + ?Sized>(
    w: &mut W,
    s: State,
    op: OpCode,
    payload: &mut [u8],
) -> io::Result<()> {
    let mask = if s.client_side() {
        let mask = new_mask();
        cipher(payload, mask, 0);
        mask
    } else {
        [0; 4]
    };
    let length = frame_length(payload.len())?;
    let header = Header { fin: true, rsv: 0, op_code: op, masked: s.client_side(), mask, length };
    write_header(w, &header).await?;
    w.write_all(payload).await
}

#[derive(Debug)]
struct ActiveFrame {
    remaining: i64,
    mask: Option<[u8; 4]>,
    cipher_pos: usize,
}

/// The frame reader: the active frame's payload position and the message's fragmentation state.
///
/// Extensions, the frame-size cap, UTF-8 checking and the continuation/intermediate hooks are not supported
/// (see module docs); the header-check skip is, for callers that need it. No
/// caller here sets `skip_header_check`; `Reader::new` always starts it `false`.
#[derive(Debug)]
pub struct Reader {
    pub state: State,
    pub skip_header_check: bool,
    op_code: OpCode,
    frame: Option<ActiveFrame>,
}

impl Reader {
    #[must_use]
    pub const fn new(state: State) -> Self {
        Self { state, skip_header_check: false, op_code: OP_CONTINUATION, frame: None }
    }

    const fn reset(&mut self) {
        self.frame = None;
        self.op_code = OP_CONTINUATION;
    }

    ///
    /// `Ok(None)` is a clean connection close at a message boundary; mid-fragment closure is
    /// upgraded to `UnexpectedEof`.
    pub async fn next_frame<R: AsyncRead + Unpin + ?Sized>(&mut self, source: &mut R) -> io::Result<Option<Header>> {
        let Some(hdr) = read_header(source).await? else {
            if self.state.fragmented() {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            }
            return Ok(None);
        };
        if !self.skip_header_check {
            check_header(&hdr, self.state).map_err(io::Error::other)?;
        }

        let mask = hdr.masked.then_some(hdr.mask);
        if self.state.fragmented() && hdr.op_code.is_control() {
            discard_bytes(source, hdr.length).await?;
            return Ok(Some(hdr));
        }
        if !self.state.fragmented() {
            self.op_code = hdr.op_code;
        }
        self.frame = Some(ActiveFrame { remaining: hdr.length, mask, cipher_pos: 0 });
        if hdr.fin {
            self.state = self.state.clear(STATE_FRAGMENTED);
        } else {
            self.state = self.state.set(STATE_FRAGMENTED);
        }
        Ok(Some(hdr))
    }

    /// reads the active frame's payload, auto-advancing through continuation
    /// frames.
    ///
    /// A control frame arriving mid-message is consumed and reading continues, matching the
    /// read/next-frame pairing but without its zero-length result: to an `AsyncRead` caller
    /// `Ok(0)` is end-of-stream, so a peer that interleaves a ping would truncate the connection.
    /// Callers still see `ErrNoFrameAdvance` at a message boundary and drive
    /// [`Self::next_frame`] themselves, which is where control frames get their ping/pong/close
    /// handling.
    pub async fn read<R: AsyncRead + Unpin + ?Sized>(&mut self, source: &mut R, buf: &mut [u8]) -> io::Result<usize> {
        while self.frame.is_none() {
            if !self.state.fragmented() {
                return Err(io::Error::other(ErrNoFrameAdvance));
            }
            self.next_frame(source).await?;
        }
        // The loop above exits only with an active frame; without one there is no byte to report.
        let Some(frame) = self.frame.as_mut() else {
            return Err(io::Error::other(ErrNoFrameAdvance));
        };
        if frame.remaining == 0 {
            if self.state.fragmented() {
                self.frame = None;
            } else {
                self.reset();
            }
            return Ok(0);
        }

        let want = length_buffer(frame.remaining)?.min(buf.len());
        let (target, _) = buf.split_at_mut(want);
        let n = source.read(target).await?;
        if n == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        if let Some(mask) = frame.mask {
            let (read_bytes, _) = buf.split_at_mut(n);
            cipher(read_bytes, mask, frame.cipher_pos);
            frame.cipher_pos += n;
        }
        frame.remaining -= frame_length(n)?;
        if frame.remaining == 0 {
            if self.state.fragmented() {
                self.frame = None;
            } else {
                self.reset();
            }
        }
        Ok(n)
    }

    /// drops the current message's unread bytes, including every remaining
    /// fragment.
    ///
    /// A real connection close mid-frame is treated as plain completion rather than an error
    /// (see `discard_bytes`).
    pub async fn discard<R: AsyncRead + Unpin + ?Sized>(&mut self, source: &mut R) -> io::Result<()> {
        let result = self.discard_body(source).await;
        self.reset();
        result
    }

    async fn discard_body<R: AsyncRead + Unpin + ?Sized>(&mut self, source: &mut R) -> io::Result<()> {
        loop {
            let remaining = self.frame.as_ref().map_or(0, |f| f.remaining);
            discard_bytes(source, remaining).await?;
            if let Some(f) = self.frame.as_mut() {
                f.remaining = 0;
            }
            if !self.state.fragmented() {
                return Ok(());
            }
            if self.next_frame(source).await?.is_none() {
                return Ok(());
            }
        }
    }
}

async fn discard_bytes<R: AsyncRead + Unpin + ?Sized>(source: &mut R, remaining: i64) -> io::Result<()> {
    // A length past what a `usize` holds is still discarded in `buf.len()`-sized steps; a negative
    // one has nothing to discard.
    let mut left = usize::try_from(remaining.max(0)).unwrap_or(usize::MAX);
    let mut buf = [0u8; 4096];
    while left > 0 {
        let want = left.min(buf.len());
        let (target, _) = buf.split_at_mut(want);
        let n = source.read(target).await?;
        if n == 0 {
            break;
        }
        left -= n;
    }
    Ok(())
}

async fn read_full_via_reader<R: AsyncRead + Unpin + ?Sized>(
    reader: &mut Reader,
    source: &mut R,
    buf: &mut [u8],
) -> io::Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        let (_, rest) = buf.split_at_mut(filled);
        let n = reader.read(source, rest).await?;
        if n == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        filled += n;
    }
    Ok(())
}

async fn discard_via_reader<R: AsyncRead + Unpin + ?Sized>(
    reader: &mut Reader,
    source: &mut R,
    remaining: i64,
) -> io::Result<()> {
    // The same clamping as `discard_bytes`; only the supplier of the discarded bytes differs.
    let mut left = usize::try_from(remaining.max(0)).unwrap_or(usize::MAX);
    let mut buf = [0u8; 4096];
    while left > 0 {
        let want = left.min(buf.len());
        let (target, _) = buf.split_at_mut(want);
        let n = reader.read(source, target).await?;
        if n == 0 {
            return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
        }
        left -= n;
    }
    Ok(())
}

/// The ping handler as reached through the control-frame dispatcher (always
/// with source ciphering disabled).
///
/// `reader` already delivers unmasked bytes, so no re-unmasking here. `handle_control_frame`
/// rejects a length past `MAX_CONTROL_FRAME_PAYLOAD_SIZE` before calling this, so `hdr.length`
/// here is always small.
async fn handle_ping<C: AsyncRead + AsyncWrite + Unpin + ?Sized>(
    reader: &mut Reader,
    conn: &mut C,
    state: State,
    hdr: &Header,
) -> io::Result<()> {
    if hdr.length == 0 {
        let header =
            Header { fin: true, rsv: 0, op_code: OP_PONG, masked: state.client_side(), mask: [0; 4], length: 0 };
        return write_header(conn, &header).await;
    }
    let mut payload = vec![0u8; length_buffer(hdr.length)?];
    read_full_via_reader(reader, conn, &mut payload).await?;
    write_message(conn, state, OP_PONG, &payload).await
}

/// The pong handler: discards the payload rather than answering it.
///
/// A pong is never echoed, so unlike ping there is nothing to send back and no reason to reject
/// an oversized one — a peer gains nothing by sending a huge pong.
///
/// A declared length has no effect on how much memory this allocates: the discard is streamed
/// through a fixed-size buffer once `hdr.length` exceeds `MAX_CONTROL_FRAME_PAYLOAD_SIZE`.
async fn handle_pong<C: AsyncRead + Unpin + ?Sized>(reader: &mut Reader, conn: &mut C, hdr: &Header) -> io::Result<()> {
    if hdr.length == 0 {
        return Ok(());
    }
    if hdr.length > MAX_CONTROL_FRAME_PAYLOAD_LENGTH {
        return discard_via_reader(reader, conn, hdr.length).await;
    }
    let mut buf = vec![0u8; length_buffer(hdr.length)?];
    read_full_via_reader(reader, conn, &mut buf).await
}

async fn close_with_protocol_error<W: AsyncWrite + Unpin + ?Sized>(
    dest: &mut W,
    state: State,
    reason: &ProtocolError,
) -> io::Result<()> {
    let body = new_close_frame_body(STATUS_PROTOCOL_ERROR, reason.to_string().as_bytes());
    write_message(dest, state, OP_CLOSE, &body).await
}

/// The close handler: echoes the close code (RFC6455#5.5.1) and returns
/// `ClosedError` on success.
///
/// The caller treats that as a terminal read error — mapped here to
/// `io::Error::other(ClosedError)`. Only the two code bytes are ever needed, so nothing
/// proportional to the declared length is allocated up front.
///
/// Past `MAX_CONTROL_FRAME_PAYLOAD_SIZE`, this reads only the 2-byte code, discards the rest
/// through a fixed-size buffer, and closes with that code and an empty reason — it cannot validate
/// a reason it never buffered, so `check_close_frame_data` only runs on a close frame small enough
/// to have been read in full.
async fn handle_close<C: AsyncRead + AsyncWrite + Unpin + ?Sized>(
    reader: &mut Reader,
    conn: &mut C,
    state: State,
    hdr: &Header,
) -> io::Result<()> {
    if hdr.length == 0 {
        let header =
            Header { fin: true, rsv: 0, op_code: OP_CLOSE, masked: state.client_side(), mask: [0; 4], length: 0 };
        write_header(conn, &header).await?;
        return Err(io::Error::other(ClosedError { code: STATUS_NO_STATUS_RCVD, reason: Vec::new() }));
    }
    if hdr.length > MAX_CONTROL_FRAME_PAYLOAD_LENGTH {
        let mut code_buf = [0u8; 2];
        read_full_via_reader(reader, conn, &mut code_buf).await?;
        discard_via_reader(reader, conn, hdr.length - 2).await?;
        let code = StatusCode(u16::from_be_bytes(code_buf));
        write_message(conn, state, OP_CLOSE, &code_buf).await?;
        return Err(io::Error::other(ClosedError { code, reason: Vec::new() }));
    }
    let mut payload = vec![0u8; length_buffer(hdr.length)?];
    read_full_via_reader(reader, conn, &mut payload).await?;
    let (code, reason) = parse_close_frame_data(&payload);
    if let Err(protocol_err) = check_close_frame_data(code, &reason) {
        let _ = close_with_protocol_error(conn, state, &protocol_err).await;
        return Err(io::Error::other(protocol_err));
    }
    let (code_bytes, _) = payload.split_at(2);
    write_message(conn, state, OP_CLOSE, code_bytes).await?;
    Err(io::Error::other(ClosedError { code, reason }))
}

/// Invoked on a parsed control-frame header: dispatches to ping/pong/close.
///
/// Returns `ErrNotControlFrame` for a non-control opcode.
/// `check_header` already rejects an oversized control payload for every caller in this crate
/// today — `Reader::skip_header_check` is always `false` here, and no production caller sets it.
///
/// A caller that skips the header check would need a length cap of its own here, since a
/// huge ping would otherwise mean echoing a huge pong; the pong/close branches bound their own
/// memory instead (see their doc comments).
pub async fn handle_control_frame<C: AsyncRead + AsyncWrite + Unpin + ?Sized>(
    reader: &mut Reader,
    conn: &mut C,
    state: State,
    hdr: &Header,
) -> io::Result<()> {
    if hdr.op_code == OP_PING {
        if hdr.length > MAX_CONTROL_FRAME_PAYLOAD_LENGTH {
            return Err(io::Error::other(ProtocolError::ControlPayloadOverflow));
        }
        handle_ping(reader, conn, state, hdr).await
    } else if hdr.op_code == OP_PONG {
        handle_pong(reader, conn, hdr).await
    } else if hdr.op_code == OP_CLOSE {
        handle_close(reader, conn, state, hdr).await
    } else {
        Err(io::Error::other(ErrNotControlFrame))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `handle_control_frame` rejects an oversized ping before dispatching to `handle_ping`
    /// regardless of `skip_header_check`, because a huge ping would otherwise mean echoing a huge
    /// pong.
    ///
    /// `check_header` already enforces the same cap for every caller that has it enabled, so this
    /// proves the guarantee survives a caller that does not (see `Reader`'s doc comment).
    #[tokio::test]
    async fn handle_control_frame_ping_rejects_oversized_payload_with_header_check_skipped() {
        let mut reader = Reader::new(STATE_SERVER_SIDE);
        reader.skip_header_check = true;
        let hdr = Header { fin: true, rsv: 0, op_code: OP_PING, masked: true, mask: [0; 4], length: i64::MAX };
        let mut conn = tokio::io::empty();
        let err = handle_control_frame(&mut reader, &mut conn, STATE_SERVER_SIDE, &hdr)
            .await
            .expect_err("an oversized ping must be rejected before allocating");
        assert!(err.to_string().contains("control frame payload limit exceeded"), "unexpected error: {err}");
    }

    /// The pong handler discards an oversized pong the same way as a normal one instead of rejecting
    /// it.
    ///
    /// Nothing is ever echoed back, so a peer gains nothing by sending a huge one. This proves the
    /// port discards exactly the declared length through the fixed-size discard buffer rather than
    /// allocating one sized to it.
    #[tokio::test]
    async fn handle_pong_oversized_payload_is_discarded_without_allocating_the_full_length() {
        const LEN: usize = 4096 * 3 + 17;
        let len = i64::try_from(LEN).expect("the test length fits in i64");
        let mut reader = Reader::new(STATE_SERVER_SIDE);
        reader.frame = Some(ActiveFrame { remaining: len, mask: None, cipher_pos: 0 });
        let hdr = Header { fin: true, rsv: 0, op_code: OP_PONG, masked: false, mask: [0; 4], length: len };
        let mut conn = io::Cursor::new(vec![0xab_u8; LEN]);
        handle_pong(&mut reader, &mut conn, &hdr).await.expect("an oversized pong must be discarded, not rejected");
        assert_eq!(conn.position(), LEN as u64, "must discard exactly the declared length, no more and no less");
    }

    /// A declared pong length far beyond what the peer ever actually sends must fail with a short
    /// read once the real bytes run out.
    ///
    /// It must not hang or grow a buffer anywhere near the declared size.
    #[tokio::test]
    async fn handle_pong_declared_huge_length_short_reads_instead_of_allocating() {
        let mut reader = Reader::new(STATE_SERVER_SIDE);
        reader.frame = Some(ActiveFrame { remaining: i64::MAX, mask: None, cipher_pos: 0 });
        let hdr = Header { fin: true, rsv: 0, op_code: OP_PONG, masked: false, mask: [0; 4], length: i64::MAX };
        let mut conn = io::Cursor::new(vec![0u8; 10]);
        let err = handle_pong(&mut reader, &mut conn, &hdr)
            .await
            .expect_err("the declared length must fail once the real bytes are exhausted");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    /// Past `MAX_CONTROL_FRAME_PAYLOAD_SIZE` only the 2-byte code is read, the rest is discarded
    /// through a fixed-size buffer, and the code is echoed back with `ClosedError` and an empty
    /// reason (it was never buffered to validate).
    #[tokio::test]
    async fn handle_close_oversized_payload_echoes_code_and_returns_closed_error() {
        const LEN: usize = 300;
        let len = i64::try_from(LEN).expect("the test length fits in i64");
        let mut reader = Reader::new(STATE_SERVER_SIDE);
        reader.frame = Some(ActiveFrame { remaining: len, mask: None, cipher_pos: 0 });
        let hdr = Header { fin: true, rsv: 0, op_code: OP_CLOSE, masked: false, mask: [0; 4], length: len };
        let mut payload = vec![0x42_u8; LEN];
        payload[0..2].copy_from_slice(&STATUS_NORMAL_CLOSURE.0.to_be_bytes());
        let mut conn = tokio::io::join(io::Cursor::new(payload), tokio::io::sink());
        let err = handle_close(&mut reader, &mut conn, STATE_SERVER_SIDE, &hdr)
            .await
            .expect_err("an oversized close must still terminate the connection");
        let closed = err.get_ref().expect("closed error source").downcast_ref::<ClosedError>().expect("ClosedError");
        assert_eq!(closed.code, STATUS_NORMAL_CLOSURE);
        assert!(closed.reason.is_empty(), "an oversized close cannot buffer a reason it never read");
    }

    /// The declared close length must not be trusted for anything past the 2-byte code.
    ///
    /// A huge length with only a handful of real bytes fails with a short read rather than
    /// allocating or blocking on data the peer never sends.
    #[tokio::test]
    async fn handle_close_declared_huge_length_short_reads_instead_of_allocating() {
        let mut reader = Reader::new(STATE_SERVER_SIDE);
        reader.frame = Some(ActiveFrame { remaining: i64::MAX, mask: None, cipher_pos: 0 });
        let hdr = Header { fin: true, rsv: 0, op_code: OP_CLOSE, masked: false, mask: [0; 4], length: i64::MAX };
        let mut conn = tokio::io::join(io::Cursor::new(vec![0u8; 10]), tokio::io::sink());
        let err = handle_close(&mut reader, &mut conn, STATE_SERVER_SIDE, &hdr)
            .await
            .expect_err("the declared length must fail once the real bytes are exhausted");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    /// RFC 6455 §5.7 "Example: A single-frame masked text message": masking key `0x37fa213d`
    /// applied to `"Hello"` produces `7f 9f 4d 51 58`.
    ///
    /// `cipher` is untouched by the copy-elision change to `write_message_owned` below; this pins
    /// its output to that vector.
    #[test]
    fn cipher_matches_rfc6455_example() {
        let mut payload = *b"Hello";
        cipher(&mut payload, [0x37, 0xfa, 0x21, 0x3d], 0);
        assert_eq!(payload, *b"\x7f\x9f\x4d\x51\x58");
    }

    /// `write_message_owned` masks its caller-owned buffer in place instead of `write_message`'s
    /// copy-then-mask.
    ///
    /// This reconstructs the copy-based frame from the mask `write_message_owned` chose and asserts
    /// the two are byte-identical, then confirms the masked payload unmasks back to the original.
    #[tokio::test]
    async fn write_message_owned_matches_copy_based_masking() {
        let original = b"the quick brown fox".to_vec();

        let mut owned = original.clone();
        let mut actual = Vec::new();
        write_message_owned(&mut actual, STATE_CLIENT_SIDE, OP_BINARY, &mut owned).await.unwrap();

        let mut cursor = io::Cursor::new(actual.clone());
        let header = read_header(&mut cursor).await.unwrap().expect("frame header");
        assert!(header.masked);

        let mut expected_payload = original.clone();
        cipher(&mut expected_payload, header.mask, 0);
        let mut expected = Vec::new();
        write_header(&mut expected, &header).await.unwrap();
        expected.extend_from_slice(&expected_payload);
        assert_eq!(actual, expected);

        let mut unmasked = expected_payload;
        cipher(&mut unmasked, header.mask, 0);
        assert_eq!(unmasked, original);
    }

    /// A control frame may legally arrive between the fragments of one message (RFC 6455 §5.4:
    /// "Control frames ... MAY be injected in the middle of a fragmented message").
    ///
    /// next-frame returns that header with no active frame, and read reports
    /// a zero-length read, not an error. This crate's `read` returned `Ok(0)`
    /// directly, which to an `AsyncRead` caller is indistinguishable from end-of-stream, so a
    /// legitimate ping in the middle of a message silently truncated the connection. The skip has
    /// to be retried inside `read` so the message continues to be delivered.
    #[tokio::test]
    async fn read_skips_a_control_frame_between_fragments_instead_of_reporting_eof() {
        let mut wire = Vec::new();
        // First text fragment, not final.
        let first = Header { fin: false, rsv: 0, op_code: OP_TEXT, masked: false, mask: [0; 4], length: 5 };
        write_header(&mut wire, &first).await.unwrap();
        wire.extend_from_slice(b"hello");
        // An interleaved ping, which must not end the read.
        let ping = Header { fin: true, rsv: 0, op_code: OP_PING, masked: false, mask: [0; 4], length: 2 };
        write_header(&mut wire, &ping).await.unwrap();
        wire.extend_from_slice(b"hi");
        // Final continuation carrying the rest of the message.
        let last = Header { fin: true, rsv: 0, op_code: OP_CONTINUATION, masked: false, mask: [0; 4], length: 5 };
        write_header(&mut wire, &last).await.unwrap();
        wire.extend_from_slice(b"world");

        let mut conn = io::Cursor::new(wire);
        // A client-side reader, so the unmasked server frames above pass `check_header`.
        let mut reader = Reader::new(STATE_CLIENT_SIDE);
        let header = reader.next_frame(&mut conn).await.unwrap().expect("a frame header");
        assert_eq!(header.op_code, OP_TEXT);

        let mut got = Vec::new();
        let mut buf = [0u8; 16];
        // Read until the whole message has arrived; the ping in the middle must be skipped
        // rather than surfacing as a zero-length read.
        while got.len() < 10 {
            let n = reader.read(&mut conn, &mut buf).await.expect("read the fragmented message");
            assert_ne!(n, 0, "a control frame between fragments must not end the read as EOF");
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(got, b"helloworld");
    }
}
