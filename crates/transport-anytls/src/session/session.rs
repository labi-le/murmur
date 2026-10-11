use std::borrow::Cow;
use std::collections::HashMap;
use std::io;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwapOption;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use futures::FutureExt;
use md5::{Digest, Md5};
use parking_lot::{Mutex, RwLock};
use tokio::io::AsyncWriteExt;
use tokio::time::Instant;

use murmur_common::shared_conn::SharedConn;
use murmur_common_net::deadline::pipe::CloseSignal;
use murmur_common_pool as pool;
use murmur_compat::sing_buf::new_size;

use crate::padding::padding::{update_padding_scheme, PaddingFactory, CHECK_MARK};
use crate::util::deadline::new_deadline_watcher;
use crate::util::string_map::{string_map_from_bytes, to_bytes, StringMap};
use murmur_log::{debugln, errorln, warnln};

use super::frame::{
    header_cmd, header_length, header_stream_id, new_frame, Frame, RawHeader, CMD_ALERT, CMD_FIN, CMD_HEART_REQUEST,
    CMD_HEART_RESPONSE, CMD_PSH, CMD_SERVER_SETTINGS, CMD_SETTINGS, CMD_SYN, CMD_SYNACK, CMD_UPDATE_PADDING_SCHEME,
    CMD_WASTE, HEADER_OVER_HEAD_SIZE,
};
use super::stream::{new_stream, Stream};

pub(crate) fn err_closed_pipe() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "io: read/write on closed pipe")
}

pub(crate) fn err_net_closed() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "use of closed network connection")
}

pub(crate) fn err_deadline_exceeded() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "i/o timeout")
}

pub(crate) async fn read_full(conn: &SharedConn, buf: &mut [u8]) -> io::Result<()> {
    let mut filled = 0;
    while let Some(dst) = buf.get_mut(filled..).filter(|dst| !dst.is_empty()) {
        let read = conn.read(dst).await?;
        if read == 0 {
            return Err(if filled == 0 {
                io::Error::new(io::ErrorKind::UnexpectedEof, "EOF")
            } else {
                io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF")
            });
        }
        filled += read;
    }
    Ok(())
}

/// The maximum payload bytes per data frame, matching the wire format's uint16 length field.
pub(crate) const MAX_FRAME_DATA_LEN: usize = 0xFFFF;

/// The frame header's 16-bit payload length field.
///
/// A length above [`MAX_FRAME_DATA_LEN`] truncates, matching the 16-bit wire field.
#[expect(
    clippy::cast_possible_truncation,
    reason = "the header field is 16 bits and a longer frame truncates the same way"
)]
fn wire_len16(len: usize) -> u16 {
    len as u16
}

/// A packet size for [`new_size`], which takes the length as an `i32`.
fn frame_buffer_size(len: usize) -> io::Result<i32> {
    i32::try_from(len).map_err(|_| io::Error::other("frame buffer too large"))
}

fn waste_frame(padding_len: usize) -> Vec<u8> {
    let mut frame = Vec::with_capacity(HEADER_OVER_HEAD_SIZE + padding_len);
    frame.push(CMD_WASTE);
    frame.extend_from_slice(&0_u32.to_be_bytes());
    frame.extend_from_slice(&wire_len16(padding_len).to_be_bytes());
    frame.resize(HEADER_OVER_HEAD_SIZE + padding_len, 0);
    frame
}

type DieHook = Box<dyn Fn() + Send + Sync>;

pub struct Session {
    conn: SharedConn,
    conn_lock: tokio::sync::Mutex<()>,

    streams: RwLock<HashMap<u32, Arc<Stream>>>,
    stream_id: AtomicU32,
    die_once: AtomicBool,
    die: CloseSignal,
    die_hook: Mutex<Option<DieHook>>,

    syn_done: Mutex<Option<DieHook>>,

    seq: AtomicU64,
    idle_since: Mutex<Option<DateTime<Utc>>>,
    padding: Arc<ArcSwapOption<PaddingFactory>>,

    peer_version: AtomicU8,

    is_client: bool,
    send_padding: AtomicBool,
    buffering: AtomicBool,
    buffer: Mutex<Vec<u8>>,
    pkt_counter: AtomicU32,
    client_metadata: String,

    on_new_stream: Option<Arc<dyn Fn(Arc<Stream>) + Send + Sync>>,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("seq", &self.seq.load(Ordering::SeqCst))
            .field("stream_id", &self.stream_id.load(Ordering::SeqCst))
            .field("is_client", &self.is_client)
            .finish_non_exhaustive()
    }
}

impl Session {
    pub fn client(
        conn: Box<dyn murmur_std_compat::net::Conn>,
        padding: Arc<ArcSwapOption<PaddingFactory>>,
        client_metadata: String,
    ) -> Self {
        Self {
            conn: SharedConn::from_boxed(conn),
            conn_lock: tokio::sync::Mutex::new(()),
            streams: RwLock::new(HashMap::new()),
            stream_id: AtomicU32::new(0),
            die_once: AtomicBool::new(false),
            die: CloseSignal::default(),
            die_hook: Mutex::new(None),
            syn_done: Mutex::new(None),
            seq: AtomicU64::new(0),
            idle_since: Mutex::new(None),
            padding,
            peer_version: AtomicU8::new(0),
            is_client: true,
            send_padding: AtomicBool::new(true),
            buffering: AtomicBool::new(false),
            buffer: Mutex::new(Vec::new()),
            pkt_counter: AtomicU32::new(0),
            client_metadata,
            on_new_stream: None,
        }
    }

    pub fn server(
        conn: Box<dyn murmur_std_compat::net::Conn>,
        on_new_stream: Option<Arc<dyn Fn(Arc<Stream>) + Send + Sync>>,
        padding: Arc<ArcSwapOption<PaddingFactory>>,
    ) -> Self {
        Self {
            conn: SharedConn::from_boxed(conn),
            conn_lock: tokio::sync::Mutex::new(()),
            streams: RwLock::new(HashMap::new()),
            stream_id: AtomicU32::new(0),
            die_once: AtomicBool::new(false),
            die: CloseSignal::default(),
            die_hook: Mutex::new(None),
            syn_done: Mutex::new(None),
            seq: AtomicU64::new(0),
            idle_since: Mutex::new(None),
            padding,
            peer_version: AtomicU8::new(0),
            is_client: false,
            send_padding: AtomicBool::new(false),
            buffering: AtomicBool::new(false),
            buffer: Mutex::new(Vec::new()),
            pkt_counter: AtomicU32::new(0),
            client_metadata: String::new(),
            on_new_stream,
        }
    }

    #[expect(
        clippy::expect_used,
        reason = "the accessor's signature is infallible, and every session is built with a padding factory that is never reset"
    )]
    fn padding_factory(&self) -> Arc<PaddingFactory> {
        self.padding.load_full().expect("padding factory is initialized before any session traffic")
    }

    /// Runs the session. The server's receive loop runs on the calling task and the client's is
    /// spawned; the split is kept, so a server caller awaits this.
    pub async fn run(self: &Arc<Self>) {
        if !self.is_client {
            self.recv_loop().await;
            return;
        }

        let mut settings = StringMap::new();
        settings.insert("v".to_owned(), "2".to_owned());
        settings.insert("client".to_owned(), self.client_metadata.clone());
        settings.insert("padding-md5".to_owned(), self.padding_factory().md5.clone());
        let mut f = new_frame(CMD_SETTINGS, 0);
        f.data = to_bytes(&settings);
        self.buffering.store(true, Ordering::SeqCst);
        let _ = self.write_control_frame(f).await;

        let this = Arc::clone(self);
        tokio::spawn(async move { this.recv_loop().await });
    }

    pub fn is_closed(&self) -> bool {
        self.die.is_closed()
    }

    /// Sets the die hook.
    pub(crate) fn set_die_hook(&self, hook: DieHook) {
        *self.die_hook.lock() = Some(hook);
    }

    pub(crate) fn peer_version(&self) -> u8 {
        self.peer_version.load(Ordering::SeqCst)
    }

    /// The sequence number the pool keys on.
    pub(crate) fn seq(&self) -> u64 {
        self.seq.load(Ordering::SeqCst)
    }

    pub(crate) fn set_seq(&self, seq: u64) {
        self.seq.store(seq, Ordering::SeqCst);
    }

    /// The idle-since timestamp, read and written under the client's idle-session lock.
    pub(crate) fn idle_since(&self) -> Option<DateTime<Utc>> {
        *self.idle_since.lock()
    }

    pub(crate) fn set_idle_since(&self, t: DateTime<Utc>) {
        *self.idle_since.lock() = Some(t);
    }

    /// The session conn seen as the address source of a stream, which holds a local/remote
    /// address when the underlying conn does.
    pub(crate) fn conn_addr(&self, local: bool) -> io::Result<Box<dyn murmur_std_compat::net::Addr>> {
        if local {
            self.conn.local_addr()
        } else {
            self.conn.remote_addr()
        }
    }

    /// Closes the session and all its streams.
    pub fn close(&self) -> io::Result<()> {
        let once = !self.die_once.swap(true, Ordering::SeqCst);
        if once {
            let _ = self.conn.set_deadline(Some(Instant::now()));
            self.die.close();
            let hook = self.die_hook.lock().take();
            if let Some(hook) = hook {
                hook();
            }
            let streams: Vec<Arc<Stream>> = {
                let mut map = self.streams.write();
                std::mem::take(&mut *map).into_values().collect()
            };
            for stream in streams {
                stream.close_locally();
            }
            return self.conn.close();
        }
        Err(err_closed_pipe())
    }

    pub async fn open_stream(self: &Arc<Self>) -> io::Result<Arc<Stream>> {
        if self.is_closed() {
            return Err(err_closed_pipe());
        }

        let sid = self.stream_id.fetch_add(1, Ordering::SeqCst) + 1;
        let stream = Arc::new(new_stream(sid, Arc::clone(self)));

        if sid >= 2 && self.peer_version.load(Ordering::SeqCst) >= 2 {
            {
                let mut syn_done = self.syn_done.lock();
                if let Some(done) = syn_done.take() {
                    done();
                }
                let this = Arc::clone(self);
                *syn_done = Some(Box::new(new_deadline_watcher(Duration::from_secs(3), move || {
                    let _ = this.close();
                })));
            }
        }

        self.write_control_frame(new_frame(CMD_SYN, sid)).await?;

        self.buffering.store(false, Ordering::SeqCst);

        {
            let mut streams = self.streams.write();
            if self.is_closed() {
                return Err(err_closed_pipe());
            }
            streams.insert(sid, Arc::clone(&stream));
        }
        Ok(stream)
    }

    async fn recv_loop(self: &Arc<Self>) {
        let result = AssertUnwindSafe(self.recv_loop_inner()).catch_unwind().await;
        let _ = self.close();
        if let Err(payload) = result {
            errorln!("[BUG] {} {}", panic_message(&*payload), std::backtrace::Backtrace::force_capture());
        }
    }

    async fn recv_loop_inner(self: &Arc<Self>) -> io::Result<()> {
        let mut received_settings_from_client = false;

        loop {
            if self.is_closed() {
                return Err(err_closed_pipe());
            }
            let mut hdr: RawHeader = [0u8; HEADER_OVER_HEAD_SIZE];
            read_full(&self.conn, &mut hdr).await?;
            let sid = header_stream_id(&hdr);
            let len = header_length(&hdr);
            match header_cmd(&hdr) {
                CMD_PSH if len > 0 => self.recv_data_frame(sid, len).await?,
                CMD_SYN => {
                    if !self.is_client && !received_settings_from_client {
                        self.send_alert("client did not send its settings").await;
                        return Ok(());
                    }
                    self.accept_stream(sid);
                }
                CMD_SYNACK => {
                    let done = self.syn_done.lock().take();
                    if let Some(done) = done {
                        done();
                    }
                    if len > 0 {
                        self.recv_synack(sid, len).await?;
                    }
                }
                CMD_FIN => {
                    let stream = self.streams.write().remove(&sid);
                    if let Some(stream) = stream {
                        stream.close_locally();
                    }
                }
                CMD_WASTE if len > 0 => self.discard_body(len).await?,
                CMD_SETTINGS if len > 0 => {
                    if self.is_client {
                        self.discard_body(len).await?;
                    } else {
                        received_settings_from_client = true;
                        self.recv_client_settings(len).await?;
                    }
                }
                CMD_ALERT if len > 0 => {
                    let buffer = self.read_body(len).await?;
                    if self.is_client {
                        errorln!("[Alert from server] {}", String::from_utf8_lossy(&buffer));
                    }
                    let _ = pool::put(buffer);
                    return Ok(());
                }
                CMD_UPDATE_PADDING_SCHEME if len > 0 => self.recv_padding_scheme_update(len).await?,
                CMD_HEART_REQUEST => {
                    self.write_control_frame(new_frame(CMD_HEART_RESPONSE, sid)).await?;
                }
                CMD_SERVER_SETTINGS if len > 0 => self.recv_server_settings(len).await?,
                _ => {}
            }
        }
    }

    /// Reads a frame body of `len` bytes into a pooled buffer, releasing it again on failure.
    async fn read_body(&self, len: u16) -> io::Result<Vec<u8>> {
        let mut buffer = pool::get(usize::from(len));
        if let Err(err) = read_full(&self.conn, &mut buffer).await {
            let _ = pool::put(buffer);
            return Err(err);
        }
        Ok(buffer)
    }

    /// Reads a frame body and returns its buffer to the pool.
    async fn discard_body(&self, len: u16) -> io::Result<()> {
        let buffer = self.read_body(len).await?;
        let _ = pool::put(buffer);
        Ok(())
    }

    /// `CMD_PSH`: hands the payload to the frame's stream, or drops it when the stream is gone.
    async fn recv_data_frame(&self, sid: u32, len: u16) -> io::Result<()> {
        let buffer = self.read_body(len).await?;
        let stream = self.streams.read().get(&sid).cloned();
        let Some(stream) = stream else {
            let _ = pool::put(buffer);
            return Ok(());
        };
        let data = Bytes::from(buffer);
        let _ = stream.pipe_w().write_owned(data.clone()).await;
        if let Ok(reclaimed) = data.try_into_mut() {
            let _ = pool::put(reclaimed.into());
        }
        Ok(())
    }

    /// `CMD_SYN`: registers the stream and hands it to the accept hook.
    fn accept_stream(self: &Arc<Self>, sid: u32) {
        let stream = {
            let mut streams = self.streams.write();
            if let std::collections::hash_map::Entry::Vacant(e) = streams.entry(sid) {
                let stream = Arc::new(new_stream(sid, Arc::clone(self)));
                e.insert(Arc::clone(&stream));
                Some(stream)
            } else {
                None
            }
        };
        if let Some(stream) = stream {
            let on_new_stream = self.on_new_stream.clone();
            tokio::spawn(async move {
                match on_new_stream {
                    Some(on_new_stream) => on_new_stream(stream),
                    None => {
                        let _ = stream.close_with_error(err_closed_pipe()).await;
                    }
                }
            });
        }
    }

    /// `CMD_SYNACK`: a payload closes the frame's stream with the error it carries.
    async fn recv_synack(&self, sid: u32, len: u16) -> io::Result<()> {
        let buffer = self.read_body(len).await?;
        let stream = self.streams.read().get(&sid).cloned();
        if let Some(stream) = stream {
            let err = io::Error::other(format!("remote: {}", String::from_utf8_lossy(&buffer)));
            let _ = stream.close_with_error(err).await;
        }
        let _ = pool::put(buffer);
        Ok(())
    }

    /// `CMD_ALERT` carrying `msg` to the peer.
    async fn send_alert(&self, msg: &str) {
        let mut f = new_frame(CMD_ALERT, 0);
        f.data = msg.as_bytes().to_vec();
        let _ = self.write_control_frame(f).await;
    }

    /// `CMD_SETTINGS` from a client: answers with the padding scheme and the server settings,
    /// because the client waits for the scheme before it follows one.
    async fn recv_client_settings(&self, len: u16) -> io::Result<()> {
        let buffer = self.read_body(len).await?;
        let m = string_map_from_bytes(&buffer);
        let padding_f = self.padding_factory();
        if m.get("padding-md5").map(String::as_str) != Some(padding_f.md5.as_str()) {
            let mut f = new_frame(CMD_UPDATE_PADDING_SCHEME, 0);
            f.data.clone_from(&padding_f.raw_scheme);
            if let Err(err) = self.write_control_frame(f).await {
                let _ = pool::put(buffer);
                return Err(err);
            }
        }
        if let Ok(v) = m.get("v").map_or("", String::as_str).parse::<i32>() {
            if v >= 2 {
                self.peer_version.store(u8::try_from(v & 0xff).unwrap_or_default(), Ordering::SeqCst);
                let mut settings = StringMap::new();
                settings.insert("v".to_owned(), "2".to_owned());
                let mut f = new_frame(CMD_SERVER_SETTINGS, 0);
                f.data = to_bytes(&settings);
                if let Err(err) = self.write_control_frame(f).await {
                    let _ = pool::put(buffer);
                    return Err(err);
                }
            }
        }
        let _ = pool::put(buffer);
        Ok(())
    }

    /// `CMD_UPDATE_PADDING_SCHEME`: a client follows the scheme it can apply and logs the one it
    /// cannot; a server ignores the frame.
    async fn recv_padding_scheme_update(&self, len: u16) -> io::Result<()> {
        let mut raw_scheme = vec![0u8; usize::from(len)];
        read_full(&self.conn, &mut raw_scheme).await?;
        if self.is_client {
            if update_padding_scheme(&raw_scheme, &self.padding) {
                debugln!("[Update padding succeed] {}\n", hex::encode(Md5::digest(&raw_scheme)));
            } else {
                warnln!("[Update padding failed] {}\n", hex::encode(Md5::digest(&raw_scheme)));
            }
        }
        Ok(())
    }

    /// `CMD_SERVER_SETTINGS`: records the server's protocol version.
    async fn recv_server_settings(&self, len: u16) -> io::Result<()> {
        let buffer = self.read_body(len).await?;
        if self.is_client {
            let m = string_map_from_bytes(&buffer);
            if let Ok(v) = m.get("v").map_or("", String::as_str).parse::<i32>() {
                self.peer_version.store(u8::try_from(v & 0xff).unwrap_or_default(), Ordering::SeqCst);
            }
        }
        let _ = pool::put(buffer);
        Ok(())
    }

    pub(crate) async fn stream_closed(&self, sid: u32) -> io::Result<()> {
        if self.is_closed() {
            return Err(err_closed_pipe());
        }
        let err = self.write_control_frame(new_frame(CMD_FIN, sid)).await.err();
        let _ = self.streams.write().remove(&sid);
        match err {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    pub(crate) async fn write_data_frame(&self, sid: u32, data: &[u8]) -> io::Result<usize> {
        let data_len = data.len();
        if data_len == 0 {
            return Ok(0);
        }
        if data_len <= MAX_FRAME_DATA_LEN {
            let mut buffer = new_size(frame_buffer_size(data_len + HEADER_OVER_HEAD_SIZE)?);
            let _ = buffer.write_byte(CMD_PSH);
            buffer.extend(4).copy_from_slice(&sid.to_be_bytes());
            buffer.extend(2).copy_from_slice(&wire_len16(data_len).to_be_bytes());
            let _ = buffer.write_bytes(data);
            let result = self.write_conn(buffer.bytes()).await;
            buffer.release();
            result?;
            return Ok(data_len);
        }

        let frame_count = data_len.div_ceil(MAX_FRAME_DATA_LEN);
        let mut buffer = new_size(frame_buffer_size(data_len + frame_count * HEADER_OVER_HEAD_SIZE)?);

        let mut rest = data;
        while !rest.is_empty() {
            let (part, tail) = rest.split_at(rest.len().min(MAX_FRAME_DATA_LEN));
            let _ = buffer.write_byte(CMD_PSH);
            buffer.extend(4).copy_from_slice(&sid.to_be_bytes());
            buffer.extend(2).copy_from_slice(&wire_len16(part.len()).to_be_bytes());
            let _ = buffer.write_bytes(part);
            rest = tail;
        }

        let result = self.write_conn(buffer.bytes()).await;
        buffer.release();
        result?;
        Ok(data_len)
    }

    /// The 5 s write deadline on the session conn for a control frame, set before the conn lock
    /// is taken, so a data frame write already holding the lock is bounded too.
    pub(crate) fn arm_control_write_deadline(&self) {
        let _ = self.conn.set_write_deadline(Some(Instant::now() + Duration::from_secs(5)));
    }

    pub(crate) async fn write_control_frame(&self, frame: Frame) -> io::Result<usize> {
        let data_len = frame.data.len();

        let mut buffer = new_size(frame_buffer_size(data_len + HEADER_OVER_HEAD_SIZE)?);
        let _ = buffer.write_byte(frame.cmd);
        buffer.extend(4).copy_from_slice(&frame.sid.to_be_bytes());
        buffer.extend(2).copy_from_slice(&wire_len16(data_len).to_be_bytes());
        let _ = buffer.write_bytes(&frame.data);

        self.arm_control_write_deadline();

        let result = self.write_conn(buffer.bytes()).await;
        buffer.release();
        if let Err(err) = result {
            let _ = self.close();
            return Err(err);
        }

        let _ = self.conn.set_write_deadline(None);

        Ok(data_len)
    }

    async fn write_conn(&self, b: &[u8]) -> io::Result<usize> {
        let _guard = self.conn_lock.lock().await;

        if self.buffering.load(Ordering::SeqCst) {
            self.buffer.lock().extend_from_slice(b);
            return Ok(b.len());
        }

        let mut payload: Cow<'_, [u8]> = {
            let mut combined = std::mem::take(&mut *self.buffer.lock());
            if combined.is_empty() {
                Cow::Borrowed(b)
            } else {
                combined.extend_from_slice(b);
                Cow::Owned(combined)
            }
        };
        let mut start = 0usize;
        let mut n = 0usize;

        if self.send_padding.load(Ordering::SeqCst) {
            let pkt = self.pkt_counter.fetch_add(1, Ordering::SeqCst) + 1;
            let padding_f = self.padding_factory();
            if pkt < padding_f.stop {
                for l in padding_f.generate_record_payload_sizes(pkt) {
                    let remain_payload_len = payload.len() - start;
                    if l == CHECK_MARK {
                        if remain_payload_len == 0 {
                            break;
                        }
                        continue;
                    }
                    let Ok(l) = usize::try_from(l) else {
                        continue;
                    };
                    if remain_payload_len > l {
                        let (_, rest) = payload.split_at(start);
                        let (part, _) = rest.split_at(l);
                        self.conn.write_all(part).await?;
                        n += l;
                        start += l;
                    } else if remain_payload_len > 0 {
                        if let Some(padding_len) = l
                            .checked_sub(remain_payload_len)
                            .and_then(|len| len.checked_sub(HEADER_OVER_HEAD_SIZE))
                            .filter(|len| *len > 0)
                        {
                            let padding = waste_frame(padding_len);
                            let mut combined = Vec::with_capacity(remain_payload_len + padding.len());
                            let (_, tail) = payload.split_at(start);
                            combined.extend_from_slice(tail);
                            combined.extend_from_slice(&padding);
                            payload = Cow::Owned(combined);
                            start = 0;
                        }
                        let (_, tail) = payload.split_at(start);
                        self.conn.write_all(tail).await?;
                        n += remain_payload_len;
                        start = payload.len();
                    } else {
                        let padding = waste_frame(l);
                        self.conn.write_all(&padding).await?;
                    }
                }
                if payload.len() == start {
                    self.conn.clone().flush().await?;
                    return Ok(n);
                }
                let remaining = payload.len() - start;
                let (_, tail) = payload.split_at(start);
                self.conn.write_all(tail).await?;
                self.conn.clone().flush().await?;
                return Ok(n + remaining);
            }
            self.send_padding.store(false, Ordering::SeqCst);
        }

        let written = payload.len() - start;
        let (_, tail) = payload.split_at(start);
        self.conn.write_all(tail).await?;
        self.conn.clone().flush().await?;
        Ok(written)
    }
}

/// the rendering of the value recovered from a panic.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_owned()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        format!("{payload:?}")
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

    use super::*;
    use crate::padding::padding::new_padding_factory;
    use murmur_std_compat::net::{Addr, Conn as NetConn, TcpAddr};

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

    fn padding_pointer(scheme: &[u8]) -> Arc<ArcSwapOption<PaddingFactory>> {
        let factory = new_padding_factory(scheme).expect("test scheme parses");
        let pointer = ArcSwapOption::default();
        pointer.store(Some(Arc::new(factory)));
        Arc::new(pointer)
    }

    /// `DEFAULT_PADDING_SCHEME` holds the padding scheme byte for byte; its MD5 is
    /// `75cff2ad89aadf5e257059ee571ebe11` for the 137-byte scheme.
    #[test]
    fn default_padding_scheme_md5_matches_reference() {
        assert_eq!(crate::padding::padding::DEFAULT_PADDING_SCHEME.len(), 137);
        assert_eq!(
            hex::encode(Md5::digest(crate::padding::padding::DEFAULT_PADDING_SCHEME)),
            "75cff2ad89aadf5e257059ee571ebe11"
        );
    }

    /// The open-stream control frame (`cmdSYN`, stream 1) with a `stop=0` padding
    /// scheme, which disables padding on the very first record: the record is `01 00000001 0000`
    /// (cmd, big-endian stream id, big-endian zero length) with no padding bytes at all.
    #[tokio::test]
    async fn open_stream_syn_frame_matches_header_layout() {
        let (client, mut server) = tokio::io::duplex(256);
        let session =
            Arc::new(Session::client(Box::new(DuplexConn(client)), padding_pointer(b"stop=0"), "meta".to_owned()));

        session.open_stream().await.unwrap();

        let mut got = [0u8; 7];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(got, [0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00]);
    }

    /// The same `OpenStream` SYN frame with a `stop=2\n1=20-20` scheme, whose fixed 20-byte
    /// target on the very first record forces `writeConn` to inject a padding (`cmdWaste`)
    /// frame: the 7-byte SYN header is followed by a 13-byte waste frame (`00 00000000 0006` plus
    /// 6 zero bytes), 20 bytes in total.
    #[tokio::test]
    async fn open_stream_syn_frame_gets_padded_to_fixed_target() {
        let (client, mut server) = tokio::io::duplex(256);
        let session = Arc::new(Session::client(
            Box::new(DuplexConn(client)),
            padding_pointer(b"stop=2\n1=20-20"),
            "meta".to_owned(),
        ));

        session.open_stream().await.unwrap();

        let mut got = [0u8; 20];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(hex::encode(got), "0100000001000000000000000006000000000000");
    }

    /// The stream-closed control frame (`cmdFIN`, the stream id) on a server
    /// session, whose padding send starts `false`: the frame reaches the wire unpadded, so this
    /// pins the raw `cmd, sid, length` header layout independent of the padding scheme.
    #[tokio::test]
    async fn server_session_fin_frame_is_unpadded_header_only() {
        let (client, mut server) = tokio::io::duplex(256);
        let session = Arc::new(Session::server(Box::new(DuplexConn(client)), None, padding_pointer(b"stop=0")));

        session.stream_closed(7).await.unwrap();

        let mut got = [0u8; 7];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(got, [0x03, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00]);
    }
}
