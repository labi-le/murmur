use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf as _, BufMut as _, BytesMut};
use rand::{Rng as _, RngCore as _};
use subtle::ConstantTimeEq as _;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::tools;
use murmur_common_net::io::Stream;
use murmur_common_pool as pool;
use murmur_ntp as ntp;

use super::base::Base;
use super::obfs::{
    register, AuthData, ErrTLS12TicketAuthHMACError, ErrTLS12TicketAuthIncorrectMagicNumber,
    ErrTLS12TicketAuthTooShortData, Obfs, ObfsList,
};

/// `init()`, called from the registry's initializer instead of at package load.
pub(crate) fn init(list: &mut ObfsList) {
    register(list, "tls1.2_ticket_auth", new_tls12_ticket, 5);
    register(list, "tls1.2_ticket_fastauth", new_tls12_ticket, 5);
}
#[derive(Clone, Debug)]
pub(crate) struct Tls12Ticket {
    pub(crate) base: Base,
    pub(crate) auth_data: AuthData,
}

pub(crate) fn new_tls12_ticket(b: &Base) -> Box<dyn Obfs> {
    let mut auth_data = AuthData::default();
    rand::rng().fill_bytes(&mut auth_data.client_id);
    Box::new(Tls12Ticket { base: b.clone(), auth_data })
}
pub(crate) struct Tls12TicketConn {
    conn: Box<dyn Stream>,
    ticket: Tls12Ticket,
    handshake_status: i32,
    decoded: BytesMut,
    under_decoded: BytesMut,
    send_buf: BytesMut,
    /// A write is reported done only once its block is fully accepted, so partially accepted
    /// blocks still go out in the order they were staged.
    queue: VecDeque<BytesMut>,
    queue_written: usize,
    /// A connector write failure seen while draining, kept for the caller `Write` that staged it.
    queue_error: Option<io::Error>,
    /// Set while a caller `Write` waits for its staged block, so it stages its bytes only once.
    caller_pending: bool,
    /// the return value of the caller `Write` whose block is in the queue.
    caller_result: usize,
}

/// The low 32 bits of `value`, the width of the protocol's timestamp field.
fn low_u32(value: i64) -> u32 {
    let [b0, b1, b2, b3, ..] = value.to_le_bytes();
    u32::from_le_bytes([b0, b1, b2, b3])
}

/// The low 16 bits of `value`, the width of the protocol's length fields.
fn low_u16(value: usize) -> u16 {
    let [b0, b1, ..] = value.to_le_bytes();
    u16::from_le_bytes([b0, b1])
}

impl Tls12Ticket {
    fn pack_auth_data(&self, buf: &mut BytesMut) {
        buf.put_slice(&low_u32(ntp::time::now().timestamp()).to_be_bytes());
        tools::buf_pool::append_rand_bytes(buf, 18);
        let start = buf.len() - 22;
        let mac = self.hmac_sha1(buf.get(start..).unwrap_or_default());
        buf.put_slice(&mac);
    }

    /// HMAC-SHA1 over the key and client id, truncated to its wire length.
    fn hmac_sha1(&self, data: &[u8]) -> Vec<u8> {
        let key_length = self.base.key.len();
        let mut key = pool::get(key_length + 32);
        let (base_key, client_id) = key.split_at_mut(key_length);
        base_key.copy_from_slice(&self.base.key);
        client_id.copy_from_slice(&self.auth_data.client_id);
        let mut sha1_data = tools::crypto::hmac_sha1(&key, data);
        pool::put(key).ok();
        sha1_data.truncate(tools::crypto::HMAC_SHA1_LEN);
        sha1_data
    }

    fn get_host(&self) -> String {
        let mut host = self.base.param.clone();
        if host.is_empty() {
            host.clone_from(&self.base.host);
        }
        if host.as_bytes().last().is_some_and(u8::is_ascii_digit) {
            host = String::new();
        }
        let hosts: Vec<&str> = host.split(',').collect();
        let host = hosts.get(rand::rng().random_range(0..hosts.len())).copied().unwrap_or_default();
        host.to_owned()
    }
}

impl Tls12TicketConn {
    /// Packs the ticket buffer; the host parameter is unused.
    fn pack_ticket_buf(buf: &mut BytesMut, _u: &str) {
        let length: usize = 16 * (rand::rng().random_range(0..17) + 8);
        buf.put_slice(&[0, 0x23]);
        buf.put_slice(&low_u16(length).to_be_bytes());
        tools::buf_pool::append_rand_bytes(buf, length);
    }

    /// `Write`'s branches that produce a block for the connector, paired with the count `Write`
    /// returns for them.
    fn build_write(&mut self, b: &[u8]) -> (Option<BytesMut>, usize) {
        let length = b.len();
        if self.handshake_status == 8 {
            let mut buf = pool::get_buffer();
            let mut rest = b;
            while rest.len() > 2048 {
                let mut size: usize = rand::rng().random_range(0..4096) + 100;
                if rest.len() < size {
                    size = rest.len();
                }
                let (chunk, tail) = rest.split_at(size);
                pack_data(&mut buf, chunk);
                rest = tail;
            }
            if !rest.is_empty() {
                pack_data(&mut buf, rest);
            }
            return (Some(buf), length);
        }

        if !b.is_empty() {
            pack_data(&mut self.send_buf, b);
        }

        if self.handshake_status == 0 {
            self.handshake_status = 1;

            let mut data = pool::get_buffer();

            data.put_slice(&[3, 3]);
            self.ticket.pack_auth_data(&mut data);
            data.put_u8(0x20);
            data.put_slice(&self.ticket.auth_data.client_id);
            data.put_slice(&[
                0x00, 0x1c, 0xc0, 0x2b, 0xc0, 0x2f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0x14, 0xcc, 0x13, 0xc0, 0x0a, 0xc0,
                0x14, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x9c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0x0a,
            ]);
            data.put_slice(&[0x1, 0x0]);

            let mut ext = pool::get_buffer();

            let host = self.ticket.get_host();
            ext.put_slice(&[0xff, 0x01, 0x00, 0x01, 0x00]);
            pack_sni_data(&mut ext, &host);
            ext.put_slice(&[0, 0x17, 0, 0]);
            Self::pack_ticket_buf(&mut ext, &host);
            ext.put_slice(&[
                0x00, 0x0d, 0x00, 0x16, 0x00, 0x14, 0x06, 0x01, 0x06, 0x03, 0x05, 0x01, 0x05, 0x03, 0x04, 0x01, 0x04,
                0x03, 0x03, 0x01, 0x03, 0x03, 0x02, 0x01, 0x02, 0x03,
            ]);
            ext.put_slice(&[0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00]);
            ext.put_slice(&[0x00, 0x12, 0x00, 0x00]);
            ext.put_slice(&[0x75, 0x50, 0x00, 0x00]);
            ext.put_slice(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]);
            ext.put_slice(&[0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x17, 0x00, 0x18]);

            data.put_slice(&low_u16(ext.len()).to_be_bytes());
            data.put_slice(&ext);
            pool::put_buffer(ext);

            let mut ret = pool::get_buffer();

            ret.put_slice(&[0x16, 3, 1]);
            ret.put_slice(&low_u16(data.len() + 4).to_be_bytes());
            ret.put_slice(&[1, 0]);
            ret.put_slice(&low_u16(data.len()).to_be_bytes());
            ret.put_slice(&data);
            pool::put_buffer(data);

            return (Some(ret), length);
        }
        if self.handshake_status == 1 && b.is_empty() {
            let mut buf = pool::get_buffer();

            buf.put_slice(&[0x14, 3, 3, 0, 1, 1, 0x16, 3, 3, 0, 0x20]);
            tools::buf_pool::append_rand_bytes(&mut buf, 22);
            let mac = self.ticket.hmac_sha1(&buf);
            buf.put_slice(&mac);
            buf.put_slice(&self.send_buf);
            self.send_buf.clear();

            self.handshake_status = 8;

            return (Some(buf), 0);
        }
        (None, length)
    }

    /// Writes a chunk; `from_read` marks the empty write a read makes, whose result it discards.
    fn poll_write_body(&mut self, cx: &mut Context<'_>, b: &[u8], from_read: bool) -> Poll<io::Result<usize>> {
        if from_read {
            if let Some(block) = self.build_write(b).0 {
                self.queue.push_back(block);
            }
            return self.drain(cx).map(|done| done.map(|()| b.len()));
        }

        if let Some(err) = self.queue_error.take() {
            self.caller_pending = false;
            return Poll::Ready(Err(err));
        }

        if !self.caller_pending {
            let (block, result) = self.build_write(b);
            self.caller_result = result;
            self.caller_pending = true;
            let Some(block) = block else {
                self.caller_pending = false;
                return Poll::Ready(Ok(b.len()));
            };
            self.queue.push_back(block);
        }

        match self.drain(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => {
                self.caller_pending = false;
                Poll::Ready(Err(err))
            }
            Poll::Ready(Ok(())) => {
                let result = self.caller_result;
                self.caller_pending = false;
                Poll::Ready(Ok(result))
            }
        }
    }

    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            if self.queue.is_empty() {
                return Poll::Ready(Ok(()));
            }
            if self.queue_written >= self.queue.front().map_or(0, BytesMut::len) {
                if let Some(done) = self.queue.pop_front() {
                    pool::put_buffer(done);
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

impl Obfs for Tls12Ticket {
    fn stream_conn(&self, c: Box<dyn Stream>) -> Box<dyn Stream> {
        Box::new(Tls12TicketConn {
            conn: c,
            ticket: self.clone(),
            handshake_status: 0,
            decoded: BytesMut::new(),
            under_decoded: BytesMut::new(),
            send_buf: BytesMut::new(),
            queue: VecDeque::new(),
            queue_written: 0,
            queue_error: None,
            caller_pending: false,
            caller_result: 0,
        })
    }
}

impl AsyncRead for Tls12TicketConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.decoded.is_empty() {
                let n = buf.remaining().min(this.decoded.len());
                buf.put_slice(this.decoded.get(..n).unwrap_or_default());
                this.decoded.advance(n);
                return Poll::Ready(Ok(()));
            }

            if !this.queue.is_empty() {
                match this.drain(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(err)) => {
                        if this.caller_pending {
                            this.queue_error = Some(err);
                        }
                    }
                    Poll::Ready(Ok(())) => {}
                }
                continue;
            }

            let mut scratch = pool::get(pool::RELAY_BUFFER_SIZE);
            let poll = {
                let mut read_buf = ReadBuf::new(&mut scratch);
                match Pin::new(&mut *this.conn).poll_read(cx, &mut read_buf) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                    Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
                }
            };
            let n = match poll {
                Poll::Pending => {
                    pool::put(scratch).ok();
                    return Poll::Pending;
                }
                Poll::Ready(Err(err)) => {
                    pool::put(scratch).ok();
                    return Poll::Ready(Err(err));
                }
                Poll::Ready(Ok(n)) => n,
            };
            if n == 0 {
                pool::put(scratch).ok();
                return Poll::Ready(Ok(()));
            }

            if this.handshake_status == 8 {
                this.under_decoded.put_slice(scratch.get(..n).unwrap_or_default());
                while this.under_decoded.len() > 5 {
                    if !this.under_decoded.starts_with(&[0x17, 3, 3]) {
                        this.under_decoded.clear();
                        pool::put(scratch).ok();
                        return Poll::Ready(Err(io::Error::other(ErrTLS12TicketAuthIncorrectMagicNumber)));
                    }
                    let (_, record_head) = this.under_decoded.split_at(3);
                    let [high, low, ..] = record_head else {
                        break;
                    };
                    let size = usize::from(u16::from_be_bytes([*high, *low]));
                    if this.under_decoded.len() < 5 + size {
                        break;
                    }
                    this.under_decoded.advance(5);
                    let record = this.under_decoded.split_to(size);
                    this.decoded.put_slice(&record);
                }
                pool::put(scratch).ok();
                continue;
            }

            if n < 11 + 32 + 1 + 32 {
                pool::put(scratch).ok();
                return Poll::Ready(Err(io::Error::other(ErrTLS12TicketAuthTooShortData)));
            }

            let head_mac = scratch.get(33..43).unwrap_or_default();
            let head_data = scratch.get(11..33).unwrap_or_default();
            let tail_mac = scratch.get(n - 10..n).unwrap_or_default();
            let body = scratch.get(..n - 10).unwrap_or_default();
            let hmac_ok = constant_time_eq(head_mac, &this.ticket.hmac_sha1(head_data))
                && constant_time_eq(tail_mac, &this.ticket.hmac_sha1(body));
            if !hmac_ok {
                pool::put(scratch).ok();
                return Poll::Ready(Err(io::Error::other(ErrTLS12TicketAuthHMACError)));
            }

            pool::put(scratch).ok();
            match this.poll_write_body(cx, &[], true) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(_) => {}
            }
        }
    }
}

impl AsyncWrite for Tls12TicketConn {
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

impl Stream for Tls12TicketConn {
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

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

fn pack_data(buf: &mut BytesMut, data: &[u8]) {
    buf.put_slice(&[0x17, 3, 3]);
    buf.put_slice(&low_u16(data.len()).to_be_bytes());
    buf.put_slice(data);
}

fn pack_sni_data(buf: &mut BytesMut, u: &str) {
    let len = low_u16(u.len());
    buf.put_slice(&[0, 0]);
    buf.put_slice(&len.wrapping_add(5).to_be_bytes());
    buf.put_slice(&len.wrapping_add(3).to_be_bytes());
    buf.put_u8(0);
    buf.put_slice(&len.to_be_bytes());
    buf.put_slice(u.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A TLS handshake record head (`0x17 0x03 0x03`) and the big-endian payload length.
    #[test]
    fn pack_data_writes_handshake_head() {
        let mut buf = BytesMut::new();
        pack_data(&mut buf, b"hello world");
        assert_eq!(hex::encode(&buf), "170303000b68656c6c6f20776f726c64");
    }

    /// The SNI extension nests the host length inside two longer prefixes.
    #[test]
    fn pack_sni_data_nests_host_length() {
        let mut buf = BytesMut::new();
        pack_sni_data(&mut buf, "example.com");
        assert_eq!(hex::encode(&buf), "00000010000e00000b6578616d706c652e636f6d");
    }

    /// The HMAC key is `key || clientID` before hashing.
    #[test]
    fn hmac_sha1_keys_with_key_then_client_id() {
        let ticket = Tls12Ticket {
            base: Base { key: b"0123456789abcdef".to_vec(), ..Default::default() },
            auth_data: AuthData { client_id: [0x42u8; 32] },
        };
        assert_eq!(hex::encode(ticket.hmac_sha1(b"hello world")), "d609b10a5348cf2ab529");
    }
}
