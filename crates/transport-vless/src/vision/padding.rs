use std::io;

use rand::Rng;

use murmur_common_net::sing::{new_read_wait_options, UpstreamNode};
use murmur_compat::sing_buf::{new_size, Buffer};
use murmur_log::debugln;

use super::conn::Conn;
use super::filter::{rindex_of, TLS_APPLICATION_DATA_START};

pub(crate) const UUID_SIZE: usize = 16;

pub const PADDING_HEADER_LEN: usize = UUID_SIZE + 1 + 2 + 2;

pub(crate) const COMMAND_PADDING_CONTINUE: u8 = 0x00;
pub(crate) const COMMAND_PADDING_END: u8 = 0x01;
pub(crate) const COMMAND_PADDING_DIRECT: u8 = 0x02;

pub(crate) const XRAY_BUF_SIZE: usize = 8192;

/// The empty node that reports nothing.
struct NilUpstreamNode;

impl UpstreamNode for NilUpstreamNode {}

fn short_buffer() -> io::Error {
    io::Error::new(io::ErrorKind::WriteZero, "short buffer")
}

fn eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "EOF")
}

fn unexpected_eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF")
}

/// The synchronous buffer-to-buffer read for an in-memory source.
pub(crate) fn read_full_from_buffer(dst: &mut Buffer, src: &mut Buffer, size: usize) -> io::Result<()> {
    if dst.free_len() < size {
        return Err(short_buffer());
    }
    let n = size.min(src.len());
    {
        // `free_len() >= size >= n` and `n <= src.len()` keep both halves in range.
        let (dst_head, _) = dst.free_bytes().split_at_mut(n);
        let (src_head, _) = src.bytes().split_at(n);
        dst_head.copy_from_slice(src_head);
    }
    dst.truncate(dst.len() + n);
    src.advance(n);
    if n < size {
        return Err(if n == 0 { eof() } else { unexpected_eof() });
    }
    Ok(())
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "both lengths are 16-bit wire fields: `padding_len` is capped at 900 + 500 \
              and `content_len` is one sing buffer of at most 32 KiB"
)]
pub(crate) fn apply_padding(
    buffer: &mut Buffer,
    command: u8,
    user_uuid: &mut Option<[u8; UUID_SIZE]>,
    padding_tls: bool,
) {
    let content_len = buffer.len();
    let padding_len = if content_len < 900 {
        if padding_tls {
            rand::rng().random_range(0..500) + 900 - content_len
        } else {
            rand::rng().random_range(0..256)
        }
    } else {
        0
    };

    buffer.extend_header(2).copy_from_slice(&(padding_len as u16).to_be_bytes());
    buffer.extend_header(2).copy_from_slice(&(content_len as u16).to_be_bytes());
    buffer.extend_header(1).copy_from_slice(&[command]);
    if let Some(uuid) = user_uuid.take() {
        buffer.extend_header(UUID_SIZE).copy_from_slice(&uuid);
    }

    buffer.extend(padding_len);
    debugln!("XTLS Vision write padding: command={}, payloadLen={}, paddingLen={}", command, content_len, padding_len);
}

fn new_split_buffer(content_len: usize, front: usize, rear: usize) -> io::Result<Buffer> {
    let size = content_len
        .checked_add(front)
        .and_then(|size| size.checked_add(rear))
        .and_then(|size| i32::try_from(size).ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "Vision split buffer headroom overflow"))?;
    let mut buffer = new_size(size);
    buffer.resize(front, 0);
    Ok(buffer)
}

impl Conn {
    /// Splits `buffer` into wire-sized frames, filling the caller's queue so its allocation is
    /// reused across frames.
    pub(crate) fn reshape_buffer(&self, mut buffer: Buffer, buffers: &mut Vec<Buffer>) -> io::Result<()> {
        const BUFFER_LIMIT: usize = XRAY_BUF_SIZE - PADDING_HEADER_LEN;
        buffers.clear();
        if buffer.len() < BUFFER_LIMIT {
            buffers.push(buffer);
            return Ok(());
        }
        let options = new_read_wait_options(&NilUpstreamNode, self);
        while buffer.len() >= BUFFER_LIMIT {
            let found = usize::try_from(rindex_of(buffer.bytes(), &TLS_APPLICATION_DATA_START)).unwrap_or(0);
            let cut_at = if (21..=BUFFER_LIMIT).contains(&found) { found } else { XRAY_BUF_SIZE / 2 };
            let result =
                new_split_buffer(cut_at, options.front_headroom, options.rear_headroom).and_then(|mut segment| {
                    if let Err(err) = read_full_from_buffer(&mut segment, &mut buffer, cut_at) {
                        segment.release();
                        return Err(err);
                    }
                    Ok(segment)
                });
            match result {
                Ok(segment) => buffers.push(segment),
                Err(err) => {
                    buffer.release();
                    for segment in buffers.iter_mut() {
                        segment.release();
                    }
                    buffers.clear();
                    return Err(err);
                }
            }
        }
        buffers.push(buffer);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_buffer_rejects_unrepresentable_headroom() {
        for (content, front, rear) in [(1, usize::MAX, 0), (1, 0, usize::MAX), (1, i32::MAX as usize, 0)] {
            assert_eq!(new_split_buffer(content, front, rear).unwrap_err().kind(), io::ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn split_buffer_keeps_transport_room_after_tls_padding() {
        for content in [21, 899, 900, 4096, 8171] {
            let front = PADDING_HEADER_LEN + 137;
            let rear = 1400 + 263;
            let mut buffer = new_split_buffer(content, front, rear).unwrap();
            buffer.write_bytes(&vec![0x41; content]).unwrap();
            let mut uuid = Some([0x11; UUID_SIZE]);
            apply_padding(&mut buffer, COMMAND_PADDING_CONTINUE, &mut uuid, true);
            assert_eq!(buffer.start(), 137);
            assert!(buffer.free_len() >= 263);
            assert_eq!(&buffer.bytes()[PADDING_HEADER_LEN..PADDING_HEADER_LEN + content], &vec![0x41; content]);
            buffer.release();
        }
    }
}
