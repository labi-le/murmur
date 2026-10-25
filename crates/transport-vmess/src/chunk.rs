//! `Conn` (see `conn.rs`) drives multi-`await` reads and writes through a shared underlying conn,
//! so the chunked reader and writer take the live conn as an explicit parameter per call.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use murmur_common_pool as pool;

pub(crate) const LEN_SIZE: usize = 2;
pub(crate) const CHUNK_SIZE: usize = 1 << 14;
pub(crate) const MAX_SIZE: usize = 17 * 1024;

fn err_buffer_too_large() -> io::Error {
    io::Error::other("buffer is larger than standard")
}

#[derive(Default)]
pub(crate) struct ChunkReader {
    buf: Option<Vec<u8>>,
    offset: usize,
}

impl ChunkReader {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) async fn read<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        reader: &mut R,
        b: &mut [u8],
    ) -> io::Result<usize> {
        if let Some(buf) = self.buf.take() {
            let (_, remaining) = buf.split_at(self.offset);
            let n = copy_bytes(b, remaining);
            self.offset += n;
            if self.offset == buf.len() {
                let _ = pool::put(buf);
            } else {
                self.buf = Some(buf);
            }
            return Ok(n);
        }

        let mut size_buf = [0u8; LEN_SIZE];
        reader.read_exact(&mut size_buf).await?;

        let size = u16::from_be_bytes(size_buf) as usize;
        if size > MAX_SIZE {
            return Err(err_buffer_too_large());
        }

        if let Some(dst) = b.get_mut(..size) {
            reader.read_exact(dst).await?;
            return Ok(size);
        }

        let mut buf = pool::get(size);
        if let Err(err) = reader.read_exact(&mut buf).await {
            let _ = pool::put(buf);
            return Err(err);
        }
        let n = copy_bytes(b, &buf);
        self.offset = n;
        self.buf = Some(buf);
        Ok(n)
    }
}

fn copy_bytes(dst: &mut [u8], src: &[u8]) -> usize {
    let n = dst.len().min(src.len());
    let (dst, _) = dst.split_at_mut(n);
    let (src, _) = src.split_at(n);
    dst.copy_from_slice(src);
    n
}

pub(crate) struct ChunkWriter;

impl ChunkWriter {
    pub(crate) const fn new() -> Self {
        Self
    }

    pub(crate) async fn write<W: AsyncWrite + Unpin + ?Sized>(&self, writer: &mut W, b: &[u8]) -> io::Result<usize> {
        let mut n = 0usize;
        let mut length = b.len();
        loop {
            if length == 0 {
                break;
            }
            let read_len = length.min(CHUNK_SIZE);
            let (_, remaining) = b.split_at(n);
            let (chunk, _) = remaining.split_at(read_len);

            let mut frame = Vec::with_capacity(LEN_SIZE + read_len);
            #[expect(
                clippy::cast_possible_truncation,
                reason = "`read_len` is bounded by `CHUNK_SIZE` and the chunk length is the 16-bit wire field"
            )]
            frame.extend_from_slice(&(read_len as u16).to_be_bytes());
            frame.extend_from_slice(chunk);

            writer.write_all(&frame).await?;
            writer.flush().await?;
            n += read_len;
            length -= read_len;
        }
        Ok(n)
    }
}
