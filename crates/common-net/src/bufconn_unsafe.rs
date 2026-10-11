use super::bufconn::BufferedConn;

/// The read buffer grows geometrically to avoid repeated allocations. A shift of a full word wraps
/// to zero, which `checked_shl` keeps.
fn new_read_buffer(size: usize) -> Vec<u8> {
    let bits = usize::BITS - size.saturating_sub(1).leading_zeros();
    let mut new_size = 1usize.checked_shl(bits).unwrap_or(0);
    if new_size > usize::MAX >> 1 {
        new_size = size;
    }
    vec![0u8; new_size]
}

impl BufferedConn {
    /// Grows the reader's buffer to at least `size` bytes.
    #[expect(
        clippy::expect_used,
        reason = "the reader is dropped only by `read_cached`, and nothing calls this method after that"
    )]
    pub fn grow(&mut self, size: usize) {
        let reader = self.r.as_mut().expect("the reader is dropped only by ReadCached");
        if size <= reader.buf.len() {
            return;
        }

        let mut new_buf = new_read_buffer(size);
        let buffered = {
            let src = reader.buf.get(reader.r..reader.w).unwrap_or_default();
            if let Some(dst) = new_buf.get_mut(..src.len()) {
                dst.copy_from_slice(src);
            }
            src.len()
        };
        reader.buf = new_buf;
        reader.r = 0;
        reader.w = buffered;
    }

    #[expect(
        clippy::expect_used,
        reason = "the reader is dropped only by `read_cached`, and nothing calls this method after that"
    )]
    pub fn append_data(&mut self, buf: &[u8]) -> bool {
        let needed = {
            let reader = self.r.as_ref().expect("the reader is dropped only by ReadCached");
            reader.w - reader.r + buf.len()
        };
        if needed > self.r.as_ref().expect("the reader is dropped only by ReadCached").buf.len() {
            self.grow(needed);
        }

        let reader = self.r.as_mut().expect("the reader is dropped only by ReadCached");
        let pos = reader.buf.len().cast_signed() - reader.w.cast_signed() - buf.len().cast_signed();
        if pos >= -reader.r.cast_signed() {
            if pos < 0 {
                // Slide the unread data to the beginning.
                reader.buf.copy_within(reader.r..reader.w, 0);
                reader.w -= reader.r;
                reader.r = 0;
            }

            let w = reader.w;
            if let Some(dst) = reader.buf.get_mut(w..w + buf.len()) {
                dst.copy_from_slice(buf);
            }
            reader.w += buf.len();
            return true;
        }
        false
    }

    #[expect(
        clippy::expect_used,
        reason = "the reader is dropped only by `read_cached`, and nothing calls this method after that"
    )]
    pub fn prepend_data(&mut self, buf: &[u8]) {
        if buf.is_empty() {
            return;
        }

        let reader = self.r.as_mut().expect("the reader is dropped only by ReadCached");
        if buf.len() <= reader.r {
            // Reuse the consumed space before the unread data.
            reader.r -= buf.len();
            if let Some(dst) = reader.buf.get_mut(reader.r..reader.r + buf.len()) {
                dst.copy_from_slice(buf);
            }
        } else {
            let buffered = reader.w - reader.r;
            let needed = buffered + buf.len();
            if needed > reader.buf.len() {
                // Build the final layout directly, in one pass over the unread data.
                let mut new_buf = new_read_buffer(needed);
                if let Some(dst) = new_buf.get_mut(..buf.len()) {
                    dst.copy_from_slice(buf);
                }
                if let Some(dst) = new_buf.get_mut(buf.len()..needed) {
                    dst.copy_from_slice(reader.buf.get(reader.r..reader.w).unwrap_or_default());
                }
                reader.buf = new_buf;
            } else {
                // Shift the unread data right to make room at the beginning.
                reader.buf.copy_within(reader.r..reader.w, buf.len());
                if let Some(dst) = reader.buf.get_mut(..buf.len()) {
                    dst.copy_from_slice(buf);
                }
            }
            reader.r = 0;
            reader.w = needed;
        }
        reader.last_byte = -1;
        reader.last_rune_size = -1;
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Cursor};
    use std::net::{IpAddr, Ipv4Addr};
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use async_trait::async_trait;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

    use crate::bufconn::{is_bufio_error, new_buffered_conn, BufioError};
    use crate::sing::{ExtendedConn, UpstreamNode};
    use murmur_compat::sing_buf::Buffer;
    use murmur_std_compat::net::{Addr, Conn, ExtendedConn as NetExtendedConn, TcpAddr};

    use super::*;

    /// A conn whose reads come from a byte slice.
    struct TestReaderConn {
        reader: Cursor<Vec<u8>>,
    }

    impl TestReaderConn {
        fn boxed(data: &[u8]) -> Box<dyn ExtendedConn> {
            Box::new(Self { reader: Cursor::new(data.to_vec()) })
        }
    }

    impl AsyncRead for TestReaderConn {
        fn poll_read(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            let position = this.reader.position() as usize;
            let remaining = &this.reader.get_ref()[position..];
            let n = core::cmp::min(buf.remaining(), remaining.len());
            buf.put_slice(&remaining[..n]);
            this.reader.set_position((position + n) as u64);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for TestReaderConn {
        fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    impl Conn for TestReaderConn {
        fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(TcpAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)))
        }

        fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
            Ok(Box::new(TcpAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)))
        }

        fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    impl NetExtendedConn for TestReaderConn {}

    impl UpstreamNode for TestReaderConn {}

    impl crate::io::Stream for TestReaderConn {
        fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
            Ok(std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        }
        fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
            Ok(std::net::SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
        }
        fn old_conn(&self) -> Option<&dyn Conn> {
            Some(self)
        }
    }

    impl crate::io::ExtendedStream for TestReaderConn {}

    #[async_trait]
    impl ExtendedConn for TestReaderConn {
        async fn read_buffer(&mut self, buffer: &mut Buffer) -> io::Result<()> {
            let n = AsyncReadExt::read(self, buffer.free_bytes()).await?;
            buffer.truncate(n);
            Ok(())
        }

        async fn write_buffer(&mut self, buffer: &mut Buffer) -> io::Result<()> {
            buffer.release();
            Ok(())
        }
    }

    fn reader_size(conn: &BufferedConn) -> usize {
        conn.reader().expect("the reader is present").size()
    }

    #[tokio::test]
    async fn buffered_conn_grow() {
        let data: Vec<u8> = (0u32..32 * 1024).map(|i| i as u8).collect();

        let mut conn = new_buffered_conn(TestReaderConn::boxed(&data));
        let reader = std::ptr::from_ref(conn.reader().expect("the reader is present"));

        let (first, err) = conn.peek(1).await;
        assert!(err.is_ok(), "peek(1) failed");
        assert_eq!(&data[..1], first);
        assert!(conn.buffered() < data.len());

        conn.grow(data.len());
        let (peeked, err) = conn.peek(data.len()).await;
        assert!(err.is_ok(), "peek(len(data)) failed");
        assert_eq!(data.as_slice(), peeked);
        assert_eq!(reader, std::ptr::from_ref(conn.reader().expect("the reader is present")));
        assert_eq!(32 * 1024, reader_size(&conn));

        let (_, err) = conn.peek(32 * 1024 + 1).await;
        assert!(is_bufio_error(&err.expect_err("buffer full"), BufioError::BufferFull));
        assert_eq!(32 * 1024, reader_size(&conn));

        let mut read = vec![0u8; data.len()];
        conn.read_exact(&mut read).await.expect("read full");
        assert_eq!(data, read);

        let mut conn = new_buffered_conn(TestReaderConn::boxed(&data));
        let initial_size = reader_size(&conn);
        let (peeked, err) = conn.peek(32 * 1024 + 1).await;
        assert!(is_bufio_error(&err.expect_err("buffer full"), BufioError::BufferFull));
        assert_eq!(&data[..initial_size], peeked);
        assert_eq!(initial_size, reader_size(&conn));
    }

    async fn read_all(conn: &mut BufferedConn) -> Vec<u8> {
        let mut data = Vec::new();
        conn.read_to_end(&mut data).await.expect("read to end");
        data
    }

    #[tokio::test]
    async fn peek_reports_the_end_of_stream_with_the_short_data() {
        let mut conn = new_buffered_conn(TestReaderConn::boxed(b"abc"));
        let (data, err) = conn.peek(5).await;
        assert_eq!(b"abc", data);
        assert_eq!(io::ErrorKind::UnexpectedEof, err.expect_err("the peek is short").kind());
    }

    #[tokio::test]
    async fn discard_past_the_end_answers_the_count_and_the_end_of_stream() {
        let mut conn = new_buffered_conn(TestReaderConn::boxed(b"abc"));
        let (n, err) = conn.discard(5).await;
        assert_eq!(3, n);
        assert_eq!(io::ErrorKind::UnexpectedEof, err.expect_err("the discard is short").kind());
    }

    #[tokio::test]
    async fn unread_byte_returns_the_last_read_byte_only() {
        let mut conn = new_buffered_conn(TestReaderConn::boxed(b"ab"));
        assert_eq!(b'a', conn.read_byte().await.expect("first byte"));
        conn.unread_byte().expect("the last byte is unreadable");
        assert_eq!(b'a', conn.read_byte().await.expect("first byte again"));
        let _ = conn.peek(1).await;
        assert!(is_bufio_error(
            &conn.unread_byte().expect_err("a peek invalidates the last byte"),
            BufioError::InvalidUnreadByte
        ));
    }

    #[tokio::test]
    async fn read_buffer_serves_the_buffered_bytes_first() {
        let mut conn = new_buffered_conn(TestReaderConn::boxed(b"hello world"));
        let (data, err) = conn.peek(5).await;
        assert_eq!(b"hello", data);
        assert!(err.is_ok(), "peek(5) failed");
        let mut buffer = murmur_compat::sing_buf::new_size(32);
        conn.read_buffer(&mut buffer).await.expect("read buffer");
        assert_eq!(b"hello world", buffer.bytes());
        assert!(conn.peeked(), "ReadBuffer leaves the peeked flag alone");
    }

    #[tokio::test]
    async fn buffered_conn_append_data() {
        // Prepends to unread underlying data.
        let mut conn = new_buffered_conn(TestReaderConn::boxed(b"underlying"));
        assert!(conn.append_data(b"appended"));
        assert_eq!(b"appendedunderlying".to_vec(), read_all(&mut conn).await);

        // Slides buffered data to make room.
        let original = vec![b'a'; 4096];
        let mut conn = new_buffered_conn(TestReaderConn::boxed(&original));
        let (_, err) = conn.peek(4096).await;
        assert!(err.is_ok(), "peek(4096) failed");
        let (_, err) = conn.discard(2048).await;
        assert!(err.is_ok(), "discard(2048) failed");
        assert!(conn.append_data(&vec![b'b'; 2048]));
        let mut expected = original[..2048].to_vec();
        expected.extend_from_slice(&vec![b'b'; 2048]);
        assert_eq!(expected, read_all(&mut conn).await);

        // Grows to make room.
        let original = vec![b'a'; 4096];
        let appended = vec![b'b'; 2048];
        let mut conn = new_buffered_conn(TestReaderConn::boxed(&original));
        let (_, err) = conn.peek(4096).await;
        assert!(err.is_ok(), "peek(4096) failed");
        let (_, err) = conn.discard(1024).await;
        assert!(err.is_ok(), "discard(1024) failed");
        assert!(conn.append_data(&appended));
        assert_eq!(8192, reader_size(&conn));
        let mut expected = original[1024..].to_vec();
        expected.extend_from_slice(&appended);
        assert_eq!(expected, read_all(&mut conn).await);

        // Grows beyond 32 KiB.
        let original = vec![b'a'; 32 * 1024];
        let appended = vec![b'b'; 1025];
        let mut conn = new_buffered_conn(TestReaderConn::boxed(&original));
        conn.grow(original.len());
        let (_, err) = conn.peek(32 * 1024).await;
        assert!(err.is_ok(), "peek(32*1024) failed");
        let (_, err) = conn.discard(1024).await;
        assert!(err.is_ok(), "discard(1024) failed");
        assert!(conn.append_data(&appended));
        assert!(reader_size(&conn) > 32 * 1024);
        let mut expected = original[1024..].to_vec();
        expected.extend_from_slice(&appended);
        assert_eq!(expected, read_all(&mut conn).await);

        // Appends after explicit growth.
        let original = vec![b'a'; 5000];
        let appended = vec![b'b'; 1000];
        let mut conn = new_buffered_conn(TestReaderConn::boxed(&original));
        conn.grow(original.len());
        let (_, err) = conn.peek(original.len()).await;
        assert!(err.is_ok(), "peek(len(original)) failed");
        assert!(conn.append_data(&appended));
        let mut expected = original.clone();
        expected.extend_from_slice(&appended);
        assert_eq!(expected, read_all(&mut conn).await);
    }

    #[tokio::test]
    async fn buffered_conn_prepend_data() {
        // Before unbuffered data.
        let mut conn = new_buffered_conn(TestReaderConn::boxed(b"underlying"));
        conn.prepend_data(b"prepended");
        assert_eq!(b"prependedunderlying".to_vec(), read_all(&mut conn).await);

        // Uses the consumed headroom.
        let original = vec![b'a'; 4096];
        let prepended = vec![b'b'; 1024];
        let mut conn = new_buffered_conn(TestReaderConn::boxed(&original));
        let (_, err) = conn.peek(original.len()).await;
        assert!(err.is_ok(), "peek(len(original)) failed");
        let (_, err) = conn.discard(2048).await;
        assert!(err.is_ok(), "discard(2048) failed");
        conn.prepend_data(&prepended);
        assert_eq!(4096, reader_size(&conn));
        let mut expected = prepended.clone();
        expected.extend_from_slice(&original[2048..]);
        assert_eq!(expected, read_all(&mut conn).await);

        // Shifts buffered data.
        let original = vec![b'a'; 2048];
        let prepended = vec![b'b'; 1024];
        let mut conn = new_buffered_conn(TestReaderConn::boxed(&original));
        let (_, err) = conn.peek(original.len()).await;
        assert!(err.is_ok(), "peek(len(original)) failed");
        conn.prepend_data(&prepended);
        assert_eq!(4096, reader_size(&conn));
        let mut expected = prepended.clone();
        expected.extend_from_slice(&original);
        assert_eq!(expected, read_all(&mut conn).await);

        // Grows to make room.
        let original = vec![b'a'; 4096];
        let prepended = vec![b'b'; 2048];
        let mut conn = new_buffered_conn(TestReaderConn::boxed(&original));
        let (_, err) = conn.peek(original.len()).await;
        assert!(err.is_ok(), "peek(len(original)) failed");
        conn.prepend_data(&prepended);
        assert_eq!(8192, reader_size(&conn));
        let mut expected = prepended.clone();
        expected.extend_from_slice(&original);
        assert_eq!(expected, read_all(&mut conn).await);
    }
}
