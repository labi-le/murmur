use std::io;

use tokio::io::{AsyncWrite, AsyncWriteExt};

use murmur_common_net::io::Stream;

/// Caps an HTTP header read: a peer that never ends a line, or never sends the blank line that
/// ends the header, must not make the reader buffer more than this.
pub(crate) const MAX_HTTP_HEADER_BYTES: usize = 32 * 1024;

/// A full write. `AsyncWriteExt::write_all` already loops until `p` is exhausted and reports
/// `WriteZero` on a zero-length successful write, matching the hand-rolled loop and its
/// a short-write error fallback.
// NOT cancel-safe: `write_all` is not cancel-safe, so a dropped timeout leaves the output
// half-written.
pub(crate) async fn write_full<W: AsyncWrite + Unpin + ?Sized>(w: &mut W, p: &[u8]) -> io::Result<()> {
    w.write_all(p).await
}

/// Closes the read half. An optional close-read interface is type-asserted,
/// [`Stream::shutdown_read`] is already a universal method defaulting to a no-op when a conn has
/// no real half-close, so the assertion collapses to a direct call.
pub(crate) fn try_close_read(conn: &dyn Stream) -> io::Result<()> {
    conn.shutdown_read()
}

/// Closes the write half. The documented behaviour falls back to a full `Close()` when the target has no
/// close-write method; [`Stream::shutdown_write`] already has a universal no-op default,
/// so there is no way to distinguish "unimplemented" from "implemented as a no-op" and the
/// full-close fallback is dropped (see wave report DEVIATIONS).
pub(crate) fn try_close_write(conn: &dyn Stream) -> io::Result<()> {
    conn.shutdown_write()
}
