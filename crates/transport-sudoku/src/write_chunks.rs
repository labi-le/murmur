use std::io;

use tokio::io::{AsyncWrite, AsyncWriteExt};

pub(crate) async fn write_all_chunks<W: AsyncWrite + Unpin + ?Sized>(w: &mut W, chunks: &[&[u8]]) -> io::Result<()> {
    for chunk in chunks {
        w.write_all(chunk).await?;
    }
    Ok(())
}
