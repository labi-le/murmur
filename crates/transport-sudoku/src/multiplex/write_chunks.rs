use tokio::io::{AsyncWrite, AsyncWriteExt as _};

pub(crate) async fn write_all_chunks<W: AsyncWrite + Unpin>(w: &mut W, chunks: &[&[u8]]) -> std::io::Result<()> {
    for chunk in chunks {
        w.write_all(chunk).await?;
    }
    Ok(())
}
