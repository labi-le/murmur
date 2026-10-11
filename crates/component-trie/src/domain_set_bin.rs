use anyhow::{anyhow, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::domain_set::DomainSet;

impl DomainSet {
    pub async fn write_bin<W: AsyncWrite + Unpin>(&self, w: &mut W) -> Result<()> {
        w.write_all(&[1]).await?;

        w.write_all(&i64::try_from(self.leaves.len())?.to_be_bytes()).await?;
        for d in &self.leaves {
            w.write_all(&d.to_be_bytes()).await?;
        }

        w.write_all(&i64::try_from(self.label_bitmap.len())?.to_be_bytes()).await?;
        for d in &self.label_bitmap {
            w.write_all(&d.to_be_bytes()).await?;
        }

        w.write_all(&i64::try_from(self.labels.len())?.to_be_bytes()).await?;
        w.write_all(&self.labels).await?;

        Ok(())
    }
}

pub async fn read_domain_set_bin<R: AsyncRead + Unpin>(r: &mut R) -> Result<DomainSet> {
    let mut version = [0u8; 1];
    r.read_exact(&mut version).await?;
    if version[0] != 1 {
        return Err(anyhow!("version is invalid"));
    }

    let mut ds = DomainSet::default();

    let length = read_i64_bin(r).await?;
    if length < 1 {
        return Err(anyhow!("length is invalid"));
    }
    ds.leaves = Vec::with_capacity(usize::try_from(length)?);
    let mut word_bin = [0u8; 8];
    for _ in 0..length {
        r.read_exact(&mut word_bin).await?;
        ds.leaves.push(u64::from_be_bytes(word_bin));
    }

    let length = read_i64_bin(r).await?;
    if length < 1 {
        return Err(anyhow!("length is invalid"));
    }
    ds.label_bitmap = Vec::with_capacity(usize::try_from(length)?);
    for _ in 0..length {
        r.read_exact(&mut word_bin).await?;
        ds.label_bitmap.push(u64::from_be_bytes(word_bin));
    }

    let length = read_i64_bin(r).await?;
    if length < 1 {
        return Err(anyhow!("length is invalid"));
    }
    ds.labels = vec![0u8; usize::try_from(length)?];
    r.read_exact(&mut ds.labels).await?;

    ds.init();
    Ok(ds)
}

pub(crate) async fn read_i64_bin<R: AsyncRead + Unpin>(r: &mut R) -> Result<i64> {
    let mut bin = [0u8; 8];
    r.read_exact(&mut bin).await?;
    Ok(i64::from_be_bytes(bin))
}
