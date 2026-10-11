use anyhow::{anyhow, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::domain_set::DomainSet;

/// The largest count a serialized set or map may declare — leaf bits, bitmap words, label bytes or
/// map values. Far past any real rule set, so a larger count is a malformed payload rather than
/// work to do.
pub(crate) const MAX_BIN_COUNT: i64 = 1 << 26;

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
    if length > MAX_BIN_COUNT {
        return Err(anyhow!("leaf count {length} exceeds the maximum of {MAX_BIN_COUNT}"));
    }
    let mut word_bin = [0u8; 8];
    for _ in 0..length {
        r.read_exact(&mut word_bin).await?;
        ds.leaves.push(u64::from_be_bytes(word_bin));
    }

    let length = read_i64_bin(r).await?;
    if length < 1 {
        return Err(anyhow!("length is invalid"));
    }
    if length > MAX_BIN_COUNT {
        return Err(anyhow!("bitmap count {length} exceeds the maximum of {MAX_BIN_COUNT}"));
    }
    for _ in 0..length {
        r.read_exact(&mut word_bin).await?;
        ds.label_bitmap.push(u64::from_be_bytes(word_bin));
    }

    let length = read_i64_bin(r).await?;
    if length < 1 {
        return Err(anyhow!("length is invalid"));
    }
    if length > MAX_BIN_COUNT {
        return Err(anyhow!("label count {length} exceeds the maximum of {MAX_BIN_COUNT}"));
    }
    let mut labels: Vec<u8> = Vec::new();
    (&mut *r).take(u64::try_from(length)?).read_to_end(&mut labels).await?;
    if labels.len() != usize::try_from(length)? {
        return Err(anyhow!("labels are truncated"));
    }
    ds.labels = labels;

    ds.init();
    Ok(ds)
}

pub(crate) async fn read_i64_bin<R: AsyncRead + Unpin>(r: &mut R) -> Result<i64> {
    let mut bin = [0u8; 8];
    r.read_exact(&mut bin).await?;
    Ok(i64::from_be_bytes(bin))
}

#[cfg(test)]
mod tests {
    use tokio::io::AsyncWriteExt;

    use super::read_domain_set_bin;

    #[tokio::test]
    async fn a_stream_declaring_a_leaf_count_past_the_bound_is_rejected() {
        let mut stream: Vec<u8> = Vec::new();
        stream.write_all(&[1]).await.expect("version byte");
        stream.write_all(&(1i64 << 40).to_be_bytes()).await.expect("leaf count");

        let err = read_domain_set_bin(&mut stream.as_slice()).await.expect_err("implausible leaf count");

        assert!(err.to_string().contains("exceeds the maximum"), "{err}");
    }

    #[tokio::test]
    async fn a_stream_declaring_a_label_byte_count_past_the_bound_is_rejected() {
        let mut stream: Vec<u8> = Vec::new();
        stream.write_all(&[1]).await.expect("version byte");
        stream.write_all(&1i64.to_be_bytes()).await.expect("leaf count");
        stream.write_all(&0u64.to_be_bytes()).await.expect("leaf");
        stream.write_all(&1i64.to_be_bytes()).await.expect("bitmap count");
        stream.write_all(&0u64.to_be_bytes()).await.expect("bitmap word");
        stream.write_all(&(1i64 << 40).to_be_bytes()).await.expect("label byte count");

        let err = read_domain_set_bin(&mut stream.as_slice()).await.expect_err("implausible label count");

        assert!(err.to_string().contains("exceeds the maximum"), "{err}");
    }
}
