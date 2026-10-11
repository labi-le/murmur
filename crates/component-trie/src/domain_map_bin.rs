use anyhow::{anyhow, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::domain_map::{DomainMap, DomainMapIndex};
use super::domain_set_bin::{read_domain_set_bin, read_i64_bin};

impl<T> DomainMap<T> {
    /// The wire format is unchanged. `write_value` appends the encoding of one
    /// value to `value_bin`.
    #[expect(clippy::future_not_send, reason = "the public signature cannot add a `Send + Sync` bound to `T`")]
    pub async fn write_bin<W, F>(&self, writer: &mut W, mut write_value: F) -> Result<()>
    where
        W: AsyncWrite + Unpin,
        F: FnMut(&T, &mut Vec<u8>) -> Result<()>,
    {
        if self.is_empty() {
            return Err(anyhow!("empty domainMap"));
        }

        let set = self.index.set();
        set.write_bin(writer).await?;

        writer.write_all(&[0]).await?;
        writer.write_all(&[1]).await?;

        writer.write_all(&i64::try_from(self.values.len())?.to_be_bytes()).await?;
        let mut value_bin: Vec<u8> = Vec::new();
        for value in &self.values {
            value_bin.clear();
            write_value(value, &mut value_bin)?;
            writer.write_all(&value_bin).await?;
        }

        Ok(())
    }
}

/// Parses one value from the front of `buffer`, with the number of bytes it consumed.
///
/// Returns `None` while `buffer` is still too short. [`read_domain_map_bin`] then reads one
/// further byte and retries, so the reader stays positioned right behind the values.
pub async fn read_domain_map_bin<R, T, F>(reader: &mut R, mut read_value: F) -> Result<DomainMap<T>>
where
    R: AsyncRead + Unpin,
    F: FnMut(&[u8]) -> Result<Option<(T, usize)>>,
{
    let set = read_domain_set_bin(reader).await?;

    let mut separator = [0u8; 1];
    reader.read_exact(&mut separator).await?;
    if separator[0] != 0 {
        return Err(anyhow!("separator is invalid"));
    }

    let mut version = [0u8; 1];
    reader.read_exact(&mut version).await?;
    if version[0] != 1 {
        return Err(anyhow!("version is invalid"));
    }

    let length = read_i64_bin(reader).await?;
    if length < 1 {
        return Err(anyhow!("length is invalid"));
    }
    let mut buffer: Vec<u8> = Vec::new();
    let mut offset: usize = 0;
    let mut values: Vec<T> = Vec::with_capacity(usize::try_from(length)?);
    for _ in 0..length {
        loop {
            let rest = buffer.get(offset..).unwrap_or_default();
            if let Some((value, used)) = read_value(rest)? {
                offset += used;
                values.push(value);
                break;
            }
            let mut byte = [0u8; 1];
            reader.read_exact(&mut byte).await?;
            buffer.push(byte[0]);
        }
    }

    let mut mapping = DomainMap {
        index: DomainMapIndex { domain_set: Some(set), select_deltas: Vec::new() },
        leaf_ranks: Vec::new(),
        values,
    };

    mapping.init();
    Ok(mapping)
}
