use anyhow::{anyhow, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::ipcidr_set::{addr_as16, addr_from16_unmap, ip_range_from, IpCidrSet};

impl IpCidrSet {
    /// The wire format is unchanged.
    pub async fn write_bin<W: AsyncWrite + Unpin>(&self, w: &mut W) -> Result<()> {
        w.write_all(&[1]).await?;

        let length = i64::try_from(self.rr.len()).map_err(|_| anyhow!("length is invalid"))?;
        w.write_all(&length.to_be_bytes()).await?;
        for r in &self.rr {
            w.write_all(&addr_as16(r.from())).await?;
            w.write_all(&addr_as16(r.to())).await?;
        }

        Ok(())
    }
}

pub async fn read_ip_cidr_set<R: AsyncRead + Unpin>(r: &mut R) -> Result<IpCidrSet> {
    let mut version = [0u8; 1];
    r.read_exact(&mut version).await?;
    if version[0] != 1 {
        return Err(anyhow!("version is invalid"));
    }

    let mut ss = IpCidrSet::new_ip_cidr_set();
    let mut length_bin = [0u8; 8];
    r.read_exact(&mut length_bin).await?;
    let length = i64::from_be_bytes(length_bin);
    if length < 1 {
        return Err(anyhow!("length is invalid"));
    }
    ss.rr = Vec::with_capacity(usize::try_from(length).map_err(|_| anyhow!("length is invalid"))?);
    let mut a16 = [0u8; 16];
    for _ in 0..length {
        r.read_exact(&mut a16).await?;
        let from = addr_from16_unmap(a16);
        r.read_exact(&mut a16).await?;
        let to = addr_from16_unmap(a16);
        ss.rr.push(ip_range_from(from, to));
    }

    Ok(ss)
}
