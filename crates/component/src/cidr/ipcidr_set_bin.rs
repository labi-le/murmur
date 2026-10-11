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
    ss.merge().map_err(|err| anyhow!("invalid range in the ip cidr stream: {err}"))?;

    Ok(ss)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use tokio::io::AsyncWriteExt;

    use super::read_ip_cidr_set;
    use crate::cidr::ipcidr_set::addr_as16;

    async fn stream_of(ranges: &[(Ipv4Addr, Ipv4Addr)]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.write_all(&[1]).await.expect("version byte");
        buf.write_all(&i64::try_from(ranges.len()).expect("count fits").to_be_bytes())
            .await
            .expect("count");
        for (from, to) in ranges {
            buf.write_all(&addr_as16(IpAddr::V4(*from))).await.expect("range start");
            buf.write_all(&addr_as16(IpAddr::V4(*to))).await.expect("range end");
        }
        buf
    }

    #[tokio::test]
    async fn an_unsorted_stream_still_contains_the_addresses_it_lists() {
        let stream = stream_of(&[
            (Ipv4Addr::new(192, 168, 0, 0), Ipv4Addr::new(192, 168, 255, 255)),
            (Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(10, 255, 255, 255)),
        ])
        .await;

        let set = read_ip_cidr_set(&mut stream.as_slice()).await.expect("valid stream");

        assert!(set.is_contain(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(set.is_contain(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
        assert!(!set.is_contain(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
    }

    #[tokio::test]
    async fn a_stream_whose_range_ends_before_it_starts_is_rejected() {
        let stream = stream_of(&[(Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 0))]).await;

        let err = read_ip_cidr_set(&mut stream.as_slice()).await.expect_err("inverted range");

        assert!(err.to_string().contains("10.0.0.1-10.0.0.0"), "{err}");
    }
}
