use anyhow::{anyhow, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::ipcidr_set::{addr_as16, addr_from16_unmap, ip_range_from, IpCidrSet};

/// The largest range count a serialized set may declare; far past any real IP-CIDR rule set, so a
/// larger count is a malformed payload rather than work to do.
const MAX_RANGES: usize = 1 << 24;

impl IpCidrSet {
    /// The wire format is unchanged.
    pub async fn write_bin<W: AsyncWrite + Unpin>(&self, w: &mut W) -> Result<()> {
        if self.rr.is_empty() {
            return Err(anyhow!("empty ip cidr set"));
        }

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
    let count = usize::try_from(length).map_err(|_| anyhow!("length is invalid"))?;
    if count > MAX_RANGES {
        return Err(anyhow!("range count {count} exceeds the maximum of {MAX_RANGES}"));
    }
    let mut a16 = [0u8; 16];
    for _ in 0..count {
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
    use crate::cidr::ipcidr_set::{addr_as16, IpCidrSet};

    async fn stream_of(ranges: &[(Ipv4Addr, Ipv4Addr)]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.write_all(&[1]).await.expect("version byte");
        buf.write_all(&i64::try_from(ranges.len()).expect("count fits").to_be_bytes()).await.expect("count");
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

    #[tokio::test]
    async fn a_stream_declaring_a_range_count_past_the_bound_is_rejected() {
        let mut stream = Vec::new();
        stream.write_all(&[1]).await.expect("version byte");
        stream.write_all(&(1i64 << 40).to_be_bytes()).await.expect("count");

        let err = read_ip_cidr_set(&mut stream.as_slice()).await.expect_err("implausible count");

        assert!(err.to_string().contains("exceeds the maximum"), "{err}");
    }

    #[tokio::test]
    async fn an_empty_set_is_refused_instead_of_written_as_a_stream_the_reader_rejects() {
        let mut stream: Vec<u8> = Vec::new();

        let err = IpCidrSet::new_ip_cidr_set().write_bin(&mut stream).await.err().expect("empty set");

        assert!(stream.is_empty(), "the writer must not emit a partial stream");
        assert!(err.to_string().contains("empty ip cidr set"), "{err}");
    }

    #[tokio::test]
    async fn a_non_empty_set_round_trips_through_the_writer_and_the_reader() {
        let mut set = IpCidrSet::new_ip_cidr_set();
        set.add_ip_cidr_for_string("10.0.0.0/8").expect("valid cidr");
        set.add_ip_cidr_for_string("192.168.0.0/16").expect("valid cidr");
        let mut stream: Vec<u8> = Vec::new();
        set.write_bin(&mut stream).await.expect("non-empty set");

        let restored = read_ip_cidr_set(&mut stream.as_slice()).await.expect("valid stream");

        assert_eq!(restored.rr, set.rr);
        assert!(restored.is_contain_for_string("10.1.2.3"));
        assert!(restored.is_contain_for_string("192.168.1.1"));
    }
}
