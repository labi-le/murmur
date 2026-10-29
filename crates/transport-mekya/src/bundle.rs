use std::io;

use tokio::io::{AsyncRead, AsyncReadExt};

pub(crate) const PACKET_BUNDLE_OVERHEAD: usize = 2;

pub(crate) fn write_packet_bundle(w: &mut impl io::Write, packet: &[u8]) -> io::Result<()> {
    let header = u16::try_from(packet.len()).map_err(|_| io::Error::other("short buffer"))?.to_be_bytes();
    w.write_all(&header)?;
    w.write_all(packet)?;
    Ok(())
}

/// The in-memory-reader variant; `read_packet_bundle`
/// below is the streaming-reader variant used against an HTTP response body.
pub(crate) fn read_packet_bundle_sync(r: &mut impl io::Read) -> io::Result<Vec<u8>> {
    let mut header = [0u8; PACKET_BUNDLE_OVERHEAD];
    r.read_exact(&mut header)?;
    let length = usize::from(u16::from_be_bytes(header));
    let mut packet = vec![0u8; length];
    r.read_exact(&mut packet)?;
    Ok(packet)
}

// NOT cancel-safe: a dropped call has already consumed framing bytes from the stream, so a later read would start mid-frame; the arms that await it drop it only while the connection is being torn down.
pub(crate) async fn read_packet_bundle(r: &mut (impl AsyncRead + Unpin)) -> io::Result<Vec<u8>> {
    let mut header = [0u8; PACKET_BUNDLE_OVERHEAD];
    r.read_exact(&mut header).await?;
    let length = usize::from(u16::from_be_bytes(header));
    let mut packet = vec![0u8; length];
    r.read_exact(&mut packet).await?;
    Ok(packet)
}
