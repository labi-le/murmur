use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use murmur_quic::jls::Conn as JlsConn;

pub(crate) const EXTENSION_OPCODE_CONN: u64 = 0x01;
pub(crate) const EXTENSION_OPCODE_USER: u64 = 0x02;

pub(crate) const EXTENSION_CONN_GET_STATS: u8 = 0x00;

pub(crate) const EXTENSION_RESULT_OK: u8 = 0x00;
pub(crate) const EXTENSION_RESULT_ERR: u8 = 0x01;

pub(crate) const EXTENSION_ERR_NOT_AVAILABLE: u8 = 0x00;
#[allow(
    dead_code,
    reason = "only exercised by the encode-path test (test_write_extension_error_result); the wire error-code table is part of the protocol's fixed enum"
)]
pub(crate) const EXTENSION_ERR_PERMISSION_DENIED: u8 = 0x01;
#[allow(
    dead_code,
    reason = "documents the wire error-code table; this crate's send path never emits it, but the byte value is part of the protocol's fixed enum"
)]
pub(crate) const EXTENSION_ERR_NOT_FOUND: u8 = 0x02;
pub(crate) const EXTENSION_ERR_OTHER: u8 = 0xff;

pub(crate) const EXTENSION_CONN_STATS_LEN: u32 = 8 + 8 + 8 + 2;

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct ExtensionConnStats {
    pub lost_packets: u64,
    pub sent_packets: u64,
    pub rtt: f64,
    pub current_mtu: u16,
}

pub async fn read_extension_opcode<R>(r: &mut R) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut buf = [0u8; 8];
    r.read_exact(&mut buf).await?;
    Ok(u64::from_be_bytes(buf))
}

pub(crate) async fn read_extension_subcommand<R>(r: &mut R) -> std::io::Result<u8>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut buf = [0u8; 1];
    r.read_exact(&mut buf).await?;
    Ok(buf[0])
}

pub async fn write_extension_conn_stats_result<W>(w: &mut W, stats: ExtensionConnStats) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    let mut buf = [0u8; 1 + 4 + (8 + 8 + 8 + 2)];
    buf[0] = EXTENSION_RESULT_OK;
    buf[1..5].copy_from_slice(&EXTENSION_CONN_STATS_LEN.to_be_bytes());
    buf[5..13].copy_from_slice(&stats.lost_packets.to_be_bytes());
    buf[13..21].copy_from_slice(&stats.sent_packets.to_be_bytes());
    buf[21..29].copy_from_slice(&stats.rtt.to_bits().to_be_bytes());
    buf[29..31].copy_from_slice(&stats.current_mtu.to_be_bytes());
    w.write_all(&buf).await
}

pub async fn write_extension_error_result<W>(w: &mut W, code: u8, message: &str) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    w.write_all(&[EXTENSION_RESULT_ERR, code]).await?;
    if code != EXTENSION_ERR_OTHER {
        return Ok(());
    }
    let msg = message.as_bytes();
    #[expect(
        clippy::cast_possible_truncation,
        reason = "the protocol encodes the error message length as a 32-bit field, and an in-process message never approaches 4 GiB"
    )]
    w.write_all(&(msg.len() as u32).to_be_bytes()).await?;
    w.write_all(msg).await
}

pub(crate) fn shadow_quic_conn_stats(conn: &dyn JlsConn) -> ExtensionConnStats {
    let stats = conn.connection_stats();
    let mut rtt = stats.smoothed_rtt;
    if rtt.is_zero() {
        rtt = stats.latest_rtt;
    }
    ExtensionConnStats {
        lost_packets: stats.packets_lost,
        sent_packets: stats.packets_sent,
        rtt: rtt.as_secs_f64() * 1000.0,
        current_mtu: stats.current_mtu,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::Server;

    #[tokio::test]
    async fn test_write_extension_conn_stats_result() {
        let mut buf = Vec::new();
        write_extension_conn_stats_result(
            &mut buf,
            ExtensionConnStats { lost_packets: 3, sent_packets: 5, rtt: 12.5, current_mtu: 1400 },
        )
        .await
        .unwrap();

        assert_eq!(buf.len(), 31, "encoded length");
        assert_eq!(buf[0], EXTENSION_RESULT_OK, "result tag");
        assert_eq!(u32::from_be_bytes(buf[1..5].try_into().unwrap()), EXTENSION_CONN_STATS_LEN, "stats length");
        assert_eq!(u64::from_be_bytes(buf[5..13].try_into().unwrap()), 3, "lost packets");
        assert_eq!(u64::from_be_bytes(buf[13..21].try_into().unwrap()), 5, "sent packets");
        assert_eq!(f64::from_bits(u64::from_be_bytes(buf[21..29].try_into().unwrap())), 12.5, "rtt");
        assert_eq!(u16::from_be_bytes(buf[29..31].try_into().unwrap()), 1400, "mtu");
    }

    #[tokio::test]
    async fn test_write_extension_error_result() {
        let mut buf = Vec::new();
        write_extension_error_result(&mut buf, EXTENSION_ERR_PERMISSION_DENIED, "").await.unwrap();
        assert_eq!(buf, vec![EXTENSION_RESULT_ERR, EXTENSION_ERR_PERMISSION_DENIED]);
    }

    #[tokio::test]
    async fn test_user_extension_is_unavailable() {
        let (mut client, server_conn) = tokio::io::duplex(4096);
        let done = tokio::spawn(async move {
            let mut server_conn = server_conn;
            Server::handle_extension_for_test(None, &mut server_conn).await;
        });

        let mut request = [0u8; 9];
        request[..8].copy_from_slice(&EXTENSION_OPCODE_USER.to_be_bytes());
        client.write_all(&request).await.unwrap();

        let mut response = [0u8; 2];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [EXTENSION_RESULT_ERR, EXTENSION_ERR_NOT_AVAILABLE]);

        drop(client);
        done.await.unwrap();
    }
}
