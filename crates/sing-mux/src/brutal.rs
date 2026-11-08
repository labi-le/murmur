use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::protocol::write_vstring;

pub const BRUTAL_EXCHANGE_DOMAIN: &str = "_BrutalBwExchange";
pub const BRUTAL_MIN_SPEED_BPS: u64 = 65536;

pub async fn write_brutal_request<W: AsyncWrite + Unpin + ?Sized>(writer: &mut W, receive_bps: u64) -> io::Result<()> {
    writer.write_all(&receive_bps.to_be_bytes()).await
}

pub async fn read_brutal_request<R: AsyncRead + Unpin + ?Sized>(reader: &mut R) -> io::Result<u64> {
    let mut buf = [0u8; 8];
    reader.read_exact(&mut buf).await?;
    Ok(u64::from_be_bytes(buf))
}

pub async fn write_brutal_response<W: AsyncWrite + Unpin + ?Sized>(
    writer: &mut W,
    receive_bps: u64,
    ok: bool,
    message: &str,
) -> io::Result<()> {
    let mut buffer = vec![u8::from(ok)];
    if ok {
        buffer.extend_from_slice(&receive_bps.to_be_bytes());
    } else {
        write_vstring(&mut buffer, message);
    }
    writer.write_all(&buffer).await
}

pub async fn read_brutal_response<R: AsyncRead + Unpin + ?Sized>(reader: &mut R) -> io::Result<u64> {
    let mut ok = [0u8; 1];
    reader.read_exact(&mut ok).await?;
    if ok[0] != 0 {
        let mut bps = [0u8; 8];
        reader.read_exact(&mut bps).await?;
        Ok(u64::from_be_bytes(bps))
    } else {
        let mut len = [0u8; 1];
        reader.read_exact(&mut len).await?;
        let mut message = vec![0u8; len[0] as usize];
        reader.read_exact(&mut message).await?;
        Err(io::Error::other(format!("remote error: {}", String::from_utf8_lossy(&message))))
    }
}

#[cfg(target_os = "linux")]
pub const BRUTAL_AVAILABLE: bool = true;
#[cfg(not(target_os = "linux"))]
pub const BRUTAL_AVAILABLE: bool = false;

/// The Linux TCP brutal socket option.
#[cfg(target_os = "linux")]
const TCP_BRUTAL_PARAMS: libc::c_int = 23301;

#[cfg(target_os = "linux")]
#[repr(C)]
struct TcpBrutalParams {
    rate: u64,
    cwnd_gain: u32,
}

/// The OS socket behind a carrier connection. `0` means the carrier is not a plain socket,
/// which is every TLS-wrapped or otherwise nested case.
pub type RawSocket = usize;

/// The socket behind a carrier connection, expressed with the `as_socket` capability
/// `murmur_common_net::io::Stream` already exposes.
#[cfg(unix)]
#[must_use]
pub fn raw_socket(socket: Option<socket2::SockRef<'_>>) -> RawSocket {
    use std::os::fd::AsRawFd;
    socket.map_or(0, |socket| usize::try_from(socket.as_raw_fd()).unwrap_or_default())
}

#[cfg(not(unix))]
#[must_use]
pub fn raw_socket(_socket: Option<socket2::SockRef<'_>>) -> RawSocket {
    0
}

/// The brutal-options set, applied to the carrier's own socket.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub fn set_brutal_options(socket: RawSocket, send_bps: u64) -> io::Result<()> {
    if socket == 0 {
        return Err(err_no_socket());
    }
    #[expect(
        clippy::cast_possible_wrap,
        clippy::cast_possible_truncation,
        reason = "a raw socket fd is a non-negative `c_int` to begin with, so narrowing it back cannot wrap or truncate; the `0` sentinel is rejected above"
    )]
    let fd = socket as libc::c_int;
    // SAFETY: `fd` is a live socket owned by the caller for the duration of this synchronous call;
    // both `setsockopt` calls only read their local `params`, which outlives the call.
    unsafe {
        let congestion = b"brutal\0";
        #[expect(
            clippy::cast_possible_truncation,
            reason = "the congestion algorithm name is 7 bytes, far below the 32-bit `socklen_t` bound"
        )]
        let congestion_len = (congestion.len() - 1) as libc::socklen_t;
        let rc =
            libc::setsockopt(fd, libc::IPPROTO_TCP, libc::TCP_CONGESTION, congestion.as_ptr().cast(), congestion_len);
        if rc != 0 {
            return Err(io::Error::new(
                io::Error::last_os_error().kind(),
                "setsockopt IPPROTO_TCP TCP_CONGESTION brutal: please make sure you have installed the tcp-brutal kernel module",
            ));
        }
        let params = TcpBrutalParams { rate: send_bps, cwnd_gain: 20 };
        #[expect(
            clippy::cast_possible_truncation,
            reason = "`TcpBrutalParams` is 16 bytes, far below the 32-bit `socklen_t` bound"
        )]
        let params_len = size_of::<TcpBrutalParams>() as libc::socklen_t;
        let rc =
            libc::setsockopt(fd, libc::IPPROTO_TCP, TCP_BRUTAL_PARAMS, std::ptr::addr_of!(params).cast(), params_len);
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn set_brutal_options(_socket: RawSocket, _send_bps: u64) -> io::Result<()> {
    Err(io::Error::other("TCP Brutal is only supported on Linux"))
}

/// The failure path (`"brutal: nested multiplexing is not supported"`) for carriers that are not
/// a plain socket.
#[must_use]
pub fn err_no_socket() -> io::Error {
    io::Error::other(
        "brutal: nested multiplexing is not supported: cannot get a raw socket from the carrier connection",
    )
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use tokio::net::{TcpListener, TcpStream};

    use super::*;

    #[tokio::test]
    async fn brutal_request_response_round_trip() {
        let (mut client, mut server) = tokio::io::duplex(4096);
        write_brutal_request(&mut client, 12345).await.unwrap();
        let received = read_brutal_request(&mut server).await.unwrap();
        assert_eq!(received, 12345);

        write_brutal_response(&mut server, 9999, true, "").await.unwrap();
        let bps = read_brutal_response(&mut client).await.unwrap();
        assert_eq!(bps, 9999);

        write_brutal_response(&mut server, 0, false, "denied").await.unwrap();
        let err = read_brutal_response(&mut client).await.unwrap_err();
        assert!(err.to_string().contains("denied"));
    }

    #[tokio::test]
    async fn set_brutal_options_on_a_real_socket() {
        use std::os::fd::AsRawFd;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();

        let result = set_brutal_options(client.as_raw_fd() as RawSocket, 1_000_000);
        let _ = server;
        if let Err(err) = &result {
            let msg = err.to_string();
            assert!(msg.contains("tcp-brutal kernel module") || msg.contains("Operation not permitted"), "{msg}");
        }
    }
}
