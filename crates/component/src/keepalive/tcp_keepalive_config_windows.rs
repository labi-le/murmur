//! Keep-alive support probing against the Windows build number.

use std::sync::LazyLock;

use murmur_constant_features::{WINDOWS_BUILD_NUMBER, WINDOWS_MAJOR_VERSION};

/// The Windows socket handle.
type Socket = usize;

const AF_INET: i32 = 2;
const SOCK_STREAM: i32 = 1;
const IPPROTO_TCP: i32 = 6;
const TCP_KEEPIDLE: i32 = 3;
const TCP_KEEPINTVL: i32 = 4;
const TCP_KEEPCNT: i32 = 5;
const WSA_FLAG_NO_HANDLE_INHERIT: u32 = 0x80;
const INVALID_SOCKET: Socket = usize::MAX;
const SOCKET_ERROR: i32 = -1;
/// `WSAENOPROTOOPT`, meaning the option is unsupported.
const WSAENOPROTOOPT: i32 = 10042;

#[link(name = "ws2_32")]
extern "system" {
    fn WSASocketW(af: i32, socket_type: i32, protocol: i32, protocol_info: *mut u8, group: u32, flags: u32) -> Socket;
    fn setsockopt(s: Socket, level: i32, optname: i32, optval: *const i8, optlen: i32) -> i32;
    fn closesocket(s: Socket) -> i32;
}

struct Support {
    idle: bool,
    interval: bool,
    count: bool,
}

static SUPPORT: LazyLock<Support> = LazyLock::new(|| {
    let Ok(socket) = wsa_socket() else {
        return version_support();
    };
    let support = Support {
        idle: opt_supported(socket, TCP_KEEPIDLE),
        interval: opt_supported(socket, TCP_KEEPINTVL),
        count: opt_supported(socket, TCP_KEEPCNT),
    };
    close_socket(socket);
    support
});

/// The error is the `WSAGetLastError()` code.
#[expect(unsafe_code, reason = "`WSASocketW` is a raw FFI call with no safe wrapper in the pinned crates")]
fn wsa_socket() -> Result<Socket, i32> {
    // SAFETY: `lpProtocolInfo` is null and no group is requested; the socket handle is fresh.
    let s =
        unsafe { WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, std::ptr::null_mut(), 0, WSA_FLAG_NO_HANDLE_INHERIT) };
    if s == INVALID_SOCKET {
        return Err(last_wsa_error());
    }
    Ok(s)
}

#[expect(unsafe_code, reason = "`setsockopt` is a raw FFI call; the SAFETY comment below states the buffer invariant")]
fn set_sock_opt_int(s: Socket, level: i32, optname: i32, optval: i32) -> Result<(), i32> {
    // SAFETY: `optval` is a live `c_int` that stays valid for the duration of the call.
    let rc = unsafe {
        setsockopt(
            s,
            level,
            optname,
            std::ptr::from_ref(&optval).cast(),
            i32::try_from(size_of::<i32>()).unwrap_or(i32::MAX),
        )
    };
    if rc == SOCKET_ERROR {
        return Err(last_wsa_error());
    }
    Ok(())
}

#[expect(unsafe_code, reason = "`closesocket` on a socket this module owns has no safe wrapper in the pinned crates")]
fn close_socket(s: Socket) {
    // SAFETY: `s` is a socket this module created and has not closed yet.
    unsafe {
        closesocket(s);
    }
}

fn last_wsa_error() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn opt_supported(s: Socket, opt: i32) -> bool {
    match set_sock_opt_int(s, IPPROTO_TCP, opt, 1) {
        Ok(()) => true,
        Err(code) => code != WSAENOPROTOOPT,
    }
}

/// Fallback to checking the Windows version.
fn version_support() -> Support {
    let major = *WINDOWS_MAJOR_VERSION;
    let build = *WINDOWS_BUILD_NUMBER;
    Support {
        idle: major >= 10 && build >= 16299,
        interval: major >= 10 && build >= 16299,
        count: major >= 10 && build >= 15063,
    }
}

/// SupportTCPKeepAliveIdle indicates whether TCP_KEEPIDLE is supported.
/// The minimal requirement is Windows 10.0.16299.
#[must_use]
pub fn support_tcp_keep_alive_idle() -> bool {
    SUPPORT.idle
}

/// SupportTCPKeepAliveInterval indicates whether TCP_KEEPINTVL is supported.
/// The minimal requirement is Windows 10.0.16299.
#[must_use]
pub fn support_tcp_keep_alive_interval() -> bool {
    SUPPORT.interval
}

/// SupportTCPKeepAliveCount indicates whether TCP_KEEPCNT is supported.
/// The minimal requirement is Windows 10.0.15063.
#[must_use]
pub fn support_tcp_keep_alive_count() -> bool {
    SUPPORT.count
}
