//! The socket construction and the option set a TPROXY listener needs on Linux.

use std::net::SocketAddr;
use std::os::fd::{AsRawFd, RawFd};

use anyhow::{anyhow, Result};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::net::{TcpListener as TokioTcpListener, UdpSocket as TokioUdpSocket};

use super::udp_linux::IPV6_RECVORIGDSTADDR;

/// The backlog `std::net::TcpListener::bind` passes on Linux and `mio` (and so `tokio`) copies.
const LISTEN_BACKLOG: i32 = 128;

#[expect(unsafe_code, reason = "setsockopt on a descriptor open for the call")]
fn set_int_opt(fd: RawFd, level: libc::c_int, name: libc::c_int, value: libc::c_int) -> std::io::Result<()> {
    #[expect(
        clippy::cast_possible_truncation,
        reason = "a `socklen_t` describes a length in bytes and is never narrower than the `int` above it"
    )]
    // SAFETY: `fd` is a valid, open socket for the lifetime of this call; `value` is passed as a
    // plain `c_int` matching `setsockopt`'s documented `SOL_SOCKET`/`SOL_IP`/`SOL_IPV6` usage.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            std::ptr::from_ref(&value).cast::<libc::c_void>(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// The literal address `addr` names. A name is not resolved: every caller passes a literal, and a
/// lookup would block the reactor thread.
fn bind_addr(addr: &str) -> Result<SocketAddr> {
    addr.parse::<SocketAddr>().map_err(|err| anyhow!("tproxy listen address {addr}: {err}"))
}

/// A 4-in-6 address is IPv4-shaped for the kernel, as in the dial path.
fn is_ipv6(addr: SocketAddr) -> bool {
    matches!(addr, SocketAddr::V6(v6) if v6.ip().to_ipv4_mapped().is_none())
}

const fn domain(addr: SocketAddr) -> Domain {
    if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    }
}

/// The options a TPROXY socket carries. `SO_REUSEADDR` is read by `bind` and `IP_TRANSPARENT` has
/// to be in force before it, so this runs on a socket that is still unbound; the receive options
/// are read per `recvmsg` and ride along here so one call is the whole set.
fn tproxy_socket_options(socket: &Socket, addr: SocketAddr) -> Result<()> {
    let ipv6 = is_ipv6(addr);
    socket.set_reuse_address(true)?;
    socket.set_ip_transparent_v4(true)?;
    if ipv6 {
        socket.set_ip_transparent_v6(true)?;
    }
    let fd = socket.as_raw_fd();
    set_int_opt(fd, libc::SOL_IP, libc::IP_RECVORIGDSTADDR, 1)?;
    if ipv6 {
        set_int_opt(fd, libc::SOL_IPV6, IPV6_RECVORIGDSTADDR, 1)?;
    }
    let _ = set_dscp_sockopt(fd, ipv6);
    Ok(())
}

/// A bound socket for `addr`, with `options` applied while it is still unbound. A failing option
/// leaves the address unbound instead of handing back a socket that only looks configured.
///
/// The option set is a parameter so the tests can watch that ordering with one this host may
/// apply without `CAP_NET_ADMIN`.
fn socket_with_options(
    addr: SocketAddr,
    socket_type: Type,
    protocol: Protocol,
    options: impl FnOnce(&Socket) -> Result<()>,
) -> Result<Socket> {
    let socket = Socket::new(domain(addr), socket_type, Some(protocol))?;
    socket.set_nonblocking(true)?;
    options(&socket)?;
    socket.bind(&SockAddr::from(addr))?;
    Ok(socket)
}

fn tcp_listener_with(addr: SocketAddr, options: impl FnOnce(&Socket) -> Result<()>) -> Result<TokioTcpListener> {
    let socket = socket_with_options(addr, Type::STREAM, Protocol::TCP, options)?;
    socket.listen(LISTEN_BACKLOG)?;
    Ok(TokioTcpListener::from_std(std::net::TcpListener::from(socket))?)
}

/// Binds the TPROXY TCP listener `addr` names, transparent pair in force before the bind.
pub fn tcp_listener(addr: &str) -> Result<TokioTcpListener> {
    let addr = bind_addr(addr)?;
    tcp_listener_with(addr, |socket| tproxy_socket_options(socket, addr))
}

/// Binds the TPROXY UDP listener `addr` names, transparent pair in force before the bind.
pub fn udp_socket(addr: &str) -> Result<TokioUdpSocket> {
    let addr = bind_addr(addr)?;
    let socket = socket_with_options(addr, Type::DGRAM, Protocol::UDP, |socket| tproxy_socket_options(socket, addr))?;
    Ok(TokioUdpSocket::from_std(std::net::UdpSocket::from(socket))?)
}

fn set_dscp_sockopt(fd: RawFd, is_ipv6: bool) -> Result<()> {
    set_int_opt(fd, libc::SOL_IP, libc::IP_RECVTOS, 1)?;
    if is_ipv6 {
        set_int_opt(fd, libc::SOL_IPV6, libc::IPV6_RECVTCLASS, 1)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::*;

    fn free_addr() -> SocketAddr {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").expect("an ephemeral port is free");
        probe.local_addr().expect("the probe is bound")
    }

    fn reuse_only(socket: &Socket) -> Result<()> {
        Ok(socket.set_reuse_address(true)?)
    }

    /// The options have to be in force at `bind` time, which is visible as the state of the socket
    /// while the option pass runs.
    #[test]
    fn socket_options_are_applied_while_the_socket_is_still_unbound() {
        let seen = Arc::new(Mutex::new(None));
        let recorder = Arc::clone(&seen);
        let socket = socket_with_options(free_addr(), Type::STREAM, Protocol::TCP, move |socket| {
            let bound = socket.local_addr().expect("getsockname").as_socket().expect("an IP address");
            *recorder.lock().expect("the recorder is not poisoned") = Some(bound);
            Ok(socket.set_reuse_address(true)?)
        })
        .expect("the socket is created and bound");

        let at_option_time = seen.lock().expect("the recorder is not poisoned").expect("the option pass ran");
        assert_eq!(at_option_time.port(), 0, "the option pass ran after the bind");
        let bound = socket.local_addr().expect("getsockname").as_socket().expect("an IP address");
        assert_ne!(bound.port(), 0, "the socket is bound");
    }

    /// `SO_REUSEADDR` is read by `bind`, so a port a previous listener left in `TIME_WAIT` - the
    /// restart this option exists for - is rebound only when the option precedes the bind.
    #[tokio::test]
    async fn a_port_left_in_time_wait_is_rebound_because_the_reuse_option_precedes_the_bind() {
        let addr = free_addr();
        let listener = tcp_listener_with(addr, reuse_only).expect("the listener binds");
        let accept = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("the client connects");
            // The accepted side closes first, so `addr` is the endpoint left in `TIME_WAIT`.
            drop(stream);
        });
        let client = tokio::net::TcpStream::connect(addr).await.expect("the client connects");
        accept.await.expect("the accept task finishes");
        drop(client);
        wait_for_time_wait(addr).await;

        let control = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).expect("a socket opens");
        let err = control.bind(&SockAddr::from(addr)).expect_err("only `SO_REUSEADDR` reopens a `TIME_WAIT` port");
        assert_eq!(err.raw_os_error(), Some(libc::EADDRINUSE));

        tcp_listener_with(addr, reuse_only).expect("the option was in force for the bind");
    }

    /// Waits for the kernel to show `addr` in `TIME_WAIT`, so the rebind above is not racing the
    /// close that put it there.
    async fn wait_for_time_wait(addr: SocketAddr) {
        for _ in 0..400 {
            let table = std::fs::read_to_string("/proc/net/tcp").unwrap_or_default();
            let waiting = table.lines().skip(1).any(|line| {
                let mut fields = line.split_whitespace();
                let local = fields.nth(1);
                let state = fields.nth(1);
                matches!((local, state), (Some(local), Some("06")) if hex_port(local) == Some(addr.port()))
            });
            if waiting {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("{addr} did not reach `TIME_WAIT`");
    }

    fn hex_port(local_address: &str) -> Option<u16> {
        u16::from_str_radix(local_address.rsplit(':').next()?, 16).ok()
    }
}
