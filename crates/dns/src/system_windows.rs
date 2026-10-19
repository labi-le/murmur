//! NEEDED CRATE: windows-sys = "0.59", features "Win32_NetworkManagement_IpHelper,
//! Win32_Networking_WinSock, Win32_Foundation".
//!
//! Not in `rust/Cargo.toml`; this module cannot be
//! compiled or exercised on the Linux workstation this build ran on, so the FFI shape below is a
//! best-effort, unverified use of the Windows IP Helper API.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use windows_sys::Win32::Foundation::ERROR_BUFFER_OVERFLOW;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetAdaptersAddresses, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_INCLUDE_PREFIX, IP_ADAPTER_ADDRESSES_LH,
};
use windows_sys::Win32::NetworkManagement::Ndis::IF_OPER_STATUS;
use windows_sys::Win32::Networking::WinSock::{AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6};

const IF_OPER_STATUS_UP: IF_OPER_STATUS = 1;

pub(crate) fn dns_read_config() -> anyhow::Result<Vec<String>> {
    let mut servers: Vec<String> = Vec::new();

    for adapter in adapter_addresses()? {
        if adapter.oper_status != IF_OPER_STATUS_UP {
            continue;
        }
        if !adapter.has_gateway {
            continue;
        }

        for ip in adapter.dns_servers {
            let ip_str = ip.to_string();
            if servers.contains(&ip_str) {
                continue;
            }
            servers.push(ip_str);
        }
    }

    Ok(servers)
}

struct AdapterInfo {
    oper_status: IF_OPER_STATUS,
    has_gateway: bool,
    dns_servers: Vec<IpAddr>,
}

/// Returns the flattened per-adapter DNS servers rather than the raw `IP_ADAPTER_ADDRESSES`
/// linked list.
#[expect(
    unsafe_code,
    reason = "the Win32 adapter enumeration only exposes a raw struct chain, so the walk over it is unsafe"
)]
fn adapter_addresses() -> anyhow::Result<Vec<AdapterInfo>> {
    // SAFETY: `GetAdaptersAddresses` is called in a loop that grows `buffer` until the call
    // reports success or a non-`ERROR_BUFFER_OVERFLOW` error, matching the retry loop. The
    // adapter list is only read back while `buffer` (and the memory it points into) is alive.
    unsafe {
        let flags = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS;
        let mut size: u32 = 15000;
        let mut buffer: Vec<u8>;
        loop {
            buffer = vec![0u8; size as usize];
            let head = buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
            let err = GetAdaptersAddresses(u32::from(AF_UNSPEC), flags, std::ptr::null_mut(), head, &raw mut size);
            if err == 0 {
                if size == 0 {
                    return Ok(Vec::new());
                }
                break;
            }
            if err != ERROR_BUFFER_OVERFLOW {
                return Err(anyhow::anyhow!("getadaptersaddresses: error code {err}"));
            }
            if size as usize <= buffer.len() {
                return Err(anyhow::anyhow!("getadaptersaddresses: error code {err}"));
            }
        }

        let mut result = Vec::new();
        let mut adapter = buffer.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        while !adapter.is_null() {
            let aa = &*adapter;
            let mut dns_servers = Vec::new();
            let mut dns_addr = aa.FirstDnsServerAddress;
            while !dns_addr.is_null() {
                let sockaddr = (*dns_addr).Address.lpSockaddr;
                if let Some(ip) = socket_address_to_ip(sockaddr) {
                    dns_servers.push(ip);
                }
                dns_addr = (*dns_addr).Next;
            }
            result.push(AdapterInfo {
                oper_status: aa.OperStatus,
                has_gateway: !aa.FirstGatewayAddress.is_null(),
                dns_servers,
            });
            adapter = aa.Next;
        }
        Ok(result)
    }
}

/// Converts a socket address to an IP, including the `fec0/10` skip and the IPv6 zone suffix.
#[expect(unsafe_code, reason = "reading the `SOCKADDR` union by family needs a raw pointer dereference")]
#[expect(
    clippy::cast_ptr_alignment,
    reason = "`GetAdaptersAddresses` lays the list out aligned for the widest union member, and `sa_family` only selects a narrower member of that same allocation"
)]
fn socket_address_to_ip(sockaddr: *const windows_sys::Win32::Networking::WinSock::SOCKADDR) -> Option<IpAddr> {
    if sockaddr.is_null() {
        return None;
    }
    // SAFETY: `sockaddr` was produced by `GetAdaptersAddresses` and is valid for the lifetime of
    // the enclosing `adapter_addresses` call; `sa_family` selects which union member is read.
    unsafe {
        match (*sockaddr).sa_family {
            windows_sys::Win32::Networking::WinSock::AF_INET => {
                let addr = sockaddr.cast::<SOCKADDR_IN>();
                let octets = (*addr).sin_addr.S_un.S_addr.to_ne_bytes();
                Some(IpAddr::V4(Ipv4Addr::from(octets)))
            }
            windows_sys::Win32::Networking::WinSock::AF_INET6 => {
                let addr = sockaddr.cast::<SOCKADDR_IN6>();
                let octets = (*addr).sin6_addr.u.Byte;
                if octets[0] == 0xfe && octets[1] == 0xc0 {
                    return None;
                }
                Some(IpAddr::V6(Ipv6Addr::from(octets)))
            }
            _ => None,
        }
    }
}
