//! The rtnetlink messages the TUN device needs to become a usable interface.
//!
//! The rtnetlink wire format is written by hand here, because the crate has no netlink dependency.
//! Only the messages a layer-3 device needs are built — `RTM_NEWADDR`, `RTM_NEWROUTE` and their
//! deletes — and every send is acknowledged, so a missing privilege surfaces as an error naming the
//! message rather than as traffic that silently goes nowhere.

use std::io;
use std::net::IpAddr;
use std::os::fd::RawFd;

use anyhow::{Context, Result};
use ipnet::IpNet;

const AF_NETLINK: libc::c_int = 16;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const NETLINK_ROUTE: libc::c_int = 0;

const NLMSG_ERROR: u16 = 2;

const NLM_F_REQUEST: u16 = 0x001;
const NLM_F_ACK: u16 = 0x004;
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_EXCL: u16 = 0x200;

const RTM_NEWADDR: u16 = 20;
const RTM_DELADDR: u16 = 21;
const RTM_NEWROUTE: u16 = 24;
const RTM_DELROUTE: u16 = 25;

const RTA_DST: u16 = 1;
const RTA_OIF: u16 = 4;

/// `RT_TABLE_MAIN`, so the routes this installs are the ones the kernel already consults and no
/// extra policy rule is needed. The default is a private table reached through `ip rule` entries,
/// which exist to keep the excluded ranges out of the TUN — a config asking for
/// those is rejected rather than silently half-applied.
const RT_TABLE_MAIN: u8 = 254;
const RTPROT_BOOT: u8 = 3;
const RT_SCOPE_UNIVERSE: u8 = 0;

const IFA_F_PERMANENT: u8 = 0x10;

const NLMSG_HDR_LEN: usize = 16;
const IFADDR_MSG_LEN: usize = 8;
const RTMSG_LEN: usize = 12;
const RTATTR_HDR_LEN: usize = 4;
/// Only acks and errors are ever read here, so a `PATH_MAX`-sized buffer is ample; a route dump
/// would need more, and none is ever asked for.
const RECV_BUFFER_LEN: usize = 8192;

fn family_of(addr: &IpAddr) -> u8 {
    if addr.is_ipv4() {
        AF_INET
    } else {
        AF_INET6
    }
}

fn addr_octets(addr: &IpAddr) -> Vec<u8> {
    match addr {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

/// A `struct nlmsghdr` plus the body it introduces, ready to send once the sequence number is
/// stamped in.
struct Message {
    kind: u16,
    bytes: Vec<u8>,
}

impl Message {
    #[expect(
        clippy::cast_possible_truncation,
        reason = "nlmsg_len is a 32-bit field by definition; the messages built here are tens of bytes"
    )]
    fn new(kind: u16, flags: u16, body: &[u8]) -> Self {
        let mut bytes = Vec::with_capacity(NLMSG_HDR_LEN + body.len());
        let message_len = (NLMSG_HDR_LEN + body.len()) as u32;
        bytes.extend_from_slice(&message_len.to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(&(flags | NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
        bytes.extend_from_slice(&0u32.to_ne_bytes());
        bytes.extend_from_slice(&0u32.to_ne_bytes());
        bytes.extend_from_slice(body);
        Self { kind, bytes }
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "rta_len is a 16-bit field by definition; the attribute values written here are 4 and 16 bytes"
    )]
    fn with_attr(mut self, attr: u16, value: &[u8]) -> Self {
        let attr_len = (RTATTR_HDR_LEN + value.len()) as u16;
        self.bytes.extend_from_slice(&attr_len.to_ne_bytes());
        self.bytes.extend_from_slice(&attr.to_ne_bytes());
        self.bytes.extend_from_slice(value);
        self
    }

    fn name(&self) -> &'static str {
        match self.kind {
            RTM_NEWADDR => "RTM_NEWADDR",
            RTM_DELADDR => "RTM_DELADDR",
            RTM_NEWROUTE => "RTM_NEWROUTE",
            RTM_DELROUTE => "RTM_DELROUTE",
            _ => "netlink request",
        }
    }
}

/// The `N`-byte field at `start` of a received netlink buffer; a buffer too short to hold it reads
/// as zero, which never compares equal to a live sequence number.
fn netlink_field<const N: usize>(buf: &[u8], start: usize) -> [u8; N] {
    buf.get(start..start + N).and_then(|field| <[u8; N]>::try_from(field).ok()).unwrap_or([0u8; N])
}

fn address_message(kind: u16, index: u32, addr: &IpAddr, prefix_len: u8, flags: u16) -> Message {
    let mut body = Vec::with_capacity(IFADDR_MSG_LEN + 24);
    body.push(family_of(addr));
    body.push(prefix_len);
    body.push(IFA_F_PERMANENT);
    body.push(0);
    body.extend_from_slice(&index.to_ne_bytes());
    Message::new(kind, flags, &body).with_attr(RTA_DST, &addr_octets(addr))
}

fn route_message(kind: u16, dst: &IpNet, index: u32, flags: u16) -> Message {
    let mut body = Vec::with_capacity(RTMSG_LEN + 24);
    body.push(family_of(&dst.addr()));
    body.push(dst.prefix_len());
    body.extend_from_slice(&[0, 0]);
    body.push(RT_TABLE_MAIN);
    body.push(RTPROT_BOOT);
    body.push(RT_SCOPE_UNIVERSE);
    body.push(1);
    body.extend_from_slice(&0u32.to_ne_bytes());
    Message::new(kind, flags, &body)
        .with_attr(RTA_OIF, &index.to_ne_bytes())
        .with_attr(RTA_DST, &addr_octets(&dst.addr()))
}

/// Adding an address that is already present is the state a restart re-creates, so it is
/// not an error; anything else is, because a TUN without its address carries nothing.
pub fn add_address(index: u32, addr: &IpAddr, prefix_len: u8) -> Result<()> {
    let message = address_message(RTM_NEWADDR, index, addr, prefix_len, NLM_F_CREATE | NLM_F_EXCL);
    match Socket::open()?.send(&message) {
        Ok(()) => Ok(()),
        Err(err) if err.downcast_ref::<io::Error>().is_some_and(|e| e.kind() == io::ErrorKind::AlreadyExists) => Ok(()),
        Err(err) => Err(err),
    }
}

pub fn del_address(index: u32, addr: &IpAddr, prefix_len: u8) -> Result<()> {
    Socket::open()?.send(&address_message(RTM_DELADDR, index, addr, prefix_len, 0))
}

pub fn add_route(dst: &IpNet, index: u32) -> Result<()> {
    Socket::open()?.send(&route_message(RTM_NEWROUTE, dst, index, NLM_F_CREATE | NLM_F_EXCL))
}

pub fn del_route(dst: &IpNet, index: u32) -> Result<()> {
    Socket::open()?.send(&route_message(RTM_DELROUTE, dst, index, 0))
}

/// A bound `NETLINK_ROUTE` socket. Binding is what makes the kernel route the acks back here, and
/// dropping the value is what releases the port.
struct Socket {
    fd: RawFd,
    seq: u32,
    local: libc::sockaddr_nl,
}

impl Socket {
    fn open() -> Result<Self> {
        let (fd, local) = open_socket()?;
        Ok(Self { fd, seq: 0, local })
    }

    #[expect(unsafe_code, reason = "libc::sendto over the message buffer and the bound address")]
    #[expect(
        clippy::cast_possible_truncation,
        reason = "sockaddr_nl is 12 bytes, far below the 32-bit socklen_t bound"
    )]
    fn send(&mut self, message: &Message) -> Result<()> {
        self.seq += 1;
        let seq = self.seq;
        let mut bytes = message.bytes.clone();
        let (_, after_lengths) = bytes.split_at_mut(8);
        let (seq_field, _) = after_lengths.split_at_mut(4);
        seq_field.copy_from_slice(&seq.to_ne_bytes());
        let len = bytes.len();
        let addr_len = size_of::<libc::sockaddr_nl>() as libc::socklen_t;
        // Safety: `bytes` is a live allocation of `len`, and `self.local` is the bound address
        // read back from the kernel when the socket was opened; both are only read for this call.
        let sent = unsafe {
            libc::sendto(
                self.fd,
                bytes.as_ptr().cast(),
                len,
                0,
                (&raw const self.local).cast::<libc::sockaddr>(),
                addr_len,
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error()).with_context(|| format!("send {}", message.name()));
        }
        self.await_ack(seq).with_context(|| message.name().to_owned())
    }

    #[expect(unsafe_code, reason = "libc::recv into the buffer, bounded by its length")]
    fn await_ack(&self, seq: u32) -> io::Result<()> {
        let mut buf = vec![0u8; RECV_BUFFER_LEN];
        loop {
            // Safety: `buf` is a live allocation of the length handed to the same call.
            let len = unsafe { libc::recv(self.fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
            if len < NLMSG_HDR_LEN.cast_signed() {
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
            let kind = u16::from_ne_bytes(netlink_field(&buf, 4));
            let msg_seq = u32::from_ne_bytes(netlink_field(&buf, 8));
            if kind != NLMSG_ERROR || msg_seq != seq {
                continue;
            }
            let code = i32::from_ne_bytes(netlink_field(&buf, NLMSG_HDR_LEN));
            return if code == 0 { Ok(()) } else { Err(io::Error::from_raw_os_error(-code)) };
        }
    }
}

impl Drop for Socket {
    #[expect(unsafe_code, reason = "closes the descriptor this value owns")]
    fn drop(&mut self) {
        // Safety: `fd` is owned by this value and closed exactly once, here.
        unsafe { libc::close(self.fd) };
    }
}

#[expect(unsafe_code, reason = "libc::socket/bind/getsockname on live locals")]
#[expect(
    clippy::cast_possible_truncation,
    reason = "AF_NETLINK is 16, which fits the 16-bit nl_family field, and sockaddr_nl is 12 bytes, far below the 32-bit socklen_t bound"
)]
fn open_socket() -> Result<(RawFd, libc::sockaddr_nl)> {
    // Safety: every pointer below points at a live local of the stated type and length, the file
    // descriptor is checked before use, and `fd` is closed on every path that does not return it.
    unsafe {
        let fd = libc::socket(AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, NETLINK_ROUTE);
        if fd < 0 {
            return Err(io::Error::last_os_error()).context("socket(AF_NETLINK)");
        }
        let mut bind_addr: libc::sockaddr_nl = std::mem::zeroed();
        bind_addr.nl_family = AF_NETLINK as libc::c_ushort;
        // Port 0 asks the kernel to pick one; `getsockname` below reads back what it chose, which
        // is the address the acks have to be sent to.
        let addr_len = size_of::<libc::sockaddr_nl>() as libc::socklen_t;
        if libc::bind(fd, (&raw const bind_addr).cast(), addr_len) < 0 {
            let err = io::Error::last_os_error();
            libc::close(fd);
            return Err(err).context("bind(AF_NETLINK)");
        }
        let mut local: libc::sockaddr_nl = std::mem::zeroed();
        let mut len = size_of::<libc::sockaddr_nl>() as libc::socklen_t;
        if libc::getsockname(fd, (&raw mut local).cast(), &raw mut len) < 0 {
            let err = io::Error::last_os_error();
            libc::close(fd);
            return Err(err).context("getsockname(AF_NETLINK)");
        }
        Ok((fd, local))
    }
}
