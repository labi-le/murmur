use std::mem::size_of;

use anyhow::{anyhow, Result};

use super::{einval, FdGuard};

/// A netlink message header.
#[derive(Clone, Copy, Debug, Default)]
pub struct NlMsghdr {
    pub len: u32,
    pub type_: u16,
    pub flags: u16,
    pub seq: u32,
    pub pid: u32,
}

/// A netlink route message header.
#[derive(Clone, Copy, Debug, Default)]
pub struct RtGenmsg {
    pub family: u8,
}

/// A netlink route attribute.
#[derive(Clone, Copy, Debug, Default)]
pub struct RtAttr {
    pub len: u16,
    pub type_: u16,
}

/// A netlink socket address; the trailing pad keeps the C layout.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SockaddrNl {
    pub family: u16,
    pub pad: u16,
    pub pid: u32,
    pub groups: u32,
}

/// `NetlinkRouteRequest` represents a request message to receive routing and link states from the
/// kernel.
#[derive(Clone, Copy, Debug, Default)]
pub struct NetlinkRouteRequest {
    pub header: NlMsghdr,
    pub data: RtGenmsg,
}

/// `NetlinkMessage` represents a netlink message.
#[derive(Clone, Copy, Debug)]
pub struct NetlinkMessage<'a> {
    pub header: NlMsghdr,
    pub data: &'a [u8],
}

/// `NetlinkRouteAttr` represents a netlink route attribute.
#[derive(Clone, Copy, Debug)]
pub struct NetlinkRouteAttr<'a> {
    pub attr: RtAttr,
    pub value: &'a [u8],
}

pub(crate) const NLMSG_HDRLEN: usize = 16;
const NLMSG_ALIGNTO: usize = 4;
const RTA_ALIGNTO: usize = 4;
const SIZEOF_RTGENMSG: usize = 1;
pub(crate) const SIZEOF_IFADDRMSG: usize = 8;
const SIZEOF_IFINFOMSG: usize = 16;
const SIZEOF_RTMSG: usize = 12;
pub(crate) const SIZEOF_RTATTR: usize = 4;

const NLM_F_REQUEST: u16 = 1;
const NLM_F_DUMP: u16 = 0x300;

pub(crate) const NLMSG_ERROR: u16 = 2;
pub(crate) const NLMSG_DONE: u16 = 3;

pub(crate) const RTM_NEWLINK: u16 = 16;
pub(crate) const RTM_DELLINK: u16 = 17;
pub(crate) const RTM_NEWADDR: u16 = 20;
pub(crate) const RTM_DELADDR: u16 = 21;
pub(crate) const RTM_GETADDR: i32 = 22;
pub(crate) const RTM_NEWROUTE: u16 = 24;
pub(crate) const RTM_DELROUTE: u16 = 25;

pub(crate) const IFA_ADDRESS: u16 = 1;
pub(crate) const IFA_LOCAL: u16 = 2;

const NETLINK_ROUTE: i32 = 0;

fn last_os_error() -> anyhow::Error {
    anyhow!(std::io::Error::last_os_error())
}

fn nlm_align_of(msglen: usize) -> usize {
    (msglen + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1)
}

fn rta_align_of(attrlen: usize) -> usize {
    (attrlen + RTA_ALIGNTO - 1) & !(RTA_ALIGNTO - 1)
}

impl NetlinkRouteRequest {
    fn to_wire_format(&self) -> Vec<u8> {
        let mut b = vec![0u8; self.header.len as usize];
        b[0..4].copy_from_slice(&self.header.len.to_ne_bytes());
        b[4..6].copy_from_slice(&self.header.type_.to_ne_bytes());
        b[6..8].copy_from_slice(&self.header.flags.to_ne_bytes());
        b[8..12].copy_from_slice(&self.header.seq.to_ne_bytes());
        b[12..16].copy_from_slice(&self.header.pid.to_ne_bytes());
        b[16] = self.data.family;
        b
    }
}

fn new_netlink_route_request(proto: i32, seq: i32, family: i32) -> Vec<u8> {
    let rr = NetlinkRouteRequest {
        header: NlMsghdr {
            len: (NLMSG_HDRLEN + SIZEOF_RTGENMSG) as u32,
            type_: proto as u16,
            flags: NLM_F_DUMP | NLM_F_REQUEST,
            seq: seq as u32,
            pid: 0,
        },
        data: RtGenmsg { family: family as u8 },
    };
    rr.to_wire_format()
}

#[expect(unsafe_code, reason = "`socket` is a raw syscall with no safe wrapper in std")]
fn open_netlink_socket() -> Result<i32> {
    // SAFETY: a plain socket(2) call, no pointers handed over.
    let s = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, NETLINK_ROUTE) };
    if s < 0 {
        return Err(last_os_error());
    }
    Ok(s)
}

#[expect(
    unsafe_code,
    reason = "`sendto` is a raw syscall; the SAFETY comment below states the buffer and address invariants"
)]
fn send_to(s: i32, buf: &[u8], sa: &SockaddrNl) -> Result<usize> {
    // SAFETY: `buf` and `sa` outlive the call and are described by the pointers and length passed.
    let n = unsafe {
        libc::sendto(
            s,
            buf.as_ptr() as *const libc::c_void,
            buf.len(),
            0,
            sa as *const SockaddrNl as *const libc::sockaddr,
            size_of::<SockaddrNl>() as libc::socklen_t,
        )
    };
    if n < 0 {
        return Err(last_os_error());
    }
    Ok(n as usize)
}

#[expect(unsafe_code, reason = "`recv` is a raw syscall; the SAFETY comment below states the buffer invariant")]
fn recv_into(s: i32, buf: &mut [u8]) -> Result<usize> {
    // SAFETY: `buf` is exclusively borrowed for the duration of the call.
    let n = unsafe { libc::recv(s, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
    if n < 0 {
        return Err(last_os_error());
    }
    Ok(n as usize)
}

#[expect(
    unsafe_code,
    reason = "`getsockname` fills its result through an out-parameter, which safe Rust cannot express"
)]
fn sock_name(s: i32) -> Result<SockaddrNl> {
    let mut sa = SockaddrNl::default();
    let mut len = size_of::<SockaddrNl>() as libc::socklen_t;
    // SAFETY: `sa` is a live `sockaddr_nl` of the size handed to getsockname.
    let rc = unsafe { libc::getsockname(s, &mut sa as *mut SockaddrNl as *mut libc::sockaddr, &mut len) };
    if rc != 0 {
        return Err(last_os_error());
    }
    Ok(sa)
}

/// Returns routing information base, also known as RIB, which consists of network
/// facility information, states and parameters.
pub fn netlink_rib(proto: i32, family: i32) -> Result<Vec<u8>> {
    let s = open_netlink_socket()?;
    let _guard = FdGuard(s);

    let sa = SockaddrNl { family: libc::AF_NETLINK as u16, pad: 0, pid: 0, groups: 0 };
    let wb = new_netlink_route_request(proto, 1, family);
    send_to(s, &wb, &sa)?;

    let lsa = sock_name(s)?;
    let mut tab: Vec<u8> = Vec::new();
    let page_size = page_size();
    let mut rb = vec![0u8; page_size];
    loop {
        let nr = recv_into(s, &mut rb)?;
        if nr < NLMSG_HDRLEN {
            return Err(einval());
        }
        let chunk = &rb[..nr];
        tab.extend_from_slice(chunk);
        let msgs = parse_netlink_message(chunk)?;
        for m in &msgs {
            if m.header.seq != 1 || m.header.pid != lsa.pid {
                return Err(einval());
            }
            if m.header.type_ == NLMSG_DONE {
                return Ok(tab);
            }
            if m.header.type_ == NLMSG_ERROR {
                return Err(einval());
            }
        }
    }
}

#[expect(unsafe_code, reason = "`sysconf` has no safe wrapper in std")]
fn page_size() -> usize {
    // SAFETY: sysconf takes no pointers.
    let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if n <= 0 {
        4096
    } else {
        n as usize
    }
}

/// Parses `b` as an array of netlink messages and returns the slice
/// containing the `NetlinkMessage` structures.
pub fn parse_netlink_message<'a>(b: &'a [u8]) -> Result<Vec<NetlinkMessage<'a>>> {
    let mut msgs: Vec<NetlinkMessage<'a>> = Vec::new();
    let mut b = b;
    while b.len() >= NLMSG_HDRLEN {
        let (h, dbuf, dlen) = netlink_message_header_and_data(b)?;
        let data_len = (h.len as usize) - NLMSG_HDRLEN;
        msgs.push(NetlinkMessage { header: h, data: &dbuf[..data_len] });
        b = &b[dlen..];
    }
    Ok(msgs)
}

fn netlink_message_header_and_data(b: &[u8]) -> Result<(NlMsghdr, &[u8], usize)> {
    let Some(h) = nlmsghdr_from(b) else {
        return Err(einval());
    };
    let l = nlm_align_of(h.len as usize);
    if (h.len as usize) < NLMSG_HDRLEN || l > b.len() {
        return Err(einval());
    }
    Ok((h, &b[NLMSG_HDRLEN..], l))
}

fn nlmsghdr_from(b: &[u8]) -> Option<NlMsghdr> {
    if b.len() < NLMSG_HDRLEN {
        return None;
    }
    Some(NlMsghdr {
        len: u32::from_ne_bytes([b[0], b[1], b[2], b[3]]),
        type_: u16::from_ne_bytes([b[4], b[5]]),
        flags: u16::from_ne_bytes([b[6], b[7]]),
        seq: u32::from_ne_bytes([b[8], b[9], b[10], b[11]]),
        pid: u32::from_ne_bytes([b[12], b[13], b[14], b[15]]),
    })
}

/// Parses `m`'s payload as an array of netlink route attributes and
/// returns the slice containing the `NetlinkRouteAttr` structures.
pub fn parse_netlink_route_attr<'a>(m: &NetlinkMessage<'a>) -> Result<Vec<NetlinkRouteAttr<'a>>> {
    let b = match m.header.type_ {
        RTM_NEWLINK | RTM_DELLINK => m.data.get(SIZEOF_IFINFOMSG..),
        RTM_NEWADDR | RTM_DELADDR => m.data.get(SIZEOF_IFADDRMSG..),
        RTM_NEWROUTE | RTM_DELROUTE => m.data.get(SIZEOF_RTMSG..),
        _ => return Err(einval()),
    };
    let Some(mut b) = b else {
        return Err(einval());
    };
    let mut attrs: Vec<NetlinkRouteAttr<'a>> = Vec::new();
    while b.len() >= SIZEOF_RTATTR {
        let (a, vbuf, alen) = netlink_route_attr_and_value(b)?;
        attrs.push(NetlinkRouteAttr { attr: a, value: &vbuf[..(a.len as usize) - SIZEOF_RTATTR] });
        b = &b[alen..];
    }
    Ok(attrs)
}

fn netlink_route_attr_and_value(b: &[u8]) -> Result<(RtAttr, &[u8], usize)> {
    if b.len() < SIZEOF_RTATTR {
        return Err(einval());
    }
    let a = RtAttr { len: u16::from_ne_bytes([b[0], b[1]]), type_: u16::from_ne_bytes([b[2], b[3]]) };
    if (a.len as usize) < SIZEOF_RTATTR || (a.len as usize) > b.len() {
        return Err(einval());
    }
    Ok((a, &b[SIZEOF_RTATTR..], rta_align_of(a.len as usize)))
}
