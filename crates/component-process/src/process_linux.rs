use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::mem::{offset_of, size_of};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::FromRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use anyhow::anyhow;

use super::process::ProcessError;

pub const SOCK_DIAG_BY_FAMILY: u16 = 20;

pub(crate) const INET_DIAG_REQUEST_SIZE: usize = size_of::<InetDiagRequest>();
pub(crate) const INET_DIAG_RESPONSE_SIZE: usize = size_of::<InetDiagResponse>();

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct InetDiagRequest {
    pub(crate) family: u8,
    pub(crate) protocol: u8,
    pub(crate) ext: u8,
    pub(crate) pad: u8,
    pub(crate) states: u32,
    pub(crate) src_port: [u8; 2],
    pub(crate) dst_port: [u8; 2],
    pub(crate) src: [u8; 16],
    pub(crate) dst: [u8; 16],
    pub(crate) if_: u32,
    pub(crate) cookie: [u32; 2],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct InetDiagResponse {
    pub(crate) family: u8,
    pub(crate) state: u8,
    pub(crate) timer: u8,
    pub(crate) re_trans: u8,
    pub(crate) src_port: [u8; 2],
    pub(crate) dst_port: [u8; 2],
    pub(crate) src: [u8; 16],
    pub(crate) dst: [u8; 16],
    pub(crate) if_: u32,
    pub(crate) cookie: [u32; 2],
    pub(crate) expires: u32,
    pub(crate) r_queue: u32,
    pub(crate) w_queue: u32,
    pub(crate) uid: u32,
    pub(crate) inode: u32,
}

impl InetDiagRequest {
    pub(crate) fn to_bytes(self) -> [u8; INET_DIAG_REQUEST_SIZE] {
        let mut buf = [0u8; INET_DIAG_REQUEST_SIZE];
        buf[offset_of!(Self, family)] = self.family;
        buf[offset_of!(Self, protocol)] = self.protocol;
        buf[offset_of!(Self, ext)] = self.ext;
        buf[offset_of!(Self, pad)] = self.pad;
        write_ne_u32(&mut buf, offset_of!(Self, states), self.states);
        set_bytes(&mut buf, offset_of!(Self, src_port), &self.src_port);
        set_bytes(&mut buf, offset_of!(Self, dst_port), &self.dst_port);
        set_bytes(&mut buf, offset_of!(Self, src), &self.src);
        set_bytes(&mut buf, offset_of!(Self, dst), &self.dst);
        write_ne_u32(&mut buf, offset_of!(Self, if_), self.if_);
        write_ne_u32(&mut buf, offset_of!(Self, cookie), self.cookie[0]);
        write_ne_u32(&mut buf, offset_of!(Self, cookie) + size_of::<u32>(), self.cookie[1]);
        buf
    }
}

/// Read natively from the raw buffer.
impl InetDiagResponse {
    pub(crate) fn from_bytes(data: &[u8]) -> Self {
        let cookie = offset_of!(Self, cookie);
        Self {
            family: read_byte(data, offset_of!(Self, family)),
            state: read_byte(data, offset_of!(Self, state)),
            timer: read_byte(data, offset_of!(Self, timer)),
            re_trans: read_byte(data, offset_of!(Self, re_trans)),
            src_port: read_pair(data, offset_of!(Self, src_port)),
            dst_port: read_pair(data, offset_of!(Self, dst_port)),
            src: read_16(data, offset_of!(Self, src)),
            dst: read_16(data, offset_of!(Self, dst)),
            if_: read_ne_u32(data, offset_of!(Self, if_)),
            cookie: [read_ne_u32(data, cookie), read_ne_u32(data, cookie + size_of::<u32>())],
            expires: read_ne_u32(data, offset_of!(Self, expires)),
            r_queue: read_ne_u32(data, offset_of!(Self, r_queue)),
            w_queue: read_ne_u32(data, offset_of!(Self, w_queue)),
            uid: read_ne_u32(data, offset_of!(Self, uid)),
            inode: read_ne_u32(data, offset_of!(Self, inode)),
        }
    }
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "libc's AF_INET is 2 on every supported target, so the family byte is exact"
)]
const AF_INET: u8 = libc::AF_INET as u8;
#[expect(
    clippy::cast_possible_truncation,
    reason = "libc's AF_INET6 is 10 on every supported target, so the family byte is exact"
)]
const AF_INET6: u8 = libc::AF_INET6 as u8;

const NETLINK_INET_DIAG: i32 = 4;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLMSG_HEADER_SIZE: usize = 16;
const NLMSG_ALIGNTO: usize = 4;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_DUMP: u16 = 0x300;
const NETLINK_READ_SIZE: usize = 32 * 1024;

/// Stand-in for the netlink conn methods used here: a bound `NETLINK_INET_DIAG` socket whose fd
/// closes with the value.
struct NetlinkConn {
    file: File,
    sequence: u32,
}

impl NetlinkConn {
    fn dial() -> io::Result<Self> {
        Ok(Self { file: open_netlink_socket(NETLINK_INET_DIAG)?, sequence: 0 })
    }

    /// For a dump request: send the message, then read the
    /// multipart replies until the terminating `NLMSG_DONE`.
    fn execute(&mut self, type_: u16, flags: u16, data: &[u8]) -> io::Result<Vec<Vec<u8>>> {
        self.sequence += 1;
        let length = NLMSG_HEADER_SIZE + data.len();
        let length_field = u32::try_from(length).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "netlink: message length exceeds the header field")
        })?;
        let mut frame = Vec::with_capacity(length + NLMSG_ALIGNTO);
        frame.extend_from_slice(&length_field.to_ne_bytes());
        frame.extend_from_slice(&type_.to_ne_bytes());
        frame.extend_from_slice(&flags.to_ne_bytes());
        frame.extend_from_slice(&self.sequence.to_ne_bytes());
        frame.extend_from_slice(&0u32.to_ne_bytes());
        frame.extend_from_slice(data);
        while !frame.len().is_multiple_of(NLMSG_ALIGNTO) {
            frame.push(0);
        }
        self.file.write_all(&frame)?;

        let mut pending: Vec<u8> = Vec::new();
        let mut buf = vec![0u8; NETLINK_READ_SIZE];
        let mut messages = Vec::new();
        loop {
            let mut consumed = 0;
            while pending.len() - consumed >= NLMSG_HEADER_SIZE {
                let length = read_ne_u32(&pending, consumed) as usize;
                if length < NLMSG_HEADER_SIZE {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "netlink: invalid message length"));
                }
                if pending.len() - consumed < length {
                    break;
                }
                let type_ = read_pair(&pending, consumed + size_of::<u32>());
                let payload = pending
                    .get(consumed + NLMSG_HEADER_SIZE..consumed + length)
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "netlink: truncated message"))?;
                match u16::from_ne_bytes(type_) {
                    NLMSG_ERROR => {
                        if payload.len() >= size_of::<u32>() {
                            let code = read_ne_u32(payload, 0).cast_signed();
                            if code != 0 {
                                return Err(io::Error::from_raw_os_error(-code));
                            }
                        }
                    }
                    NLMSG_DONE => return Ok(messages),
                    _ => messages.push(payload.to_vec()),
                }
                consumed += length.div_ceil(NLMSG_ALIGNTO) * NLMSG_ALIGNTO;
            }
            pending.drain(..consumed);
            let n = self.file.read(&mut buf)?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "netlink: socket closed"));
            }
            let chunk =
                buf.get(..n).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "netlink: short read"))?;
            pending.extend_from_slice(chunk);
        }
    }
}

#[allow(unsafe_code)]
fn open_netlink_socket(family: i32) -> io::Result<File> {
    // SAFETY: `socket(2)` is called with a valid family, socket type and protocol; the returned
    // descriptor is checked before anything else uses it.
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, family) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: `addr` is zeroed and fully initialised before `bind(2)` reads it; a port id of 0 asks
    // the kernel to assign one, as a netlink dial does.
    let ret = unsafe {
        let mut addr: libc::sockaddr_nl = std::mem::zeroed();
        #[expect(
            clippy::cast_possible_truncation,
            reason = "libc's AF_NETLINK is 16 on every supported target, so the family field is exact"
        )]
        let nl_family = libc::AF_NETLINK as libc::sa_family_t;
        addr.nl_family = nl_family;
        addr.nl_pid = 0;
        #[expect(
            clippy::cast_possible_truncation,
            reason = "the sockaddr length field is 32 bits by definition and the address is 12 bytes"
        )]
        let addr_len = size_of::<libc::sockaddr_nl>() as libc::socklen_t;
        libc::bind(fd, std::ptr::addr_of!(addr).cast(), addr_len)
    };
    if ret < 0 {
        let err = io::Error::last_os_error();
        // SAFETY: `fd` is the live descriptor created above and nothing else owns it yet.
        unsafe { libc::close(fd) };
        return Err(err);
    }

    // SAFETY: `fd` is a live descriptor that nothing else owns.
    Ok(unsafe { File::from_raw_fd(fd) })
}

pub(crate) fn find_process_name(network: &str, ip: Option<IpAddr>, src_port: i32) -> anyhow::Result<(u32, String)> {
    let mut resolved = resolve_socket_by_netlink(network, ip, src_port);
    if cfg!(target_os = "android") {
        // on Android (especially recent releases), netlink INET_DIAG can fail or return UID 0 / empty process info for some apps
        // so trying fallback to resolve /proc/net/{tcp,tcp6,udp,udp6}
        match resolved {
            Err(_) => resolved = resolve_socket_by_proc_fs(network, ip, src_port),
            Ok((0, _)) => {
                if let Ok((p_uid, p_inode)) = resolve_socket_by_proc_fs(network, ip, src_port) {
                    if p_uid != 0 {
                        resolved = Ok((p_uid, p_inode));
                    }
                }
            }
            Ok(_) => {}
        }
    }
    let (uid, inode) = resolved?;

    let mut pp = resolve_process_name_by_proc_search(inode, uid);
    if cfg!(target_os = "android") {
        // if inode-based /proc/<pid>/fd resolution fails but UID is known,
        // fall back to resolving the process/package name by UID (typical on Android where all app processes share one UID).
        if pp.is_err() && uid != 0 {
            pp = resolve_process_name_by_uid(uid);
        }
    }
    Ok((uid, pp?))
}

pub(crate) fn resolve_socket_by_netlink(
    network: &str,
    ip: Option<IpAddr>,
    src_port: i32,
) -> anyhow::Result<(u32, u32)> {
    let mut request = InetDiagRequest {
        family: 0,
        protocol: 0,
        ext: 0,
        pad: 0,
        states: 0xffffffff,
        src_port: [0; 2],
        dst_port: [0; 2],
        src: [0; 16],
        dst: [0; 16],
        if_: 0,
        cookie: [0xffffffff, 0xffffffff],
    };

    if matches!(ip, Some(IpAddr::V4(_))) {
        request.family = AF_INET;
    } else {
        request.family = AF_INET6;
    }

    if network.starts_with("tcp") {
        request.protocol = u8::try_from(libc::IPPROTO_TCP)?;
    } else if network.starts_with("udp") {
        request.protocol = u8::try_from(libc::IPPROTO_UDP)?;
    } else {
        return Err(ProcessError::InvalidNetwork.into());
    }

    match ip {
        Some(IpAddr::V4(v4)) => {
            if let Some(dst) = request.src.get_mut(..4) {
                dst.copy_from_slice(&v4.octets());
            }
        }
        Some(IpAddr::V6(v6)) => request.src.copy_from_slice(&v6.octets()),
        None => {}
    }

    request.src_port.copy_from_slice(&port_u16(src_port).to_be_bytes());

    let mut conn = NetlinkConn::dial()?;
    let messages = conn.execute(SOCK_DIAG_BY_FAMILY, NLM_F_REQUEST | NLM_F_DUMP, &request.to_bytes())?;

    let mut uid = 0;
    let mut inode = 0;
    let mut err = Some(ProcessError::NotFound);
    for msg in &messages {
        if msg.len() < INET_DIAG_RESPONSE_SIZE {
            continue;
        }

        let response = InetDiagResponse::from_bytes(msg);

        // always set to allow fallback when check fails
        uid = response.uid;
        inode = response.inode;
        err = None;

        // check src port
        if u16::from_be_bytes(response.src_port) != port_u16(src_port) {
            continue;
        }

        // check src IP
        let src = match response.family {
            AF_INET => {
                let octets = response.src.get(..4).and_then(|b| <[u8; 4]>::try_from(b).ok());
                octets.map(Ipv4Addr::from).map(IpAddr::V4)
            }
            AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(response.src))),
            _ => None,
        };
        let Some(src) = src else { continue };
        if Some(unmap(src)) != ip.map(unmap) {
            continue;
        }

        // this is the one we want
        break;
    }

    match err {
        Some(err) => Err(err.into()),
        None => Ok((uid, inode)),
    }
}

pub(crate) fn resolve_process_name_by_proc_search(inode: u32, uid: u32) -> anyhow::Result<String> {
    let files = read_dir_sorted(Path::new("/proc"))?;

    let socket = format!("socket:[{inode}]").into_bytes();

    for f in files {
        if !f.file_type().is_ok_and(|t| t.is_dir()) || !is_pid(&f.file_name().to_string_lossy()) {
            continue;
        }

        let info = f.metadata()?;
        if info.uid() != uid {
            continue;
        }

        let process_path = Path::new("/proc").join(f.file_name());
        let fd_path = process_path.join("fd");

        let Ok(fds) = read_dir_sorted(&fd_path) else { continue };

        for fd in fds {
            let Ok(target) = fs::read_link(fd_path.join(fd.file_name())) else { continue };

            if target.as_os_str().as_bytes() != socket.as_slice() {
                continue;
            }

            if cfg!(target_os = "android") {
                let cmdline = fs::read(process_path.join("cmdline"))?;
                return Ok(split_cmdline(&cmdline));
            }
            return Ok(os_string(&fs::read_link(process_path.join("exe"))?));
        }
    }

    Err(anyhow!("process of uid({uid}),inode({inode}) not found"))
}

/// Returns a process name for any process with uid.
/// On Android all processes of one app share the same UID; used when inode
/// lookup fails (socket closed / `TIME_WAIT`).
pub(crate) fn resolve_process_name_by_uid(uid: u32) -> anyhow::Result<String> {
    let files = read_dir_sorted(Path::new("/proc"))?;

    for f in files {
        if !f.file_type().is_ok_and(|t| t.is_dir()) || !is_pid(&f.file_name().to_string_lossy()) {
            continue;
        }

        let Ok(info) = f.metadata() else { continue };
        if info.uid() != uid {
            continue;
        }

        let process_path = Path::new("/proc").join(f.file_name());
        if cfg!(target_os = "android") {
            let Ok(cmdline) = fs::read(process_path.join("cmdline")) else { continue };
            let name = split_cmdline(&cmdline);
            if !name.is_empty() {
                return Ok(name);
            }
        } else if let Ok(exe) = fs::read_link(process_path.join("exe")) {
            return Ok(os_string(&exe));
        }
    }

    Err(anyhow!("no process found with uid {uid}"))
}

pub(crate) fn split_cmdline(cmdline: &[u8]) -> String {
    let cmdline = trim_spaces(cmdline);

    let idx = first_delimiter(cmdline);

    match idx {
        None => base_name(cmdline),
        Some(idx) => base_name(cmdline.get(..idx).unwrap_or_default()),
    }
}

/// Scans over a control-or-space rune, answering a byte offset. An invalid byte
/// decodes to U+FFFD, which is neither, so the scan steps over it.
fn first_delimiter(bytes: &[u8]) -> Option<usize> {
    let mut offset = 0;
    while offset < bytes.len() {
        let rest = bytes.get(offset..)?;
        let (len, delimiter) = match std::str::from_utf8(rest) {
            Ok(text) => {
                let r = text.chars().next()?;
                (r.len_utf8(), r.is_control() || r.is_whitespace())
            }
            Err(err) if err.valid_up_to() > 0 => {
                let text = std::str::from_utf8(rest.get(..err.valid_up_to())?).ok()?;
                let r = text.chars().next()?;
                (r.len_utf8(), r.is_control() || r.is_whitespace())
            }
            Err(_) => (1, false),
        };
        if delimiter {
            return Some(offset);
        }
        offset += len;
    }
    None
}

pub(crate) fn is_pid(s: &str) -> bool {
    s.chars().all(|r| r.is_ascii_digit())
}

/// Finds UID and inode from /proc/net/{tcp,tcp6,udp,udp6}.
/// In TUN mode metadata sourceIP is often the gateway (e.g. fake-ip range), not
/// the socket's real local address; we match by local port first and prefer
/// exact IP+port when it matches.
pub(crate) fn resolve_socket_by_proc_fs(
    network: &str,
    ip: Option<IpAddr>,
    src_port: i32,
) -> anyhow::Result<(u32, u32)> {
    let proto = if network.starts_with("tcp") {
        "tcp"
    } else if network.starts_with("udp") {
        "udp"
    } else {
        return Err(ProcessError::InvalidNetwork.into());
    };

    let target_port = port_u16(src_port);
    let unmapped = ip.map(unmap);
    let files = [format!("/proc/net/{proto}"), format!("/proc/net/{proto}6")];

    let mut best_uid = 0;
    let mut best_inode = 0;
    let mut found = false;

    for path in files {
        let is_v6 = path.ends_with('6');

        let match_ip = if let Some(IpAddr::V4(v4)) = unmapped {
            if is_v6 {
                Some(IpAddr::V6(v4.to_ipv6_mapped()))
            } else {
                Some(IpAddr::V4(v4))
            }
        } else {
            if !is_v6 {
                continue;
            }
            unmapped
        };

        let Ok((uid, inode, exact)) = search_proc_net_file_by_port(&path, match_ip, target_port) else {
            continue;
        };

        if exact {
            return Ok((uid, inode));
        }

        if !found || (best_uid == 0 && uid != 0) {
            best_uid = uid;
            best_inode = inode;
            found = true;
        }
    }

    if found {
        return Ok((best_uid, best_inode));
    }
    Err(ProcessError::NotFound.into())
}

/// Scans /proc/net/* for `local_address` matching targetPort.
/// Exact IP+port wins; else port-only (skips inode==0 entries used by `TIME_WAIT`).
pub(crate) fn search_proc_net_file_by_port(
    path: &str,
    target_ip: Option<IpAddr>,
    target_port: u16,
) -> anyhow::Result<(u32, u32, bool)> {
    let f = File::open(path)?;

    let is_v6 = path.ends_with('6');
    let mut lines = BufReader::new(f).lines();

    if lines.next().is_none() {
        return Err(ProcessError::NotFound.into());
    }

    let mut best_uid = 0;
    let mut best_inode = 0;
    let mut found = false;

    for line in lines {
        let Ok(line) = line else { break };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let fields: Vec<&str> = line.split_whitespace().collect();
        let [_, local_address, _, _, _, _, _, uid, _, inode, ..] = fields.as_slice() else {
            continue;
        };

        let Ok((line_ip, line_port)) = parse_hex_addr_port(local_address, is_v6) else {
            continue;
        };
        if line_port != target_port {
            continue;
        }

        let Ok(line_uid) = uid.parse::<u32>() else { continue };
        let Ok(line_inode) = inode.parse::<u32>() else { continue };

        if Some(line_ip) == target_ip {
            return Ok((line_uid, line_inode, true));
        }

        if line_inode == 0 {
            continue;
        }

        if !found || (best_uid == 0 && line_uid != 0) {
            best_uid = line_uid;
            best_inode = line_inode;
            found = true;
        }
    }

    if found {
        return Ok((best_uid, best_inode, false));
    }
    Err(ProcessError::NotFound.into())
}

pub(crate) fn parse_hex_addr_port(s: &str, is_v6: bool) -> anyhow::Result<(IpAddr, u16)> {
    let Some((address, port)) = s.split_once(':') else {
        return Err(anyhow!("invalid addr:port: {s}"));
    };

    let port = u16::from_str_radix(port, 16)?;

    let addr = if is_v6 { parse_hex_ipv6(address) } else { parse_hex_ipv4(address) };
    Ok((addr?, port))
}

pub(crate) fn parse_hex_ipv4(s: &str) -> anyhow::Result<IpAddr> {
    if s.len() != 8 {
        return Err(anyhow!("invalid ipv4 hex len: {}", s.len()));
    }
    let b = hex::decode(s)?;
    let Ok([b0, b1, b2, b3]) = <[u8; 4]>::try_from(b.as_slice()) else {
        return Err(anyhow!("invalid ipv4 hex len: {}", s.len()));
    };
    let ip = if LITTLE_ENDIAN { [b3, b2, b1, b0] } else { [b0, b1, b2, b3] };
    Ok(IpAddr::V4(Ipv4Addr::from(ip)))
}

pub(crate) fn parse_hex_ipv6(s: &str) -> anyhow::Result<IpAddr> {
    if s.len() != 32 {
        return Err(anyhow!("invalid ipv6 hex len: {}", s.len()));
    }
    let mut ip = [0u8; 16];
    for (dst, chunk) in ip.chunks_exact_mut(4).zip(s.as_bytes().chunks_exact(8)) {
        let decoded = hex::decode(chunk)?;
        let Ok([b0, b1, b2, b3]) = <[u8; 4]>::try_from(decoded.as_slice()) else {
            continue;
        };
        if LITTLE_ENDIAN {
            dst.copy_from_slice(&[b3, b2, b1, b0]);
        } else {
            dst.copy_from_slice(&[b0, b1, b2, b3]);
        }
    }
    Ok(IpAddr::V6(Ipv6Addr::from(ip)))
}

pub(crate) const LITTLE_ENDIAN: bool = cfg!(target_endian = "little");

fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        IpAddr::V4(v4) => IpAddr::V4(v4),
    }
}

/// Narrows a source port to the protocol's 16-bit port field.
#[expect(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the port field is 16 bits by definition of the protocol and the argument is a socket port"
)]
fn port_u16(port: i32) -> u16 {
    port as u16
}

/// Reads a byte at `offset`; a short buffer reads as zero, which the callers exclude by checking
/// the response size first.
fn read_byte(data: &[u8], offset: usize) -> u8 {
    data.get(offset).copied().unwrap_or_default()
}

fn read_ne_u32(data: &[u8], offset: usize) -> u32 {
    data.get(offset..offset + 4).and_then(|b| <[u8; 4]>::try_from(b).ok()).map_or(0, u32::from_ne_bytes)
}

fn write_ne_u32(data: &mut [u8], offset: usize, value: u32) {
    if let Some(slot) = data.get_mut(offset..offset + 4).and_then(|b| <&mut [u8; 4]>::try_from(b).ok()) {
        *slot = value.to_ne_bytes();
    }
}

/// Writes a fixed-width field at its wire offset; `offset_of!` keeps the offset inside a buffer
/// sized by `size_of` of the same struct.
fn set_bytes(data: &mut [u8], offset: usize, value: &[u8]) {
    if let Some(slot) = data.get_mut(offset..offset + value.len()) {
        slot.copy_from_slice(value);
    }
}

fn read_pair(data: &[u8], offset: usize) -> [u8; 2] {
    data.get(offset..offset + 2).and_then(|b| <[u8; 2]>::try_from(b).ok()).unwrap_or_default()
}

fn read_16(data: &[u8], offset: usize) -> [u8; 16] {
    data.get(offset..offset + 16).and_then(|b| <[u8; 16]>::try_from(b).ok()).unwrap_or_default()
}

fn os_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Entries sorted by filename; `fs::read_dir` yields readdir order.
fn read_dir_sorted(path: &Path) -> io::Result<Vec<fs::DirEntry>> {
    let mut entries: Vec<fs::DirEntry> = fs::read_dir(path)?.collect::<io::Result<Vec<_>>>()?;
    entries.sort_unstable_by_key(fs::DirEntry::file_name);
    Ok(entries)
}

fn trim_spaces(cmdline: &[u8]) -> &[u8] {
    let start = cmdline.iter().position(|b| *b != b' ').unwrap_or(cmdline.len());
    let end = cmdline.iter().rposition(|b| *b != b' ').map_or(start, |i| i + 1);
    cmdline.get(start..end).unwrap_or_default()
}

fn base_name(path: &[u8]) -> String {
    let Some(&first) = path.first() else {
        return ".".to_owned();
    };

    let mut end = path.len();
    while end > 1 && path.get(end - 1) == Some(&b'/') {
        end -= 1;
    }
    if end == 1 && first == b'/' {
        return "/".to_owned();
    }

    let head = path.get(..end).unwrap_or_default();
    let start = head.iter().rposition(|b| *b == b'/').map_or(0, |i| i + 1);
    String::from_utf8_lossy(path.get(start..end).unwrap_or_default()).into_owned()
}
