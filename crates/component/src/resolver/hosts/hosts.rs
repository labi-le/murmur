use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::LazyLock;

use chrono::{DateTime, TimeDelta, Utc};
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;

pub(crate) static HOSTS_FILE_PATH: LazyLock<String> = LazyLock::new(default_hosts_file_path);

const CACHE_MAX_AGE: TimeDelta = TimeDelta::seconds(5);

const DATA_CAPACITY: usize = 64 * 1024;

#[cfg(target_os = "windows")]
fn default_hosts_file_path() -> String {
    super::hosts_windows::system_hosts_file_path()
}

#[cfg(not(target_os = "windows"))]
fn default_hosts_file_path() -> String {
    "/etc/hosts".to_owned()
}

pub(crate) fn parse_literal_ip(addr: &str) -> String {
    match addr.parse::<IpAddr>() {
        Ok(ip) => ip.to_string(),
        Err(_) => match addr.split_once('%') {
            Some((base, zone)) if !zone.is_empty() => match base.parse::<Ipv6Addr>() {
                Ok(ip) => format!("{ip}%{zone}"),
                Err(_) => String::new(),
            },
            _ => String::new(),
        },
    }
}

#[derive(Debug)]
pub(crate) struct ByName {
    addrs: Vec<String>,
    canonical_name: String,
}

/// The known host entries; the `Mutex` wrapping this state is the lock over them.
#[derive(Debug)]
pub(crate) struct Hosts {
    /// Key for the list of literal IP addresses must be a host name. It would be
    /// part of DNS labels, a FQDN or an absolute FQDN; for now the key is
    /// converted to lower case for convenience.
    by_name: HashMap<String, ByName>,

    /// Key for the list of host names must be a literal IP address including
    /// IPv6 address with zone identifier. Old-classful IP address notation is
    /// not supported.
    by_addr: HashMap<String, Vec<String>>,

    expire: DateTime<Utc>,
    path: String,
    mtime: DateTime<Utc>,
    size: i64,
}

impl Default for Hosts {
    fn default() -> Self {
        Self {
            by_name: HashMap::new(),
            by_addr: HashMap::new(),
            expire: DateTime::<Utc>::MIN_UTC,
            path: String::new(),
            mtime: DateTime::<Utc>::MIN_UTC,
            size: 0,
        }
    }
}

pub(crate) static HOSTS: LazyLock<Mutex<Hosts>> = LazyLock::new(|| Mutex::new(Hosts::default()));

pub(crate) async fn read_hosts(state: &mut Hosts) {
    let now = Utc::now();
    let hp = (*HOSTS_FILE_PATH).clone();
    let expire = now + CACHE_MAX_AGE;

    if now < state.expire && state.path == hp && !state.by_name.is_empty() {
        return;
    }
    let (mtime, size) = match stat(&hp).await {
        Ok((mtime, size)) => {
            if state.path == hp && state.mtime == mtime && state.size == size {
                state.expire = expire;
                return;
            }
            (mtime, size)
        }
        Err(_) => (DateTime::<Utc>::MIN_UTC, 0),
    };

    let mut hs: HashMap<String, ByName> = HashMap::new();
    let mut is: HashMap<String, Vec<String>> = HashMap::new();

    let file = match open(&hp).await {
        Ok(file) => Some(file),
        Err(err) => {
            if !matches!(err.kind(), ErrorKind::NotFound | ErrorKind::PermissionDenied) {
                return;
            }
            None
        }
    };

    if let Some(mut file) = file {
        while let Some(mut line) = file.read_line().await {
            if let Some(i) = line.find('#') {
                // Discard comments.
                line.truncate(i);
            }
            let f = get_fields(&line);
            let [addr_field, rest @ ..] = f.as_slice() else {
                continue;
            };
            if rest.is_empty() {
                continue;
            }
            let addr = parse_literal_ip(addr_field);
            if addr.is_empty() {
                continue;
            }

            let mut canonical = String::new();
            for (i, field) in rest.iter().enumerate() {
                let name = abs_domain_name(field);
                let mut h = field.clone().into_bytes();
                lower_ascii_bytes(&mut h);
                let key = abs_domain_name(&String::from_utf8_lossy(&h));

                if i == 0 {
                    canonical.clone_from(&key);
                }

                is.entry(addr.clone()).or_default().push(name);

                match hs.entry(key) {
                    Entry::Occupied(mut entry) => {
                        entry.get_mut().addrs.push(addr.clone());
                    }
                    Entry::Vacant(entry) => {
                        entry.insert(ByName { addrs: vec![addr.clone()], canonical_name: canonical.clone() });
                    }
                }
            }
        }
        file.close();
    }
    // Update the data cache.
    state.expire = expire;
    state.path = hp;
    state.by_name = hs;
    state.by_addr = is;
    state.mtime = mtime;
    state.size = size;
}

/// Looks up the addresses and the canonical name for the given host from /etc/hosts.
pub async fn lookup_static_host(host: &str) -> (Vec<String>, String) {
    let mut guard = HOSTS.lock().await;
    read_hosts(&mut guard).await;
    if !guard.by_name.is_empty() {
        let mut host = host.to_owned();
        if has_upper_case(&host) {
            let mut lower_host = host.clone().into_bytes();
            lower_ascii_bytes(&mut lower_host);
            host = String::from_utf8_lossy(&lower_host).into_owned();
        }
        if let Some(entry) = guard.by_name.get(&abs_domain_name(&host)) {
            return (entry.addrs.clone(), entry.canonical_name.clone());
        }
    }
    (Vec::new(), String::new())
}

/// Looks up the hosts for the given address from /etc/hosts.
pub async fn lookup_static_addr(addr: &str) -> Vec<String> {
    let mut guard = HOSTS.lock().await;
    read_hosts(&mut guard).await;
    let addr = parse_literal_ip(addr);
    if addr.is_empty() {
        return Vec::new();
    }
    let addrs = if guard.by_addr.is_empty() { None } else { guard.by_addr.get(&addr) };
    if let Some(addrs) = addrs {
        return addrs.clone();
    }
    Vec::new()
}

pub(crate) async fn stat(name: &str) -> std::io::Result<(DateTime<Utc>, i64)> {
    let st = tokio::fs::metadata(name).await?;
    Ok((DateTime::<Utc>::from(st.modified()?), i64::try_from(st.len()).unwrap_or(i64::MAX)))
}

#[derive(Debug)]
pub(crate) struct File {
    inner: tokio::fs::File,
    data: Vec<u8>,
    at_eof: bool,
}

impl File {
    pub(crate) fn close(self) {
        drop(self.inner);
    }

    fn get_line_from_data(&mut self) -> Option<String> {
        if let Some(i) = self.data.iter().position(|b| *b == b'\n') {
            let s = String::from_utf8_lossy(self.data.get(..i).unwrap_or_default()).into_owned();
            self.data.drain(..=i);
            return Some(s);
        }
        if self.at_eof && !self.data.is_empty() {
            // EOF, return all we have
            let s = String::from_utf8_lossy(&self.data).into_owned();
            self.data.clear();
            return Some(s);
        }
        None
    }

    pub(crate) async fn read_line(&mut self) -> Option<String> {
        if let Some(s) = self.get_line_from_data() {
            return Some(s);
        }
        if self.data.len() < DATA_CAPACITY {
            let ln = self.data.len();
            self.data.resize(DATA_CAPACITY, 0);
            let (_, tail) = self.data.split_at_mut(ln);
            let (n, at_eof) = read_full(&mut self.inner, tail).await;
            self.data.truncate(ln + n);
            if at_eof {
                self.at_eof = true;
            }
        }
        self.get_line_from_data()
    }
}

/// Reads `buf` to its end, reporting a short read and discarding every other read error.
pub(crate) async fn read_full(file: &mut tokio::fs::File, buf: &mut [u8]) -> (usize, bool) {
    let mut n = 0;
    while n < buf.len() {
        let (_, tail) = buf.split_at_mut(n);
        let read = file.read(tail).await;
        match &read {
            Ok(0) => return (n, true),
            Ok(k) => n += *k,
            Err(err) if err.kind() == ErrorKind::Interrupted => {}
            Err(_) => return (n, false),
        }
    }
    (n, false)
}

pub(crate) async fn open(name: &str) -> std::io::Result<File> {
    let fd = tokio::fs::File::open(name).await?;
    Ok(File { inner: fd, data: Vec::with_capacity(DATA_CAPACITY), at_eof: false })
}

pub(crate) fn get_fields(s: &str) -> Vec<String> {
    split_at_bytes(s, " \r\t\n")
}

/// Count occurrences in s of any bytes in t.
pub(crate) fn count_any_byte(s: &str, t: &str) -> usize {
    let s = s.as_bytes();
    let t = t.as_bytes();
    let mut n = 0;
    for b in s {
        if t.contains(b) {
            n += 1;
        }
    }
    n
}

/// Split s at any bytes in t.
pub(crate) fn split_at_bytes(s: &str, t: &str) -> Vec<String> {
    let sb = s.as_bytes();
    let tb = t.as_bytes();
    let mut a: Vec<String> = Vec::with_capacity(1 + count_any_byte(s, t));
    let mut last = 0;
    for (i, b) in sb.iter().enumerate() {
        if tb.contains(b) {
            if last < i {
                a.push(String::from_utf8_lossy(sb.get(last..i).unwrap_or_default()).into_owned());
            }
            last = i + 1;
        }
    }
    if last < sb.len() {
        a.push(String::from_utf8_lossy(sb.get(last..).unwrap_or_default()).into_owned());
    }
    a
}

/// Makes `x` ASCII lowercase in-place.
pub(crate) fn lower_ascii_bytes(x: &mut [u8]) {
    for b in x {
        if b'A' <= *b && *b <= b'Z' {
            *b += b'a' - b'A';
        }
    }
}

/// Tells whether the given string contains at least one upper-case.
pub(crate) fn has_upper_case(s: &str) -> bool {
    for b in s.as_bytes() {
        if b'A' <= *b && *b <= b'Z' {
            return true;
        }
    }
    false
}

/// Returns an absolute domain name ending with a trailing dot, matching the reverse resolver and
/// every other lookup routine. Names from `/etc/hosts` should not get a dot and it is hard to tell
/// them apart, so the heuristic is: a name without a dot (like "localhost") keeps none, any other
/// name gets one.
pub(crate) fn abs_domain_name(s: &str) -> String {
    if s.contains('.') && !s.ends_with('.') {
        format!("{s}.")
    } else {
        s.to_owned()
    }
}
