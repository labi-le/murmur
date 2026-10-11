//!
//! The TCP header is built and parsed inline and `iptables` is driven through its binary.
//!
//! Neither has a Rust counterpart, so the header layout, the TCP/IP checksum and the few
//! `iptables` commands this file issues are implemented here. The packet conn is a raw `socket2`
//! socket kept in blocking mode, and the IPv4 header the packet arrives with is stripped on
//! receive.

use std::collections::HashMap;
use std::io;
use std::mem::size_of;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Once};
use std::time::Duration;

use anyhow::{anyhow, Error, Result};
use async_trait::async_trait;
use parking_lot::{Mutex, RwLock};
use rand::Rng;
use socket2::{Domain, Protocol as SocketProtocol, SockAddr, Socket, Type};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use murmur_common_net::io::close_stream;
use murmur_component::dialer::bind::{lookup_local_addr_from_iface_name, unmap_addr};
use murmur_component::dialer::options::{DEFAULT_INTERFACE, DEFAULT_INTERFACE_FINDER};
use murmur_std_compat::net::{Addr, TcpAddr as NetTcpAddr};

/// The timeout error callers compare, identified by its `ErrorKind` rather than a sentinel value.
#[must_use]
pub fn err_timeout() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "timeout")
}

fn err_eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "EOF")
}

pub const EXPIRE: Duration = Duration::from_secs(60);

struct Message {
    bts: Vec<u8>,
    addr: Box<dyn Addr>,
}

#[derive(Debug)]
struct TcpFlow {
    conn: Option<Arc<TcpStream>>,
    handle: Option<Arc<IpConn>>,
    seq: u32,
    ack: u32,
    ts: Instant,
    buf: Vec<u8>,
    tcp_header: TcpHeader,
}

impl TcpFlow {
    fn new() -> Self {
        Self {
            conn: None,
            handle: None,
            seq: 0,
            ack: 0,
            ts: Instant::now(),
            buf: Vec::new(),
            tcp_header: TcpHeader::default(),
        }
    }
}

#[derive(Debug)]
pub struct TCPConn {
    die: CancellationToken,
    die_once: Once,
    tcpconn: Option<Arc<TcpStream>>,
    listener: Option<Arc<TcpListener>>,
    handles: Vec<Arc<IpConn>>,
    ch_message: mpsc::Sender<Message>,
    ch_message_rx: tokio::sync::Mutex<mpsc::Receiver<Message>>,
    flow_table: Arc<Mutex<HashMap<String, TcpFlow>>>,
    iptables: Option<iptables::IPTables>,
    iprule: Vec<String>,
    ip6tables: Option<iptables::IPTables>,
    ip6rule: Vec<String>,
    read_deadline: RwLock<Option<Instant>>,
    write_deadline: RwLock<Option<Instant>>,
    opts: SerializeOptions,
}

fn lockflow(flow_table: &Mutex<HashMap<String, TcpFlow>>, addr: &dyn Addr, f: impl FnOnce(&mut TcpFlow)) {
    let key = addr.string();
    let mut flows = flow_table.lock();
    f(flows.entry(key).or_insert_with(TcpFlow::new));
}

// cancel-safe: each tick mutates the flow table under a short-lived lock, and the wait only decides when the
// sweep runs.
async fn cleaner(die: CancellationToken, flow_table: Arc<Mutex<HashMap<String, TcpFlow>>>) {
    let mut ticker = tokio::time::interval_at(Instant::now() + EXPIRE, EXPIRE);
    tokio::select! {
        () = die.cancelled() => {}
        _ = ticker.tick() => {
            let mut flows = flow_table.lock();
            flows.retain(|_, flow| {
                if flow.ts.elapsed() <= EXPIRE {
                    return true;
                }
                if let Some(conn) = &flow.conn {
                    let _ = set_ttl(conn, 64);
                    let _ = close_stream(&**conn);
                }
                false
            });
        }
    }
}

/// Captures one direction of the flow. The loop reads a blocking packet conn, so it runs on a
/// blocking task; the read timeout bounds the wait for `die`.
fn capture_flow(
    die: CancellationToken,
    flow_table: Arc<Mutex<HashMap<String, TcpFlow>>>,
    ch_message: mpsc::Sender<Message>,
    handle: Arc<IpConn>,
    port: u16,
) {
    tokio::task::spawn_blocking(move || {
        let mut buf = vec![0u8; 2048];
        loop {
            if die.is_cancelled() {
                return;
            }
            let (n, addr) = match handle.read_from_ip(&mut buf) {
                Ok(read) => read,
                Err(err) if err.kind() == io::ErrorKind::WouldBlock || err.kind() == io::ErrorKind::TimedOut => {
                    continue;
                }
                Err(_) => return,
            };

            let Some(packet) = buf.get(..n) else {
                continue;
            };
            let tcp = TcpHeader::decode_from_bytes(packet);

            if tcp.dst_port != port {
                continue;
            }

            let src = NetTcpAddr::new(addr, tcp.src_port);

            let mut orphan = false;
            lockflow(&flow_table, &src, |flow| {
                if flow.conn.is_none() {
                    orphan = true;
                }

                flow.ts = Instant::now();
                if tcp.ack_flag {
                    flow.seq = tcp.ack;
                }
                if tcp.syn {
                    flow.ack = tcp.seq.wrapping_add(1);
                }
                if tcp.psh && flow.ack == tcp.seq {
                    flow.ack = tcp.seq.wrapping_add(u32::try_from(tcp.payload.len()).unwrap_or(u32::MAX));
                }
                flow.handle = Some(Arc::clone(&handle));
            });

            if !orphan && tcp.psh {
                let message = Message { bts: tcp.payload, addr: Box::new(src) };
                if ch_message.blocking_send(message).is_err() {
                    return;
                }
            }
        }
    });
}

/// Keeps the hijacked TCP connection drained.
fn discard_conn(conn: Arc<TcpStream>) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            if conn.readable().await.is_err() {
                return;
            }
            match conn.try_read(&mut buf) {
                Ok(0) => return,
                Ok(_) => {}
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => return,
            }
        }
    });
}

impl TCPConn {
    fn lockflow(&self, addr: &dyn Addr, f: impl FnOnce(&mut TcpFlow)) {
        lockflow(&self.flow_table, addr, f);
    }

    pub fn syscall_conn(&self) -> Result<usize> {
        let Some(handle) = self.handles.first() else {
            return Err(anyhow!("no handles"));
        };
        Ok(handle.syscall_conn())
    }

    pub fn set_dscp(&self, dscp: i32) -> io::Result<()> {
        for handle in &self.handles {
            set_dscp(handle, dscp)?;
        }
        Ok(())
    }

    pub fn set_read_buffer(&self, bytes: usize) -> io::Result<()> {
        for handle in &self.handles {
            handle.set_read_buffer(bytes)?;
        }
        Ok(())
    }

    pub fn set_write_buffer(&self, bytes: usize) -> io::Result<()> {
        for handle in &self.handles {
            handle.set_write_buffer(bytes)?;
        }
        Ok(())
    }

    // cancel-safe: receives from a channel, and a dropped `recv` leaves the message queued for the next call.
    async fn recv_message(&self) -> Option<Message> {
        let mut rx = self.ch_message_rx.lock().await;
        rx.recv().await
    }
}

#[async_trait]
impl murmur_std_compat::net::PacketConn for TCPConn {
    // cancel-safe: a cancelled wait leaves the queued message for the next call, and the timeout arm only
    // decides the error.
    async fn read_from(&self, p: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        let deadline = *self.read_deadline.read();
        let timeout = async move {
            match deadline {
                Some(deadline) => tokio::time::sleep_until(deadline).await,
                None => std::future::pending::<()>().await,
            }
        };

        let packet = tokio::select! {
            () = timeout => return Err(err_timeout()),
            () = self.die.cancelled() => return Err(err_eof()),
            packet = self.recv_message() => match packet {
                Some(packet) => packet,
                None => return Err(err_eof()),
            },
        };

        let n = p.len().min(packet.bts.len());
        let (Some(dst), Some(src)) = (p.get_mut(..n), packet.bts.get(..n)) else {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "packet larger than the buffer"));
        };
        dst.copy_from_slice(src);
        Ok((n, packet.addr))
    }

    // cancel-safe: the only await is the address lookup, and the flow state is mutated inside the blocking
    // send that follows it.
    async fn write_to(&self, p: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        let write_deadline = *self.write_deadline.read();
        if let Some(deadline) = write_deadline {
            if Instant::now() >= deadline {
                return Err(err_timeout());
            }
        }
        if self.die.is_cancelled() {
            return Err(err_eof());
        }

        let raddr = resolve_tcp_addr("tcp", &addr.string()).await.map_err(io_err)?;

        let lport = if let Some(tcpconn) = &self.tcpconn {
            tcpconn.local_addr()?.port()
        } else if let Some(listener) = &self.listener {
            listener.local_addr()?.port()
        } else {
            return Err(io::Error::new(io::ErrorKind::NotConnected, "no local address"));
        };

        let mut error = None;
        let mut written = 0;
        tokio::task::block_in_place(|| {
            lockflow(&self.flow_table, addr, |flow| {
                let Some(handle) = flow.handle.as_ref().map(Arc::clone) else {
                    written = p.len();
                    return;
                };

                flow.tcp_header.src_port = lport;
                flow.tcp_header.dst_port = raddr.port();
                flow.tcp_header.window = rand::rng().random::<u16>() | 0x8000;
                flow.tcp_header.ack = flow.ack;
                flow.tcp_header.seq = flow.seq;
                flow.tcp_header.psh = true;
                flow.tcp_header.ack_flag = true;

                let local_ip = handle.local_addr();
                flow.tcp_header.pseudoheader = match raddr {
                    SocketAddr::V4(v4) => match local_ip {
                        IpAddr::V4(src) => Some(PseudoHeader::V4 { src: src.octets(), dst: v4.ip().octets() }),
                        // an IPv4 remote address paired with an IPv6 local address has no IPv4 form
                        // here, so the checksum stays the zero already written.
                        IpAddr::V6(_) => None,
                    },
                    SocketAddr::V6(v6) => {
                        let src = match local_ip {
                            IpAddr::V4(src) => src.to_ipv6_mapped().octets(),
                            IpAddr::V6(src) => src.octets(),
                        };
                        Some(PseudoHeader::V6 { src, dst: v6.ip().octets() })
                    }
                };

                flow.buf.clear();
                serialize_layers(&mut flow.buf, self.opts, &flow.tcp_header, p);
                let result = if self.tcpconn.is_some() {
                    handle.write(&flow.buf)
                } else {
                    handle.write_to_ip(&flow.buf, raddr.ip())
                };

                flow.seq = flow.seq.wrapping_add(u32::try_from(p.len()).unwrap_or(u32::MAX));
                written = p.len();
                error = result.err();
            });
        });

        match error {
            Some(err) => Err(err),
            None => Ok(written),
        }
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        if let Some(tcpconn) = &self.tcpconn {
            return murmur_std_compat::net::Conn::local_addr(&**tcpconn);
        }
        if let Some(listener) = &self.listener {
            return listener.local_addr().map(|addr| -> Box<dyn Addr> { Box::new(NetTcpAddr::from(addr)) });
        }
        Err(io::Error::new(io::ErrorKind::NotConnected, "no local address"))
    }

    fn close(&self) -> io::Result<()> {
        let error = Mutex::new(None);
        self.die_once.call_once(|| {
            self.die.cancel();

            if let Some(tcpconn) = &self.tcpconn {
                let _ = set_ttl(tcpconn, 64);
                if let Err(err) = close_stream(&**tcpconn) {
                    *error.lock() = Some(err);
                }
            } else if let Some(listener) = &self.listener {
                if let Err(err) = murmur_common_net::io::Acceptor::close(&**listener) {
                    *error.lock() = Some(err);
                }
                let mut flows = self.flow_table.lock();
                for (_, flow) in flows.drain() {
                    if let Some(conn) = &flow.conn {
                        let _ = set_ttl(conn, 64);
                        let _ = close_stream(&**conn);
                    }
                }
            }

            for handle in &self.handles {
                let _ = handle.close();
            }

            if let Some(iptables) = &self.iptables {
                let _ = iptables.delete("filter", "OUTPUT", &string_slice(&self.iprule));
            }
            if let Some(ip6tables) = &self.ip6tables {
                let _ = ip6tables.delete("filter", "OUTPUT", &string_slice(&self.ip6rule));
            }
        });
        match error.into_inner() {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    fn set_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        self.set_read_deadline(deadline)?;
        self.set_write_deadline(deadline)
    }

    fn set_read_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        *self.read_deadline.write() = deadline;
        Ok(())
    }

    fn set_write_deadline(&self, deadline: Option<Instant>) -> io::Result<()> {
        *self.write_deadline.write() = deadline;
        Ok(())
    }
}

/// Wraps the resolver error as an `io::Error`, which is what the packet-conn methods return.
fn io_err(err: Error) -> io::Error {
    io::Error::other(err)
}

fn string_slice(values: &[String]) -> Vec<&str> {
    values.iter().map(String::as_str).collect()
}

pub async fn dial(network: &str, address: &str) -> Result<TCPConn> {
    let raddr = resolve_tcp_addr(network, address).await?;

    let mut l_tcp_addr: Option<SocketAddr> = None;
    let mut l_ip_addr: Option<IpAddr> = None;
    let mut iface_name = DEFAULT_INTERFACE.load();
    if iface_name.is_empty() {
        if let Some(finder) = DEFAULT_INTERFACE_FINDER.load() {
            iface_name = finder.find_interface_name(unmap_addr(Some(raddr.ip())));
        }
    }
    if !iface_name.is_empty() {
        let addr = lookup_local_addr_from_iface_name(&iface_name, network, Some(raddr.ip()), raddr.port()).await?;
        l_tcp_addr = Some(addr);
        l_ip_addr = Some(addr.ip());
    }

    let handle = Arc::new(IpConn::dial_ip("ip:tcp", l_ip_addr, raddr.ip())?);
    let tcpconn = Arc::new(dial_tcp(network, l_tcp_addr, raddr).await?);

    let (ch_message, ch_message_rx) = mpsc::channel(1);
    let conn = TCPConn {
        die: CancellationToken::new(),
        die_once: Once::new(),
        tcpconn: Some(Arc::clone(&tcpconn)),
        listener: None,
        handles: vec![Arc::clone(&handle)],
        ch_message,
        ch_message_rx: tokio::sync::Mutex::new(ch_message_rx),
        flow_table: Arc::new(Mutex::new(HashMap::new())),
        iptables: None,
        iprule: Vec::new(),
        ip6tables: None,
        ip6rule: Vec::new(),
        read_deadline: RwLock::new(None),
        write_deadline: RwLock::new(None),
        opts: SerializeOptions { fix_lengths: true, compute_checksums: true },
    };

    conn.lockflow(&*murmur_std_compat::net::Conn::remote_addr(&*tcpconn)?, |flow| {
        flow.conn = Some(Arc::clone(&tcpconn));
    });

    let port = tcpconn.local_addr()?.port();

    capture_flow(conn.die.clone(), Arc::clone(&conn.flow_table), conn.ch_message.clone(), Arc::clone(&handle), port);
    tokio::spawn(cleaner(conn.die.clone(), Arc::clone(&conn.flow_table)));

    set_ttl(&tcpconn, 1)?;

    let (v4_tables, v4_rule, v6_tables, v6_rule) = tokio::task::block_in_place(|| set_forward_rules(&raddr));
    let conn = TCPConn { iptables: v4_tables, iprule: v4_rule, ip6tables: v6_tables, ip6rule: v6_rule, ..conn };

    discard_conn(Arc::clone(&tcpconn));

    Ok(conn)
}

/// the `iptables.NewWithProtocol(...)` blocks on the `iptables` binary, hence the blocking task.
fn set_forward_rules(
    raddr: &SocketAddr,
) -> (Option<iptables::IPTables>, Vec<String>, Option<iptables::IPTables>, Vec<String>) {
    let mut v4_tables = None;
    let mut v4_rule = Vec::new();
    let mut v6_tables = None;
    let mut v6_rule = Vec::new();

    if let Ok(ipt) = iptables::IPTables::new(iptables::Protocol::Ipv4) {
        let rule = vec![
            "-m".to_owned(),
            "ttl".to_owned(),
            "--ttl-eq".to_owned(),
            "1".to_owned(),
            "-p".to_owned(),
            "tcp".to_owned(),
            "-d".to_owned(),
            raddr.ip().to_string(),
            "--dport".to_owned(),
            raddr.port().to_string(),
            "-j".to_owned(),
            "DROP".to_owned(),
        ];
        if let Ok(exists) = ipt.exists("filter", "OUTPUT", &string_slice(&rule)) {
            if !exists && ipt.append("filter", "OUTPUT", &string_slice(&rule)).is_ok() {
                v4_rule = rule;
                v4_tables = Some(ipt);
            }
        }
    }
    if let Ok(ipt) = iptables::IPTables::new(iptables::Protocol::Ipv6) {
        let rule = vec![
            "-m".to_owned(),
            "hl".to_owned(),
            "--hl-eq".to_owned(),
            "1".to_owned(),
            "-p".to_owned(),
            "tcp".to_owned(),
            "-d".to_owned(),
            raddr.ip().to_string(),
            "--dport".to_owned(),
            raddr.port().to_string(),
            "-j".to_owned(),
            "DROP".to_owned(),
        ];
        if let Ok(exists) = ipt.exists("filter", "OUTPUT", &string_slice(&rule)) {
            if !exists && ipt.append("filter", "OUTPUT", &string_slice(&rule)).is_ok() {
                v6_rule = rule;
                v6_tables = Some(ipt);
            }
        }
    }

    (v4_tables, v4_rule, v6_tables, v6_rule)
}

/// the `iptables` setup done when listening, which drops the packets the listener marks with TTL 1.
fn set_listen_rules(port: u16) -> (Option<iptables::IPTables>, Vec<String>, Option<iptables::IPTables>, Vec<String>) {
    let mut v4_tables = None;
    let mut v4_rule = Vec::new();
    let mut v6_tables = None;
    let mut v6_rule = Vec::new();

    if let Ok(ipt) = iptables::IPTables::new(iptables::Protocol::Ipv4) {
        let rule = vec![
            "-m".to_owned(),
            "ttl".to_owned(),
            "--ttl-eq".to_owned(),
            "1".to_owned(),
            "-p".to_owned(),
            "tcp".to_owned(),
            "--sport".to_owned(),
            port.to_string(),
            "-j".to_owned(),
            "DROP".to_owned(),
        ];
        if let Ok(exists) = ipt.exists("filter", "OUTPUT", &string_slice(&rule)) {
            if !exists && ipt.append("filter", "OUTPUT", &string_slice(&rule)).is_ok() {
                v4_rule = rule;
                v4_tables = Some(ipt);
            }
        }
    }
    if let Ok(ipt) = iptables::IPTables::new(iptables::Protocol::Ipv6) {
        let rule = vec![
            "-m".to_owned(),
            "hl".to_owned(),
            "--hl-eq".to_owned(),
            "1".to_owned(),
            "-p".to_owned(),
            "tcp".to_owned(),
            "--sport".to_owned(),
            port.to_string(),
            "-j".to_owned(),
            "DROP".to_owned(),
        ];
        if let Ok(exists) = ipt.exists("filter", "OUTPUT", &string_slice(&rule)) {
            if !exists && ipt.append("filter", "OUTPUT", &string_slice(&rule)).is_ok() {
                v6_rule = rule;
                v6_tables = Some(ipt);
            }
        }
    }

    (v4_tables, v4_rule, v6_tables, v6_rule)
}

// NOT cancel-safe: the packet-capture and cleaner tasks it spawns are stopped only by the token the
// returning connection owns, so a drop before the return leaves them running.
pub async fn listen(network: &str, address: &str) -> Result<TCPConn> {
    let laddr = resolve_tcp_addr(network, address).await?;

    let (ch_message, ch_message_rx) = mpsc::channel::<Message>(1);
    let die = CancellationToken::new();
    let flow_table = Arc::new(Mutex::new(HashMap::new()));
    let mut handles: Vec<Arc<IpConn>> = Vec::new();

    if laddr.ip().is_unspecified() {
        let mut lasterr: Option<io::Error> = None;
        for iface in if_addrs::get_if_addrs()? {
            match IpConn::listen_ip("ip:tcp", iface.ip()) {
                Ok(handle) => {
                    let handle = Arc::new(handle);
                    capture_flow(
                        die.clone(),
                        Arc::clone(&flow_table),
                        ch_message.clone(),
                        Arc::clone(&handle),
                        laddr.port(),
                    );
                    handles.push(handle);
                }
                Err(err) => lasterr = Some(err),
            }
        }
        if handles.is_empty() {
            return Err(match lasterr {
                Some(err) => err.into(),
                None => anyhow!("no interfaces to capture on"),
            });
        }
    } else {
        let handle = Arc::new(IpConn::listen_ip("ip:tcp", laddr.ip())?);
        capture_flow(die.clone(), Arc::clone(&flow_table), ch_message.clone(), Arc::clone(&handle), laddr.port());
        handles.push(handle);
    }

    let listener = Arc::new(listen_tcp(network, laddr).await?);

    let mut conn = TCPConn {
        die: die.clone(),
        die_once: Once::new(),
        tcpconn: None,
        listener: Some(Arc::clone(&listener)),
        handles,
        ch_message,
        ch_message_rx: tokio::sync::Mutex::new(ch_message_rx),
        flow_table: Arc::clone(&flow_table),
        iptables: None,
        iprule: Vec::new(),
        ip6tables: None,
        ip6rule: Vec::new(),
        read_deadline: RwLock::new(None),
        write_deadline: RwLock::new(None),
        opts: SerializeOptions { fix_lengths: true, compute_checksums: true },
    };

    tokio::spawn(cleaner(die.clone(), Arc::clone(&flow_table)));

    let (v4_tables, v4_rule, v6_tables, v6_rule) = tokio::task::block_in_place(|| set_listen_rules(laddr.port()));
    conn.iptables = v4_tables;
    conn.iprule = v4_rule;
    conn.ip6tables = v6_tables;
    conn.ip6rule = v6_rule;

    let accept_die = die.clone();
    let accept_flow_table = Arc::clone(&flow_table);
    tokio::spawn(async move {
        loop {
            let accepted = tokio::select! {
                () = accept_die.cancelled() => return,
                accepted = listener.accept() => accepted,
            };
            let Ok((tcpconn, _)) = accepted else {
                return;
            };

            if let Err(err) = set_ttl(&tcpconn, 1) {
                // without the marker ttl the listener's iptables rules never see this connection
                murmur_log::errorln!("faketcp: setting the accepted connection's ttl failed: {err}");
                return;
            }
            let _ = tcpconn.set_nodelay(true);

            let tcpconn = Arc::new(tcpconn);
            match murmur_std_compat::net::Conn::remote_addr(&*tcpconn) {
                Ok(remote_addr) => {
                    lockflow(&accept_flow_table, &*remote_addr, |flow| {
                        flow.conn = Some(Arc::clone(&tcpconn));
                    });
                }
                Err(_) => continue,
            }

            discard_conn(tcpconn);
        }
    });

    Ok(conn)
}

/// Resolves through the system resolver and keeps the first match of the requested family. The
/// hysteria outbound pre-resolves its own addresses, so it only ever passes this a literal, and no
/// caller here uses the system resolver.
async fn resolve_tcp_addr(network: &str, address: &str) -> Result<SocketAddr> {
    match network {
        "tcp" | "tcp4" | "tcp6" => {}
        _ => return Err(anyhow!("unknown network {network}")),
    }

    // the resolver accepts a bare port and answers the IPv4 wildcard for network "tcp".
    if let Some(port) = address.strip_prefix(':') {
        let port: u16 = port.parse()?;
        return Ok(SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), port));
    }

    let addrs = tokio::net::lookup_host(address).await?;
    addrs
        .into_iter()
        .find(|addr| match network {
            "tcp4" => addr.is_ipv4(),
            "tcp6" => addr.is_ipv6(),
            _ => true,
        })
        .ok_or_else(|| anyhow!("address {address}: no suitable address found"))
}

/// Binds the local address chosen by the interface lookup before connecting.
async fn dial_tcp(network: &str, laddr: Option<SocketAddr>, raddr: SocketAddr) -> io::Result<TcpStream> {
    if !matches!(network, "tcp" | "tcp4" | "tcp6") {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("unknown network {network}")));
    }

    let Some(laddr) = laddr else {
        let conn = TcpStream::connect(raddr).await?;
        let _ = conn.set_nodelay(true);
        return Ok(conn);
    };

    tokio::task::spawn_blocking(move || {
        let domain = if raddr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
        let socket = Socket::new(domain, Type::STREAM, Some(SocketProtocol::TCP))?;
        socket.bind(&SockAddr::from(laddr))?;
        socket.connect(&SockAddr::from(raddr))?;
        socket.set_nonblocking(true)?;
        let conn = TcpStream::from_std(std::net::TcpStream::from(socket))?;
        let _ = conn.set_nodelay(true);
        Ok(conn)
    })
    .await
    .map_err(io::Error::other)?
}

async fn listen_tcp(network: &str, laddr: SocketAddr) -> io::Result<TcpListener> {
    if !matches!(network, "tcp" | "tcp4" | "tcp6") {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("unknown network {network}")));
    }
    TcpListener::bind(laddr).await
}

/// A raw socket bound to one IP address.
#[derive(Debug)]
pub struct IpConn {
    socket: Socket,
    local_addr: IpAddr,
}

impl IpConn {
    fn dial_ip(network: &str, laddr: Option<IpAddr>, raddr: IpAddr) -> io::Result<Self> {
        let socket = new_raw_socket(network, raddr)?;
        if let Some(laddr) = laddr {
            socket.bind(&SockAddr::from(SocketAddr::new(laddr, 0)))?;
        }
        socket.connect(&SockAddr::from(SocketAddr::new(raddr, 0)))?;
        Ok(Self { socket, local_addr: raddr })
    }

    fn listen_ip(network: &str, laddr: IpAddr) -> io::Result<Self> {
        let socket = new_raw_socket(network, laddr)?;
        socket.bind(&SockAddr::from(SocketAddr::new(laddr, 0)))?;
        Ok(Self { socket, local_addr: laddr })
    }

    /// Receives one packet; the IPv4 branch strips the header the raw socket delivers.
    fn read_from_ip(&self, buf: &mut [u8]) -> io::Result<(usize, IpAddr)> {
        let (n, addr) = self.socket.recv_from(as_uninit(buf))?;
        let addr = sock_addr_ip(&addr);
        if addr.is_ipv4() {
            return Ok((strip_ipv4_header(n, buf), addr));
        }
        Ok((n, addr))
    }

    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        self.socket.send(buf)
    }

    fn write_to_ip(&self, buf: &[u8], addr: IpAddr) -> io::Result<usize> {
        self.socket.send_to(buf, &SockAddr::from(SocketAddr::new(addr, 0)))
    }

    const fn local_addr(&self) -> IpAddr {
        self.local_addr
    }

    fn close(&self) -> io::Result<()> {
        self.socket.shutdown(std::net::Shutdown::Both)
    }

    fn set_read_buffer(&self, bytes: usize) -> io::Result<()> {
        self.socket.set_recv_buffer_size(bytes)
    }

    fn set_write_buffer(&self, bytes: usize) -> io::Result<()> {
        self.socket.set_send_buffer_size(bytes)
    }

    /// Answers the syscall-conn assertion with the descriptor.
    fn syscall_conn(&self) -> usize {
        use std::os::fd::AsRawFd;

        usize::try_from(self.socket.as_raw_fd()).unwrap_or_default()
    }
}

/// the `net` package keeps the raw socket blocking; the read timeout is what lets a capture loop
/// notice `die` after the connection closes.
const RAW_READ_TIMEOUT: Duration = Duration::from_secs(1);

fn new_raw_socket(network: &str, addr: IpAddr) -> io::Result<Socket> {
    let protocol = match network.split_once(':') {
        Some((_, "tcp")) | None => libc::IPPROTO_TCP,
        Some((_, proto)) => {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("unknown IP protocol: {proto}")));
        }
    };
    let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    // `socket2` gates its own `Type::RAW` behind a feature this crate does not enable.
    let socket = Socket::new(domain, Type::from(libc::SOCK_RAW), Some(SocketProtocol::from(protocol)))?;
    socket.set_broadcast(true)?;
    socket.set_read_timeout(Some(RAW_READ_TIMEOUT))?;
    Ok(socket)
}

/// `socket2` reads into `MaybeUninit` bytes; every byte of the caller's buffer is initialised, so
/// the same memory is a valid `&mut [MaybeUninit<u8>]`.
#[expect(
    unsafe_code,
    reason = "viewing an initialised buffer as `MaybeUninit` bytes is the only way to hand it to socket2's raw recv"
)]
const fn as_uninit(buf: &mut [u8]) -> &mut [std::mem::MaybeUninit<u8>] {
    let ptr = buf.as_mut_ptr().cast::<std::mem::MaybeUninit<u8>>();
    // SAFETY: `MaybeUninit<u8>` has the same size and alignment as `u8`, and the pointer comes
    // from a live slice of the same length.
    unsafe { std::slice::from_raw_parts_mut(ptr, buf.len()) }
}

fn sock_addr_ip(addr: &SockAddr) -> IpAddr {
    match addr.as_socket() {
        Some(addr) => addr.ip(),
        None => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
    }
}

fn strip_ipv4_header(n: usize, b: &mut [u8]) -> usize {
    let Some(&first) = b.first() else {
        return n;
    };
    if b.len() < 20 {
        return n;
    }
    let l = (usize::from(first) & 0x0f) << 2;
    if !(20..=b.len()).contains(&l) {
        return n;
    }
    if first >> 4 != 4 {
        return n;
    }
    b.copy_within(l..n, 0);
    n - l
}

fn set_ttl(c: &TcpStream, ttl: i32) -> io::Result<()> {
    let ipv4 = c.local_addr()?.is_ipv4();
    set_socket_int_option(c, ipv4, ttl, libc::IP_TTL, libc::IPV6_UNICAST_HOPS)
}

fn set_dscp(c: &IpConn, dscp: i32) -> io::Result<()> {
    set_socket_int_option(&c.socket, c.local_addr().is_ipv4(), dscp << 2, libc::IP_TOS, libc::IPV6_TCLASS)
}

/// Sets one integer socket option on the raw descriptor, choosing the IPv4 or IPv6 option name.
#[expect(unsafe_code, reason = "`libc::setsockopt` is the only way to set TTL/DSCP on the raw socket")]
fn set_socket_int_option<T: std::os::fd::AsRawFd>(
    socket: &T,
    ipv4: bool,
    value: i32,
    v4_option: libc::c_int,
    v6_option: libc::c_int,
) -> io::Result<()> {
    let (level, option) = if ipv4 { (libc::IPPROTO_IP, v4_option) } else { (libc::IPPROTO_IPV6, v6_option) };
    // SAFETY: `socket.as_raw_fd()` is a live fd for the call's duration and `value` outlives it;
    // the return value is checked below.
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            option,
            std::ptr::addr_of!(value).cast(),
            libc::socklen_t::try_from(size_of::<libc::c_int>()).unwrap_or_default(),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[expect(
    clippy::struct_excessive_bools,
    reason = "one flag per TCP control bit; collapsing them would change the public header shape"
)]
#[derive(Clone, Debug, Default)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub data_offset: u8,
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack_flag: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
    pub ns: bool,
    pub window: u16,
    pub checksum: u16,
    pub urgent: u16,
    pub payload: Vec<u8>,
    pub pseudoheader: Option<PseudoHeader>,
}

/// The IPv4/IPv6 pseudo header, reduced to the fields the checksum needs.
#[derive(Clone, Copy, Debug)]
pub enum PseudoHeader {
    V4 { src: [u8; 4], dst: [u8; 4] },
    V6 { src: [u8; 16], dst: [u8; 16] },
}

#[derive(Clone, Copy, Debug)]
pub struct SerializeOptions {
    pub fix_lengths: bool,
    pub compute_checksums: bool,
}

const IP_PROTOCOL_TCP: u8 = 6;

impl TcpHeader {
    /// Decodes the TCP layer from the first byte of the buffer, which is where the packet starts.
    /// The fields are set before any length check, so a short header yields the zeroes left
    /// behind.
    fn decode_from_bytes(data: &[u8]) -> Self {
        let mut tcp = Self::default();
        let Some(header) = data.first_chunk::<20>() else {
            return tcp;
        };
        let [src_hi, src_lo, dst_hi, dst_lo, seq_0, seq_1, seq_2, seq_3, ack_0, ack_1, ack_2, ack_3, offset_and_ns, flags, window_hi, window_lo, checksum_hi, checksum_lo, urgent_hi, urgent_lo] =
            *header;

        tcp.src_port = u16::from_be_bytes([src_hi, src_lo]);
        tcp.dst_port = u16::from_be_bytes([dst_hi, dst_lo]);
        tcp.seq = u32::from_be_bytes([seq_0, seq_1, seq_2, seq_3]);
        tcp.ack = u32::from_be_bytes([ack_0, ack_1, ack_2, ack_3]);
        tcp.data_offset = offset_and_ns >> 4;
        tcp.ns = offset_and_ns & 0x01 != 0;
        tcp.fin = flags & 0x01 != 0;
        tcp.syn = flags & 0x02 != 0;
        tcp.rst = flags & 0x04 != 0;
        tcp.psh = flags & 0x08 != 0;
        tcp.ack_flag = flags & 0x10 != 0;
        tcp.urg = flags & 0x20 != 0;
        tcp.ece = flags & 0x40 != 0;
        tcp.cwr = flags & 0x80 != 0;
        tcp.window = u16::from_be_bytes([window_hi, window_lo]);
        tcp.checksum = u16::from_be_bytes([checksum_hi, checksum_lo]);
        tcp.urgent = u16::from_be_bytes([urgent_hi, urgent_lo]);
        if tcp.data_offset >= 5 {
            let data_start = usize::from(tcp.data_offset) * 4;
            if let Some(payload) = data.get(data_start..) {
                tcp.payload = payload.to_vec();
            }
        }
        tcp
    }

    /// Packs the data offset and the flag bits into one 16-bit word.
    fn flags_and_offset(&self, data_offset: u8) -> u16 {
        let mut f = u16::from(data_offset) << 12;
        if self.fin {
            f |= 0x0001;
        }
        if self.syn {
            f |= 0x0002;
        }
        if self.rst {
            f |= 0x0004;
        }
        if self.psh {
            f |= 0x0008;
        }
        if self.ack_flag {
            f |= 0x0010;
        }
        if self.urg {
            f |= 0x0020;
        }
        if self.ece {
            f |= 0x0040;
        }
        if self.cwr {
            f |= 0x0080;
        }
        if self.ns {
            f |= 0x0100;
        }
        f
    }

    /// A missing network layer reports an error and keeps the zero checksum it has already
    /// written; `serialize_layers` mirrors that, since its caller discards the error.
    fn compute_checksum(&self, header_and_payload: &[u8]) -> u16 {
        let Some(pseudoheader) = self.pseudoheader else {
            return 0;
        };
        let length = u32::try_from(header_and_payload.len()).unwrap_or(u32::MAX);
        let mut csum = pseudoheader.checksum();
        csum += u32::from(IP_PROTOCOL_TCP);
        csum += length & 0xffff;
        csum += length >> 16;
        tcp_ip_checksum(header_and_payload, csum)
    }
}

impl PseudoHeader {
    fn checksum(&self) -> u32 {
        match self {
            Self::V4 { src, dst } => {
                let mut csum = 0u32;
                csum += (u32::from(src[0]) + u32::from(src[2])) << 8;
                csum += u32::from(src[1]) + u32::from(src[3]);
                csum += (u32::from(dst[0]) + u32::from(dst[2])) << 8;
                csum += u32::from(dst[1]) + u32::from(dst[3]);
                csum
            }
            Self::V6 { src, dst } => {
                let mut csum = 0u32;
                for (s, d) in src.chunks_exact(2).zip(dst.chunks_exact(2)) {
                    let [s_hi, s_lo] = s else { continue };
                    let [d_hi, d_lo] = d else { continue };
                    csum += (u32::from(*s_hi) << 8) + u32::from(*s_lo);
                    csum += (u32::from(*d_hi) << 8) + u32::from(*d_lo);
                }
                csum
            }
        }
    }
}

fn tcp_ip_checksum(data: &[u8], mut csum: u32) -> u16 {
    let mut words = data.chunks_exact(2);
    for word in words.by_ref() {
        let [hi, lo] = word else { continue };
        csum += (u32::from(*hi) << 8) + u32::from(*lo);
    }
    if let [last] = words.remainder() {
        csum += u32::from(*last) << 8;
    }
    while csum > 0xffff {
        csum = (csum >> 16) + (csum & 0xffff);
    }
    !u16::try_from(csum & 0xFFFF).unwrap_or_default()
}

/// Serializes the TCP header and the payload. The header carries no options, so `fix_lengths`
/// always writes a data offset of 5.
fn serialize_layers(buf: &mut Vec<u8>, opts: SerializeOptions, header: &TcpHeader, payload: &[u8]) {
    let data_offset = if opts.fix_lengths { 5u8 } else { header.data_offset };
    let mut out = Vec::with_capacity(20 + payload.len());
    out.extend_from_slice(&header.src_port.to_be_bytes());
    out.extend_from_slice(&header.dst_port.to_be_bytes());
    out.extend_from_slice(&header.seq.to_be_bytes());
    out.extend_from_slice(&header.ack.to_be_bytes());
    out.extend_from_slice(&header.flags_and_offset(data_offset).to_be_bytes());
    out.extend_from_slice(&header.window.to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&header.urgent.to_be_bytes());
    out.extend_from_slice(payload);

    let checksum = if opts.compute_checksums { header.compute_checksum(&out) } else { header.checksum };
    if let Some(field) = out.get_mut(16..18) {
        field.copy_from_slice(&checksum.to_be_bytes());
    }

    buf.clear();
    buf.extend_from_slice(&out);
}

/// The subset of the `iptables` command-line interface this file drives.
mod iptables {
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::process::Command;

    use anyhow::{anyhow, Result};
    use regex::Regex;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum Protocol {
        Ipv4,
        Ipv6,
    }

    #[derive(Debug)]
    pub(super) struct IPTables {
        path: String,
        has_check: bool,
        has_wait: bool,
        wait_support_second: bool,
        timeout: i32,
    }

    /// The error a failed `iptables` invocation returns; its exit status is what the caller
    /// inspects.
    #[derive(Debug, thiserror::Error)]
    enum RunError {
        #[error("running [{}]: exit status {}: {stderr}", args.join(" "), exit_status.unwrap_or(-1))]
        ExitStatus { args: Vec<String>, exit_status: Option<i32>, stderr: String },
        #[error(transparent)]
        Io(#[from] io::Error),
    }

    const XTABLES_LOCK_FILE_PATH: &str = "/var/run/xtables.lock";

    /// Holds the `xtables.lock` descriptor; it is closed on drop, including after a failed
    /// non-blocking lock.
    struct FileLock {
        fd: Option<OwnedFd>,
    }

    impl FileLock {
        #[expect(
            unsafe_code,
            reason = "`libc::open`/`OwnedFd::from_raw_fd` keep the xtables lock descriptor alive for the run"
        )]
        fn new() -> io::Result<Self> {
            let path = std::ffi::CString::new(XTABLES_LOCK_FILE_PATH)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
            // SAFETY: `path` is a live, NUL-terminated `CString` for the call's duration; the
            // returned fd is checked before being wrapped and takes exclusive ownership below.
            let fd = unsafe { libc::open(path.as_ptr(), libc::O_CREAT, 0o600) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: `fd` was just returned by `open(2)` above and is owned by nothing else yet.
            Ok(Self { fd: Some(unsafe { OwnedFd::from_raw_fd(fd) }) })
        }

        #[expect(unsafe_code, reason = "`libc::flock` is the only non-blocking lock available for the descriptor")]
        fn try_lock(&self) -> io::Result<()> {
            let Some(fd) = &self.fd else {
                return Ok(());
            };
            // SAFETY: `fd` is a live descriptor owned by `self`; the return value is checked below.
            let rc = unsafe { libc::flock(fd.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if rc == 0 {
                return Ok(());
            }
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
                return Ok(());
            }
            Err(err)
        }
    }

    impl IPTables {
        pub(super) fn new(proto: Protocol) -> Result<Self> {
            let cmd = match proto {
                Protocol::Ipv4 => "iptables",
                Protocol::Ipv6 => "ip6tables",
            };
            let path = which(cmd).ok_or_else(|| anyhow!("executable file not found in $PATH: {cmd}"))?;

            let version_string = {
                let output = Command::new(&path).arg("--version").output()?;
                if !output.status.success() {
                    return Err(anyhow!("could not get iptables version"));
                }
                String::from_utf8_lossy(&output.stdout).into_owned()
            };
            let (v1, v2, v3, _mode) = extract_iptables_version(&version_string)?;

            Ok(Self {
                path,
                has_check: iptables_has_check_command(v1, v2, v3),
                has_wait: iptables_has_wait_command(v1, v2, v3),
                wait_support_second: iptables_wait_support_second(v1, v2, v3),
                timeout: 0,
            })
        }

        pub(super) fn exists(&self, table: &str, chain: &str, rulespec: &[&str]) -> Result<bool> {
            if !self.has_check {
                return self.exists_for_old_iptables(table, chain, rulespec);
            }
            let args = self.build_args(&["-t", table, "-C", chain], rulespec);
            match self.run(&args) {
                Ok(()) => Ok(true),
                Err(RunError::ExitStatus { exit_status: Some(1), .. }) => Ok(false),
                Err(err) => Err(err.into()),
            }
        }

        pub(super) fn append(&self, table: &str, chain: &str, rulespec: &[&str]) -> Result<()> {
            let args = self.build_args(&["-t", table, "-A", chain], rulespec);
            Ok(self.run(&args)?)
        }

        pub(super) fn delete(&self, table: &str, chain: &str, rulespec: &[&str]) -> Result<()> {
            let args = self.build_args(&["-t", table, "-D", chain], rulespec);
            Ok(self.run(&args)?)
        }

        fn exists_for_old_iptables(&self, table: &str, chain: &str, rulespec: &[&str]) -> Result<bool> {
            let rule = format!("-A {chain} {}", rulespec.join(" "));
            let args = self.build_args(&["-t", table, "-S"], &[]);
            let stdout = self.run_with_stdout(&args)?;
            Ok(stdout.contains(&rule))
        }

        fn build_args(&self, prefix: &[&str], rulespec: &[&str]) -> Vec<String> {
            let mut args: Vec<String> = prefix.iter().map(|arg| (*arg).to_owned()).collect();
            args.extend(rulespec.iter().map(|arg| (*arg).to_owned()));
            if self.has_wait {
                args.push("--wait".to_owned());
                if self.timeout != 0 && self.wait_support_second {
                    args.push(self.timeout.to_string());
                }
            }
            args
        }

        fn run(&self, args: &[String]) -> std::result::Result<(), RunError> {
            self.run_with_stdout(args).map(|_| ())
        }

        fn run_with_stdout(&self, args: &[String]) -> std::result::Result<String, RunError> {
            let _lock = if self.has_wait {
                None
            } else {
                let lock = FileLock::new()?;
                lock.try_lock()?;
                Some(lock)
            };

            let output = Command::new(&self.path).args(args).output()?;
            if !output.status.success() {
                return Err(RunError::ExitStatus {
                    args: std::iter::once(self.path.clone()).chain(args.iter().cloned()).collect(),
                    exit_status: output.status.code(),
                    stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
                });
            }
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        }
    }

    fn which(cmd: &str) -> Option<String> {
        let path = std::env::var_os("PATH")?;
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join(cmd);
            if candidate.is_file() {
                return Some(candidate.to_string_lossy().into_owned());
            }
        }
        None
    }

    fn extract_iptables_version(str: &str) -> Result<(i32, i32, i32, String)> {
        let version_matcher = Regex::new(r"v([0-9]+)\.([0-9]+)\.([0-9]+)(?:\s+\((\w+))?")?;
        let Some(result) = version_matcher.captures(str) else {
            return Err(anyhow!("no iptables version found in string: {str}"));
        };
        let v1 = result[1].parse::<i32>()?;
        let v2 = result[2].parse::<i32>()?;
        let v3 = result[3].parse::<i32>()?;
        let mode = match result.get(4) {
            Some(mode) if !mode.as_str().is_empty() => mode.as_str().to_owned(),
            _ => "legacy".to_owned(),
        };
        Ok((v1, v2, v3, mode))
    }

    const fn iptables_has_check_command(v1: i32, v2: i32, v3: i32) -> bool {
        v1 > 1 || (v1 == 1 && v2 > 4) || (v1 == 1 && v2 == 4 && v3 >= 11)
    }

    const fn iptables_has_wait_command(v1: i32, v2: i32, v3: i32) -> bool {
        v1 > 1 || (v1 == 1 && v2 > 4) || (v1 == 1 && v2 == 4 && v3 >= 20)
    }

    const fn iptables_wait_support_second(v1: i32, v2: i32, _v3: i32) -> bool {
        v1 > 1 || (v1 == 1 && v2 >= 6)
    }
}
