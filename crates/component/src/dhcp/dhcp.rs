//! The DHCPv4 client subset this crate reaches, in `mod dhcpv4` below.
//!
//! No crate provides a DHCPv4 client, so discovery construction, the wire codec and the
//! message-type and DNS option accessors live here, keeping the standard byte layout and error
//! text.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::iface::iface::resolve_interface;
use crate::resolver::host::unmap_addr;
use murmur_common_net::io::Datagram;

use super::conn::listen_dhcp_client;

/// The sentinel errors of the DHCP client.
#[derive(thiserror::Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum DHCPError {
    #[error("DHCP not responding")]
    NotResponding,
    #[error("DNS option not found")]
    NotFound,
}

// cancel-safe: a drop runs `ConnGuard`, which closes the connection and aborts the receive task.
pub async fn resolve_dns_from_dhcp(ctx: &CancellationToken, iface_name: &str) -> anyhow::Result<Vec<IpAddr>> {
    let conn: Arc<dyn Datagram> = listen_dhcp_client(ctx, iface_name).await?.into();

    let (result_tx, mut result_rx) = mpsc::channel::<Vec<IpAddr>>(1);

    let mut guard = ConnGuard::new(Arc::clone(&conn));

    let iface_obj = resolve_interface(iface_name).await?;

    let discovery = dhcpv4::new_discovery(
        &iface_obj.hardware_addr.0,
        vec![dhcpv4::with_broadcast(true), dhcpv4::with_requested_options(&[dhcpv4::OptionCode::DOMAIN_NAME_SERVER])],
    )?;

    guard.task = Some(tokio::spawn(receive_offer(Arc::clone(&conn), discovery.transaction_id, result_tx)));

    let destination = SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), 67);
    conn.send_to(&discovery.to_bytes(), destination).await?;

    tokio::select! {
        r = result_rx.recv() => match r {
            Some(r) => Ok(r),
            None => Err(DHCPError::NotFound.into()),
        },
        () = ctx.cancelled() => Err(DHCPError::NotResponding.into()),
    }
}

/// Closes the conn on drop; its read error is what ends the receive loop.
struct ConnGuard {
    conn: Arc<dyn Datagram>,
    task: Option<JoinHandle<()>>,
}

impl ConnGuard {
    fn new(conn: Arc<dyn Datagram>) -> Self {
        Self { conn, task: None }
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        let _ = self.conn.close();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

// NOT cancel-safe: an abort mid-receive can drop a datagram already taken off the socket; the
// guard that aborts the task closes the connection in the same drop.
async fn receive_offer(conn: Arc<dyn Datagram>, id: dhcpv4::TransactionID, result: mpsc::Sender<Vec<IpAddr>>) {
    let mut buf = vec![0u8; dhcpv4::MAX_MESSAGE_SIZE];

    loop {
        let Ok((n, _)) = conn.recv_from(&mut buf).await else {
            return;
        };

        let Some(packet) = buf.get(..n) else {
            continue;
        };
        let Ok(pkt) = dhcpv4::from_bytes(packet) else {
            continue;
        };

        if pkt.message_type() != dhcpv4::MessageType::OFFER {
            continue;
        }

        if pkt.transaction_id != id {
            continue;
        }

        let dns = pkt.dns();
        if dns.is_empty() {
            return;
        }

        let mut results = Vec::with_capacity(dns.len());
        for ip in &dns {
            if let Some(addr) = addr_from_slice(ip) {
                results.push(unmap_addr(addr));
            }
        }

        let _ = result.send(results).await;

        return;
    }
}

/// Builds an address from a byte slice, accepting only 4 or 16 bytes.
fn addr_from_slice(slice: &[u8]) -> Option<IpAddr> {
    match slice.len() {
        4 => {
            let mut octets = [0u8; 4];
            octets.copy_from_slice(slice);
            Some(IpAddr::from(octets))
        }
        16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(slice);
            Some(IpAddr::from(octets))
        }
        _ => None,
    }
}

mod dhcpv4 {
    use std::collections::HashMap;
    use std::io;

    use anyhow::anyhow;
    use rand::rngs::OsRng;
    use rand::TryRngCore;

    const MIN_PACKET_LEN: usize = 236;
    const MAX_HW_ADDR_LEN: usize = 16;
    const BOOTP_MIN_LEN: usize = 300;
    const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

    pub(super) const MAX_MESSAGE_SIZE: usize = 576;

    const OPT_PAD: u8 = 0;
    const OPT_AGENT_INFO: u8 = 82;
    const OPT_END: u8 = 255;

    const OPCODE_BOOT_REQUEST: u8 = 1;
    const HW_TYPE_ETHERNET: u8 = 1;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub(super) struct TransactionID(pub [u8; 4]);

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) struct MessageType(u8);

    impl MessageType {
        pub(super) const NONE: Self = Self(0);
        pub(super) const DISCOVER: Self = Self(1);
        pub(super) const OFFER: Self = Self(2);

        pub(super) fn to_bytes(self) -> Vec<u8> {
            vec![self.0]
        }

        pub(super) fn from_bytes(data: &[u8]) -> anyhow::Result<Self> {
            let mut buf = Reader::new(data);
            let m = Self(buf.read8());
            if let Some(err) = buf.fin_error() {
                return Err(anyhow!("{err}"));
            }
            Ok(m)
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
    pub(super) struct OptionCode(u8);

    impl OptionCode {
        pub(super) const PAD: Self = Self(0);
        pub(super) const SUBNET_MASK: Self = Self(1);
        pub(super) const ROUTER: Self = Self(3);
        pub(super) const DOMAIN_NAME_SERVER: Self = Self(6);
        pub(super) const DOMAIN_NAME: Self = Self(15);
        pub(super) const DHCP_MESSAGE_TYPE: Self = Self(53);
        pub(super) const PARAMETER_REQUEST_LIST: Self = Self(55);
        pub(super) const END: Self = Self(255);

        pub(super) const fn code(self) -> u8 {
            self.0
        }
    }

    #[derive(Clone, Debug, Default)]
    pub(super) struct OptionCodeList(Vec<OptionCode>);

    impl OptionCodeList {
        pub(super) fn has(&self, c: OptionCode) -> bool {
            self.0.contains(&c)
        }

        pub(super) fn add(&mut self, cs: &[OptionCode]) {
            for &c in cs {
                if !self.has(c) {
                    self.0.push(c);
                }
            }
        }

        pub(super) fn to_bytes(&self) -> Vec<u8> {
            let mut buf = Writer::new();
            for req in &self.0 {
                buf.write8(req.code());
            }
            buf.data().to_vec()
        }

        pub(super) fn from_bytes(data: &[u8]) -> anyhow::Result<Self> {
            let mut buf = Reader::new(data);
            let mut list = Vec::with_capacity(buf.len());
            while buf.has(1) {
                list.push(OptionCode(buf.read8()));
            }
            if let Some(err) = buf.fin_error() {
                return Err(anyhow!("{err}"));
            }
            Ok(Self(list))
        }
    }

    pub(super) struct Option {
        pub code: OptionCode,
        pub value: OptionValue,
    }

    pub(super) enum OptionValue {
        MessageType(MessageType),
        OptionCodeList(OptionCodeList),
    }

    impl OptionValue {
        pub(super) fn to_bytes(&self) -> Vec<u8> {
            match self {
                Self::MessageType(m) => m.to_bytes(),
                Self::OptionCodeList(l) => l.to_bytes(),
            }
        }
    }

    /// The options, keyed by option code.
    #[derive(Clone, Debug, Default)]
    pub(super) struct Options {
        map: HashMap<u8, Vec<u8>>,
    }

    impl Options {
        pub(super) fn get(&self, code: OptionCode) -> std::option::Option<&[u8]> {
            self.map.get(&code.code()).map(Vec::as_slice)
        }

        pub(super) fn update(&mut self, option: &Option) {
            self.map.insert(option.code.code(), option.value.to_bytes());
        }

        /// Reads options from `data`, honouring `check_end_option`. The `from_` prefix is
        /// deliberate, though clippy's receiver convention dislikes it.
        #[expect(
            clippy::wrong_self_convention,
            reason = "the `from_bytes` spelling is the wire codec's name; the receiver is `&mut self` because parsing fills the option map in place"
        )]
        pub(super) fn from_bytes_check_end(&mut self, data: &[u8], check_end_option: bool) -> anyhow::Result<()> {
            if data.is_empty() {
                return Ok(());
            }
            let mut buf = Reader::new(data);

            let mut end = false;
            while !buf.is_empty() {
                let code = buf.read8();

                if code == OPT_END {
                    end = true;
                    break;
                }
                if code == OPT_PAD {
                    continue;
                }
                let length = usize::from(buf.read8());

                let Some(data) = buf.consume(length) else {
                    return Err(anyhow!("error collecting options: {}", buf.error().unwrap_or_default()));
                };

                self.map.entry(code).or_default().extend_from_slice(data);
            }

            if !end && check_end_option {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "unexpected EOF").into());
            }

            Ok(())
        }

        /// Keeps option 82 last, before End.
        fn sorted_keys(&self) -> Vec<u8> {
            let mut codes = Vec::new();
            let mut has_opt_agent_info = false;
            let mut has_opt_end = false;
            for &k in self.map.keys() {
                if k == OPT_AGENT_INFO {
                    has_opt_agent_info = true;
                    continue;
                }
                if k == OPT_END {
                    has_opt_end = true;
                    continue;
                }
                codes.push(k);
            }

            codes.sort_unstable();

            if has_opt_agent_info {
                codes.push(OPT_AGENT_INFO);
            }
            if has_opt_end {
                codes.push(OPT_END);
            }
            codes
        }

        fn marshal(&self, b: &mut Writer) {
            for code in self.sorted_keys() {
                if code == OPT_END || code == OPT_PAD {
                    continue;
                }

                let Some(data) = self.map.get(&code).map(Vec::as_slice) else {
                    continue;
                };
                if data.is_empty() {
                    b.write8(code);
                    b.write8(0);
                    continue;
                }

                let mut rest = data;
                while !rest.is_empty() {
                    b.write8(code);

                    let n = rest.len().min(usize::from(u8::MAX));
                    let (chunk, tail) = rest.split_at(n);

                    #[expect(
                        clippy::cast_possible_truncation,
                        reason = "the length is capped at `u8::MAX` by the `min` above"
                    )]
                    b.write8(n as u8);

                    b.write_bytes(chunk);
                    rest = tail;
                }
            }
        }
    }

    pub(super) struct DHCPv4 {
        pub op_code: u8,
        pub hw_type: u8,
        pub hop_count: u8,
        pub transaction_id: TransactionID,
        pub num_seconds: u16,
        pub flags: u16,
        pub client_ip_addr: [u8; 4],
        pub your_ip_addr: [u8; 4],
        pub server_ip_addr: [u8; 4],
        pub gateway_ip_addr: [u8; 4],
        pub client_hw_addr: Vec<u8>,
        pub server_host_name: String,
        pub boot_file_name: String,
        pub options: Options,
    }

    impl DHCPv4 {
        pub(super) const fn set_broadcast(&mut self) {
            self.flags |= 0x8000;
        }

        pub(super) const fn set_unicast(&mut self) {
            self.flags &= !0x8000;
        }

        pub(super) fn update_option(&mut self, option: &Option) {
            self.options.update(option);
        }

        pub(super) fn message_type(&self) -> MessageType {
            let Some(v) = self.options.get(OptionCode::DHCP_MESSAGE_TYPE) else {
                return MessageType::NONE;
            };
            MessageType::from_bytes(v).unwrap_or(MessageType::NONE)
        }

        pub(super) fn parameter_request_list(&self) -> std::option::Option<OptionCodeList> {
            let v = self.options.get(OptionCode::PARAMETER_REQUEST_LIST)?;
            OptionCodeList::from_bytes(v).ok()
        }

        pub(super) fn dns(&self) -> Vec<Vec<u8>> {
            get_ips(OptionCode::DOMAIN_NAME_SERVER, &self.options)
        }

        pub(super) fn to_bytes(&self) -> Vec<u8> {
            let mut buf = Writer::new();
            buf.write8(self.op_code);
            buf.write8(self.hw_type);

            #[expect(
                clippy::cast_possible_truncation,
                reason = "a link-layer address is at most `MAX_HW_ADDR_LEN` bytes; the wire length field is one byte"
            )]
            buf.write8(self.client_hw_addr.len() as u8);
            buf.write8(self.hop_count);
            buf.write_bytes(&self.transaction_id.0);
            buf.write16(self.num_seconds);
            buf.write16(self.flags);

            buf.write_bytes(&self.client_ip_addr);
            buf.write_bytes(&self.your_ip_addr);
            buf.write_bytes(&self.server_ip_addr);
            buf.write_bytes(&self.gateway_ip_addr);
            buf.write_n(&self.client_hw_addr, MAX_HW_ADDR_LEN);

            let mut sname = [0u8; 64];
            let name = self.server_host_name.as_bytes();
            let n = name.len().min(63);
            let (sname_head, _) = sname.split_at_mut(n);
            let (name_head, _) = name.split_at(n);
            sname_head.copy_from_slice(name_head);
            buf.write_bytes(&sname);

            let mut file = [0u8; 128];
            let name = self.boot_file_name.as_bytes();
            let n = name.len().min(127);
            let (file_head, _) = file.split_at_mut(n);
            let (name_head, _) = name.split_at(n);
            file_head.copy_from_slice(name_head);
            buf.write_bytes(&file);

            buf.write_bytes(&MAGIC_COOKIE);

            self.options.marshal(&mut buf);

            buf.write8(OptionCode::END.code());

            if buf.len() < BOOTP_MIN_LEN {
                buf.write_bytes(&vec![OptionCode::PAD.code(); BOOTP_MIN_LEN - buf.len()]);
            }

            buf.data().to_vec()
        }
    }

    pub(super) type Modifier = Box<dyn Fn(&mut DHCPv4)>;

    pub(super) fn new(modifiers: &[Modifier]) -> anyhow::Result<DHCPv4> {
        let xid = generate_transaction_id()?;
        Ok(new_dhcpv4(xid, modifiers))
    }

    fn generate_transaction_id() -> anyhow::Result<TransactionID> {
        let mut xid = TransactionID([0u8; 4]);
        let n = OsRng
            .try_fill_bytes(&mut xid.0)
            .map(|()| xid.0.len())
            .map_err(|err| anyhow!("could not get random number: {err}"))?;
        if n != 4 {
            return Err(anyhow!("invalid random sequence for transaction ID: smaller than 32 bits"));
        }
        Ok(xid)
    }

    fn new_dhcpv4(xid: TransactionID, modifiers: &[Modifier]) -> DHCPv4 {
        let mut d = DHCPv4 {
            op_code: OPCODE_BOOT_REQUEST,
            hw_type: HW_TYPE_ETHERNET,
            client_hw_addr: vec![0u8; 6],
            hop_count: 0,
            transaction_id: xid,
            num_seconds: 0,
            flags: 0,
            client_ip_addr: [0; 4],
            your_ip_addr: [0; 4],
            server_ip_addr: [0; 4],
            gateway_ip_addr: [0; 4],
            server_host_name: String::new(),
            boot_file_name: String::new(),
            options: Options::default(),
        };
        for modifier in modifiers {
            modifier(&mut d);
        }
        d
    }

    pub(super) fn new_discovery(hwaddr: &[u8], modifiers: Vec<Modifier>) -> anyhow::Result<DHCPv4> {
        new(&prepend_modifiers(
            modifiers,
            vec![
                with_hw_addr(hwaddr),
                with_requested_options(&[
                    OptionCode::SUBNET_MASK,
                    OptionCode::ROUTER,
                    OptionCode::DOMAIN_NAME,
                    OptionCode::DOMAIN_NAME_SERVER,
                ]),
                with_message_type(MessageType::DISCOVER),
            ],
        ))
    }

    fn prepend_modifiers(m: Vec<Modifier>, other: Vec<Modifier>) -> Vec<Modifier> {
        let mut out = other;
        out.extend(m);
        out
    }

    pub(super) fn with_hw_addr(hwaddr: &[u8]) -> Modifier {
        let hwaddr = hwaddr.to_vec();
        Box::new(move |d: &mut DHCPv4| {
            d.client_hw_addr.clone_from(&hwaddr);
        })
    }

    pub(super) fn with_broadcast(broadcast: bool) -> Modifier {
        Box::new(move |d: &mut DHCPv4| {
            if broadcast {
                d.set_broadcast();
            } else {
                d.set_unicast();
            }
        })
    }

    pub(super) fn with_message_type(m: MessageType) -> Modifier {
        Box::new(move |d: &mut DHCPv4| {
            d.update_option(&Option { code: OptionCode::DHCP_MESSAGE_TYPE, value: OptionValue::MessageType(m) });
        })
    }

    pub(super) fn with_requested_options(option_codes: &[OptionCode]) -> Modifier {
        let option_codes = option_codes.to_vec();
        Box::new(move |d: &mut DHCPv4| {
            let mut cl = d.parameter_request_list().unwrap_or_default();
            cl.add(&option_codes);
            d.update_option(&Option {
                code: OptionCode::PARAMETER_REQUEST_LIST,
                value: OptionValue::OptionCodeList(cl),
            });
        })
    }

    pub(super) fn from_bytes(q: &[u8]) -> anyhow::Result<DHCPv4> {
        let mut p = DHCPv4 {
            op_code: 0,
            hw_type: 0,
            hop_count: 0,
            transaction_id: TransactionID([0; 4]),
            num_seconds: 0,
            flags: 0,
            client_ip_addr: [0; 4],
            your_ip_addr: [0; 4],
            server_ip_addr: [0; 4],
            gateway_ip_addr: [0; 4],
            client_hw_addr: Vec::new(),
            server_host_name: String::new(),
            boot_file_name: String::new(),
            options: Options::default(),
        };
        let mut buf = Reader::new(q);

        p.op_code = buf.read8();
        p.hw_type = buf.read8();
        let mut hw_addr_len = usize::from(buf.read8());

        p.hop_count = buf.read8();
        buf.read_bytes(&mut p.transaction_id.0);
        p.num_seconds = buf.read16();
        p.flags = buf.read16();

        buf.read_bytes(&mut p.client_ip_addr);
        buf.read_bytes(&mut p.your_ip_addr);
        buf.read_bytes(&mut p.server_ip_addr);
        buf.read_bytes(&mut p.gateway_ip_addr);

        if hw_addr_len > MAX_HW_ADDR_LEN {
            hw_addr_len = MAX_HW_ADDR_LEN;
        }
        p.client_hw_addr = vec![0u8; MAX_HW_ADDR_LEN];
        buf.read_bytes(&mut p.client_hw_addr);
        p.client_hw_addr.truncate(hw_addr_len);

        let mut sname = [0u8; 64];
        buf.read_bytes(&mut sname);
        let length = sname.iter().position(|&b| b == 0).unwrap_or(sname.len());
        let (sname_head, _) = sname.split_at(length);
        p.server_host_name = String::from_utf8_lossy(sname_head).into_owned();

        let mut file = [0u8; 128];
        buf.read_bytes(&mut file);
        let length = file.iter().position(|&b| b == 0).unwrap_or(file.len());
        let (file_head, _) = file.split_at(length);
        p.boot_file_name = String::from_utf8_lossy(file_head).into_owned();

        let mut cookie = [0u8; 4];
        buf.read_bytes(&mut cookie);

        if let Some(err) = buf.error() {
            return Err(anyhow!("{err}"));
        }
        if cookie != MAGIC_COOKIE {
            return Err(anyhow!(
                "malformed DHCP packet: got magic cookie {}, want {}",
                bytes_debug(&cookie),
                bytes_debug(&MAGIC_COOKIE)
            ));
        }

        p.options.from_bytes_check_end(buf.remaining(), true)?;
        Ok(p)
    }

    fn get_ips(code: OptionCode, o: &Options) -> Vec<Vec<u8>> {
        let Some(v) = o.get(code) else {
            return Vec::new();
        };
        let mut ips = Vec::new();
        if ips_from_bytes(&mut ips, v).is_err() {
            return Vec::new();
        }
        ips
    }

    fn ips_from_bytes(ips: &mut Vec<Vec<u8>>, data: &[u8]) -> anyhow::Result<()> {
        let mut buf = Reader::new(data);
        if buf.is_empty() {
            return Err(anyhow!("IP DHCP options must always list at least one IP"));
        }

        ips.reserve(buf.len() / 4);
        while buf.has(4) {
            ips.push(buf.copy_n(4).unwrap_or_default());
        }
        if let Some(err) = buf.fin_error() {
            return Err(anyhow!("{err}"));
        }
        Ok(())
    }

    /// Formats a byte slice as space-separated decimals in brackets.
    fn bytes_debug(bytes: &[u8]) -> String {
        let parts: Vec<String> = bytes.iter().map(u8::to_string).collect();
        format!("[{}]", parts.join(" "))
    }

    /// The read half, which keeps the first error and answers zeroes after it.
    struct Reader<'a> {
        data: &'a [u8],
        pos: usize,
        byte_count: usize,
        err: std::option::Option<String>,
    }

    impl<'a> Reader<'a> {
        const fn new(data: &'a [u8]) -> Self {
            Self { data, pos: 0, byte_count: 0, err: None }
        }

        const fn len(&self) -> usize {
            self.data.len() - self.pos
        }

        fn is_empty(&self) -> bool {
            self.len() == 0
        }

        fn has(&self, n: usize) -> bool {
            self.len() >= n
        }

        fn set_error(&mut self, err: String) {
            if self.err.is_none() {
                self.err = Some(err);
            }
        }

        fn consume(&mut self, n: usize) -> std::option::Option<&'a [u8]> {
            if !self.has(n) {
                let (position, have) = (self.byte_count, self.len());
                self.set_error(format!("buffer too short at position {position}: have {have} bytes, want {n} bytes"));
                return None;
            }
            let data: &'a [u8] = self.data;
            let out = data.get(self.pos..self.pos + n)?;
            self.pos += n;
            self.byte_count += n;
            Some(out)
        }

        fn read8(&mut self) -> u8 {
            let Some([v]) = self.consume(1) else {
                return 0;
            };
            *v
        }

        fn read16(&mut self) -> u16 {
            let Some([hi, lo]) = self.consume(2) else {
                return 0;
            };
            u16::from_be_bytes([*hi, *lo])
        }

        fn copy_n(&mut self, n: usize) -> std::option::Option<Vec<u8>> {
            self.consume(n).map(<[u8]>::to_vec)
        }

        fn read_bytes(&mut self, p: &mut [u8]) {
            if let Some(v) = self.consume(p.len()) {
                p.copy_from_slice(v);
            }
        }

        fn error(&self) -> std::option::Option<&str> {
            self.err.as_deref()
        }

        fn fin_error(&self) -> std::option::Option<String> {
            if let Some(err) = &self.err {
                return Some(err.clone());
            }
            if !self.is_empty() {
                return Some("buffer contains unread bytes".to_owned());
            }
            None
        }

        fn remaining(&self) -> &'a [u8] {
            let data: &'a [u8] = self.data;
            data.get(self.pos..).unwrap_or_default()
        }
    }

    /// The write half.
    struct Writer {
        data: Vec<u8>,
    }

    impl Writer {
        fn new() -> Self {
            Self { data: Vec::with_capacity(MIN_PACKET_LEN) }
        }

        const fn len(&self) -> usize {
            self.data.len()
        }

        fn write8(&mut self, v: u8) {
            self.data.push(v);
        }

        fn write16(&mut self, v: u16) {
            self.data.extend_from_slice(&v.to_be_bytes());
        }

        fn write_bytes(&mut self, p: &[u8]) {
            self.data.extend_from_slice(p);
        }

        /// Writes n bytes, with only what `src` holds copied over.
        fn write_n(&mut self, src: &[u8], n: usize) {
            let start = self.data.len();
            self.data.resize(start + n, 0);
            let m = src.len().min(n);
            let (_, tail) = self.data.split_at_mut(start);
            let (dst, _) = tail.split_at_mut(m);
            let (src_head, _) = src.split_at(m);
            dst.copy_from_slice(src_head);
        }

        fn data(&self) -> &[u8] {
            &self.data
        }
    }
}
