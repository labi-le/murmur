use rand::Rng;

pub(crate) trait PacketHeader: Send + Sync + std::fmt::Debug {
    fn size(&self) -> usize;

    fn serialize(&mut self, b: &mut [u8]);
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct NoopHeader {}

impl PacketHeader for NoopHeader {
    fn size(&self) -> usize {
        0
    }

    fn serialize(&mut self, _b: &mut [u8]) {}
}

pub(crate) fn rand_u16() -> u16 {
    let [low, high, ..] = (rand::rng().random::<u64>() >> 47).to_le_bytes();
    u16::from_le_bytes([low, high])
}

pub(crate) fn new_packet_header(name: &str) -> Box<dyn PacketHeader> {
    match name.to_lowercase().as_str() {
        "srtp" => Box::new(SrtpHeader { header: 0xb5e8, number: rand_u16() }),
        "utp" => Box::new(UtpHeader { header: 1, extension: 0, connection_id: rand_u16() }),
        "wechat-video" | "wechat" => Box::new(WechatVideoHeader { sn: u32::from(rand_u16()) }),
        "dtls" => Box::new(DtlsHeader { epoch: rand_u16(), length: 17, sequence: 0 }),
        "wireguard" => Box::new(WireguardHeader {}),
        // "", "none", "noop" and anything unrecognised: no extra header.
        _ => Box::new(NoopHeader {}),
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct SrtpHeader {
    header: u16,
    number: u16,
}

impl PacketHeader for SrtpHeader {
    fn size(&self) -> usize {
        4
    }

    fn serialize(&mut self, b: &mut [u8]) {
        self.number = self.number.wrapping_add(1);
        for (out, byte) in b.iter_mut().zip(self.header.to_be_bytes().into_iter().chain(self.number.to_be_bytes())) {
            *out = byte;
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct UtpHeader {
    header: u8,
    extension: u8,
    connection_id: u16,
}

impl PacketHeader for UtpHeader {
    fn size(&self) -> usize {
        4
    }

    fn serialize(&mut self, b: &mut [u8]) {
        for (out, byte) in
            b.iter_mut().zip(self.connection_id.to_be_bytes().into_iter().chain([self.header, self.extension]))
        {
            *out = byte;
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct WechatVideoHeader {
    sn: u32,
}

impl PacketHeader for WechatVideoHeader {
    fn size(&self) -> usize {
        13
    }

    fn serialize(&mut self, b: &mut [u8]) {
        self.sn = self.sn.wrapping_add(1);
        for (out, byte) in b.iter_mut().zip(
            [0xa1, 0x08].into_iter().chain(self.sn.to_be_bytes()).chain([0x00, 0x10, 0x11, 0x18, 0x30, 0x22, 0x30]),
        ) {
            *out = byte;
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct DtlsHeader {
    epoch: u16,
    length: u16,
    sequence: u32,
}

impl PacketHeader for DtlsHeader {
    fn size(&self) -> usize {
        13
    }

    fn serialize(&mut self, b: &mut [u8]) {
        for (out, byte) in b.iter_mut().zip(
            [23, 254, 253]
                .into_iter()
                .chain(self.epoch.to_be_bytes())
                .chain([0, 0])
                .chain(self.sequence.to_be_bytes())
                .chain(self.length.to_be_bytes()),
        ) {
            *out = byte;
        }
        self.sequence = self.sequence.wrapping_add(1);
        self.length = self.length.wrapping_add(17);
        if self.length > 100 {
            self.length = self.length.wrapping_sub(50);
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct WireguardHeader {}

impl PacketHeader for WireguardHeader {
    fn size(&self) -> usize {
        4
    }

    fn serialize(&mut self, b: &mut [u8]) {
        for (out, byte) in b.iter_mut().zip([0x04, 0x00, 0x00, 0x00]) {
            *out = byte;
        }
    }
}
