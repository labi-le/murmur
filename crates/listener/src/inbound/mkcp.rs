use murmur_listener_config::mkcp as lc_mkcp;

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct MKCPConfig {
    pub enable: bool,
    pub mtu: u32,
    pub tti: u32,
    pub uplink_capacity: u32,
    pub downlink_capacity: u32,
    pub congestion: bool,
    pub write_buffer: u32,
    pub read_buffer: u32,
    pub seed: String,
    pub header: String,
}

impl MKCPConfig {
    #[must_use]
    pub fn build(&self) -> lc_mkcp::MKCPConfig {
        lc_mkcp::MKCPConfig {
            enable: self.enable,
            mtu: self.mtu,
            tti: self.tti,
            uplink_capacity: self.uplink_capacity,
            downlink_capacity: self.downlink_capacity,
            congestion: self.congestion,
            write_buffer: self.write_buffer,
            read_buffer: self.read_buffer,
            seed: self.seed.clone(),
            header: self.header.clone(),
        }
    }
}
