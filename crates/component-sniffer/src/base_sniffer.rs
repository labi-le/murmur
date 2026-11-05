use murmur_common::utils::ranges::IntRanges;
use murmur_constant::metadata::NetWork;
use murmur_constant::sniffer::sniffer::Sniffer;

use super::dispatcher::ErrorUnsupportedSniffer;

#[derive(Clone, Debug, Default)]
pub struct SnifferConfig {
    pub override_dest: bool,
    pub ports: IntRanges<u16>,
}

#[derive(Clone, Debug, Default)]
pub struct BaseSniffer {
    pub(crate) ports: IntRanges<u16>,
    pub(crate) support_network_type: NetWork,
}

impl BaseSniffer {
    #[must_use]
    pub const fn new(ports: IntRanges<u16>, network_type: NetWork) -> Self {
        Self { ports, support_network_type: network_type }
    }
}

impl Sniffer for BaseSniffer {
    fn support_network(&self) -> NetWork {
        self.support_network_type
    }

    fn sniff_data(&self, _bytes: &[u8]) -> anyhow::Result<String> {
        Err(ErrorUnsupportedSniffer.into())
    }

    fn protocol(&self) -> String {
        "unknown".to_owned()
    }

    fn support_port(&self, port: u16) -> bool {
        self.ports.check(port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dispatcher::ErrorUnsupportedSniffer;

    #[test]
    fn base_sniffer_names_the_unsupported_protocol() {
        let sniffer = BaseSniffer::new(IntRanges::default(), NetWork::TCP);

        let err = sniffer.sniff_data(b"").unwrap_err();

        assert!(err.is::<ErrorUnsupportedSniffer>(), "expected a named unsupported-protocol error, got {err}");
    }
}
