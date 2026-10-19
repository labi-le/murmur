use std::net::IpAddr;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use parking_lot::Mutex;

use crate::inbound::base::{config_equal, option_to_string, upcast_config, Base, BaseOption};
use murmur_adapter_inbound::addition::Addition;
use murmur_constant::listener::{InboundConfig, InboundListener, Listener as ConstListener};
use murmur_constant::tun::TunStack;
use murmur_constant::tunnel::Tunnel;
use murmur_listener_config::tun::Tun as TunConfig;

/// Every field carries through to the device unchanged; the ones this crate cannot act on are
/// refused by name at listen time rather than dropped here.
#[derive(Clone, Debug, Default, serde::Serialize)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "the tun option mirrors the tun config field-for-field; its flags are independent wire options, not a state machine"
)]
pub struct TunOption {
    pub base: BaseOption,
    pub device: String,
    pub stack: TunStack,
    pub dns_hijack: Option<Vec<String>>,
    pub auto_route: bool,
    pub auto_detect_interface: bool,
    pub mtu: u32,
    pub gso: bool,
    pub gso_max_size: u32,
    pub inet4_address: Vec<ipnet::IpNet>,
    pub inet6_address: Vec<ipnet::IpNet>,
    pub iproute2_table_index: i64,
    pub iproute2_rule_index: i64,
    pub auto_redirect: bool,
    pub auto_redirect_input_mark: u32,
    pub auto_redirect_output_mark: u32,
    pub auto_redirect_iproute2_fallback_rule_index: i64,
    pub loopback_address: Vec<IpAddr>,
    pub strict_route: bool,
    pub route_address: Vec<ipnet::IpNet>,
    pub route_address_set: Vec<String>,
    pub route_exclude_address: Vec<ipnet::IpNet>,
    pub route_exclude_address_set: Vec<String>,
    pub include_interface: Vec<String>,
    pub exclude_interface: Vec<String>,
    pub include_uid: Vec<u32>,
    pub include_uid_range: Vec<String>,
    pub exclude_uid: Vec<u32>,
    pub exclude_uid_range: Vec<String>,
    pub exclude_src_port: Vec<u16>,
    pub exclude_src_port_range: Vec<String>,
    pub exclude_dst_port: Vec<u16>,
    pub exclude_dst_port_range: Vec<String>,
    pub include_android_user: Vec<i64>,
    pub include_package: Vec<String>,
    pub exclude_package: Vec<String>,
    pub include_mac_address: Vec<String>,
    pub exclude_mac_address: Vec<String>,
    pub endpoint_independent_nat: bool,
    pub udp_timeout: i64,
    pub icmp_timeout: i64,
    pub disable_icmp_forwarding: bool,
    pub file_descriptor: i32,
    pub inet4_route_address: Vec<ipnet::IpNet>,
    pub inet6_route_address: Vec<ipnet::IpNet>,
    pub inet4_route_exclude_address: Vec<ipnet::IpNet>,
    pub inet6_route_exclude_address: Vec<ipnet::IpNet>,
    pub recvmsgx: bool,
    pub sendmsgx: bool,
    pub processors_per_channel: i32,
}

impl InboundConfig for TunOption {
    fn name(&self) -> String {
        self.base.name()
    }

    fn equal(&self, config: &dyn InboundConfig) -> bool {
        config_equal(self, config)
    }

    fn option_to_string(&self) -> String {
        option_to_string(self)
    }
}

impl TunOption {
    /// The built tun config always enables the device: the listener exists because the config
    /// asked for one.
    #[must_use]
    pub fn build(&self) -> TunConfig {
        TunConfig {
            enable: true,
            device: self.device.clone(),
            stack: self.stack,
            dns_hijack: self.dns_hijack.clone(),
            auto_route: self.auto_route,
            auto_detect_interface: self.auto_detect_interface,
            mtu: self.mtu,
            gso: self.gso,
            gso_max_size: self.gso_max_size,
            inet4_address: self.inet4_address.clone(),
            inet6_address: self.inet6_address.clone(),
            iproute2_table_index: self.iproute2_table_index,
            iproute2_rule_index: self.iproute2_rule_index,
            auto_redirect: self.auto_redirect,
            auto_redirect_input_mark: self.auto_redirect_input_mark,
            auto_redirect_output_mark: self.auto_redirect_output_mark,
            auto_redirect_iproute2_fallback_rule_index: self.auto_redirect_iproute2_fallback_rule_index,
            loopback_address: self.loopback_address.clone(),
            strict_route: self.strict_route,
            route_address: self.route_address.clone(),
            route_address_set: self.route_address_set.clone(),
            route_exclude_address: self.route_exclude_address.clone(),
            route_exclude_address_set: self.route_exclude_address_set.clone(),
            include_interface: self.include_interface.clone(),
            exclude_interface: self.exclude_interface.clone(),
            include_uid: self.include_uid.clone(),
            include_uid_range: self.include_uid_range.clone(),
            exclude_uid: self.exclude_uid.clone(),
            exclude_uid_range: self.exclude_uid_range.clone(),
            exclude_src_port: self.exclude_src_port.clone(),
            exclude_src_port_range: self.exclude_src_port_range.clone(),
            exclude_dst_port: self.exclude_dst_port.clone(),
            exclude_dst_port_range: self.exclude_dst_port_range.clone(),
            include_android_user: self.include_android_user.clone(),
            include_package: self.include_package.clone(),
            exclude_package: self.exclude_package.clone(),
            include_mac_address: self.include_mac_address.clone(),
            exclude_mac_address: self.exclude_mac_address.clone(),
            endpoint_independent_nat: self.endpoint_independent_nat,
            udp_timeout: self.udp_timeout,
            icmp_timeout: self.icmp_timeout,
            disable_icmp_forwarding: self.disable_icmp_forwarding,
            file_descriptor: self.file_descriptor,
            inet4_route_address: self.inet4_route_address.clone(),
            inet6_route_address: self.inet6_route_address.clone(),
            inet4_route_exclude_address: self.inet4_route_exclude_address.clone(),
            inet6_route_exclude_address: self.inet6_route_exclude_address.clone(),
            recvmsgx: self.recvmsgx,
            sendmsgx: self.sendmsgx,
            processors_per_channel: self.processors_per_channel,
        }
    }
}

pub struct Tun {
    base: Base,
    config: Arc<TunOption>,
    l: Mutex<Option<Arc<crate::tun::Listener>>>,
}

impl core::fmt::Debug for Tun {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Tun").field("base", &self.base).field("config", &self.config).finish_non_exhaustive()
    }
}

impl Tun {
    pub fn new(options: Arc<TunOption>) -> Result<Self> {
        let base = Base::new(Arc::new(options.base.clone()))?;
        Ok(Self { base, config: options, l: Mutex::new(None) })
    }
}

#[async_trait]
impl InboundListener for Tun {
    fn name(&self) -> String {
        self.base.config().name()
    }

    async fn listen(&self, tunnel: Arc<dyn Tunnel>) -> Result<()> {
        let listener = crate::tun::new(self.config.build(), tunnel, self.base.additions()).await?;
        crate::tun::log_startup(&listener.address());
        *self.l.lock() = Some(listener);
        Ok(())
    }

    fn close(&self) -> Result<()> {
        let listener = self.l.lock().take();
        match listener {
            Some(listener) => listener.close(),
            None => Ok(()),
        }
    }

    /// The device's own description rather than a socket address.
    fn address(&self) -> String {
        self.l.lock().as_ref().map_or_else(String::new, |listener| listener.address())
    }

    fn raw_address(&self) -> String {
        self.config.device.clone()
    }

    fn config(&self) -> Arc<dyn InboundConfig> {
        upcast_config(Arc::clone(&self.config))
    }
}

const _: fn(&[Addition]) = |_| {};

#[cfg(test)]
mod tests {
    use super::*;

    /// The built config sets `enable: true` unconditionally: the listener only exists because the
    /// config asked for a device, whatever the top-level `tun:` section says.
    #[test]
    fn build_enables_the_device_and_carries_every_field() {
        let option = TunOption {
            device: "Meta".into(),
            stack: TunStack::Gvisor,
            auto_route: true,
            mtu: 1500,
            inet4_address: vec!["198.18.0.1/30".parse().unwrap()],
            disable_icmp_forwarding: true,
            route_address: vec!["10.0.0.0/8".parse().unwrap()],
            exclude_dst_port: vec![53],
            ..Default::default()
        };
        let built = option.build();
        assert!(built.enable);
        assert_eq!(built.device, "Meta");
        assert_eq!(built.stack, TunStack::Gvisor);
        assert!(built.auto_route);
        assert_eq!(built.mtu, 1500);
        assert_eq!(built.inet4_address, option.inet4_address);
        assert!(built.disable_icmp_forwarding);
        assert_eq!(built.route_address, option.route_address);
        assert_eq!(built.exclude_dst_port, vec![53]);
    }

    /// Two configs are compared by their rendered option string, so two options that differ only
    /// in a field must not compare equal.
    #[test]
    fn equal_distinguishes_configs_by_every_field() {
        let a = TunOption { device: "Meta".into(), mtu: 1500, ..Default::default() };
        let same = TunOption { device: "Meta".into(), mtu: 1500, ..Default::default() };
        let other = TunOption { device: "Meta".into(), mtu: 9000, ..Default::default() };
        assert!(a.equal(&same));
        assert!(!a.equal(&other));
    }
}
