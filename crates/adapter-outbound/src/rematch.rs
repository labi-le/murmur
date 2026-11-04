use std::sync::{Arc, Weak};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;

use murmur_constant::adapters::AdapterType;
use murmur_constant::adapters::{
    Conn as CConn, PacketConn as CPacketConn, Proxy, ProxyAdapter as CProxyAdapter, ProxyInfo,
};
use murmur_constant::metadata::Metadata;

use super::base::{new_conn, new_packet_conn, Base, BaseOption, BasicOption, ProxyAdapter};
use super::reject::{NopConn, NopPacketConn};

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct RematchOption {
    #[serde(flatten)]
    pub basic_option: BasicOption,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "target-rematch-name", default)]
    pub target_rematch_name: Option<String>,
    #[serde(rename = "target-sub-rule", default)]
    pub target_sub_rule: Option<String>,
}

impl std::fmt::Debug for RematchOption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RematchOption")
            .field("name", &self.name)
            .field("target_rematch_name", &self.target_rematch_name)
            .field("target_sub_rule", &self.target_sub_rule)
            .finish_non_exhaustive()
    }
}

/// `self_weak` upgrades to the `Arc<Rematch>` the `l` receiver already is.
///
/// It is needed only by `new_packet_conn` (which retains the adapter for `resolve_udp`);
/// populated by `Arc::new_cyclic` — DEVIATION, see the wave report.
pub struct Rematch {
    base: Base,
    target_rematch_name: Option<String>,
    target_sub_rule: Option<String>,
    self_weak: Weak<Self>,
}

impl std::fmt::Debug for Rematch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rematch")
            .field("target_rematch_name", &self.target_rematch_name)
            .field("target_sub_rule", &self.target_sub_rule)
            .finish_non_exhaustive()
    }
}

impl Rematch {
    pub fn new(option: RematchOption) -> Result<Arc<Self>> {
        if option.target_rematch_name.is_none() && option.target_sub_rule.is_none() {
            return Err(anyhow!(
                "rematch {} requires at least one of target-rematch-name or target-sub-rule",
                option.name
            ));
        }
        Ok(Arc::new_cyclic(|weak| Self {
            base: Base::new(BaseOption {
                name: option.name,
                type_: AdapterType::REMATCH,
                provider_name: option.basic_option.provider_name.clone(),
                udp: true,
                addr: String::new(),
                xudp: false,
                tfo: false,
                mptcp: false,
                interface: String::new(),
                routing_mark: 0,
                prefer: murmur_constant::dns::DNSPrefer::default(),
            }),
            target_rematch_name: option.target_rematch_name,
            target_sub_rule: option.target_sub_rule,
            self_weak: Weak::clone(weak),
        }))
    }

    fn self_arc(&self) -> Result<Arc<Self>> {
        self.self_weak.upgrade().ok_or_else(|| anyhow!("Rematch adapter dropped while still in use"))
    }

    fn apply_metadata(&self, metadata: &mut Metadata) {
        if let Some(target_rematch_name) = &self.target_rematch_name {
            metadata.rematch_name.clone_from(target_rematch_name);
        }
        if let Some(target_sub_rule) = &self.target_sub_rule {
            metadata.special_rules.clone_from(target_sub_rule);
        }
    }
}

#[async_trait]
impl CProxyAdapter for Rematch {
    fn name(&self) -> String {
        self.base.name()
    }

    fn type_(&self) -> AdapterType {
        self.base.type_()
    }

    fn addr(&self) -> String {
        self.base.addr()
    }

    fn support_udp(&self) -> bool {
        self.base.support_udp()
    }

    fn proxy_info(&self) -> ProxyInfo {
        self.base.proxy_info()
    }

    fn marshal_json(&self) -> Result<Vec<u8>> {
        self.base.marshal_json()
    }

    async fn dial_context(&self, _ctx: &CancellationToken, metadata: &mut Metadata) -> Result<Box<dyn CConn>> {
        self.apply_metadata(metadata);
        Ok(new_conn(Box::new(NopConn), self))
    }

    async fn listen_packet_context(
        &self,
        _ctx: &CancellationToken,
        metadata: &mut Metadata,
    ) -> Result<Arc<dyn CPacketConn>> {
        self.apply_metadata(metadata);
        let pc: Arc<dyn murmur_common_net::io::Datagram> = Arc::new(NopPacketConn);
        Ok(new_packet_conn(pc, self.self_arc()?))
    }

    fn support_uot(&self) -> bool {
        self.base.support_uot()
    }

    fn is_l3_protocol(&self, metadata: &Metadata) -> bool {
        self.base.is_l3_protocol(metadata)
    }

    fn unwrap(&self, metadata: &Metadata, touch: bool) -> Option<Arc<dyn Proxy>> {
        self.base.unwrap(metadata, touch)
    }

    fn close(&self) -> Result<()> {
        self.base.close()
    }
}

#[async_trait]
impl ProxyAdapter for Rematch {
    fn dial_options(&self) -> Vec<murmur_component::dialer::options::Option> {
        self.base.dial_options()
    }

    async fn resolve_udp(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> Result<()> {
        self.base.resolve_udp(ctx, metadata).await
    }
}
