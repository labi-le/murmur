use std::sync::Arc;

use murmur_constant::metadata::Metadata;
use murmur_std_compat::net::Addr;

pub type Addition = Arc<dyn Fn(&mut Metadata) + Send + Sync>;

pub fn apply_additions(metadata: &mut Metadata, additions: &[Addition]) {
    for addition in additions {
        addition(metadata);
    }
}

#[must_use]
pub fn with_in_name(name: &str) -> Addition {
    let name = name.to_owned();
    Arc::new(move |metadata: &mut Metadata| metadata.in_name.clone_from(&name))
}

#[must_use]
pub fn with_in_user(user: &str) -> Addition {
    let user = user.to_owned();
    Arc::new(move |metadata: &mut Metadata| metadata.in_user.clone_from(&user))
}

#[must_use]
pub fn with_special_rules(special_rules: &str) -> Addition {
    let special_rules = special_rules.to_owned();
    Arc::new(move |metadata: &mut Metadata| metadata.special_rules.clone_from(&special_rules))
}

#[must_use]
pub fn with_special_proxy(special_proxy: &str) -> Addition {
    let special_proxy = special_proxy.to_owned();
    Arc::new(move |metadata: &mut Metadata| metadata.special_proxy.clone_from(&special_proxy))
}

#[must_use]
pub fn with_dst_addr(addr: Option<Box<dyn Addr>>) -> Addition {
    Arc::new(move |metadata: &mut Metadata| {
        let _ = metadata.set_remote_addr(addr.as_deref());
    })
}

#[must_use]
pub fn with_src_addr(addr: Option<Box<dyn Addr>>) -> Addition {
    Arc::new(move |metadata: &mut Metadata| {
        let mut source = Metadata::default();
        if source.set_remote_addr(addr.as_deref()).is_ok() {
            metadata.src_ip = source.dst_ip;
            metadata.src_port = source.dst_port;
        }
    })
}

#[must_use]
pub fn with_in_addr(addr: Option<Box<dyn Addr>>) -> Addition {
    Arc::new(move |metadata: &mut Metadata| {
        let mut in_addr = Metadata::default();
        if in_addr.set_remote_addr(addr.as_deref()).is_ok() {
            metadata.in_ip = in_addr.dst_ip;
            metadata.in_port = in_addr.dst_port;
        }
    })
}

#[must_use]
pub fn with_dscp(dscp: u8) -> Addition {
    Arc::new(move |metadata: &mut Metadata| metadata.dscp = dscp)
}

pub const fn placeholder(_metadata: &mut Metadata) {}
