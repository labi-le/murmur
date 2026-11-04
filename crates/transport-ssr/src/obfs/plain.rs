use murmur_common_net::io::Stream;

use super::base::Base;
use super::obfs::{register, Obfs, ObfsList};
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Plain;

/// `init()`, called from the registry's initializer instead of at package load.
pub(crate) fn init(list: &mut ObfsList) {
    register(list, "plain", new_plain, 0);
}

pub(crate) fn new_plain(_b: &Base) -> Box<dyn Obfs> {
    Box::new(Plain)
}

impl Obfs for Plain {
    fn stream_conn(&self, c: Box<dyn Stream>) -> Box<dyn Stream> {
        c
    }
}
