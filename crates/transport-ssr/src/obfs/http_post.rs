use super::base::Base;
use super::http_simple::HttpObfs;
use super::obfs::{register, Obfs, ObfsList};

/// `init()`, called from the registry's initializer instead of at package load.
pub(crate) fn init(list: &mut ObfsList) {
    register(list, "http_post", new_http_post, 0);
}

pub(crate) fn new_http_post(b: &Base) -> Box<dyn Obfs> {
    Box::new(HttpObfs { base: b.clone(), post: true })
}
