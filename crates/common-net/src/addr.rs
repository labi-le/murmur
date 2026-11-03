use murmur_std_compat::net::Addr;

#[derive(Debug)]
pub struct CustomAddrImpl {
    network_str: String,
    addr_str: String,
    raw_addr: Option<Box<dyn Addr>>,
}

impl Addr for CustomAddrImpl {
    fn network(&self) -> &str {
        &self.network_str
    }

    fn string(&self) -> String {
        self.addr_str.clone()
    }

    fn raw_addr(&self) -> Option<&dyn Addr> {
        self.raw_addr.as_deref()
    }
}

#[must_use]
pub fn new_custom_addr(network_str: String, addr_str: String, raw_addr: Box<dyn Addr>) -> Box<dyn Addr> {
    Box::new(CustomAddrImpl { network_str, addr_str, raw_addr: Some(raw_addr) })
}
