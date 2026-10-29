//! The accepted connection's addresses, carried into every hyper request served on it.
//!
//! Go's `net/http` sets `Request.RemoteAddr` and the `http.LocalAddrContextKey` context value on
//! every server request. `hyper` does not: its service sees only the request. The gRPC and XHTTP
//! inbound layers read both through `set_addr_from_request`, so without this bridge a tunneled
//! connection reports no peer or local address, the relay's `metadata.source` comes out empty,
//! and Trojan's UDP handler — which keys its NAT entries on the accepted conn's peer — cannot
//! start its packet loop at all.

use std::sync::Arc;

use murmur_common_httputils::addr::{LocalAddrContextKey, RemoteAddr};
use murmur_common_net::io::Stream;
use murmur_std_compat::net::{Addr, TcpAddr};

#[derive(Clone, Default)]
pub(crate) struct ConnAddrs {
    remote: Option<String>,
    local: Option<Arc<dyn Addr>>,
}

impl ConnAddrs {
    /// Reads both addresses once, before the conn is moved into the HTTP server.
    pub(crate) fn capture(conn: &dyn Stream) -> Self {
        Self {
            remote: conn.peer_addr().ok().map(|addr| addr.to_string()),
            local: conn.local_addr().ok().map(|addr| -> Arc<dyn Addr> { Arc::new(TcpAddr::from(addr)) }),
        }
    }

    pub(crate) fn insert<B>(&self, request: &mut http::Request<B>) {
        if let Some(remote) = &self.remote {
            request.extensions_mut().insert(RemoteAddr(remote.clone()));
        }
        if let Some(local) = &self.local {
            request.extensions_mut().insert(LocalAddrContextKey(Arc::clone(local)));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use murmur_common_httputils::addr::{set_addr_from_request, NetAddr};

    use super::*;

    #[test]
    fn captured_addresses_reach_the_net_addr_through_a_request() {
        let addrs = ConnAddrs {
            remote: Some("203.0.113.9:4242".to_owned()),
            local: Some(Arc::new(TcpAddr::new("127.0.0.1".parse::<IpAddr>().expect("valid IP"), 443))),
        };
        let mut request = http::Request::new(());
        addrs.insert(&mut request);

        let net_addr = NetAddr::default();
        set_addr_from_request(&net_addr, &request);

        assert_eq!(net_addr.remote_addr().expect("remote address").string(), "203.0.113.9:4242");
        assert_eq!(net_addr.local_addr().expect("local address").string(), "127.0.0.1:443");
    }

    #[test]
    fn a_missing_address_leaves_that_half_unset() {
        let mut request = http::Request::new(());
        ConnAddrs { remote: Some("198.51.100.7:9".to_owned()), local: None }.insert(&mut request);

        let net_addr = NetAddr::default();
        set_addr_from_request(&net_addr, &request);

        assert!(net_addr.remote_addr().is_some());
        assert!(net_addr.local_addr().is_none());
    }
}
