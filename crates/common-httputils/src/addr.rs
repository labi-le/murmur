use std::io;
use std::sync::Arc;

use parking_lot::Mutex;

use murmur_constant::metadata::Metadata;
use murmur_std_compat::net::{Addr, Conn, TcpAddr};

#[derive(Debug)]
struct SharedAddr(Arc<dyn Addr>);

impl Addr for SharedAddr {
    fn network(&self) -> &str {
        self.0.network()
    }

    fn string(&self) -> String {
        self.0.string()
    }

    fn addr_port(&self) -> Option<murmur_std_compat::net::AddrPort> {
        self.0.addr_port()
    }

    fn raw_addr(&self) -> Option<&dyn Addr> {
        self.0.raw_addr()
    }

    fn as_iface_prefix(&self) -> Option<ipnet::IpNet> {
        self.0.as_iface_prefix()
    }

    fn as_sock_addr(&self) -> Option<murmur_std_compat::net::SockAddr> {
        self.0.as_sock_addr()
    }
}

#[derive(Debug, Default)]
pub struct NetAddr {
    remote_addr: Mutex<Option<Arc<dyn Addr>>>,
    local_addr: Mutex<Option<Arc<dyn Addr>>>,
}

impl NetAddr {
    pub fn remote_addr(&self) -> Option<Box<dyn Addr>> {
        self.remote_addr.lock().clone().map(|addr| -> Box<dyn Addr> { Box::new(SharedAddr(addr)) })
    }

    pub fn local_addr(&self) -> Option<Box<dyn Addr>> {
        self.local_addr.lock().clone().map(|addr| -> Box<dyn Addr> { Box::new(SharedAddr(addr)) })
    }

    /// Answers the address as an error-free result.
    pub fn local_addr_result(&self) -> io::Result<Box<dyn Addr>> {
        self.local_addr().ok_or_else(|| io::Error::other("no local address"))
    }

    pub fn remote_addr_result(&self) -> io::Result<Box<dyn Addr>> {
        self.remote_addr().ok_or_else(|| io::Error::other("no remote address"))
    }
}

/// The remote address, carried in the request's extensions in place of
/// the request field.
#[derive(Clone, Debug, Default)]
pub struct RemoteAddr(pub String);

/// The local address, carried in the request's extensions in place of
/// the context value.
#[derive(Clone, Debug)]
pub struct LocalAddrContextKey(pub Arc<dyn Addr>);

/// Fills the address from the request. A remote address that carries a domain rather than an IP
/// leaves `remote_addr` unset: the address type cannot carry a null IP.
pub fn set_addr_from_request<B>(addr: &NetAddr, request: &http::Request<B>) {
    if let Some(remote_addr) = request.extensions().get::<RemoteAddr>() {
        if !remote_addr.0.is_empty() {
            let mut metadata = Metadata::default();
            if metadata.set_remote_address(&remote_addr.0).is_ok() {
                if let Some(addr_port) = metadata.addr_port() {
                    *addr.remote_addr.lock() = Some(Arc::new(TcpAddr::from(addr_port)));
                }
            }
        }
    }
    if let Some(local_addr) = request.extensions().get::<LocalAddrContextKey>() {
        *addr.local_addr.lock() = Some(Arc::clone(&local_addr.0));
    }
}

#[derive(Clone)]
pub struct GotConnInfo {
    pub conn: Arc<dyn Conn>,
    pub reused: bool,
}

impl std::fmt::Debug for GotConnInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GotConnInfo").field("reused", &self.reused).finish_non_exhaustive()
    }
}

#[derive(Clone, Default)]
pub struct ClientTrace {
    pub got_conn: Option<Arc<dyn Fn(&GotConnInfo) + Send + Sync>>,
}

impl std::fmt::Debug for ClientTrace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientTrace").field("got_conn", &self.got_conn.is_some()).finish_non_exhaustive()
    }
}

/// Installs a client trace: the request context is the request's extensions, so the trace goes
/// there, where the transport half can find it.
pub fn with_client_trace<B>(request: &mut http::Request<B>, trace: ClientTrace) {
    request.extensions_mut().insert(trace);
}

/// Hands back a context carrying the trace. The trace itself is returned, to be installed by the
/// caller with [`with_client_trace`].
pub fn new_addr_context(addr: Arc<NetAddr>) -> ClientTrace {
    ClientTrace {
        got_conn: Some(Arc::new(move |conn_info: &GotConnInfo| {
            let local_addr = conn_info.conn.local_addr().ok().map(Arc::from);
            let remote_addr = conn_info.conn.remote_addr().ok().map(Arc::from);
            *addr.local_addr.lock() = local_addr;
            *addr.remote_addr.lock() = remote_addr;
        })),
    }
}
