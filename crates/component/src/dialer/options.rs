use std::net::IpAddr;
use std::sync::{Arc, LazyLock};

use async_trait::async_trait;
use futures::future::BoxFuture;
use tokio_util::sync::CancellationToken;

use crate::resolver::resolver::SharedResolver;
use murmur_common::atomic::type_::{new_int32, Int32};
use murmur_common::atomic::value::{new_typed_value, option_arc_ptr_eq, TypedValue};
use murmur_common_net::io::Stream;

use super::control::StdDialer;

pub static DEFAULT_INTERFACE: LazyLock<TypedValue<String>> = LazyLock::new(|| new_typed_value(String::new()));

pub static DEFAULT_ROUTING_MARK: Int32 = new_int32(0);

pub static DEFAULT_INTERFACE_FINDER: LazyLock<TypedValue<std::option::Option<Arc<dyn InterfaceFinder>>>> =
    LazyLock::new(|| new_typed_value(None));

pub trait InterfaceFinder: Send + Sync {
    fn find_interface_name(&self, destination: std::option::Option<IpAddr>) -> String;
}

/// the `NetDialer` interface.
#[async_trait]
pub trait NetDialer: Send + Sync {
    async fn dial_context(
        &self,
        ctx: &CancellationToken,
        network: &str,
        address: &str,
    ) -> anyhow::Result<Box<dyn Stream>>;

    /// The dialer copy the socket policy is applied to.
    fn as_std_dialer(&self) -> std::option::Option<StdDialer> {
        None
    }
}

/// `NetDialerFunc`; arguments are passed by value so the future can be boxed.
pub struct NetDialerFunc(
    Arc<dyn Fn(CancellationToken, String, String) -> BoxFuture<'static, anyhow::Result<Box<dyn Stream>>> + Send + Sync>,
);

impl std::fmt::Debug for NetDialerFunc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetDialerFunc").finish_non_exhaustive()
    }
}

impl NetDialerFunc {
    pub fn new<F>(f: F) -> Self
    where
        F: Fn(CancellationToken, String, String) -> BoxFuture<'static, anyhow::Result<Box<dyn Stream>>>
            + Send
            + Sync
            + 'static,
    {
        Self(Arc::new(f))
    }
}

#[async_trait]
impl NetDialer for NetDialerFunc {
    async fn dial_context(
        &self,
        ctx: &CancellationToken,
        network: &str,
        address: &str,
    ) -> anyhow::Result<Box<dyn Stream>> {
        (self.0)(ctx.clone(), network.to_owned(), address.to_owned()).await
    }
}

/// the `network`/`prefer` zero value (unset); the two used values become `V4`/`V6`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum IpVersion {
    #[default]
    Any,
    V4,
    V6,
}

impl IpVersion {
    pub(crate) const fn suffix(self) -> &'static str {
        match self {
            Self::Any => "",
            Self::V4 => "4",
            Self::V6 => "6",
        }
    }
}

/// The private `option` type; `Option` is the function type, kept below.
#[expect(
    clippy::struct_excessive_bools,
    reason = "each bool is an independent dialer flag, set by its own builder function"
)]
#[derive(Clone, Default)]
pub struct Options {
    pub(crate) interface_name: String,
    pub(crate) fallback_bind: bool,
    pub(crate) addr_reuse: bool,
    pub(crate) routing_mark: i32,
    pub(crate) network: IpVersion,
    pub(crate) prefer: IpVersion,
    pub(crate) tfo: bool,
    pub(crate) mp_tcp: bool,
    pub(crate) resolver: std::option::Option<SharedResolver>,
    pub(crate) net_dialer: std::option::Option<Arc<dyn NetDialer>>,
}

impl std::fmt::Debug for Options {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Options")
            .field("interface_name", &self.interface_name)
            .field("fallback_bind", &self.fallback_bind)
            .field("addr_reuse", &self.addr_reuse)
            .field("routing_mark", &self.routing_mark)
            .field("network", &self.network)
            .field("prefer", &self.prefer)
            .field("tfo", &self.tfo)
            .field("mp_tcp", &self.mp_tcp)
            .finish_non_exhaustive()
    }
}

impl PartialEq for Options {
    fn eq(&self, other: &Self) -> bool {
        self.interface_name == other.interface_name
            && self.fallback_bind == other.fallback_bind
            && self.addr_reuse == other.addr_reuse
            && self.routing_mark == other.routing_mark
            && self.network == other.network
            && self.prefer == other.prefer
            && self.tfo == other.tfo
            && self.mp_tcp == other.mp_tcp
            && option_arc_ptr_eq(&self.resolver, &other.resolver)
            && option_arc_ptr_eq(&self.net_dialer, &other.net_dialer)
    }
}

pub type Option = Box<dyn Fn(&mut Options) + Send + Sync>;

#[must_use]
pub fn with_interface(name: &str) -> Option {
    let name = name.to_owned();
    Box::new(move |opt: &mut Options| {
        opt.interface_name.clone_from(&name);
    })
}

#[must_use]
pub fn with_fallback_bind(fallback: bool) -> Option {
    Box::new(move |opt: &mut Options| {
        opt.fallback_bind = fallback;
    })
}

#[must_use]
pub fn with_addr_reuse(reuse: bool) -> Option {
    Box::new(move |opt: &mut Options| {
        opt.addr_reuse = reuse;
    })
}

#[must_use]
pub fn with_routing_mark(mark: i32) -> Option {
    Box::new(move |opt: &mut Options| {
        opt.routing_mark = mark;
    })
}

/// `None` when no resolver is set.
#[must_use]
pub fn with_resolver(r: std::option::Option<SharedResolver>) -> Option {
    Box::new(move |opt: &mut Options| {
        opt.resolver.clone_from(&r);
    })
}

#[must_use]
pub fn with_prefer_ipv4() -> Option {
    Box::new(|opt: &mut Options| {
        opt.prefer = IpVersion::V4;
    })
}

#[must_use]
pub fn with_prefer_ipv6() -> Option {
    Box::new(|opt: &mut Options| {
        opt.prefer = IpVersion::V6;
    })
}

#[must_use]
pub fn with_only_single_stack(is_ipv4: bool) -> Option {
    Box::new(move |opt: &mut Options| {
        opt.network = if is_ipv4 { IpVersion::V4 } else { IpVersion::V6 };
    })
}

#[must_use]
pub fn with_tfo(tfo: bool) -> Option {
    Box::new(move |opt: &mut Options| {
        opt.tfo = tfo;
    })
}

#[must_use]
pub fn with_mptcp(mp_tcp: bool) -> Option {
    Box::new(move |opt: &mut Options| {
        opt.mp_tcp = mp_tcp;
    })
}

pub fn with_net_dialer(net_dialer: Arc<dyn NetDialer>) -> Option {
    Box::new(move |opt: &mut Options| {
        opt.net_dialer = Some(Arc::clone(&net_dialer));
    })
}

#[must_use]
pub fn with_option(o: Options) -> Option {
    Box::new(move |opt: &mut Options| {
        *opt = o.clone();
    })
}

#[must_use]
pub fn with_options(options: Vec<Option>) -> Option {
    Box::new(move |opt: &mut Options| {
        for o in &options {
            o(opt);
        }
    })
}

#[must_use]
pub fn is_zero_options(opts: &[Option]) -> bool {
    apply_options(opts) == Options::default()
}

pub(crate) fn apply_options(options: &[Option]) -> Options {
    let mut opt = Options::default();
    for o in options {
        o(&mut opt);
    }
    opt
}
