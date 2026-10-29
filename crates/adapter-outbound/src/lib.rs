// Test code is exempt from the production panic posture: the bans on `unwrap`,
// `expect`, `panic`, indexing and casts exist to keep a long-lived server process
// alive, and a failing test is supposed to abort. Style tiers are exempt for the
// same reason -- the scaffolding around an assertion is not product code.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::string_slice,
        clippy::print_stdout,
        clippy::print_stderr,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::pedantic,
        clippy::nursery
    )
)]

#[cfg(feature = "extra-protocols")]
pub mod anytls;
pub mod base;
pub mod direct;
pub mod dns;
#[cfg(feature = "easytier")]
pub mod easytier;
pub mod ech;
#[cfg(feature = "extra-protocols")]
pub mod gost_relay;
#[cfg(feature = "extra-protocols")]
pub mod http;
#[cfg(feature = "extra-protocols")]
pub mod hysteria;
#[cfg(feature = "extra-protocols")]
pub mod hysteria2;
#[cfg(feature = "extra-protocols")]
pub(crate) mod hysteria2_realm;
pub mod jls;
#[cfg(feature = "extra-protocols")]
pub mod masque;
#[cfg(feature = "extra-protocols")]
pub mod mieru;
#[cfg(feature = "extra-protocols")]
pub mod openvpn;
pub mod reject;
pub mod rematch;
#[cfg(feature = "extra-protocols")]
pub mod shadowquic;
#[cfg(feature = "extra-protocols")]
pub mod shadowsocks;
#[cfg(feature = "extra-protocols")]
pub mod shadowsocksr;
pub mod shadowtls;
pub mod singmux;
#[cfg(feature = "extra-protocols")]
pub mod snell;
#[cfg(feature = "extra-protocols")]
pub mod socks5;
#[cfg(feature = "extra-protocols")]
pub mod ssh;
#[cfg(feature = "extra-protocols")]
pub mod sudoku;
#[cfg(feature = "tailscale")]
pub mod tailscale;
pub mod tlsmirror;
pub mod trojan;
#[cfg(feature = "extra-protocols")]
pub mod trusttunnel;
#[cfg(feature = "extra-protocols")]
pub mod tuic;
pub mod util;
pub mod vless;
pub mod vmess;
#[cfg(feature = "extra-protocols")]
pub mod wireguard;
#[cfg(feature = "zerotier")]
pub mod zerotier;
#[cfg(feature = "zerotier")]
pub mod zerotier_link;
