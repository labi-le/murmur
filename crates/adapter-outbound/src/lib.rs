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

pub mod anytls;
pub mod base;
pub mod direct;
pub mod dns;
pub mod easytier;
pub mod easytier_stub;
pub mod ech;
pub mod gost_relay;
pub mod http;
pub mod hysteria;
pub mod hysteria2;
pub(crate) mod hysteria2_realm;
pub mod jls;
pub mod masque;
pub mod mieru;
pub mod openvpn;
pub mod reject;
pub mod rematch;
pub mod shadowquic;
pub mod shadowsocks;
pub mod shadowsocksr;
pub mod shadowtls;
pub mod singmux;
pub mod snell;
pub mod socks5;
pub mod ssh;
pub mod sudoku;
pub mod tailscale;
pub mod tailscale_stub;
pub mod tlsmirror;
pub mod trojan;
pub mod trusttunnel;
pub mod tuic;
pub mod util;
pub mod vless;
pub mod vmess;
pub mod wireguard;
pub mod zerotier;
pub mod zerotier_link;
