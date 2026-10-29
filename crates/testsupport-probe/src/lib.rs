//! Dependency-free test probes, split out of `murmur-testsupport`'s `test_support` module.
//!
//! The crate split keeps this module free of dependencies on the rest of the crate, so it can be
//! a dev-dependency of every crate, including foundational ones like `component::dialer` that
//! `test_support` itself depends on.
//!
//! `component::dialer` using the full mock-origin harness as a dev-dependency would cycle back
//! through it.
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

/// Installs the default `aws-lc-rs` `rustls` `CryptoProvider` if none is installed yet.
///
/// Tests that build a TLS or QUIC config then do not race each other over which crypto backend
/// rustls picks automatically.
///
/// A concurrent install losing the race is fine: any already-installed default provider is
/// equivalent for these tests' purposes.
pub fn ensure_test_crypto_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_some() {
        return;
    }
    let _ = rustls::crypto::CryptoProvider::install_default(rustls::crypto::aws_lc_rs::default_provider());
}

/// Detects whether the test binary is running under Wine rather than real Windows: `ntdll.dll`
/// exports `wine_get_version` only under Wine.
///
/// quinn-udp 0.5.15 (the version this crate is pinned to, and every released version up to and
/// including 0.6.2) unconditionally queries `IPV6_V6ONLY` on every socket its `UdpSocketState`
/// wraps, including plain IPv4-only ones; Wine's `ws2_32` rejects that query on an `AF_INET`
/// socket with `WSAEOPNOTSUPP`, where real Windows accepts it.
///
/// That makes every test that opens a live `quinn::Endpoint` fail under Wine for a reason that
/// cannot reproduce on real Windows. Real Windows and every other target always return `false`
/// here.
#[cfg(windows)]
#[allow(unsafe_code)]
#[must_use]
pub fn is_wine() -> bool {
    use windows_sys::Win32::Foundation::HMODULE;
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

    // SAFETY: both calls take a NUL-terminated ANSI name of a module/procedure already loaded
    // into this process (`ntdll.dll` is always loaded); `ntdll` is checked for null before use.
    unsafe {
        let ntdll: HMODULE = GetModuleHandleA(c"ntdll.dll".as_ptr().cast());
        if ntdll.is_null() {
            return false;
        }
        GetProcAddress(ntdll, c"wine_get_version".as_ptr().cast()).is_some()
    }
}

#[cfg(not(windows))]
#[must_use]
pub const fn is_wine() -> bool {
    false
}
