//! Shadowsocks 2022 AEAD ciphers (`2022-blake3-*`).
//!
//! The server half is restricted to the single-PSK path `listener::sing_shadowsocks::server`
//! reaches: the multi-user server and server-side EIH decode have no caller in this crate and are
//! not implemented. Client-side EIH is implemented for both the TCP request and the UDP packet
//! path's AES identity-header branch, since `adapter::outbound::shadowsocks` can dial a
//! multi-user server with a colon-joined password over either transport; the UDP EIH branch is
//! unsupported for chacha ciphers, and is likewise not implemented here, matching the limitation
//! rather than adding one.
//!
//! Both the outbound (`adapter::outbound::shadowsocks`) and inbound
//! (`listener::sing_shadowsocks::server`) sides import this one copy, exactly as
//! `transport::shadowsocks::shadowaead` already serves both directions of the classic AEAD
//! ciphers.
//!
//! Scope: all six ciphers of the method list are implemented, including the non-standard extras
//! (`2022-blake3-chacha8-poly1305`, `2022-blake3-aes-128-ccm`, `2022-blake3-aes-256-ccm`), reusing
//! the AES-CCM and reduced-round-ChaCha AEAD implementations
//! `transport::shadowsocks::shadowaead::cipher` already built for the classic cipher list's own
//! `aes-*-ccm`/`chacha8-ietf-poly1305` entries, plus a genuine 8-round `XChaCha8` for this
//! protocol's own UDP `xchacha8-ietf-poly1305`-shaped nonce (the classic list's
//! `xchacha8-ietf-poly1305` name maps to full 20-round `XChaCha20Poly1305`, which this protocol's
//! `2022-blake3-chacha8-poly1305` UDP path does not use).

pub mod client;
pub mod protocol;
pub mod server;
pub mod sliding_window;
