//! Enables embed mode for the android+cmfa build.
//!
//! Rust has no import-time side effects (see `hub/executor/executor.rs`'s module doc), so this is
//! a plain function. Whichever `main.rs` wires the android+cmfa entry point must call [`init`]
//! once at startup to match that build's default embed mode.

#[cfg(all(target_os = "android", feature = "cmfa"))]
pub fn init() {
    super::server::set_embed_mode(true);
}
