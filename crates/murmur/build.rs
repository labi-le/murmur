//! Emits `RUSTC_VERSION` for the `-v` line: Cargo exposes no variable for the compiler in use
//! (`CARGO_PKG_RUST_VERSION` is the manifest's MSRV, not the toolchain that built the binary), so
//! the version is read from `rustc -V` at build time.

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let Ok(output) = Command::new(rustc).arg("-V").output() else {
        return;
    };
    if !output.status.success() {
        return;
    }

    // `rustc -V` prints `rustc 1.97.1 (8bdf9cf43 2026-02-12)`; only the bare version token is
    // forwarded.
    let stdout = String::from_utf8_lossy(&output.stdout);
    if let Some(version) = stdout.split_whitespace().nth(1) {
        println!("cargo:rustc-env=RUSTC_VERSION={version}");
    }
}
