//! Emits `GIT_COMMIT` for `murmur -v` and the controller's `/version`: the release `VERSION`
//! alone cannot tell two nightly builds apart, and the checkout that produced the binary is the
//! identity that can.

use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let commit = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|stdout| stdout.trim().to_owned())
        .filter(|commit| !commit.is_empty())
        .unwrap_or_else(|| "unknown".to_owned());
    println!("cargo:rustc-env=GIT_COMMIT={commit}");

    // A checkout whose HEAD moved must not keep the previous hash, so watch `HEAD` and the ref it
    // names. A `.git` file (linked worktree, submodule) is not a directory this can follow: there
    // the build keeps whatever hash it baked in last.
    let head = "../../.git/HEAD";
    if !Path::new(head).is_file() {
        return;
    }
    println!("cargo:rerun-if-changed={head}");
    let Ok(contents) = std::fs::read_to_string(head) else {
        return;
    };
    let Some(reference) = contents.trim().strip_prefix("ref: ") else {
        return;
    };
    let path = format!("../../.git/{reference}");
    if Path::new(&path).is_file() {
        println!("cargo:rerun-if-changed={path}");
    }
}
