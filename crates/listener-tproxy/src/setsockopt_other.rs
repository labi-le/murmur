use anyhow::{anyhow, Result};

/// Not supported on this platform, so the socket fd is not a parameter.
pub fn setsockopt(_addr: &str) -> Result<()> {
    Err(anyhow!("not supported on current platform"))
}
