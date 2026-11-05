#[cfg(not(target_os = "windows"))]
pub const SUPPORT_NAMED_PIPE: bool = false;

/// The invalid-input kind names the unsupported-pipe error.
#[cfg(not(target_os = "windows"))]
pub fn listen_named_pipe(_path: &str) -> anyhow::Result<Box<dyn murmur_std_compat::net::Listener>> {
    Err(std::io::Error::from(std::io::ErrorKind::InvalidInput).into())
}
