use murmur_std_compat::net::Listener;

#[cfg(target_os = "windows")]
pub const SUPPORT_NAMED_PIPE: bool = true;

/// Grants read/write access to all users and the local system.
#[cfg(target_os = "windows")]
pub const WINDOWS_SDDL: &str = "D:PAI(A;OICI;GWGR;;;BU)(A;OICI;GWGR;;;SY)";

/// Named-pipe listener over tokio's named pipes with a settable security descriptor and buffer
/// sizes. Without them the pipe cannot be built with the security descriptor set here.
#[cfg(target_os = "windows")]
pub fn listen_named_pipe(path: &str) -> anyhow::Result<Box<dyn Listener>> {
    let sddl = std::env::var("LISTEN_NAMEDPIPE_SDDL").unwrap_or_default();
    let sddl = if sddl.is_empty() { WINDOWS_SDDL.to_owned() } else { sddl };
    Err(anyhow::anyhow!(
        "listen named pipe {path}: named pipe listener with security descriptor {sddl} needs windows-sys"
    ))
}
