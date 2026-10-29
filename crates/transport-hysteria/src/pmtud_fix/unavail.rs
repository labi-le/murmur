#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
pub const DISABLE_PATH_MTU_DISCOVERY: bool = true;
