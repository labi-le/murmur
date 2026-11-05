pub mod avail;
pub mod unavail;

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "macos"))]
pub use avail::DISABLE_PATH_MTU_DISCOVERY;
#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
pub use unavail::DISABLE_PATH_MTU_DISCOVERY;
