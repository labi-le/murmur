pub mod service;
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub mod time_stub;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod time_unix;
#[cfg(target_os = "windows")]
pub mod time_windows;
