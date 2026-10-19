pub mod cmd;
#[cfg(not(target_os = "windows"))]
pub mod cmd_other;
#[cfg(target_os = "windows")]
pub mod cmd_windows;

pub use cmd::{exec_cmd, exec_shell};
