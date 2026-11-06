use tokio::process::Command;

/// No process attributes need preparing outside Windows.
pub(crate) const fn prepare_background_command(_cmd: &mut Command) {}
