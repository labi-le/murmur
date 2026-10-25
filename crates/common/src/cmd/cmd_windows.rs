use tokio::process::Command;

/// Keeps the child from opening a console window.
pub(crate) fn prepare_background_command(cmd: &mut Command) {
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    cmd.creation_flags(CREATE_NO_WINDOW);
}
