use std::os::windows::io::AsSocket;

use socket2::SockRef;

pub(crate) fn reuse_control<S: AsSocket>(socket: &S) -> anyhow::Result<()> {
    SockRef::from(socket).set_reuse_address(true)?;
    Ok(())
}
