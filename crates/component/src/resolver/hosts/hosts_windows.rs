const MAX_PATH: u32 = 260;

#[link(name = "kernel32")]
extern "system" {
    fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
}

/// Sets the hosts file path to `GetSystemDirectory() + "/Drivers/etc/hosts"`; the default path
/// stays in place when the call fails. The retry loop is written out here because no pinned crate
/// exposes the call.
#[expect(
    unsafe_code,
    reason = "`GetSystemDirectoryW` is a raw FFI call; the SAFETY comment below states the buffer invariant"
)]
pub(crate) fn system_hosts_file_path() -> String {
    let mut n = MAX_PATH;
    loop {
        let mut buffer = vec![0u16; n as usize];
        // SAFETY: the buffer is local and its length is passed alongside its
        // pointer; the returned length is checked against that length before the
        // buffer is read.
        let l = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), n) };
        if l == 0 {
            return "/etc/hosts".to_owned();
        }
        if l <= n {
            return match String::from_utf16(buffer.get(..l as usize).unwrap_or_default()) {
                Ok(dir) => format!("{dir}/Drivers/etc/hosts"),
                Err(_) => "/etc/hosts".to_owned(),
            };
        }
        n = l;
    }
}
