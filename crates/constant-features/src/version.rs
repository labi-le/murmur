use std::sync::LazyLock;

static PLATFORM_VERSION: LazyLock<(u32, u32, u32)> = LazyLock::new(platform_version);

pub static WINDOWS_MAJOR_VERSION: LazyLock<u32> = LazyLock::new(|| PLATFORM_VERSION.0);
pub static WINDOWS_MINOR_VERSION: LazyLock<u32> = LazyLock::new(|| PLATFORM_VERSION.1);
pub static WINDOWS_BUILD_NUMBER: LazyLock<u32> = LazyLock::new(|| PLATFORM_VERSION.2);

#[cfg(target_os = "windows")]
fn platform_version() -> (u32, u32, u32) {
    super::version_windows::rtl_version()
}

#[cfg(not(target_os = "windows"))]
const fn platform_version() -> (u32, u32, u32) {
    (0, 0, 0)
}
