#[repr(C)]
struct RtlOsVersionInfoW {
    os_version_info_size: u32,
    major_version: u32,
    minor_version: u32,
    build_number: u32,
    platform_id: u32,
    csd_version: [u16; 128],
}

#[link(name = "ntdll")]
extern "system" {
    fn RtlGetVersion(version_information: *mut RtlOsVersionInfoW) -> i32;
}

/// Major, minor and build number of the running Windows version.
///
/// A failed call reports zeros rather than panicking.
#[allow(unsafe_code)]
pub(crate) fn rtl_version() -> (u32, u32, u32) {
    // SAFETY: `RtlGetVersion` writes only into the `RTL_OSVERSIONINFOW` structure
    // whose size field is initialised with `size_of::<RtlOsVersionInfoW>()`, and
    // the pointer stays valid for the duration of the call.
    unsafe {
        let mut info: RtlOsVersionInfoW = std::mem::zeroed();
        info.os_version_info_size = u32::try_from(size_of::<RtlOsVersionInfoW>()).unwrap_or(u32::MAX);
        if RtlGetVersion(&raw mut info) < 0 {
            return (0, 0, 0);
        }
        (info.major_version, info.minor_version, info.build_number)
    }
}
