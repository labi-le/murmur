//! System wall-clock adjustment on Windows.

use chrono::{DateTime, Datelike, Timelike, Utc};

/// Win32 `SYSTEMTIME`.
#[repr(C)]
struct SystemTime {
    year: u16,
    month: u16,
    day_of_week: u16,
    day: u16,
    hour: u16,
    minute: u16,
    second: u16,
    milliseconds: u16,
}

#[link(name = "kernel32")]
extern "system" {
    fn SetSystemTime(st: *const SystemTime) -> i32;
    #[link_name = "GetLastError"]
    fn get_last_error() -> u32;
}

#[allow(unsafe_code)]
pub(crate) fn set_system_time(now_time: DateTime<Utc>) -> std::io::Result<()> {
    let milliseconds = u16::try_from(now_time.timestamp_millis() - now_time.timestamp() * 1000).unwrap_or_default();
    let system_time = SystemTime {
        year: u16::try_from(now_time.year()).unwrap_or_default(),
        month: u16::try_from(now_time.month()).unwrap_or_default(),
        day_of_week: 0,
        day: u16::try_from(now_time.day()).unwrap_or_default(),
        hour: u16::try_from(now_time.hour()).unwrap_or_default(),
        minute: u16::try_from(now_time.minute()).unwrap_or_default(),
        second: u16::try_from(now_time.second()).unwrap_or_default(),
        milliseconds,
    };

    // SAFETY: `system_time` is a fully-initialized, stack-local `SYSTEMTIME`; `SetSystemTime`
    // only reads through the pointer for the duration of the call.
    let ok = unsafe { SetSystemTime(&raw const system_time) };
    if ok != 0 {
        return Ok(());
    }
    // SAFETY: `GetLastError` takes no arguments and only reads thread-local state.
    let err = unsafe { get_last_error() };
    Err(std::io::Error::from_raw_os_error(i32::try_from(err).unwrap_or(i32::MAX)))
}
