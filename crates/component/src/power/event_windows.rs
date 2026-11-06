use std::ffi::{c_void, CStr};
use std::ptr;
use std::sync::Arc;

use parking_lot::Mutex;

use super::event::{Type, RESUME, RESUMEAUTOMATIC, SUSPEND};

type Handle = *mut c_void;

const PBT_APMSUSPEND: u32 = 4;
const PBT_APMRESUMESUSPEND: u32 = 7;
const PBT_APMRESUMEAUTOMATIC: u32 = 18;

const DEVICE_NOTIFY_CALLBACK: u32 = 2;

#[repr(C)]
struct DeviceNotifySubscribeParameters {
    callback: usize,
    context: usize,
}

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryA(lp_lib_file_name: *const u8) -> Handle;
    fn GetProcAddress(h_module: Handle, lp_proc_name: *const u8) -> *mut c_void;
}

type PowerNotifyCallback = extern "system" fn(usize, u32, usize) -> usize;
type PowerRegisterSuspendResumeNotification =
    unsafe extern "system" fn(u32, *const DeviceNotifySubscribeParameters, *mut usize) -> u32;
type PowerUnregisterSuspendResumeNotification = unsafe extern "system" fn(usize) -> u32;

struct Listener {
    cb: Box<dyn Fn(Type) + Send + Sync>,
}

struct Registration {
    unregister: PowerUnregisterSuspendResumeNotification,
    /// `Some` until released, so the closer is idempotent and `Drop` cannot re-unregister it.
    handle: Mutex<Option<usize>>,
    /// Dropped only after `Drop::drop` returns, keeping the callback's context alive across the
    /// unregistration.
    _listener: Arc<Listener>,
}

impl Registration {
    /// the returned stop function.
    #[expect(unsafe_code, reason = "the unregister procedure is a raw function pointer called through FFI")]
    fn release(&self) {
        let Some(handle) = self.handle.lock().take() else {
            return;
        };
        // SAFETY: `unregister` and `handle` are the procedure and handle of this registration, and
        // the `take` makes the handle reachable here exactly once.
        unsafe { (self.unregister)(handle) };
    }
}

// A dropped closer must unregister too: otherwise the system keeps invoking a callback whose
// `Listener` the drop has already freed.
impl Drop for Registration {
    fn drop(&mut self) {
        self.release();
    }
}

#[expect(
    unsafe_code,
    reason = "the callback receives a raw context pointer from the system, which safe Rust cannot express"
)]
extern "system" fn power_notify_callback(context: usize, change_type: u32, _setting: usize) -> usize {
    if context == 0 {
        return 0;
    }
    // SAFETY: `context` is the `Listener` pointer handed to the registration call.
    let listener = unsafe { &*(context as *const Listener) };
    match change_type {
        PBT_APMSUSPEND => (listener.cb)(SUSPEND),
        PBT_APMRESUMESUSPEND => (listener.cb)(RESUME),
        PBT_APMRESUMEAUTOMATIC => (listener.cb)(RESUMEAUTOMATIC),
        _ => {}
    }
    0
}

/// Both procedures come from `powrprof.dll`, loaded once here and kept for the life of the
/// process. The module is deliberately never freed: the `unregister` pointer resolved from it is
/// still called during shutdown.
#[expect(unsafe_code, reason = "`LoadLibraryA` is a raw FFI call with no safe wrapper in the pinned crates")]
fn load_powrprof() -> anyhow::Result<Handle> {
    // SAFETY: `LoadLibraryA` takes a NUL-terminated DLL name; `powrprof.dll` ships with every
    // Windows version this build targets.
    let module = unsafe { LoadLibraryA(c"powrprof.dll".as_ptr().cast::<u8>()) };
    if module.is_null() {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(module)
}

#[expect(unsafe_code, reason = "`GetProcAddress` is a raw FFI call with no safe wrapper in the pinned crates")]
fn find_proc(module: Handle, name: &CStr) -> anyhow::Result<usize> {
    // SAFETY: `module` is a live handle from `LoadLibraryA` and `name` is NUL-terminated.
    let proc = unsafe { GetProcAddress(module, name.as_ptr().cast::<u8>()) };
    if proc.is_null() {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(proc as usize)
}

#[expect(
    unsafe_code,
    reason = "the registration procedures are raw function pointers resolved at runtime and called through FFI"
)]
pub fn new_event_listener<F>(cb: F) -> anyhow::Result<Box<dyn Fn() + Send + Sync>>
where
    F: Fn(Type) + Send + Sync + 'static,
{
    let module = load_powrprof()?;
    let register = find_proc(module, c"PowerRegisterSuspendResumeNotification")?;
    let unregister = find_proc(module, c"PowerUnregisterSuspendResumeNotification")?;

    let listener = Arc::new(Listener { cb: Box::new(cb) });
    let callback: PowerNotifyCallback = power_notify_callback;
    let params =
        DeviceNotifySubscribeParameters { callback: callback as usize, context: Arc::as_ptr(&listener) as usize };
    let mut handle: usize = 0;

    // SAFETY: `register` resolved from `GetProcAddress(module, "PowerRegisterSuspendResumeNotification")`.
    // The transmute target is ABI-equivalent to the documented signature:
    // `DWORD PowerRegisterSuspendResumeNotification(DWORD Flags, HANDLE Recipient, PHPOWERNOTIFY RegistrationHandle)`,
    // https://learn.microsoft.com/en-us/windows/win32/api/powerbase/nf-powerbase-powerregistersuspendresumenotification
    // (both functions are WINAPI, i.e. `extern "system"`; `DWORD` = `u32`, `HANDLE` = pointer-sized;
    // `PHPOWERNOTIFY` points at an `HPOWERNOTIFY`, a `PVOID`, represented here as `usize` because
    // only `HPOWERNOTIFY` needs the `Win32_System_Power` feature, which is not enabled). `params`/
    // `handle` are live locals that outlive the call.
    let ret = {
        let register: PowerRegisterSuspendResumeNotification = unsafe { std::mem::transmute(register) };
        unsafe { register(DEVICE_NOTIFY_CALLBACK, ptr::addr_of!(params), ptr::addr_of_mut!(handle)) }
    };
    if ret != 0 {
        return Err(std::io::Error::from_raw_os_error(i32::try_from(ret).unwrap_or(i32::MAX)).into());
    }

    // SAFETY: `unregister` resolved from `GetProcAddress(module, "PowerUnregisterSuspendResumeNotification")`.
    // The transmute target is ABI-equivalent to the documented signature:
    // `DWORD PowerUnregisterSuspendResumeNotification(HPOWERNOTIFY RegistrationHandle)`,
    // https://learn.microsoft.com/en-us/windows/win32/api/powerbase/nf-powerbase-powerunregistersuspendresumenotification
    // (both functions are WINAPI, i.e. `extern "system"`; `HPOWERNOTIFY`, a `PVOID`, is represented
    // here as `usize`).
    let unregister: PowerUnregisterSuspendResumeNotification = unsafe { std::mem::transmute(unregister) };
    let registration = Arc::new(Registration { unregister, handle: Mutex::new(Some(handle)), _listener: listener });

    // `Arc`, not a plain move: the closer is `Fn` and may be called repeatedly, and `Drop` is what
    // unregisters when the caller drops the box instead of calling it.
    let closer = Arc::clone(&registration);
    Ok(Box::new(move || closer.release()))
}
