use std::any::Any;
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};

use parking_lot::Mutex;

use super::once_native::Once;

/// The captured variables each closure keeps alongside its once. A
/// present `result` marks a successful run; `panic_value`/`message` mark a failed one.
struct OnceState<T> {
    panic_value: Option<Box<dyn Any + Send>>,
    message: String,
    result: Option<T>,
}

impl<T> OnceState<T> {
    fn new() -> Self {
        Self { panic_value: None, message: String::new(), result: None }
    }

    fn fail(&mut self, value: Box<dyn Any + Send>) {
        self.message = panic_message(&*value);
        self.panic_value = Some(value);
    }

    /// The same panic value cannot be re-thrown on every call, since a Rust panic payload can only
    /// be resumed once; later calls panic with the first panic's message.
    #[allow(
        clippy::panic,
        reason = "the once cell re-panics the stored payload on every call"
    )]
    fn raise(&mut self) -> ! {
        match self.panic_value.take() {
            Some(value) => resume_unwind(value),
            None => panic!("{}", self.message),
        }
    }
}

fn panic_message(payload: &(dyn Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_owned()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        String::from("once: function panicked")
    }
}

/// Returns a function that invokes `f` only once. The returned function may be called
/// concurrently.
///
/// If `f` panics, the returned function will panic on every call.
pub fn once_func<F>(f: F) -> impl Fn() + Send + Sync + 'static
where
    F: Fn() + Send + 'static,
{
    let once = Once::new();
    let f = Mutex::new(Some(f));
    let state = Mutex::new(OnceState::<()>::new());
    move || {
        once.call_once(|| {
            let func = f.lock().take();
            let result = catch_unwind(AssertUnwindSafe(|| {
                if let Some(func) = func {
                    func();
                }
            }));
            match result {
                Ok(()) => state.lock().result = Some(()),
                Err(value) => {
                    let mut state = state.lock();
                    state.fail(value);
                    state.raise();
                }
            }
        });
        let mut state = state.lock();
        if state.result.is_none() {
            state.raise();
        }
    }
}

/// Returns a function that invokes `f` only once and returns the value returned by `f`. The
/// returned function may be called concurrently.
///
/// The value is cloned out on every call.
///
/// If `f` panics, the returned function will panic on every call.
pub fn once_value<T, F>(f: F) -> impl Fn() -> T + Send + Sync + 'static
where
    T: Clone + Send + 'static,
    F: Fn() -> T + Send + 'static,
{
    let once = Once::new();
    let f = Mutex::new(Some(f));
    let state = Mutex::new(OnceState::<T>::new());
    move || {
        once.call_once(|| {
            let func = f.lock().take();
            let result = catch_unwind(AssertUnwindSafe(|| func.map(|func| func())));
            match result {
                Ok(result) => {
                    let mut state = state.lock();
                    state.result = result;
                }
                Err(value) => {
                    let mut state = state.lock();
                    state.fail(value);
                    state.raise();
                }
            }
        });
        let mut state = state.lock();
        match state.result.clone() {
            Some(result) => result,
            None => state.raise(),
        }
    }
}

/// Returns a function that invokes `f` only once and returns the values returned by `f`.
/// The returned function may be called concurrently.
///
/// The values are cloned out on every call.
///
/// If `f` panics, the returned function will panic on every call.
pub fn once_values<T1, T2, F>(f: F) -> impl Fn() -> (T1, T2) + Send + Sync + 'static
where
    T1: Clone + Send + 'static,
    T2: Clone + Send + 'static,
    F: Fn() -> (T1, T2) + Send + 'static,
{
    let once = Once::new();
    let f = Mutex::new(Some(f));
    let state = Mutex::new(OnceState::<(T1, T2)>::new());
    move || {
        once.call_once(|| {
            let func = f.lock().take();
            let result = catch_unwind(AssertUnwindSafe(|| func.map(|func| func())));
            match result {
                Ok(result) => {
                    let mut state = state.lock();
                    state.result = result;
                }
                Err(value) => {
                    let mut state = state.lock();
                    state.fail(value);
                    state.raise();
                }
            }
        });
        let mut state = state.lock();
        match state.result.clone() {
            Some(result) => result,
            None => state.raise(),
        }
    }
}
