use std::sync::atomic::{AtomicU32, Ordering};

use parking_lot::Mutex;

/// A one-shot flag whose layout lets [`done`] and [`reset`] reach
/// the flag; the type is owned here, since Rust's `std::sync::Once` exposes no such flag.
#[derive(Debug)]
pub struct Once {
    done: AtomicU32,
    m: Mutex<()>,
}

impl Once {
    #[must_use]
    pub const fn new() -> Self {
        Self { done: AtomicU32::new(0), m: Mutex::new(()) }
    }

    /// Runs `f` once, which the once-variants rely on. Named around the
    /// reserved Rust word; the flag is stored even when `f` panics.
    pub fn call_once<F: FnOnce()>(&self, f: F) {
        if self.done.load(Ordering::SeqCst) == 0 {
            self.do_slow(f);
        }
    }

    fn do_slow<F: FnOnce()>(&self, f: F) {
        let _guard = self.m.lock();
        if self.done.load(Ordering::SeqCst) == 0 {
            let _done = DoneOnDrop(&self.done);
            f();
        }
    }
}

impl Default for Once {
    fn default() -> Self {
        Self::new()
    }
}

/// Sets the flag when dropped, so it survives a panicking `f`.
struct DoneOnDrop<'a>(&'a AtomicU32);

impl Drop for DoneOnDrop<'_> {
    fn drop(&mut self) {
        self.0.store(1, Ordering::SeqCst);
    }
}

pub fn done(once: &Once) -> bool {
    once.done.load(Ordering::SeqCst) == 1
}

pub fn reset(once: &Once) {
    let _guard = once.m.lock();
    once.done.store(0, Ordering::SeqCst);
}
