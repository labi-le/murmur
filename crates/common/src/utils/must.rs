#[expect(
    clippy::panic,
    reason = "the helper's whole contract is to abort when the caller's condition is false; its signature returns the value directly so callers carry no error path"
)]
pub fn must_ok<T>(result: T, ok: bool) -> T {
    if ok {
        return result;
    }
    panic!("operation failed")
}
