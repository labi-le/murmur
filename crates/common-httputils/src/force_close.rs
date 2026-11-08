/// A round tripper that can be torn down; each teardown hook is probed on the value.
///
/// An erased `dyn` value in Rust cannot be probed for a trait it does not carry, so the three
/// hooks live on the transport trait itself and an implementation overrides the ones it supports.
pub trait RoundTripper: Send + Sync {
    fn close_idle_connections(&self) {}

    fn close_http2_connections(&self) {}

    /// Releases the transport's resources.
    fn close(&self) {}
}

pub fn close_transport(round_tripper: &dyn RoundTripper) {
    round_tripper.close_idle_connections();
    round_tripper.close_http2_connections();
    round_tripper.close();
}
