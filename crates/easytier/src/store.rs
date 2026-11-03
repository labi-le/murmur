//! The `wasmtime::Store` payload shared by the guest-calling side and the
//! host-import side.
//!
//! One store backs one guest module instance. Every host import reaches
//! the [`Reactor`] through this payload; guest-calling code ignores it apart from
//! carrying the store context.

use std::sync::Arc;

use tokio::runtime::Handle;
use wasmtime_wasi::p1::WasiP1Ctx;
use wasmtime_wasi::WasiCtxBuilder;

use crate::reactor::Reactor;

/// Store data for the embedded EasyTier core.
pub struct HostState {
    /// Dispatch core for every host-import call. The guest's linear memory and
    /// every resource handle live in the same wasm instance, so the reactor is
    /// per host, not per instance.
    pub reactor: Arc<Reactor>,
    /// Runtime the host-import closures spawn their I/O tasks on. Captured
    /// because a wasmtime host function runs on the guest's call stack, which
    /// is only inside a runtime context when the embedder drove the guest.
    pub runtime: Handle,
    /// `wasi_snapshot_preview1` state for the guest's clock, random and stdio
    /// imports.
    pub wasi: WasiP1Ctx,
}

impl HostState {
    /// Builds the store payload from a reactor and the runtime to spawn on.
    pub fn new(reactor: Arc<Reactor>, runtime: Handle) -> Self {
        Self { reactor, runtime, wasi: WasiCtxBuilder::new().build_p1() }
    }
}

impl std::fmt::Debug for HostState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("HostState").finish_non_exhaustive()
    }
}
