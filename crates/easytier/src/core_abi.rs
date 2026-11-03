//! This is the guest-calling half of the embedded `easytier_core.wasm`.
//!
//! [`Core`] owns the handles for the instance, data-plane and RPC exports plus the reusable guest
//! buffers cached on the same struct, and drives them synchronously against a
//! [`Store<HostState>`]. The host-import half lives in the sibling `host_abi` module.
//!
//! [`Core::new`] resolves and type-checks every export it uses once, so a mismatched artifact
//! fails at construction and each call is a direct typed invocation.
//!
//! **No `Drop` on [`Core`]**: the cached buffers are guest allocations, and releasing them
//! means calling into the guest — something a `Drop` impl cannot do because it has no access
//! to the store. Dropping the store instead would leave the guest's allocator holding them.
//! Call [`Core::drop_instance`] while the store is still alive; it is idempotent.
//!
//! **Cancellation** belongs to the reactor: these calls are synchronous and run on the
//! embedder's thread, so a cancellation context has nowhere to travel. Cancelling an
//! in-flight host operation is [`crate::reactor::Reactor::cancel_operation`]'s job.
//!
//! **Deviation**: a guest state outside `0..=4` is reported as an error instead of being handed
//! back as an out-of-range `State`.

use std::fmt;

use anyhow::{anyhow, bail, ensure, Result};
use wasmtime::{Instance, Memory, Store, TypedFunc};

use crate::store::HostState;
use crate::wire::{self, DataPlaneSocketAddr};

pub const DATA_PLANE_ABI_VERSION: u64 = 3;
pub const RPC_ABI_VERSION: u64 = 2;
pub const OPERATION_ID_LEN: usize = 8;
pub const COMPLETION_LEN: usize = 12;
pub const STREAM_RESULT_LEN: usize = 8 + wire::DATA_PLANE_SOCKET_ADDR_LEN * 2;
pub const BIND_RESULT_LEN: usize = 8 + wire::DATA_PLANE_SOCKET_ADDR_LEN;
pub const TCP_READ_METADATA_LEN: usize = 1;
pub const UDP_RECEIVE_METADATA_LEN: usize = wire::DATA_PLANE_SOCKET_ADDR_LEN + 1;
pub const MAX_DATA_PLANE_TRANSFER: usize = 1024 * 1024;
pub const MAX_RPC_MESSAGE: usize = 16 * 1024 * 1024;
pub const DEADLINE_READ: u32 = 1 << 0;
pub const DEADLINE_WRITE: u32 = 1 << 1;

const DATA_PLANE_CAPABILITY: u64 = 1 << 0;
const DATA_PLANE_TCP_CAPABILITY: u64 = 1 << 1;
const DATA_PLANE_UDP_CAPABILITY: u64 = 1 << 2;
const REQUIRED_DATA_PLANE_CAPABILITIES: u64 =
    DATA_PLANE_CAPABILITY | DATA_PLANE_TCP_CAPABILITY | DATA_PLANE_UDP_CAPABILITY;

/// The size probe's "not ready yet" answer.
const RPC_STATUS_PENDING: i32 = -6;

/// The `u32` view of a byte length whose constant is known to fit the ABI's length fields.
const fn len_u32(len: usize) -> u32 {
    #[expect(clippy::cast_possible_truncation, reason = "every ABI length constant is far below u32::MAX")]
    let len = len as u32;
    len
}

const OPERATION_ID_LEN_U32: u32 = len_u32(OPERATION_ID_LEN);
const STREAM_RESULT_LEN_U32: u32 = len_u32(STREAM_RESULT_LEN);
const BIND_RESULT_LEN_U32: u32 = len_u32(BIND_RESULT_LEN);
const MAX_DATA_PLANE_TRANSFER_U32: u32 = len_u32(MAX_DATA_PLANE_TRANSFER);
const ADDRESS_LEN_U32: u32 = len_u32(wire::DATA_PLANE_SOCKET_ADDR_LEN);
const TCP_READ_METADATA_LEN_U32: u32 = len_u32(TCP_READ_METADATA_LEN);
const UDP_RECEIVE_METADATA_LEN_U32: u32 = len_u32(UDP_RECEIVE_METADATA_LEN);
/// The datagram length is bounded at `u16::MAX`; the buffer is one byte larger so that the
/// inclusive bound is representable as a length.
///
/// `u16::MAX + 1` written out because `u32::from(u16)` is not callable in a `const` on this
/// toolchain (`From` is not yet a const trait).
const UDP_RECEIVE_CAPACITY: u32 = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Created,
    Starting,
    Running,
    Stopping,
    Stopped,
}

impl State {
    /// Decodes the guest's raw state value, rejecting anything the guest should never report.
    #[must_use]
    pub fn from_raw(raw: i32) -> Option<Self> {
        match raw {
            0 => Some(Self::Created),
            1 => Some(Self::Starting),
            2 => Some(Self::Running),
            3 => Some(Self::Stopping),
            4 => Some(Self::Stopped),
            _ => None,
        }
    }
}

/// The operation-kind discriminants are the wire values, so they must never be reordered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum OperationKind {
    TcpConnect = 1,
    TcpBind,
    TcpAccept,
    TcpRead,
    TcpWrite,
    UdpBind,
    UdpReceive,
    UdpSend,
}

impl OperationKind {
    fn from_raw(raw: u16) -> Option<Self> {
        match raw {
            1 => Some(Self::TcpConnect),
            2 => Some(Self::TcpBind),
            3 => Some(Self::TcpAccept),
            4 => Some(Self::TcpRead),
            5 => Some(Self::TcpWrite),
            6 => Some(Self::UdpBind),
            7 => Some(Self::UdpReceive),
            8 => Some(Self::UdpSend),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ErrorKind {
    None = 0,
    Cancelled,
    DeadlineExceeded,
    InstanceStopped,
    HandleClosed,
    NoOverlayRoute,
    PathNotReady,
    AddressFamilyUnsupported,
    AddressInUse,
    ConnectionRefused,
    NetworkChanged,
    ResourceLimit,
    Io,
    BufferTooSmall,
}

impl ErrorKind {
    /// the valid-completion-status check, as a conversion.
    #[must_use]
    pub fn from_raw(raw: u16) -> Option<Self> {
        match raw {
            0 => Some(Self::None),
            1 => Some(Self::Cancelled),
            2 => Some(Self::DeadlineExceeded),
            3 => Some(Self::InstanceStopped),
            4 => Some(Self::HandleClosed),
            5 => Some(Self::NoOverlayRoute),
            6 => Some(Self::PathNotReady),
            7 => Some(Self::AddressFamilyUnsupported),
            8 => Some(Self::AddressInUse),
            9 => Some(Self::ConnectionRefused),
            10 => Some(Self::NetworkChanged),
            11 => Some(Self::ResourceLimit),
            12 => Some(Self::Io),
            13 => Some(Self::BufferTooSmall),
            _ => None,
        }
    }
}

/// The guest reported a data-plane status, as opposed to a host-side failure.
///
/// Callers that must tell the two apart downcast the error chain
/// (`anyhow::Error::downcast_ref::<DataPlaneError>()`), so it is always returned as a
/// concrete error rather than flattened into a message.
#[derive(Debug)]
pub struct DataPlaneError {
    pub kind: ErrorKind,
    pub message: String,
}

impl fmt::Display for DataPlaneError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.message.is_empty() {
            write!(formatter, "data plane error {}", self.kind as u16)
        } else {
            formatter.write_str(&self.message)
        }
    }
}

impl std::error::Error for DataPlaneError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Completion {
    pub operation: u64,
    pub kind: OperationKind,
    pub status: ErrorKind,
}

/// Only the fields the operation's kind produces are meaningful, matching the named-return zero
/// values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationResult {
    pub kind: OperationKind,
    pub resource: u64,
    pub local: DataPlaneSocketAddr,
    pub peer: DataPlaneSocketAddr,
    pub data: Vec<u8>,
    pub length: usize,
    pub eof: bool,
    pub truncated: bool,
}

/// The two result shapes of the RPC-response take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcResponse {
    Pending,
    Ready(Vec<u8>),
}

macro_rules! guest_exports {
    ($($name:literal: $field:ident($($param:ty),*) -> $result:ty;)*) => {
        struct Exports {
            $($field: TypedFunc<($($param,)*), $result>,)*
        }

        impl Exports {
            fn resolve(store: &mut Store<HostState>, instance: &Instance) -> Result<Self> {
                Ok(Self {
                    $($field: instance
                        .get_typed_func::<($($param,)*), $result>(&mut *store, $name)
                        .map_err(|err| anyhow!("resolve EasyTier guest export {}: {err}", $name))?,)*
                })
            }
        }
    };
}

guest_exports! {
    "easytier_buffer_alloc": buffer_alloc(i32) -> i32;
    "easytier_buffer_free": buffer_free(i32) -> i32;
    "easytier_data_plane_abi_version": data_plane_abi_version() -> i32;
    "easytier_data_plane_capabilities": data_plane_capabilities() -> i64;
    "easytier_data_plane_completion_drain": data_plane_completion_drain(i64, i32, i32) -> i32;
    "easytier_data_plane_operation_cancel": data_plane_operation_cancel(i64, i64) -> i32;
    "easytier_data_plane_operation_free": data_plane_operation_free(i64, i64) -> i32;
    "easytier_data_plane_resource_close": data_plane_resource_close(i64, i64) -> i32;
    "easytier_data_plane_resource_deadline_set": data_plane_resource_deadline_set(i64, i64, i32, i64) -> i32;
    "easytier_data_plane_tcp_connect_submit": data_plane_tcp_connect_submit(i64, i32, i64, i32) -> i32;
    "easytier_data_plane_tcp_bind_submit": data_plane_tcp_bind_submit(i64, i32, i64, i32) -> i32;
    "easytier_data_plane_tcp_accept_submit": data_plane_tcp_accept_submit(i64, i64, i64, i32) -> i32;
    "easytier_data_plane_tcp_read_submit": data_plane_tcp_read_submit(i64, i64, i32, i32) -> i32;
    "easytier_data_plane_tcp_write_submit": data_plane_tcp_write_submit(i64, i64, i32, i32, i32) -> i32;
    "easytier_data_plane_udp_bind_submit": data_plane_udp_bind_submit(i64, i32, i64, i32) -> i32;
    "easytier_data_plane_udp_receive_submit": data_plane_udp_receive_submit(i64, i64, i32, i32) -> i32;
    "easytier_data_plane_udp_send_submit": data_plane_udp_send_submit(i64, i64, i32, i32, i32, i32) -> i32;
    "easytier_data_plane_tcp_connect_result_take": data_plane_tcp_connect_result_take(i64, i64, i32) -> i32;
    "easytier_data_plane_tcp_accept_result_take": data_plane_tcp_accept_result_take(i64, i64, i32) -> i32;
    "easytier_data_plane_tcp_bind_result_take": data_plane_tcp_bind_result_take(i64, i64, i32) -> i32;
    "easytier_data_plane_udp_bind_result_take": data_plane_udp_bind_result_take(i64, i64, i32) -> i32;
    "easytier_data_plane_tcp_read_result_take": data_plane_tcp_read_result_take(i64, i64, i32, i32, i32) -> i32;
    "easytier_data_plane_udp_receive_result_take": data_plane_udp_receive_result_take(i64, i64, i32, i32, i32) -> i32;
    "easytier_data_plane_tcp_write_result_take": data_plane_tcp_write_result_take(i64, i64) -> i32;
    "easytier_data_plane_udp_send_result_take": data_plane_udp_send_result_take(i64, i64) -> i32;
    "easytier_instance_create": instance_create(i32, i32, i64, i64) -> i64;
    "easytier_instance_start": instance_start(i64) -> i32;
    "easytier_instance_stop": instance_stop(i64) -> i32;
    "easytier_instance_drive": instance_drive(i64) -> i32;
    "easytier_instance_notify_completions": instance_notify_completions(i64) -> i32;
    "easytier_instance_state": instance_state(i64) -> i32;
    "easytier_instance_next_deadline_millis": instance_next_deadline_millis(i64) -> i64;
    "easytier_instance_send_packet": instance_send_packet(i64, i32, i32) -> i32;
    "easytier_instance_drop": instance_drop(i64) -> i32;
    "easytier_instance_error_len": instance_error_len(i64) -> i32;
    "easytier_instance_error_copy": instance_error_copy(i64, i32, i32) -> i32;
    "easytier_rpc_abi_version": rpc_abi_version() -> i32;
    "easytier_rpc_request_submit": rpc_request_submit(i64, i32, i32, i32) -> i32;
    "easytier_rpc_response_take": rpc_response_take(i64, i64, i32, i32) -> i32;
    "easytier_rpc_operation_free": rpc_operation_free(i64, i64) -> i32;
}

/// The guest's `*_result_take` export family: one entry per [`OperationKind`]. The variant both
/// names the export and selects the typed function to call, because the eight takes share only
/// three wasm signatures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResultTake {
    TcpConnect,
    TcpAccept,
    TcpBind,
    UdpBind,
    TcpRead,
    UdpReceive,
    TcpWrite,
    UdpSend,
}

impl ResultTake {
    fn of(kind: OperationKind) -> Self {
        match kind {
            OperationKind::TcpConnect => Self::TcpConnect,
            OperationKind::TcpAccept => Self::TcpAccept,
            OperationKind::TcpBind => Self::TcpBind,
            OperationKind::UdpBind => Self::UdpBind,
            OperationKind::TcpRead => Self::TcpRead,
            OperationKind::UdpReceive => Self::UdpReceive,
            OperationKind::TcpWrite => Self::TcpWrite,
            OperationKind::UdpSend => Self::UdpSend,
        }
    }

    fn export(self) -> &'static str {
        match self {
            Self::TcpConnect => "easytier_data_plane_tcp_connect_result_take",
            Self::TcpAccept => "easytier_data_plane_tcp_accept_result_take",
            Self::TcpBind => "easytier_data_plane_tcp_bind_result_take",
            Self::UdpBind => "easytier_data_plane_udp_bind_result_take",
            Self::TcpRead => "easytier_data_plane_tcp_read_result_take",
            Self::UdpReceive => "easytier_data_plane_udp_receive_result_take",
            Self::TcpWrite => "easytier_data_plane_tcp_write_result_take",
            Self::UdpSend => "easytier_data_plane_udp_send_result_take",
        }
    }
}

/// The guest-calling handle for one `easytier_core.wasm` instance.
pub struct Core {
    memory: Memory,
    exports: Exports,
    handle: u64,
    packet_buffer: u32,
    packet_buffer_capacity: u32,
    data_plane_address: u32,
    data_plane_input: u32,
    data_plane_input_size: u32,
    data_plane_output: u32,
    data_plane_output_size: u32,
    dropped: bool,
}

impl fmt::Debug for Core {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("Core").field("handle", &self.handle).finish_non_exhaustive()
    }
}

impl Core {
    /// Resolves the guest exports and refuses an artifact whose data-plane or RPC ABI is not the
    /// one this crate speaks.
    pub fn new(store: &mut Store<HostState>, instance: &Instance) -> Result<Self> {
        let memory = instance
            .get_memory(&mut *store, "memory")
            .ok_or_else(|| anyhow!("EasyTier guest does not export memory"))?;
        let exports = Exports::resolve(store, instance)?;
        let core = Self {
            memory,
            exports,
            handle: 0,
            packet_buffer: 0,
            packet_buffer_capacity: 0,
            data_plane_address: 0,
            data_plane_input: 0,
            data_plane_input_size: 0,
            data_plane_output: 0,
            data_plane_output_size: 0,
            dropped: false,
        };
        core.validate_data_plane_abi(store)?;
        core.validate_rpc_abi(store)?;
        Ok(core)
    }

    pub fn create(
        &mut self,
        store: &mut Store<HostState>,
        envelope: &[u8],
        packet_sink: u64,
        event_sink: u64,
    ) -> Result<()> {
        ensure!(self.handle == 0 && !self.dropped, "create EasyTier instance in used guest module");
        let length = guest_length(envelope.len())?;
        let pointer = self.allocate(store, length)?;
        self.with_guest_buffer(store, pointer, |core, store| {
            core.memory
                .write(&mut *store, pointer as usize, envelope)
                .map_err(|err| anyhow!("write EasyTier config to guest memory: {err}"))?;
            let handle = core.exports.instance_create.call(
                &mut *store,
                (guest_i32(pointer), guest_i32(length), guest_i64(packet_sink), guest_i64(event_sink)),
            )?;
            if handle == 0 {
                let message = core.error_message(store, 0)?;
                bail!("create EasyTier instance: {message}");
            }
            core.handle = u64::try_from(handle)
                .map_err(|_| anyhow!("create EasyTier instance: guest returned handle {handle}"))?;
            Ok(())
        })
    }

    pub fn start(&mut self, store: &mut Store<HostState>) -> Result<()> {
        self.ensure_live("easytier_instance_start")?;
        let status = self.exports.instance_start.call(&mut *store, (guest_i64(self.handle),))?;
        self.check_status(store, "easytier_instance_start", status)
    }

    pub fn stop(&mut self, store: &mut Store<HostState>) -> Result<()> {
        self.ensure_live("easytier_instance_stop")?;
        let status = self.exports.instance_stop.call(&mut *store, (guest_i64(self.handle),))?;
        self.check_status(store, "easytier_instance_stop", status)
    }

    pub fn drive(&mut self, store: &mut Store<HostState>) -> Result<State> {
        let raw = self.exports.instance_drive.call(&mut *store, (guest_i64(self.handle),))?;
        self.decode_state(store, "drive EasyTier instance", raw)
    }

    pub fn notify_completions(&mut self, store: &mut Store<HostState>) -> Result<()> {
        self.ensure_live("easytier_instance_notify_completions")?;
        let status = self.exports.instance_notify_completions.call(&mut *store, (guest_i64(self.handle),))?;
        self.check_status(store, "easytier_instance_notify_completions", status)
    }

    pub fn state(&mut self, store: &mut Store<HostState>) -> Result<State> {
        let raw = self.exports.instance_state.call(&mut *store, (guest_i64(self.handle),))?;
        self.decode_state(store, "query EasyTier state", raw)
    }

    pub fn next_deadline_millis(&mut self, store: &mut Store<HostState>) -> Result<i64> {
        let deadline = self.exports.instance_next_deadline_millis.call(&mut *store, (guest_i64(self.handle),))?;
        if deadline < 0 {
            #[expect(
                clippy::cast_possible_truncation,
                reason = "the negative deadline is the guest's i32 status code widened into the export's i64 return"
            )]
            let status = deadline as i32;
            return Err(self.status_error(store, "query EasyTier deadline", status));
        }
        Ok(deadline)
    }

    pub fn send_packet(&mut self, store: &mut Store<HostState>, packet: &[u8]) -> Result<()> {
        ensure!(!packet.is_empty(), "send empty packet to EasyTier instance");
        let length = guest_length(packet.len())?;
        let pointer = self.ensure_packet_buffer(store, length)?;
        self.memory
            .write(&mut *store, pointer as usize, packet)
            .map_err(|err| anyhow!("write packet to guest memory: {err}"))?;
        let status = self
            .exports
            .instance_send_packet
            .call(&mut *store, (guest_i64(self.handle), guest_i32(pointer), guest_i32(length)))?;
        self.check_status(store, "send packet to EasyTier instance", status)
    }

    /// `Drop`: drops the guest instance, then releases every cached buffer. Idempotent,
    /// and the only way for a [`Core`] to give its guest allocations back (see this
    /// module's doc comment on why there is no `Drop` impl).
    pub fn drop_instance(&mut self, store: &mut Store<HostState>) -> Result<()> {
        if self.dropped || self.handle == 0 {
            return Ok(());
        }
        self.ensure_live("easytier_instance_drop")?;
        let status = self.exports.instance_drop.call(&mut *store, (guest_i64(self.handle),))?;
        self.check_status(store, "easytier_instance_drop", status)?;
        self.dropped = true;
        self.handle = 0;

        let mut failures = Vec::new();
        if self.packet_buffer != 0 {
            if let Err(err) = self.free(store, self.packet_buffer) {
                failures.push(format!("release EasyTier packet buffer: {err}"));
            }
            self.packet_buffer = 0;
            self.packet_buffer_capacity = 0;
        }
        if self.data_plane_input != 0 {
            if let Err(err) = self.free(store, self.data_plane_input) {
                failures.push(format!("release EasyTier data plane input buffer: {err}"));
            }
            self.data_plane_input = 0;
            self.data_plane_input_size = 0;
        }
        if self.data_plane_address != 0 {
            if let Err(err) = self.free(store, self.data_plane_address) {
                failures.push(format!("release EasyTier data plane address buffer: {err}"));
            }
            self.data_plane_address = 0;
        }
        if self.data_plane_output != 0 {
            if let Err(err) = self.free(store, self.data_plane_output) {
                failures.push(format!("release EasyTier data plane output buffer: {err}"));
            }
            self.data_plane_output = 0;
            self.data_plane_output_size = 0;
        }
        ensure!(failures.is_empty(), "{}", failures.join("; "));
        Ok(())
    }

    pub fn submit_tcp_connect(
        &mut self,
        store: &mut Store<HostState>,
        peer: DataPlaneSocketAddr,
        timeout_millis: u64,
    ) -> Result<u64> {
        let address = wire::encode_data_plane_socket_addr(peer);
        let pointer = self.write_input(store, &address)?;
        self.with_guest_buffer(store, pointer, |core, store| {
            let output = core.ensure_data_plane_output(store, OPERATION_ID_LEN_U32)?;
            let status = core.exports.data_plane_tcp_connect_submit.call(
                &mut *store,
                (guest_i64(core.handle), guest_i32(pointer), guest_i64(timeout_millis), guest_i32(output)),
            )?;
            core.check_data_plane_status(store, "easytier_data_plane_tcp_connect_submit", status)?;
            core.read_operation(store, output, "easytier_data_plane_tcp_connect_submit")
        })
    }

    pub fn submit_tcp_bind(&mut self, store: &mut Store<HostState>, port: u16, timeout_millis: u64) -> Result<u64> {
        let output = self.ensure_data_plane_output(store, OPERATION_ID_LEN_U32)?;
        let status = self.exports.data_plane_tcp_bind_submit.call(
            &mut *store,
            (guest_i64(self.handle), guest_i32(u32::from(port)), guest_i64(timeout_millis), guest_i32(output)),
        )?;
        self.check_data_plane_status(store, "easytier_data_plane_tcp_bind_submit", status)?;
        self.read_operation(store, output, "easytier_data_plane_tcp_bind_submit")
    }

    pub fn submit_tcp_accept(
        &mut self,
        store: &mut Store<HostState>,
        listener: u64,
        timeout_millis: u64,
    ) -> Result<u64> {
        let output = self.ensure_data_plane_output(store, OPERATION_ID_LEN_U32)?;
        let status = self.exports.data_plane_tcp_accept_submit.call(
            &mut *store,
            (guest_i64(self.handle), guest_i64(listener), guest_i64(timeout_millis), guest_i32(output)),
        )?;
        self.check_data_plane_status(store, "easytier_data_plane_tcp_accept_submit", status)?;
        self.read_operation(store, output, "easytier_data_plane_tcp_accept_submit")
    }

    pub fn submit_tcp_read(&mut self, store: &mut Store<HostState>, stream: u64, maximum: u32) -> Result<u64> {
        let output = self.ensure_data_plane_output(store, OPERATION_ID_LEN_U32)?;
        let status = self
            .exports
            .data_plane_tcp_read_submit
            .call(&mut *store, (guest_i64(self.handle), guest_i64(stream), guest_i32(maximum), guest_i32(output)))?;
        self.check_data_plane_status(store, "easytier_data_plane_tcp_read_submit", status)?;
        self.read_operation(store, output, "easytier_data_plane_tcp_read_submit")
    }

    pub fn submit_tcp_write(&mut self, store: &mut Store<HostState>, stream: u64, data: &[u8]) -> Result<u64> {
        ensure!(
            data.len() <= MAX_DATA_PLANE_TRANSFER,
            "TCP write length {} exceeds data plane limit {MAX_DATA_PLANE_TRANSFER}",
            data.len()
        );
        let pointer = self.write_input(store, data)?;
        let length = guest_length(data.len())?;
        self.with_guest_buffer(store, pointer, |core, store| {
            let output = core.ensure_data_plane_output(store, OPERATION_ID_LEN_U32)?;
            let status = core.exports.data_plane_tcp_write_submit.call(
                &mut *store,
                (guest_i64(core.handle), guest_i64(stream), guest_i32(pointer), guest_i32(length), guest_i32(output)),
            )?;
            core.check_data_plane_status(store, "easytier_data_plane_tcp_write_submit", status)?;
            core.read_operation(store, output, "easytier_data_plane_tcp_write_submit")
        })
    }

    pub fn submit_udp_bind(&mut self, store: &mut Store<HostState>, port: u16, timeout_millis: u64) -> Result<u64> {
        let output = self.ensure_data_plane_output(store, OPERATION_ID_LEN_U32)?;
        let status = self.exports.data_plane_udp_bind_submit.call(
            &mut *store,
            (guest_i64(self.handle), guest_i32(u32::from(port)), guest_i64(timeout_millis), guest_i32(output)),
        )?;
        self.check_data_plane_status(store, "easytier_data_plane_udp_bind_submit", status)?;
        self.read_operation(store, output, "easytier_data_plane_udp_bind_submit")
    }

    pub fn submit_udp_receive(&mut self, store: &mut Store<HostState>, socket: u64, maximum: u32) -> Result<u64> {
        let output = self.ensure_data_plane_output(store, OPERATION_ID_LEN_U32)?;
        let status = self
            .exports
            .data_plane_udp_receive_submit
            .call(&mut *store, (guest_i64(self.handle), guest_i64(socket), guest_i32(maximum), guest_i32(output)))?;
        self.check_data_plane_status(store, "easytier_data_plane_udp_receive_submit", status)?;
        self.read_operation(store, output, "easytier_data_plane_udp_receive_submit")
    }

    pub fn submit_udp_send(
        &mut self,
        store: &mut Store<HostState>,
        socket: u64,
        peer: DataPlaneSocketAddr,
        data: &[u8],
    ) -> Result<u64> {
        ensure!(
            data.len() <= MAX_DATA_PLANE_TRANSFER,
            "UDP send length {} exceeds data plane limit {MAX_DATA_PLANE_TRANSFER}",
            data.len()
        );
        let address = wire::encode_data_plane_socket_addr(peer);
        let address_pointer = self.ensure_data_plane_address(store)?;
        self.memory
            .write(&mut *store, address_pointer as usize, &address)
            .map_err(|err| anyhow!("write UDP peer address to guest memory: {err}"))?;
        let length = guest_length(data.len())?;
        let data_pointer = if data.is_empty() {
            0
        } else {
            let pointer = self.ensure_data_plane_input(store, length)?;
            self.memory
                .write(&mut *store, pointer as usize, data)
                .map_err(|err| anyhow!("write UDP payload to guest memory: {err}"))?;
            pointer
        };
        let output = self.ensure_data_plane_output(store, OPERATION_ID_LEN_U32)?;
        let status = self.exports.data_plane_udp_send_submit.call(
            &mut *store,
            (
                guest_i64(self.handle),
                guest_i64(socket),
                guest_i32(address_pointer),
                guest_i32(data_pointer),
                guest_i32(length),
                guest_i32(output),
            ),
        )?;
        self.check_data_plane_status(store, "easytier_data_plane_udp_send_submit", status)?;
        self.read_operation(store, output, "easytier_data_plane_udp_send_submit")
    }

    pub fn set_resource_deadline(
        &mut self,
        store: &mut Store<HostState>,
        resource: u64,
        direction: u32,
        timeout_millis: u64,
    ) -> Result<()> {
        let status = self.exports.data_plane_resource_deadline_set.call(
            &mut *store,
            (guest_i64(self.handle), guest_i64(resource), guest_i32(direction), guest_i64(timeout_millis)),
        )?;
        self.check_data_plane_status(store, "set data plane resource deadline", status)
    }

    pub fn drain_completions(&mut self, store: &mut Store<HostState>, maximum: u32) -> Result<Vec<Completion>> {
        if maximum == 0 {
            return Ok(Vec::new());
        }
        let length = u32::try_from(u64::from(maximum) * COMPLETION_LEN as u64)
            .map_err(|_| anyhow!("completion batch {maximum} exceeds guest address space"))?;
        let pointer = self.ensure_data_plane_output(store, length)?;
        let drained = self
            .exports
            .data_plane_completion_drain
            .call(&mut *store, (guest_i64(self.handle), guest_i32(pointer), guest_i32(maximum)))?;
        let Ok(count) = u32::try_from(drained) else {
            return Err(self.data_plane_status_error(store, "drain data plane completions", drained));
        };
        ensure!(count <= maximum, "data plane drained {count} completions into capacity {maximum}");
        let bytes = self.read_bytes(store, pointer, count as usize * COMPLETION_LEN, "data plane completions")?;
        decode_completions(&bytes)
    }

    pub fn take_result(&mut self, store: &mut Store<HostState>, completion: Completion) -> Result<OperationResult> {
        let take = ResultTake::of(completion.kind);
        let mut result = empty_result(completion.kind);
        match take {
            ResultTake::TcpConnect | ResultTake::TcpAccept => {
                let (resource, local, peer) = self.take_stream_result(store, completion, take)?;
                result.resource = resource;
                result.local = local;
                result.peer = peer;
            }
            ResultTake::TcpBind | ResultTake::UdpBind => {
                let (resource, local) = self.take_bind_result(store, completion, take)?;
                result.resource = resource;
                result.local = local;
            }
            ResultTake::TcpRead => {
                let (data, eof) = self.take_tcp_read_result(store, completion, take)?;
                result.data = data;
                result.eof = eof;
            }
            ResultTake::UdpReceive => {
                let (data, peer, truncated) = self.take_udp_receive_result(store, completion, take)?;
                result.data = data;
                result.peer = peer;
                result.truncated = truncated;
            }
            ResultTake::TcpWrite | ResultTake::UdpSend => {
                result.length = self.take_length_result(store, completion, take)?;
            }
        }
        Ok(result)
    }

    pub fn cancel_operation(&mut self, store: &mut Store<HostState>, operation: u64) -> Result<()> {
        let status = self
            .exports
            .data_plane_operation_cancel
            .call(&mut *store, (guest_i64(self.handle), guest_i64(operation)))?;
        self.check_data_plane_status(store, "easytier_data_plane_operation_cancel", status)
    }

    pub fn free_operation(&mut self, store: &mut Store<HostState>, operation: u64) -> Result<()> {
        let status =
            self.exports.data_plane_operation_free.call(&mut *store, (guest_i64(self.handle), guest_i64(operation)))?;
        self.check_data_plane_status(store, "easytier_data_plane_operation_free", status)
    }

    pub fn close_resource(&mut self, store: &mut Store<HostState>, resource: u64) -> Result<()> {
        let status =
            self.exports.data_plane_resource_close.call(&mut *store, (guest_i64(self.handle), guest_i64(resource)))?;
        self.check_data_plane_status(store, "easytier_data_plane_resource_close", status)
    }

    pub fn submit_rpc(&mut self, store: &mut Store<HostState>, request: &[u8]) -> Result<u64> {
        ensure!(!request.is_empty(), "submit empty RPC request");
        ensure!(
            request.len() <= MAX_RPC_MESSAGE,
            "RPC request length {} exceeds limit {MAX_RPC_MESSAGE}",
            request.len()
        );
        let length = guest_length(request.len())?;
        let request_pointer = self.allocate(store, length)?;
        self.with_guest_buffer(store, request_pointer, |core, store| {
            core.memory
                .write(&mut *store, request_pointer as usize, request)
                .map_err(|err| anyhow!("write RPC request to guest memory: {err}"))?;
            // The operation-id buffer is allocated separately from the data-plane output buffer,
            // so an in-flight data-plane drain can never clobber it.
            let operation_pointer = core.allocate(store, OPERATION_ID_LEN_U32)?;
            core.with_guest_buffer(store, operation_pointer, |core, store| {
                let status = core.exports.rpc_request_submit.call(
                    &mut *store,
                    (
                        guest_i64(core.handle),
                        guest_i32(request_pointer),
                        guest_i32(length),
                        guest_i32(operation_pointer),
                    ),
                )?;
                if status != 0 {
                    return Err(core.status_error(store, "submit EasyTier RPC request", status));
                }
                let operation = core.read_u64(store, operation_pointer, "RPC operation ID")?;
                ensure!(operation != 0, "EasyTier RPC submit returned zero operation ID");
                Ok(operation)
            })
        })
    }

    /// Takes an RPC response: probe with a null pointer, then copy into a buffer sized from
    /// the probe. The probe answer is the only difference between "still running" and a
    /// length, which is why a non-zero output pointer is what actually consumes the
    /// guest-side operation.
    pub fn take_rpc_response(&mut self, store: &mut Store<HostState>, operation: u64) -> Result<RpcResponse> {
        let probe =
            self.exports.rpc_response_take.call(&mut *store, (guest_i64(self.handle), guest_i64(operation), 0, 0))?;
        if probe == RPC_STATUS_PENDING {
            return Ok(RpcResponse::Pending);
        }
        let Ok(required) = usize::try_from(probe) else {
            return Err(self.status_error(store, "probe EasyTier RPC response", probe));
        };
        ensure!(required <= MAX_RPC_MESSAGE, "RPC response length {required} exceeds limit {MAX_RPC_MESSAGE}");
        let capacity = guest_length(required.max(1))?;
        let pointer = self.allocate(store, capacity)?;
        self.with_guest_buffer(store, pointer, |core, store| {
            let taken = core.exports.rpc_response_take.call(
                &mut *store,
                (guest_i64(core.handle), guest_i64(operation), guest_i32(pointer), guest_i32(capacity)),
            )?;
            if taken == RPC_STATUS_PENDING {
                return Ok(RpcResponse::Pending);
            }
            let Ok(length) = usize::try_from(taken) else {
                return Err(core.status_error(store, "take EasyTier RPC response", taken));
            };
            ensure!(
                u32::try_from(length).is_ok_and(|length| length <= capacity),
                "RPC response grew from {required} to {length} bytes"
            );
            if length == 0 {
                return Ok(RpcResponse::Ready(Vec::new()));
            }
            Ok(RpcResponse::Ready(core.read_bytes(store, pointer, length, "RPC response")?))
        })
    }

    pub fn free_rpc_operation(&mut self, store: &mut Store<HostState>, operation: u64) -> Result<()> {
        let status =
            self.exports.rpc_operation_free.call(&mut *store, (guest_i64(self.handle), guest_i64(operation)))?;
        if status != 0 {
            return Err(self.status_error(store, "free EasyTier RPC operation", status));
        }
        Ok(())
    }

    fn validate_data_plane_abi(&self, store: &mut Store<HostState>) -> Result<()> {
        let version = self.exports.data_plane_abi_version.call(&mut *store, ())?;
        ensure!(
            i64::from(version) == DATA_PLANE_ABI_VERSION.cast_signed(),
            "unsupported EasyTier data plane ABI version {version}, want {DATA_PLANE_ABI_VERSION}"
        );
        let reported = self.exports.data_plane_capabilities.call(&mut *store, ())?;
        let capabilities = u64::try_from(reported)
            .map_err(|_| anyhow!("EasyTier data plane capabilities {reported} are out of range"))?;
        let missing = REQUIRED_DATA_PLANE_CAPABILITIES & !capabilities;
        ensure!(missing == 0, "EasyTier data plane capabilities {capabilities:#x} are missing {missing:#x}");
        Ok(())
    }

    fn validate_rpc_abi(&self, store: &mut Store<HostState>) -> Result<()> {
        let version = self.exports.rpc_abi_version.call(&mut *store, ())?;
        ensure!(
            i64::from(version) == RPC_ABI_VERSION.cast_signed(),
            "unsupported EasyTier RPC ABI version {version}, want {RPC_ABI_VERSION}"
        );
        Ok(())
    }

    /// The call-status guard: the guest has one instance per module, so a start/stop/
    /// notify/drop on a module that was never created (or already dropped) is a caller bug.
    fn ensure_live(&self, name: &str) -> Result<()> {
        ensure!(!self.dropped && self.handle != 0, "{name} on unavailable EasyTier instance");
        Ok(())
    }

    fn check_status(&self, store: &mut Store<HostState>, operation: &str, status: i32) -> Result<()> {
        if status == 0 {
            Ok(())
        } else {
            Err(self.status_error(store, operation, status))
        }
    }

    fn check_data_plane_status(&self, store: &mut Store<HostState>, operation: &str, status: i32) -> Result<()> {
        if status == 0 {
            Ok(())
        } else {
            Err(self.data_plane_status_error(store, operation, status))
        }
    }

    fn decode_state(&self, store: &mut Store<HostState>, operation: &str, raw: i32) -> Result<State> {
        if raw < 0 {
            return Err(self.status_error(store, operation, raw));
        }
        State::from_raw(raw).ok_or_else(|| anyhow!("{operation}: unknown EasyTier state {raw}"))
    }

    fn status_error(&self, store: &mut Store<HostState>, operation: &str, status: i32) -> anyhow::Error {
        match self.error_message(store, self.handle) {
            Ok(message) => anyhow!("{operation}: status={status}: {message}"),
            Err(err) => anyhow!("{operation}: status={status}: {err}"),
        }
    }

    /// A data-plane status error: only `-ErrorKind` negatives are data-plane errors, so the
    /// concrete [`DataPlaneError`] stays in the chain for a `downcast_ref`.
    fn data_plane_status_error(&self, store: &mut Store<HostState>, operation: &str, status: i32) -> anyhow::Error {
        if status >= 0 || status < -(ErrorKind::BufferTooSmall as i32) {
            return self.status_error(store, operation, status);
        }
        let Some(kind) = u16::try_from(-status).ok().and_then(ErrorKind::from_raw) else {
            return self.status_error(store, operation, status);
        };
        match self.error_message(store, self.handle) {
            Ok(message) => DataPlaneError { kind, message }.into(),
            // The `DataPlaneError` is joined with the read failure; anyhow carries one message,
            // so the read failure rides along in it and the kind stays recoverable through a
            // downcast.
            Err(err) => DataPlaneError { kind, message: format!("{operation}: {err}") }.into(),
        }
    }

    fn error_message(&self, store: &mut Store<HostState>, handle: u64) -> Result<String> {
        let reported = self.exports.instance_error_len.call(&mut *store, (guest_i64(handle),))?;
        if reported == 0 {
            return Ok("<no core error>".to_owned());
        }
        let Ok(length) = u32::try_from(reported) else {
            bail!("invalid EasyTier error length {reported}");
        };
        let pointer = self.allocate(store, length)?;
        let outcome = (|| {
            let status = self
                .exports
                .instance_error_copy
                .call(&mut *store, (guest_i64(handle), guest_i32(pointer), guest_i32(length)))?;
            ensure!(status >= 0, "copy EasyTier error: status={status}");
            let bytes = self.read_bytes(store, pointer, length as usize, "EasyTier error")?;
            Ok(match String::from_utf8(bytes) {
                Ok(message) => message,
                // the `string(encoded)` accepts any bytes; lossy conversion is the
                // equivalent that a Rust `String` can hold.
                Err(err) => String::from_utf8_lossy(err.as_bytes()).into_owned(),
            })
        })();
        self.release(store, pointer, outcome)
    }

    /// `allocate`: a zero pointer is the guest's allocation-failure signal.
    fn allocate(&self, store: &mut Store<HostState>, length: u32) -> Result<u32> {
        let returned = self.exports.buffer_alloc.call(&mut *store, (guest_i32(length),))?;
        let pointer =
            u32::try_from(returned).map_err(|_| anyhow!("allocate {length} guest bytes: guest returned {returned}"))?;
        ensure!(pointer != 0, "allocate {length} guest bytes");
        Ok(pointer)
    }

    fn free(&self, store: &mut Store<HostState>, pointer: u32) -> Result<()> {
        let status = self.exports.buffer_free.call(&mut *store, (guest_i32(pointer),))?;
        ensure!(status == 0, "free guest buffer: status={status}");
        Ok(())
    }

    /// `primary` wins, and a release failure is reported only when `primary` succeeded. A zero
    /// pointer means nothing was allocated (an empty write), so there is nothing to release.
    fn release<T>(&self, store: &mut Store<HostState>, pointer: u32, primary: Result<T>) -> Result<T> {
        if pointer == 0 {
            return primary;
        }
        match (primary, self.free(store, pointer)) {
            (Ok(value), Ok(())) => Ok(value),
            (Ok(_), Err(cleanup)) => Err(cleanup),
            (Err(err), _) => Err(err),
        }
    }

    /// [`Self::release`] around a body that has not run yet, so the buffer cannot outlive
    /// the call that produced its contents.
    fn with_guest_buffer<T, F>(&mut self, store: &mut Store<HostState>, pointer: u32, body: F) -> Result<T>
    where
        F: FnOnce(&mut Self, &mut Store<HostState>) -> Result<T>,
    {
        let primary = body(self, store);
        self.release(store, pointer, primary)
    }

    /// Writes an input: a one-shot allocation for data the guest only needs during the call.
    fn write_input(&self, store: &mut Store<HostState>, data: &[u8]) -> Result<u32> {
        if data.is_empty() {
            return Ok(0);
        }
        let length = guest_length(data.len())?;
        let pointer = self.allocate(store, length)?;
        if let Err(err) = self.memory.write(&mut *store, pointer as usize, data) {
            let _ = self.free(store, pointer);
            return Err(anyhow!("write data plane input to guest memory: {err}"));
        }
        Ok(pointer)
    }

    fn ensure_packet_buffer(&mut self, store: &mut Store<HostState>, length: u32) -> Result<u32> {
        if self.packet_buffer_capacity >= length {
            return Ok(self.packet_buffer);
        }
        self.release_buffer(store, self.packet_buffer, "EasyTier packet buffer")?;
        self.packet_buffer = 0;
        self.packet_buffer_capacity = 0;
        self.packet_buffer = self.allocate(store, length)?;
        self.packet_buffer_capacity = length;
        Ok(self.packet_buffer)
    }

    fn ensure_data_plane_input(&mut self, store: &mut Store<HostState>, length: u32) -> Result<u32> {
        if self.data_plane_input_size >= length {
            return Ok(self.data_plane_input);
        }
        self.release_buffer(store, self.data_plane_input, "EasyTier data plane input buffer")?;
        self.data_plane_input = 0;
        self.data_plane_input_size = 0;
        self.data_plane_input = self.allocate(store, length)?;
        self.data_plane_input_size = length;
        Ok(self.data_plane_input)
    }

    fn ensure_data_plane_address(&mut self, store: &mut Store<HostState>) -> Result<u32> {
        if self.data_plane_address != 0 {
            return Ok(self.data_plane_address);
        }
        self.data_plane_address = self.allocate(store, ADDRESS_LEN_U32)?;
        Ok(self.data_plane_address)
    }

    fn ensure_data_plane_output(&mut self, store: &mut Store<HostState>, length: u32) -> Result<u32> {
        if self.data_plane_output_size >= length {
            return Ok(self.data_plane_output);
        }
        self.release_buffer(store, self.data_plane_output, "EasyTier data plane output buffer")?;
        self.data_plane_output = 0;
        self.data_plane_output_size = 0;
        self.data_plane_output = self.allocate(store, length)?;
        self.data_plane_output_size = length;
        Ok(self.data_plane_output)
    }

    /// Releases a cached buffer that is about to be replaced. The cache is only cleared once
    /// the guest confirms the free, so a failed free leaves a pointer the guest still owns
    /// rather than one it may already have reused.
    fn release_buffer(&self, store: &mut Store<HostState>, pointer: u32, name: &str) -> Result<()> {
        if pointer == 0 {
            return Ok(());
        }
        self.free(store, pointer).map_err(|err| anyhow!("grow {name} buffer: {err}"))
    }

    fn read_bytes(&self, store: &Store<HostState>, pointer: u32, length: usize, field: &str) -> Result<Vec<u8>> {
        let mut bytes = vec![0u8; length];
        self.memory
            .read(store, pointer as usize, &mut bytes)
            .map_err(|err| anyhow!("read {field} from guest memory: {err}"))?;
        Ok(bytes)
    }

    fn read_u64(&self, store: &Store<HostState>, pointer: u32, field: &str) -> Result<u64> {
        let mut bytes = [0u8; OPERATION_ID_LEN];
        self.memory
            .read(store, pointer as usize, &mut bytes)
            .map_err(|err| anyhow!("read {field} from guest memory: {err}"))?;
        Ok(u64::from_be_bytes(bytes))
    }

    fn read_operation(&self, store: &Store<HostState>, pointer: u32, name: &str) -> Result<u64> {
        let operation = self.read_u64(store, pointer, "operation ID")?;
        ensure!(operation != 0, "{name} returned zero operation ID");
        Ok(operation)
    }

    fn take_stream_result(
        &mut self,
        store: &mut Store<HostState>,
        completion: Completion,
        take: ResultTake,
    ) -> Result<(u64, DataPlaneSocketAddr, DataPlaneSocketAddr)> {
        let bytes = self.take_fixed_result(store, completion, take, STREAM_RESULT_LEN_U32)?;
        decode_stream_result(&bytes)
    }

    fn take_bind_result(
        &mut self,
        store: &mut Store<HostState>,
        completion: Completion,
        take: ResultTake,
    ) -> Result<(u64, DataPlaneSocketAddr)> {
        let bytes = self.take_fixed_result(store, completion, take, BIND_RESULT_LEN_U32)?;
        decode_bind_result(&bytes)
    }

    fn take_fixed_result(
        &mut self,
        store: &mut Store<HostState>,
        completion: Completion,
        take: ResultTake,
        length: u32,
    ) -> Result<Vec<u8>> {
        let name = take.export();
        let pointer = self.ensure_data_plane_output(store, length)?;
        let params = (guest_i64(self.handle), guest_i64(completion.operation), guest_i32(pointer));
        let status = match take {
            ResultTake::TcpConnect => self.exports.data_plane_tcp_connect_result_take.call(&mut *store, params)?,
            ResultTake::TcpAccept => self.exports.data_plane_tcp_accept_result_take.call(&mut *store, params)?,
            ResultTake::TcpBind => self.exports.data_plane_tcp_bind_result_take.call(&mut *store, params)?,
            ResultTake::UdpBind => self.exports.data_plane_udp_bind_result_take.call(&mut *store, params)?,
            ResultTake::TcpRead | ResultTake::UdpReceive | ResultTake::TcpWrite | ResultTake::UdpSend => {
                return Err(anyhow!("{name} does not produce a fixed-size result"));
            }
        };
        self.check_data_plane_status(store, name, status)?;
        self.read_bytes(store, pointer, length as usize, "data plane result")
    }

    fn take_tcp_read_result(
        &mut self,
        store: &mut Store<HostState>,
        completion: Completion,
        take: ResultTake,
    ) -> Result<(Vec<u8>, bool)> {
        let (data, metadata) =
            self.take_variable_result(store, completion, take, MAX_DATA_PLANE_TRANSFER_U32, TCP_READ_METADATA_LEN_U32)?;
        let Some(&eof) = metadata.first() else {
            bail!("data plane returned no TCP read metadata");
        };
        ensure!(eof <= 1, "data plane returned invalid TCP EOF flag {eof}");
        Ok((data, eof == 1))
    }

    fn take_udp_receive_result(
        &mut self,
        store: &mut Store<HostState>,
        completion: Completion,
        take: ResultTake,
    ) -> Result<(Vec<u8>, DataPlaneSocketAddr, bool)> {
        let (data, metadata) =
            self.take_variable_result(store, completion, take, UDP_RECEIVE_CAPACITY, UDP_RECEIVE_METADATA_LEN_U32)?;
        let peer_bytes = metadata
            .get(..wire::DATA_PLANE_SOCKET_ADDR_LEN)
            .ok_or_else(|| anyhow!("data plane returned a truncated UDP peer address"))?;
        let peer = wire::decode_data_plane_socket_addr(peer_bytes)?;
        let Some(&truncated) = metadata.get(wire::DATA_PLANE_SOCKET_ADDR_LEN) else {
            bail!("data plane returned no UDP truncation flag");
        };
        ensure!(truncated <= 1, "data plane returned invalid UDP truncation flag {truncated}");
        Ok((data, peer, truncated == 1))
    }

    fn take_variable_result(
        &mut self,
        store: &mut Store<HostState>,
        completion: Completion,
        take: ResultTake,
        capacity: u32,
        metadata_len: u32,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let name = take.export();
        let data_pointer = self.ensure_data_plane_input(store, capacity)?;
        let metadata_pointer = self.ensure_data_plane_output(store, metadata_len)?;
        let params = (
            guest_i64(self.handle),
            guest_i64(completion.operation),
            guest_i32(data_pointer),
            guest_i32(capacity),
            guest_i32(metadata_pointer),
        );
        let length = match take {
            ResultTake::TcpRead => self.exports.data_plane_tcp_read_result_take.call(&mut *store, params)?,
            ResultTake::UdpReceive => self.exports.data_plane_udp_receive_result_take.call(&mut *store, params)?,
            ResultTake::TcpConnect
            | ResultTake::TcpAccept
            | ResultTake::TcpBind
            | ResultTake::UdpBind
            | ResultTake::TcpWrite
            | ResultTake::UdpSend => return Err(anyhow!("{name} does not produce a variable-length result")),
        };
        if length < 0 {
            return Err(self.data_plane_status_error(store, name, length));
        }
        let length =
            u32::try_from(length).map_err(|_| anyhow!("{name} returned length {length} into capacity {capacity}"))?;
        ensure!(length <= capacity, "{name} returned length {length} into capacity {capacity}");
        let data = if length == 0 {
            Vec::new()
        } else {
            self.read_bytes(store, data_pointer, length as usize, "data plane result payload")?
        };
        let metadata = self.read_bytes(store, metadata_pointer, metadata_len as usize, "data plane result metadata")?;
        Ok((data, metadata))
    }

    fn take_length_result(
        &self,
        store: &mut Store<HostState>,
        completion: Completion,
        take: ResultTake,
    ) -> Result<usize> {
        let name = take.export();
        let params = (guest_i64(self.handle), guest_i64(completion.operation));
        let length = match take {
            ResultTake::TcpWrite => self.exports.data_plane_tcp_write_result_take.call(&mut *store, params)?,
            ResultTake::UdpSend => self.exports.data_plane_udp_send_result_take.call(&mut *store, params)?,
            ResultTake::TcpConnect
            | ResultTake::TcpAccept
            | ResultTake::TcpBind
            | ResultTake::UdpBind
            | ResultTake::TcpRead
            | ResultTake::UdpReceive => return Err(anyhow!("{name} does not produce a byte count")),
        };
        if length < 0 {
            return Err(self.data_plane_status_error(store, name, length));
        }
        usize::try_from(length).map_err(|_| anyhow!("{name} returned length {length}"))
    }
}

/// The base result a per-kind take starts from and fills in only what it produced. `0.0.0.0:0`
/// stands in for the zero address-port pair.
fn empty_result(kind: OperationKind) -> OperationResult {
    OperationResult {
        kind,
        resource: 0,
        local: DataPlaneSocketAddr { ip: std::net::Ipv4Addr::UNSPECIFIED, port: 0 },
        peer: DataPlaneSocketAddr { ip: std::net::Ipv4Addr::UNSPECIFIED, port: 0 },
        data: Vec::new(),
        length: 0,
        eof: false,
        truncated: false,
    }
}

fn decode_completions(wire: &[u8]) -> Result<Vec<Completion>> {
    ensure!(wire.len().is_multiple_of(COMPLETION_LEN), "decode completion bytes with length {}", wire.len());
    let mut completions = Vec::with_capacity(wire.len() / COMPLETION_LEN);
    for record in wire.chunks_exact(COMPLETION_LEN) {
        let operation = field_u64(record.get(..8).unwrap_or_default())
            .ok_or_else(|| anyhow!("data plane returned a truncated completion"))?;
        ensure!(operation != 0, "data plane returned zero operation ID");
        let raw_kind = field_u16(record.get(8..10).unwrap_or_default())
            .ok_or_else(|| anyhow!("data plane returned a truncated completion"))?;
        let kind = OperationKind::from_raw(raw_kind)
            .ok_or_else(|| anyhow!("data plane returned operation kind {raw_kind}"))?;
        let raw_status = field_u16(record.get(10..12).unwrap_or_default())
            .ok_or_else(|| anyhow!("data plane returned a truncated completion"))?;
        let status = ErrorKind::from_raw(raw_status)
            .ok_or_else(|| anyhow!("data plane returned completion status {raw_status}"))?;
        completions.push(Completion { operation, kind, status });
    }
    Ok(completions)
}

fn decode_stream_result(wire: &[u8]) -> Result<(u64, DataPlaneSocketAddr, DataPlaneSocketAddr)> {
    ensure!(wire.len() == STREAM_RESULT_LEN, "decode stream result with length {}", wire.len());
    let resource = field_u64(wire.get(..8).unwrap_or_default())
        .ok_or_else(|| anyhow!("data plane returned a truncated stream result"))?;
    ensure!(resource != 0, "data plane returned zero stream resource ID");
    let split = 8 + wire::DATA_PLANE_SOCKET_ADDR_LEN;
    let local = wire::decode_data_plane_socket_addr(wire.get(8..split).unwrap_or_default())?;
    let peer = wire::decode_data_plane_socket_addr(wire.get(split..).unwrap_or_default())?;
    Ok((resource, local, peer))
}

fn decode_bind_result(wire: &[u8]) -> Result<(u64, DataPlaneSocketAddr)> {
    ensure!(wire.len() == BIND_RESULT_LEN, "decode bind result with length {}", wire.len());
    let resource = field_u64(wire.get(..8).unwrap_or_default())
        .ok_or_else(|| anyhow!("data plane returned a truncated bind result"))?;
    ensure!(resource != 0, "data plane returned zero bound resource ID");
    let address = wire::decode_data_plane_socket_addr(wire.get(8..).unwrap_or_default())?;
    Ok((resource, address))
}

/// wasm32 addresses every byte offset and length, so a length that does not fit is a caller
/// error rather than something to truncate silently.
fn guest_length(length: usize) -> Result<u32> {
    u32::try_from(length).map_err(|_| anyhow!("guest input length {length} exceeds wasm32"))
}

/// Guest pointers and lengths travel as `i32`; only their bit pattern is meaningful, so a
/// pointer above `i32::MAX` must wrap rather than saturate.
fn guest_i32(value: u32) -> i32 {
    value.cast_signed()
}

fn guest_i64(value: u64) -> i64 {
    value.cast_signed()
}

fn field_u16(bytes: &[u8]) -> Option<u16> {
    let bytes: [u8; 2] = bytes.try_into().ok()?;
    Some(u16::from_be_bytes(bytes))
}

fn field_u64(bytes: &[u8]) -> Option<u64> {
    let bytes: [u8; 8] = bytes.try_into().ok()?;
    Some(u64::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn completion_record(operation: u64, kind: u16, status: u16) -> [u8; COMPLETION_LEN] {
        let mut record = [0u8; COMPLETION_LEN];
        record[..8].copy_from_slice(&operation.to_be_bytes());
        record[8..10].copy_from_slice(&kind.to_be_bytes());
        record[10..12].copy_from_slice(&status.to_be_bytes());
        record
    }

    fn stream_record(resource: u64, local: DataPlaneSocketAddr, peer: DataPlaneSocketAddr) -> [u8; STREAM_RESULT_LEN] {
        let mut record = [0u8; STREAM_RESULT_LEN];
        record[..8].copy_from_slice(&resource.to_be_bytes());
        record[8..8 + wire::DATA_PLANE_SOCKET_ADDR_LEN].copy_from_slice(&wire::encode_data_plane_socket_addr(local));
        record[8 + wire::DATA_PLANE_SOCKET_ADDR_LEN..].copy_from_slice(&wire::encode_data_plane_socket_addr(peer));
        record
    }

    fn bind_record(resource: u64, local: DataPlaneSocketAddr) -> [u8; BIND_RESULT_LEN] {
        let mut record = [0u8; BIND_RESULT_LEN];
        record[..8].copy_from_slice(&resource.to_be_bytes());
        record[8..].copy_from_slice(&wire::encode_data_plane_socket_addr(local));
        record
    }

    #[test]
    fn decodes_a_completion_batch_in_order() {
        let mut batch = Vec::new();
        batch.extend_from_slice(&completion_record(7, 1, 0));
        batch.extend_from_slice(&completion_record(9, 8, 13));
        let decoded = decode_completions(&batch).expect("valid batch");
        assert_eq!(
            decoded,
            vec![
                Completion { operation: 7, kind: OperationKind::TcpConnect, status: ErrorKind::None },
                Completion { operation: 9, kind: OperationKind::UdpSend, status: ErrorKind::BufferTooSmall },
            ]
        );
    }

    #[test]
    fn decodes_every_operation_kind_from_its_wire_value() {
        for raw in 1u16..=8 {
            let batch = completion_record(1, raw, 0);
            let decoded = decode_completions(&batch).expect("valid kind");
            assert_eq!(decoded[0].kind as u16, raw, "kind {raw} must survive the round trip");
        }
    }

    #[test]
    fn rejects_a_completion_with_a_zero_operation_id() {
        let batch = completion_record(0, 1, 0);
        let err = decode_completions(&batch).expect_err("zero operation id");
        assert!(err.to_string().contains("zero operation ID"), "{err}");
    }

    #[test]
    fn rejects_a_completion_with_an_out_of_range_kind() {
        for raw in [0u16, 9] {
            let batch = completion_record(1, raw, 0);
            let err = decode_completions(&batch).expect_err("out-of-range kind");
            assert!(err.to_string().contains("operation kind"), "{err}");
        }
    }

    #[test]
    fn rejects_a_completion_with_an_out_of_range_status() {
        let batch = completion_record(1, 1, 14);
        let err = decode_completions(&batch).expect_err("out-of-range status");
        assert!(err.to_string().contains("completion status"), "{err}");
    }

    #[test]
    fn rejects_a_completion_batch_of_ragged_length() {
        let mut batch = completion_record(1, 1, 0).to_vec();
        batch.push(0);
        let err = decode_completions(&batch).expect_err("ragged batch");
        assert!(err.to_string().contains("length 13"), "{err}");
    }

    #[test]
    fn decodes_a_stream_result() {
        let local = DataPlaneSocketAddr { ip: Ipv4Addr::new(10, 0, 0, 1), port: 80 };
        let peer = DataPlaneSocketAddr { ip: Ipv4Addr::new(192, 0, 2, 9), port: 65535 };
        let record = stream_record(4, local, peer);
        assert_eq!(decode_stream_result(&record).expect("valid stream result"), (4, local, peer));
    }

    #[test]
    fn rejects_a_stream_result_without_a_resource() {
        let record = stream_record(
            0,
            DataPlaneSocketAddr { ip: Ipv4Addr::UNSPECIFIED, port: 0 },
            DataPlaneSocketAddr { ip: Ipv4Addr::UNSPECIFIED, port: 0 },
        );
        let err = decode_stream_result(&record).expect_err("zero resource");
        assert!(err.to_string().contains("zero stream resource ID"), "{err}");
    }

    #[test]
    fn rejects_a_bind_result_without_a_resource() {
        let record = bind_record(0, DataPlaneSocketAddr { ip: Ipv4Addr::UNSPECIFIED, port: 0 });
        let err = decode_bind_result(&record).expect_err("zero resource");
        assert!(err.to_string().contains("zero bound resource ID"), "{err}");
    }

    #[test]
    fn rejects_a_non_ipv4_address_family() {
        let mut record = stream_record(
            4,
            DataPlaneSocketAddr { ip: Ipv4Addr::UNSPECIFIED, port: 0 },
            DataPlaneSocketAddr { ip: Ipv4Addr::UNSPECIFIED, port: 0 },
        );
        record[8] = 6;
        let err = decode_stream_result(&record).expect_err("IPv6 family");
        assert!(err.to_string().contains("family must be 4"), "{err}");
    }

    #[test]
    fn rejects_a_non_zero_address_padding() {
        let mut record = bind_record(4, DataPlaneSocketAddr { ip: Ipv4Addr::new(192, 0, 2, 1), port: 443 });
        record[8 + 5] = 1;
        let err = decode_bind_result(&record).expect_err("non-zero padding");
        assert!(err.to_string().contains("zero-pad"), "{err}");
    }

    #[test]
    fn rejects_a_result_of_the_wrong_length() {
        assert!(decode_stream_result(&[0u8; STREAM_RESULT_LEN - 1]).is_err());
        assert!(decode_bind_result(&[0u8; BIND_RESULT_LEN + 1]).is_err());
    }

    #[test]
    fn state_round_trips_through_its_wire_value() {
        let states = [State::Created, State::Starting, State::Running, State::Stopping, State::Stopped];
        for (raw, state) in states.iter().enumerate() {
            assert_eq!(State::from_raw(i32::try_from(raw).expect("small")), Some(*state));
        }
        assert_eq!(State::from_raw(-1), None);
        assert_eq!(State::from_raw(5), None);
    }

    #[test]
    fn error_kind_round_trips_through_its_wire_value() {
        let kinds = [
            ErrorKind::None,
            ErrorKind::Cancelled,
            ErrorKind::DeadlineExceeded,
            ErrorKind::InstanceStopped,
            ErrorKind::HandleClosed,
            ErrorKind::NoOverlayRoute,
            ErrorKind::PathNotReady,
            ErrorKind::AddressFamilyUnsupported,
            ErrorKind::AddressInUse,
            ErrorKind::ConnectionRefused,
            ErrorKind::NetworkChanged,
            ErrorKind::ResourceLimit,
            ErrorKind::Io,
            ErrorKind::BufferTooSmall,
        ];
        for (raw, kind) in kinds.iter().enumerate() {
            let raw = u16::try_from(raw).expect("small");
            assert_eq!(ErrorKind::from_raw(raw), Some(*kind));
            assert_eq!(*kind as u16, raw);
        }
        assert_eq!(ErrorKind::from_raw(u16::try_from(kinds.len()).expect("small")), None);
    }

    #[test]
    fn data_plane_error_prefers_the_guest_message() {
        let described = DataPlaneError { kind: ErrorKind::ConnectionRefused, message: "no route to peer".to_owned() };
        assert_eq!(described.to_string(), "no route to peer");
    }

    #[test]
    fn data_plane_error_falls_back_to_its_kind() {
        let bare = DataPlaneError { kind: ErrorKind::PathNotReady, message: String::new() };
        assert_eq!(bare.to_string(), format!("data plane error {}", ErrorKind::PathNotReady as u16));
    }

    #[test]
    fn data_plane_error_stays_downcastable_through_anyhow() {
        // The shape every data-plane failure takes: the concrete error is the anyhow root
        // cause, so a caller can recover the kind instead of matching on a message.
        let error: anyhow::Error = DataPlaneError { kind: ErrorKind::Io, message: "reset by peer".to_owned() }.into();
        let downcast = error.downcast_ref::<DataPlaneError>().expect("the concrete error stays in the chain");
        assert_eq!(downcast.kind, ErrorKind::Io);
        assert_eq!(downcast.message, "reset by peer");
    }

    #[test]
    fn guest_parameter_conversions_preserve_the_bit_pattern() {
        assert_eq!(guest_i32(0xFFFF_FFFF), -1);
        assert_eq!(guest_i64(u64::MAX), -1);
        assert!(guest_length(MAX_RPC_MESSAGE).is_ok());
        assert!(guest_length(usize::try_from(u64::from(u32::MAX)).expect("fits") + 1).is_err());
    }

    #[test]
    fn result_take_covers_every_operation_kind() {
        let kinds = [
            OperationKind::TcpConnect,
            OperationKind::TcpBind,
            OperationKind::TcpAccept,
            OperationKind::TcpRead,
            OperationKind::TcpWrite,
            OperationKind::UdpBind,
            OperationKind::UdpReceive,
            OperationKind::UdpSend,
        ];
        for kind in kinds {
            let take = ResultTake::of(kind);
            assert!(take.export().ends_with("_result_take"), "{take:?}");
        }
    }
}
