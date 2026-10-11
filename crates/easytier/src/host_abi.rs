//! Every closure here is the wasmtime spelling of a host function: validate, hand the work to
//! [`Reactor`], return a status code.
//!
//! None of them await, block or panic — the real I/O runs on tasks the reactor spawns, and the
//! guest learns about it by polling the matching `take_X`.
//!
//! **Deviation**: the byte codecs come from [`crate::wire`] rather than living next to their
//! callers, and `connect_status` classifies the connect errno through [`std::io::ErrorKind`],
//! which is what `std` already normalizes.
//!
//! **Deviation**: no reusable AEAD cache (capacity 64) is kept. Holding a ready AEAD means
//! constructing it here, and [`crate::crypto`] is this crate's only AEAD construction point, so
//! the guest still builds its cipher per packet.

use std::io::ErrorKind;
use std::sync::Arc;

use anyhow::anyhow;
use wasmtime::{AsContext, AsContextMut, Caller, Extern, Linker, Memory};

use murmur_std_compat::net::{Addr, UdpAddr};

use crate::crypto::{aead_open, aead_seal, CryptoStatus};
use crate::reactor::{Reactor, ReactorError, TakeOutcome};
use crate::store::HostState;
use crate::wire;

/// The single import module every host function below is registered under.
pub const IMPORT_MODULE: &str = "easytier_host";

pub const STATUS_PENDING: i32 = -1;
pub const STATUS_INVALID: i32 = -2;
pub const STATUS_IO_ERROR: i32 = -3;
pub const STATUS_MEMORY: i32 = -4;
pub const STATUS_WOULD_BLOCK: i32 = -5;
/// From `take_tcp_connect` only.
pub const STATUS_CONNECTION_REFUSED: i32 = -6;
/// From `take_tcp_connect` only.
pub const STATUS_CONNECTION_ABORTED: i32 = -7;
/// From `take_tcp_connect` only.
pub const STATUS_CONNECTION_RESET: i32 = -8;
/// From `take_tcp_connect` only.
pub const STATUS_NOT_CONNECTED: i32 = -9;
pub const STATUS_CRYPTO_AUTH_FAILED: i32 = -10;
pub const STATUS_CRYPTO_FALLBACK: i32 = -11;

const MAX_FACTORY_OPTIONS_LEN: u32 = 4096;
const MAX_DNS_QUERY_LEN: u32 = 4096;
const MAX_DNS_RESULT_LEN: usize = 1024 * 1024;
const MAX_MANAGEMENT_LEN: usize = 16 * 1024 * 1024;
const MAX_EVENT_KIND_LEN: u32 = 64;
const MAX_EVENT_MESSAGE_LEN: u32 = 64 * 1024;
const MAX_HOST_PACKET_LEN: u32 = 1024 * 1024;
/// The `length > 65535` send guard.
const MAX_UDP_SEND_LEN: u32 = 65_535;

/// GCM's AEAD overhead.
const AEAD_TAG_LEN: u32 = 16;
/// GCM's AEAD nonce size.
const AEAD_NONCE_LEN: u32 = 12;

/// The coarse status mapping every non-connect family uses.
fn operation_status(error: &ReactorError) -> i32 {
    match error {
        ReactorError::AlreadyClaimed(_)
        | ReactorError::UnknownOperation(_)
        | ReactorError::WrongOperationKind(..)
        | ReactorError::UnknownHandle(_)
        | ReactorError::ManagementHandlerNotConfigured => STATUS_INVALID,
        ReactorError::Cancelled(_) => STATUS_PENDING,
        ReactorError::WouldBlock => STATUS_WOULD_BLOCK,
        ReactorError::Io(_) | ReactorError::Other(_) => STATUS_IO_ERROR,
    }
}

/// [`operation_status`] with the four connect errnos split out, for `take_tcp_connect` only.
/// `WouldBlock` has no case here either, so it lands on the catch-all like any other error.
fn connect_status(error: &ReactorError) -> i32 {
    match error {
        ReactorError::AlreadyClaimed(_)
        | ReactorError::UnknownOperation(_)
        | ReactorError::WrongOperationKind(..)
        | ReactorError::UnknownHandle(_)
        | ReactorError::ManagementHandlerNotConfigured => STATUS_INVALID,
        ReactorError::Cancelled(_) => STATUS_PENDING,
        // `ErrorKind` is `#[non_exhaustive]`, so the four connect errnos are tested in order and
        // every other kind — `WouldBlock` included — falls through to the generic I/O error.
        ReactorError::Io(io) => {
            let kind = io.kind();
            if kind == ErrorKind::ConnectionRefused {
                STATUS_CONNECTION_REFUSED
            } else if kind == ErrorKind::ConnectionAborted {
                STATUS_CONNECTION_ABORTED
            } else if kind == ErrorKind::ConnectionReset {
                STATUS_CONNECTION_RESET
            } else if kind == ErrorKind::NotConnected {
                STATUS_NOT_CONNECTED
            } else {
                STATUS_IO_ERROR
            }
        }
        ReactorError::WouldBlock | ReactorError::Other(_) => STATUS_IO_ERROR,
    }
}

/// Collapses a reactor poll into either the ready value or the exact code the call returns.
/// `NeedsCapacity` is unreachable for the `take_simple` families (it belongs to
/// `take_capacity_checked`), so it degrades to the generic I/O error rather than panicking.
fn take_ready<T>(outcome: Result<TakeOutcome<T>, ReactorError>, status: fn(&ReactorError) -> i32) -> Result<T, i32> {
    match outcome {
        Ok(TakeOutcome::Ready(value)) => Ok(value),
        Ok(TakeOutcome::Pending) => Err(STATUS_PENDING),
        Ok(TakeOutcome::NeedsCapacity(_)) => Err(STATUS_IO_ERROR),
        Err(error) => Err(status(&error)),
    }
}

/// `Reactor::claim_operation` spawns onto the ambient Tokio runtime, which a host import does not
/// inherit from the embedder's call stack. Every `start_X` and `close` therefore enters the
/// runtime captured in [`HostState`] before touching the reactor, and maps the claim's result to
/// a status code in one place.
fn in_runtime(runtime: &tokio::runtime::Handle, claim: impl FnOnce() -> Result<(), ReactorError>) -> i32 {
    let _guard = runtime.enter();
    match claim() {
        Ok(()) => 0,
        Err(error) => operation_status(&error),
    }
}

fn guest_memory(caller: &mut Caller<'_, HostState>) -> Option<Memory> {
    caller.get_export("memory").and_then(Extern::into_memory)
}

/// A bounds-checked view of guest memory: the memory read hands back a view that is already
/// range-checked, so the guest-supplied length is validated before anything is copied.
fn slice_at(data: &[u8], pointer: u32, length: u32) -> Option<&[u8]> {
    data.get(pointer as usize..)?.get(..length as usize)
}

fn read_guest(memory: &Memory, store: impl AsContext, pointer: u32, length: u32) -> Option<Vec<u8>> {
    let data = memory.data(&store);
    Some(slice_at(data, pointer, length)?.to_vec())
}

/// The factory-options ceiling, then an owned copy.
fn read_options(memory: &Memory, store: impl AsContext, pointer: u32, length: u32) -> Option<Vec<u8>> {
    if length > MAX_FACTORY_OPTIONS_LEN {
        return None;
    }
    read_guest(memory, store, pointer, length)
}

/// The fixed-size result families refuse a wrong length before touching the reactor at all.
fn valid_result_memory(memory: &Memory, store: impl AsContext, pointer: u32, length: u32, expected: usize) -> bool {
    if length as usize != expected {
        return false;
    }
    let mut probe = [0u8; wire::TCP_SOCKET_RESULT_LEN];
    let Some(window) = probe.get_mut(..length as usize) else {
        return false;
    };
    memory.read(store, pointer as usize, window).is_ok()
}

/// Whether a guest-supplied range is inside linear memory, the probe `take_udp_recv` runs for its
/// two output buffers before it asks the reactor for anything.
fn guest_range(memory: &Memory, store: impl AsContext, pointer: u32, length: u32) -> bool {
    slice_at(memory.data(&store), pointer, length).is_some()
}

/// Only a TCP/UDP address can be reported to the guest, which is what
/// [`wire::encode_socket_address`]'s absent-encoding fallback would otherwise hide.
fn socket_address(address: &dyn Addr) -> anyhow::Result<[u8; wire::SOCKET_ADDRESS_LEN]> {
    if address.as_sock_addr().is_none() {
        anyhow::bail!("unsupported socket address {address:?}: expected a TCP or UDP address");
    }
    Ok(wire::encode_socket_address(address))
}

/// The 48-byte datagram metadata is the 27-byte socket address followed by the canonical all-zero
/// "absent" secondary-IP slot.
fn udp_metadata(peer: &dyn Addr) -> anyhow::Result<[u8; wire::UDP_METADATA_LEN]> {
    let mut metadata = [0u8; wire::UDP_METADATA_LEN];
    metadata[..wire::SOCKET_ADDRESS_LEN].copy_from_slice(&socket_address(peer)?);
    Ok(metadata)
}

/// Breadcrumbs for host imports whose options blob failed to decode, and for the status every bind
/// import returns. The guest reports only "listener failed to start", so without these the
/// rejected blob — or the request the guest never made at all — is unreachable. The recording is
/// test-only, but the wrappers exist in every build: [`add_to_linker`] is compiled for dependents
/// too, where `cfg(test)` is off.
#[cfg(test)]
static IMPORT_FAILURES: std::sync::LazyLock<std::sync::Mutex<Vec<String>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(Vec::new()));

fn note_test_import(name: &str, blob: &[u8], error: &anyhow::Error) -> i32 {
    #[cfg(test)]
    {
        let head = blob.get(..blob.len().min(96)).unwrap_or_default();
        IMPORT_FAILURES
            .lock()
            .expect("the breadcrumb lock is never poisoned")
            .push(format!("{name}: {error} [len={} {head:02x?}]", blob.len()));
    }
    let _ = (name, blob, error);
    STATUS_INVALID
}

fn note_test_status(name: &str, status: i32) -> i32 {
    #[cfg(test)]
    IMPORT_FAILURES.lock().expect("the breadcrumb lock is never poisoned").push(format!("{name}: status={status}"));
    let _ = name;
    status
}

#[cfg(test)]
pub(crate) fn test_import_failures() -> Vec<String> {
    IMPORT_FAILURES.lock().expect("the breadcrumb lock is never poisoned").clone()
}

/// wire.rs keeps the inverse private; the reactor takes a `UdpAddr` for every datagram peer and
/// `try_udp_send`'s destination.
fn udp_addr(address: wire::HostSocketAddress) -> UdpAddr {
    UdpAddr {
        ip: address.ip,
        port: address.port,
        zone: if address.scope_id == 0 { String::new() } else { address.scope_id.to_string() },
    }
}

/// The shared tail of the fixed-size `take_X` families: a failed encode or write closes the
/// freshly-minted handle rather than leaking it.
fn deliver<B: AsRef<[u8]>>(
    reactor: &Reactor,
    memory: &Memory,
    store: impl AsContextMut,
    pointer: u32,
    encoded: anyhow::Result<B>,
    handle: u64,
) -> i32 {
    match encoded {
        Ok(bytes) if memory.write(store, pointer as usize, bytes.as_ref()).is_ok() => 0,
        _ => {
            let _ = reactor.close(handle);
            STATUS_MEMORY
        }
    }
}

/// The event length gate, split out so the policy is testable without a guest.
fn event_lengths_valid(kind_length: u32, message_length: u32) -> bool {
    (1..=MAX_EVENT_KIND_LEN).contains(&kind_length) && (1..=MAX_EVENT_MESSAGE_LEN).contains(&message_length)
}

#[derive(Clone, Copy)]
enum AeadDirection {
    Seal,
    Open,
}

/// Seal and open differ only in direction. Every fault here — bad algorithm, wrong key length,
/// short read, non-12-byte nonce — is [`STATUS_CRYPTO_FALLBACK`], a soft "do it yourself" signal;
/// only a GCM tag mismatch on open is [`STATUS_CRYPTO_AUTH_FAILED`].
fn aead_in_place(
    memory: &Memory,
    store: &mut impl AsContextMut,
    direction: AeadDirection,
    algorithm: i32,
    key_pointer: i32,
    key_length: i32,
    nonce_pointer: i32,
    nonce_length: i32,
    aad_pointer: i32,
    aad_length: i32,
    buffer_pointer: i32,
    text_length: i32,
) -> i32 {
    let (algorithm, expected_key_length) = match algorithm {
        1 => (1u8, 16u32),
        2 => (2u8, 32u32),
        _ => return STATUS_CRYPTO_FALLBACK,
    };
    if key_length.cast_unsigned() != expected_key_length {
        return STATUS_CRYPTO_FALLBACK;
    }
    let nonce_length = nonce_length.cast_unsigned();
    if nonce_length != AEAD_NONCE_LEN {
        return STATUS_CRYPTO_FALLBACK;
    }
    let (aad_length, text_length) = (aad_length.cast_unsigned(), text_length.cast_unsigned());
    let Some(total) = text_length.checked_add(AEAD_TAG_LEN) else {
        return STATUS_CRYPTO_FALLBACK;
    };

    let data = memory.data_mut(&mut *store);
    let Some(key) = slice_at(data, key_pointer.cast_unsigned(), expected_key_length) else {
        return STATUS_CRYPTO_FALLBACK;
    };
    let mut owned_key = [0u8; 32];
    let Some(key_slot) = owned_key.get_mut(..expected_key_length as usize) else {
        return STATUS_CRYPTO_FALLBACK;
    };
    key_slot.copy_from_slice(key);
    let owned_key: &[u8] = key_slot;
    let Some(nonce) = slice_at(data, nonce_pointer.cast_unsigned(), nonce_length) else {
        return STATUS_CRYPTO_FALLBACK;
    };
    let mut owned_nonce = [0u8; 12];
    owned_nonce.copy_from_slice(nonce);
    let Some(aad) = slice_at(data, aad_pointer.cast_unsigned(), aad_length) else {
        return STATUS_CRYPTO_FALLBACK;
    };
    let aad = aad.to_vec();
    let Some(buffer) =
        data.get_mut(buffer_pointer.cast_unsigned() as usize..).and_then(|rest| rest.get_mut(..total as usize))
    else {
        return STATUS_CRYPTO_FALLBACK;
    };

    let outcome = match direction {
        AeadDirection::Seal => aead_seal(algorithm, owned_key, &owned_nonce, &aad, buffer, text_length as usize),
        AeadDirection::Open => aead_open(algorithm, owned_key, &owned_nonce, &aad, buffer, text_length as usize),
    };
    match outcome {
        Ok(()) => 0,
        Err(CryptoStatus::AuthFailed) => STATUS_CRYPTO_AUTH_FAILED,
        Err(CryptoStatus::Fallback) => STATUS_CRYPTO_FALLBACK,
    }
}

/// Registers one host import, mapping a link failure into the crate's `anyhow` error.
macro_rules! host_import {
    ($linker:expr, $name:literal, $body:expr) => {
        $linker
            .func_wrap(IMPORT_MODULE, $name, $body)
            .map_err(|error| anyhow!("register host import {IMPORT_MODULE}.{}: {error}", $name))?
    };
}

/// Registers every host import the embedded core declares. Call once per [`Linker`], before
/// [`Linker::instantiate`].
pub fn add_to_linker(linker: &mut Linker<HostState>) -> anyhow::Result<()> {
    register_tcp_connect_imports(linker)?;
    register_bind_imports(linker)?;
    register_tcp_accept_imports(linker)?;
    register_dns_imports(linker)?;
    register_local_addr_imports(linker)?;
    register_management_imports(linker)?;
    register_stream_imports(linker)?;
    register_datagram_imports(linker)?;
    register_packet_imports(linker)?;
    register_event_imports(linker)?;
    register_crypto_imports(linker)?;
    register_misc_imports(linker)?;
    Ok(())
}

/// `start_tcp_connect` and `take_tcp_connect`.
fn register_tcp_connect_imports(linker: &mut Linker<HostState>) -> anyhow::Result<()> {
    host_import!(linker, "start_tcp_connect", |mut caller: Caller<'_, HostState>,
                                               operation: i64,
                                               options_pointer: i32,
                                               options_length: i32| {
        let Some(memory) = guest_memory(&mut caller) else { return STATUS_MEMORY };
        let Some(encoded) =
            read_options(&memory, &caller, options_pointer.cast_unsigned(), options_length.cast_unsigned())
        else {
            return STATUS_MEMORY;
        };
        let Ok(options) = wire::decode_tcp_connect_options(&encoded) else { return STATUS_INVALID };
        in_runtime(&caller.data().runtime, || {
            caller.data().reactor.start_tcp_connect(operation.cast_unsigned(), options)
        })
    });

    host_import!(linker, "take_tcp_connect", |mut caller: Caller<'_, HostState>,
                                              operation: i64,
                                              result_pointer: i32,
                                              result_length: i32| {
        let Some(memory) = guest_memory(&mut caller) else { return STATUS_MEMORY };
        if !valid_result_memory(
            &memory,
            &caller,
            result_pointer.cast_unsigned(),
            result_length.cast_unsigned(),
            wire::TCP_SOCKET_RESULT_LEN,
        ) {
            caller.data().reactor.cancel_operation(operation.cast_unsigned());
            return STATUS_MEMORY;
        }
        let result = match take_ready(caller.data().reactor.take_tcp_connect(operation.cast_unsigned()), connect_status)
        {
            Ok(result) => result,
            Err(status) => return status,
        };
        let reactor = Arc::clone(&caller.data().reactor);
        let encoded = wire::encode_tcp_socket_result(result.handle, result.local.as_ref(), result.peer.as_ref());
        deliver(&reactor, &memory, &mut caller, result_pointer.cast_unsigned(), encoded, result.handle)
    });
    Ok(())
}

/// The four bind imports: `start_udp_bind`, `take_udp_bind`, `start_tcp_bind`, `take_tcp_bind`.
fn register_bind_imports(linker: &mut Linker<HostState>) -> anyhow::Result<()> {
    host_import!(linker, "start_udp_bind", |mut caller: Caller<'_, HostState>,
                                            operation: i64,
                                            options_pointer: i32,
                                            options_length: i32| {
        let Some(memory) = guest_memory(&mut caller) else { return STATUS_MEMORY };
        let Some(encoded) =
            read_options(&memory, &caller, options_pointer.cast_unsigned(), options_length.cast_unsigned())
        else {
            return STATUS_MEMORY;
        };
        let options = match wire::decode_udp_bind_options(&encoded) {
            Ok(options) => options,
            Err(err) => return note_test_import("start_udp_bind", &encoded, &err),
        };
        let status = in_runtime(&caller.data().runtime, || {
            caller.data().reactor.start_udp_bind(operation.cast_unsigned(), options)
        });
        note_test_status("start_udp_bind", status)
    });

    host_import!(linker, "take_udp_bind", |mut caller: Caller<'_, HostState>,
                                           operation: i64,
                                           result_pointer: i32,
                                           result_length: i32| {
        let Some(memory) = guest_memory(&mut caller) else { return STATUS_MEMORY };
        if !valid_result_memory(
            &memory,
            &caller,
            result_pointer.cast_unsigned(),
            result_length.cast_unsigned(),
            wire::BOUND_SOCKET_RESULT_LEN,
        ) {
            caller.data().reactor.cancel_operation(operation.cast_unsigned());
            return STATUS_MEMORY;
        }
        let result = match take_ready(caller.data().reactor.take_udp_bind(operation.cast_unsigned()), operation_status)
        {
            Ok(result) => result,
            Err(status) => return status,
        };
        let reactor = Arc::clone(&caller.data().reactor);
        let encoded = wire::encode_bound_socket_result(result.handle, result.local.as_ref());
        deliver(&reactor, &memory, &mut caller, result_pointer.cast_unsigned(), encoded, result.handle)
    });

    host_import!(linker, "start_tcp_bind", |mut caller: Caller<'_, HostState>,
                                            operation: i64,
                                            options_pointer: i32,
                                            options_length: i32| {
        let Some(memory) = guest_memory(&mut caller) else { return STATUS_MEMORY };
        let Some(encoded) =
            read_options(&memory, &caller, options_pointer.cast_unsigned(), options_length.cast_unsigned())
        else {
            return STATUS_MEMORY;
        };
        let options = match wire::decode_tcp_listen_options(&encoded) {
            Ok(options) => options,
            Err(err) => return note_test_import("start_tcp_bind", &encoded, &err),
        };
        let status = in_runtime(&caller.data().runtime, || {
            caller.data().reactor.start_tcp_listen(operation.cast_unsigned(), options)
        });
        note_test_status("start_tcp_bind", status)
    });

    host_import!(linker, "take_tcp_bind", |mut caller: Caller<'_, HostState>,
                                           operation: i64,
                                           result_pointer: i32,
                                           result_length: i32| {
        let Some(memory) = guest_memory(&mut caller) else { return STATUS_MEMORY };
        if !valid_result_memory(
            &memory,
            &caller,
            result_pointer.cast_unsigned(),
            result_length.cast_unsigned(),
            wire::BOUND_SOCKET_RESULT_LEN,
        ) {
            caller.data().reactor.cancel_operation(operation.cast_unsigned());
            return STATUS_MEMORY;
        }
        let result =
            match take_ready(caller.data().reactor.take_tcp_listen(operation.cast_unsigned()), operation_status) {
                Ok(result) => result,
                Err(status) => return status,
            };
        let reactor = Arc::clone(&caller.data().reactor);
        let encoded = wire::encode_bound_socket_result(result.handle, result.local.as_ref());
        deliver(&reactor, &memory, &mut caller, result_pointer.cast_unsigned(), encoded, result.handle)
    });
    Ok(())
}

/// `start_tcp_accept` and `take_tcp_accept`.
fn register_tcp_accept_imports(linker: &mut Linker<HostState>) -> anyhow::Result<()> {
    host_import!(linker, "start_tcp_accept", |caller: Caller<'_, HostState>, handle: i64, operation: i64| {
        in_runtime(&caller.data().runtime, || {
            caller.data().reactor.start_tcp_accept(operation.cast_unsigned(), handle.cast_unsigned())
        })
    });

    host_import!(linker, "take_tcp_accept", |mut caller: Caller<'_, HostState>,
                                             operation: i64,
                                             result_pointer: i32,
                                             result_length: i32| {
        let Some(memory) = guest_memory(&mut caller) else { return STATUS_MEMORY };
        if !valid_result_memory(
            &memory,
            &caller,
            result_pointer.cast_unsigned(),
            result_length.cast_unsigned(),
            wire::TCP_SOCKET_RESULT_LEN,
        ) {
            caller.data().reactor.cancel_operation(operation.cast_unsigned());
            return STATUS_MEMORY;
        }
        let result =
            match take_ready(caller.data().reactor.take_tcp_accept(operation.cast_unsigned()), operation_status) {
                Ok(result) => result,
                Err(status) => return status,
            };
        let reactor = Arc::clone(&caller.data().reactor);
        let encoded = wire::encode_tcp_socket_result(result.handle, result.local.as_ref(), result.peer.as_ref());
        deliver(&reactor, &memory, &mut caller, result_pointer.cast_unsigned(), encoded, result.handle)
    });
    Ok(())
}

/// The six DNS imports, each pair delegating to [`start_dns`]/[`take_dns`].
fn register_dns_imports(linker: &mut Linker<HostState>) -> anyhow::Result<()> {
    host_import!(linker, "start_dns_resolve", |caller: Caller<'_, HostState>,
                                               operation: i64,
                                               query_pointer: i32,
                                               query_length: i32| {
        start_dns(caller, operation, query_pointer, query_length, DnsKind::Resolve)
    });

    host_import!(linker, "take_dns_resolve", |caller: Caller<'_, HostState>,
                                              operation: i64,
                                              result_pointer: i32,
                                              result_capacity: i32| {
        take_dns(caller, operation, result_pointer, result_capacity, DnsKind::Resolve)
    });

    host_import!(linker, "start_dns_txt", |caller: Caller<'_, HostState>,
                                           operation: i64,
                                           query_pointer: i32,
                                           query_length: i32| start_dns(
        caller,
        operation,
        query_pointer,
        query_length,
        DnsKind::Txt
    ));

    host_import!(linker, "take_dns_txt", |caller: Caller<'_, HostState>,
                                          operation: i64,
                                          result_pointer: i32,
                                          result_capacity: i32| take_dns(
        caller,
        operation,
        result_pointer,
        result_capacity,
        DnsKind::Txt
    ));

    host_import!(linker, "start_dns_srv", |caller: Caller<'_, HostState>,
                                           operation: i64,
                                           query_pointer: i32,
                                           query_length: i32| start_dns(
        caller,
        operation,
        query_pointer,
        query_length,
        DnsKind::Srv
    ));

    host_import!(linker, "take_dns_srv", |caller: Caller<'_, HostState>,
                                          operation: i64,
                                          result_pointer: i32,
                                          result_capacity: i32| take_dns(
        caller,
        operation,
        result_pointer,
        result_capacity,
        DnsKind::Srv
    ));
    Ok(())
}

/// The two `local_addr_for_remote` imports.
fn register_local_addr_imports(linker: &mut Linker<HostState>) -> anyhow::Result<()> {
    host_import!(
        linker,
        "start_local_addr_for_remote",
        |mut caller: Caller<'_, HostState>,
         operation: i64,
         remote_pointer: i32,
         remote_length: i32,
         context_pointer: i32,
         context_length: i32| {
            let Some(memory) = guest_memory(&mut caller) else { return STATUS_MEMORY };
            let remote_length = remote_length.cast_unsigned();
            if remote_length as usize != wire::SOCKET_ADDRESS_LEN {
                return STATUS_INVALID;
            }
            let Some(encoded) = read_guest(&memory, &caller, remote_pointer.cast_unsigned(), remote_length) else {
                return STATUS_MEMORY;
            };
            let Ok(Some(remote)) = wire::decode_socket_address(&encoded, false) else { return STATUS_INVALID };
            let context_length = context_length.cast_unsigned();
            let Some(encoded) = read_options(&memory, &caller, context_pointer.cast_unsigned(), context_length) else {
                return STATUS_MEMORY;
            };
            let Ok((context, consumed)) = wire::decode_socket_context(&encoded) else { return STATUS_INVALID };
            if consumed != context_length as usize {
                return STATUS_INVALID;
            }
            in_runtime(&caller.data().runtime, || {
                caller.data().reactor.start_local_addr_for_remote(operation.cast_unsigned(), udp_addr(remote), context)
            })
        }
    );

    host_import!(
        linker,
        "take_local_addr_for_remote",
        |mut caller: Caller<'_, HostState>, operation: i64, result_pointer: i32, result_length: i32| {
            let Some(memory) = guest_memory(&mut caller) else { return STATUS_MEMORY };
            if !valid_result_memory(
                &memory,
                &caller,
                result_pointer.cast_unsigned(),
                result_length.cast_unsigned(),
                wire::SOCKET_ADDRESS_LEN,
            ) {
                caller.data().reactor.cancel_operation(operation.cast_unsigned());
                return STATUS_MEMORY;
            }
            let address = match take_ready(
                caller.data().reactor.take_local_addr_for_remote(operation.cast_unsigned()),
                operation_status,
            ) {
                Ok(address) => address,
                Err(status) => return status,
            };
            let Ok(encoded) = socket_address(address.as_ref()) else { return STATUS_INVALID };
            if memory.write(&mut caller, result_pointer.cast_unsigned() as usize, &encoded).is_err() {
                return STATUS_MEMORY;
            }
            0
        }
    );
    Ok(())
}

/// The two `management_call` imports.
fn register_management_imports(linker: &mut Linker<HostState>) -> anyhow::Result<()> {
    host_import!(
        linker,
        "start_management_call",
        |mut caller: Caller<'_, HostState>, operation: i64, request_pointer: i32, request_length: i32| {
            let Some(memory) = guest_memory(&mut caller) else { return STATUS_MEMORY };
            let request_length = request_length.cast_unsigned();
            if request_length == 0 || request_length as usize > MAX_MANAGEMENT_LEN {
                return STATUS_INVALID;
            }
            let Some(request) = read_guest(&memory, &caller, request_pointer.cast_unsigned(), request_length) else {
                return STATUS_MEMORY;
            };
            in_runtime(&caller.data().runtime, || {
                caller.data().reactor.start_management_call(operation.cast_unsigned(), request)
            })
        }
    );

    host_import!(
        linker,
        "take_management_call",
        |mut caller: Caller<'_, HostState>, operation: i64, result_pointer: i32, result_capacity: i32| {
            let Some(memory) = guest_memory(&mut caller) else { return STATUS_MEMORY };
            let operation = operation.cast_unsigned();
            let reactor = Arc::clone(&caller.data().reactor);
            let outcome = reactor.take_management_call(operation, result_capacity.cast_unsigned() as usize);
            let response = match outcome {
                Err(error) => return operation_status(&error),
                Ok(TakeOutcome::Pending) => return STATUS_PENDING,
                Ok(TakeOutcome::NeedsCapacity(needed)) => {
                    if needed > MAX_MANAGEMENT_LEN {
                        reactor.cancel_operation(operation);
                        return STATUS_INVALID;
                    }
                    return i32::try_from(needed).unwrap_or(STATUS_INVALID);
                }
                Ok(TakeOutcome::Ready(response)) => response,
            };
            if response.len() > MAX_MANAGEMENT_LEN {
                reactor.cancel_operation(operation);
                return STATUS_INVALID;
            }
            if !response.is_empty()
                && memory.write(&mut caller, result_pointer.cast_unsigned() as usize, &response).is_err()
            {
                return STATUS_MEMORY;
            }
            i32::try_from(response.len()).unwrap_or(STATUS_INVALID)
        }
    );
    Ok(())
}

/// The stream `read`/`write` imports.
fn register_stream_imports(linker: &mut Linker<HostState>) -> anyhow::Result<()> {
    host_import!(linker, "start_read", |caller: Caller<'_, HostState>, handle: i64, operation: i64, capacity: i32| {
        in_runtime(&caller.data().runtime, || {
            caller.data().reactor.start_read(
                operation.cast_unsigned(),
                handle.cast_unsigned(),
                capacity.cast_unsigned() as usize,
            )
        })
    });

    host_import!(linker, "take_read", |mut caller: Caller<'_, HostState>,
                                       operation: i64,
                                       destination: i32,
                                       capacity: i32| {
        let Some(memory) = guest_memory(&mut caller) else { return STATUS_MEMORY };
        let outcome = caller.data().reactor.take_read(operation.cast_unsigned(), capacity.cast_unsigned() as usize);
        let read = match outcome {
            Err(error) => return operation_status(&error),
            Ok(TakeOutcome::Pending) => return STATUS_PENDING,
            Ok(TakeOutcome::NeedsCapacity(needed)) => return i32::try_from(needed).unwrap_or(STATUS_MEMORY),
            Ok(TakeOutcome::Ready(read)) => read,
        };
        if !read.data.is_empty() && memory.write(&mut caller, destination.cast_unsigned() as usize, &read.data).is_err()
        {
            return STATUS_MEMORY;
        }
        i32::try_from(read.data.len()).unwrap_or(STATUS_MEMORY)
    });

    host_import!(linker, "start_write", |mut caller: Caller<'_, HostState>,
                                         handle: i64,
                                         operation: i64,
                                         source: i32,
                                         length: i32| {
        let Some(memory) = guest_memory(&mut caller) else { return STATUS_MEMORY };
        let Some(data) = read_guest(&memory, &caller, source.cast_unsigned(), length.cast_unsigned()) else {
            return STATUS_MEMORY;
        };
        in_runtime(&caller.data().runtime, || {
            caller.data().reactor.start_write(operation.cast_unsigned(), handle.cast_unsigned(), data)
        })
    });

    host_import!(linker, "take_write", |caller: Caller<'_, HostState>, operation: i64| {
        match take_ready(caller.data().reactor.take_write(operation.cast_unsigned()), operation_status) {
            Ok(_) => 0,
            Err(status) => status,
        }
    });
    Ok(())
}

/// The datagram imports: `udp_recv`, `try_udp_send` and `udp_send_ready`.
fn register_datagram_imports(linker: &mut Linker<HostState>) -> anyhow::Result<()> {
    // The guest's capacity is accepted and discarded: the reactor always reads into its own
    // 65535-byte datagram buffer.
    host_import!(linker, "start_udp_recv", |caller: Caller<'_, HostState>,
                                            handle: i64,
                                            operation: i64,
                                            _capacity: i32| {
        in_runtime(&caller.data().runtime, || {
            caller.data().reactor.start_udp_recv(operation.cast_unsigned(), handle.cast_unsigned())
        })
    });

    host_import!(linker, "take_udp_recv", |mut caller: Caller<'_, HostState>,
                                           operation: i64,
                                           destination: i32,
                                           capacity: i32,
                                           metadata_destination: i32,
                                           metadata_length: i32| {
        let Some(memory) = guest_memory(&mut caller) else { return STATUS_MEMORY };
        let (metadata_destination, metadata_length) =
            (metadata_destination.cast_unsigned(), metadata_length.cast_unsigned());
        if metadata_length as usize != wire::UDP_METADATA_LEN
            || !guest_range(&memory, &caller, destination.cast_unsigned(), capacity.cast_unsigned())
            || !guest_range(&memory, &caller, metadata_destination, metadata_length)
        {
            return STATUS_MEMORY;
        }
        let datagram = match take_ready(
            caller.data().reactor.take_udp_recv(operation.cast_unsigned(), capacity.cast_unsigned() as usize),
            operation_status,
        ) {
            Ok(datagram) => datagram,
            Err(status) => return status,
        };
        if !datagram.data.is_empty()
            && memory.write(&mut caller, destination.cast_unsigned() as usize, &datagram.data).is_err()
        {
            return STATUS_MEMORY;
        }
        let Ok(metadata) = udp_metadata(datagram.peer.as_ref()) else { return STATUS_INVALID };
        if memory.write(&mut caller, metadata_destination as usize, &metadata).is_err() {
            return STATUS_MEMORY;
        }
        i32::try_from(datagram.data.len()).unwrap_or(STATUS_MEMORY)
    });

    host_import!(linker, "try_udp_send", |mut caller: Caller<'_, HostState>,
                                          handle: i64,
                                          source: i32,
                                          length: i32,
                                          metadata_source: i32,
                                          metadata_length: i32| {
        let Some(memory) = guest_memory(&mut caller) else { return STATUS_MEMORY };
        let (length, metadata_length) = (length.cast_unsigned(), metadata_length.cast_unsigned());
        if metadata_length as usize != wire::UDP_METADATA_LEN || length > MAX_UDP_SEND_LEN {
            return STATUS_MEMORY;
        }
        let Some(encoded) = read_guest(&memory, &caller, metadata_source.cast_unsigned(), metadata_length) else {
            return STATUS_MEMORY;
        };
        // The secondary-IP slot is receive-only in this ABI version, and the wire's own decoder
        // already rejects a nonzero flowinfo or an interface index without an IPv6 address.
        let Ok(metadata) = wire::decode_udp_metadata(&encoded) else { return STATUS_INVALID };
        if metadata.secondary.is_some() {
            return STATUS_INVALID;
        }
        let Some(data) = read_guest(&memory, &caller, source.cast_unsigned(), length) else { return STATUS_MEMORY };
        let peer = udp_addr(metadata.peer);
        in_runtime(&caller.data().runtime, || {
            caller.data().reactor.try_udp_send(handle.cast_unsigned(), data, Box::new(peer))
        })
    });

    host_import!(linker, "start_udp_send_ready", |caller: Caller<'_, HostState>, handle: i64, operation: i64| {
        in_runtime(&caller.data().runtime, || {
            caller.data().reactor.start_udp_send_ready(operation.cast_unsigned(), handle.cast_unsigned())
        })
    });

    host_import!(linker, "take_udp_send_ready", |caller: Caller<'_, HostState>, operation: i64| {
        match take_ready(caller.data().reactor.take_udp_send_ready(operation.cast_unsigned()), operation_status) {
            Ok(()) => 0,
            Err(status) => status,
        }
    });
    Ok(())
}

/// `try_packet_write` and the `packet_write_ready` pair.
fn register_packet_imports(linker: &mut Linker<HostState>) -> anyhow::Result<()> {
    host_import!(linker, "try_packet_write", |mut caller: Caller<'_, HostState>,
                                              handle: i64,
                                              packet_pointer: i32,
                                              packet_length: i32| {
        let packet_length = packet_length.cast_unsigned();
        if packet_length == 0 || packet_length > MAX_HOST_PACKET_LEN {
            return STATUS_INVALID;
        }
        let Some(memory) = guest_memory(&mut caller) else { return STATUS_MEMORY };
        let Some(packet) = read_guest(&memory, &caller, packet_pointer.cast_unsigned(), packet_length) else {
            return STATUS_MEMORY;
        };
        in_runtime(&caller.data().runtime, || caller.data().reactor.try_packet_write(handle.cast_unsigned(), packet))
    });

    host_import!(linker, "start_packet_write_ready", |caller: Caller<'_, HostState>, handle: i64, operation: i64| {
        in_runtime(&caller.data().runtime, || {
            caller.data().reactor.start_packet_write_ready(operation.cast_unsigned(), handle.cast_unsigned())
        })
    });

    host_import!(linker, "take_packet_write_ready", |caller: Caller<'_, HostState>, operation: i64| {
        match take_ready(caller.data().reactor.take_packet_write_ready(operation.cast_unsigned()), operation_status) {
            Ok(()) => 0,
            Err(status) => status,
        }
    });
    Ok(())
}

/// `emit_event`.
fn register_event_imports(linker: &mut Linker<HostState>) -> anyhow::Result<()> {
    host_import!(linker, "emit_event", |mut caller: Caller<'_, HostState>,
                                        handle: i64,
                                        kind_pointer: i32,
                                        kind_length: i32,
                                        message_pointer: i32,
                                        message_length: i32| {
        let (kind_length, message_length) = (kind_length.cast_unsigned(), message_length.cast_unsigned());
        if !event_lengths_valid(kind_length, message_length) {
            return STATUS_INVALID;
        }
        let Some(memory) = guest_memory(&mut caller) else { return STATUS_MEMORY };
        let Some(kind) = read_guest(&memory, &caller, kind_pointer.cast_unsigned(), kind_length) else {
            return STATUS_MEMORY;
        };
        let Some(message) = read_guest(&memory, &caller, message_pointer.cast_unsigned(), message_length) else {
            return STATUS_MEMORY;
        };
        // the `string(bytes)` accepts any byte sequence; Rust's `String` does not, and the reactor
        // speaks `String`, so a non-UTF-8 event is rejected rather than silently transcoded.
        let (Ok(kind), Ok(message)) = (String::from_utf8(kind), String::from_utf8(message)) else {
            return STATUS_INVALID;
        };
        in_runtime(&caller.data().runtime, || caller.data().reactor.emit_event(handle.cast_unsigned(), kind, message))
    });
    Ok(())
}

/// The two AEAD imports, both delegating to [`aead_in_place`].
fn register_crypto_imports(linker: &mut Linker<HostState>) -> anyhow::Result<()> {
    host_import!(linker, "crypto_aead_seal", |mut caller: Caller<'_, HostState>,
                                              algorithm: i32,
                                              key_pointer: i32,
                                              key_length: i32,
                                              nonce_pointer: i32,
                                              nonce_length: i32,
                                              aad_pointer: i32,
                                              aad_length: i32,
                                              buffer_pointer: i32,
                                              text_length: i32| {
        let Some(memory) = guest_memory(&mut caller) else { return STATUS_CRYPTO_FALLBACK };
        aead_in_place(
            &memory,
            &mut caller,
            AeadDirection::Seal,
            algorithm,
            key_pointer,
            key_length,
            nonce_pointer,
            nonce_length,
            aad_pointer,
            aad_length,
            buffer_pointer,
            text_length,
        )
    });

    host_import!(linker, "crypto_aead_open", |mut caller: Caller<'_, HostState>,
                                              algorithm: i32,
                                              key_pointer: i32,
                                              key_length: i32,
                                              nonce_pointer: i32,
                                              nonce_length: i32,
                                              aad_pointer: i32,
                                              aad_length: i32,
                                              buffer_pointer: i32,
                                              text_length: i32| {
        let Some(memory) = guest_memory(&mut caller) else { return STATUS_CRYPTO_FALLBACK };
        aead_in_place(
            &memory,
            &mut caller,
            AeadDirection::Open,
            algorithm,
            key_pointer,
            key_length,
            nonce_pointer,
            nonce_length,
            aad_pointer,
            aad_length,
            buffer_pointer,
            text_length,
        )
    });
    Ok(())
}

/// `cancel_operation` and `close`.
fn register_misc_imports(linker: &mut Linker<HostState>) -> anyhow::Result<()> {
    host_import!(linker, "cancel_operation", |caller: Caller<'_, HostState>, operation: i64| {
        caller.data().reactor.cancel_operation(operation.cast_unsigned());
        0
    });

    host_import!(linker, "close", |caller: Caller<'_, HostState>, handle: i64| {
        in_runtime(&caller.data().runtime, || caller.data().reactor.close(handle.cast_unsigned()))
    });

    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DnsKind {
    Resolve,
    Txt,
    Srv,
}

fn start_dns(
    mut caller: Caller<'_, HostState>,
    operation: i64,
    query_pointer: i32,
    query_length: i32,
    kind: DnsKind,
) -> i32 {
    let query_length = query_length.cast_unsigned();
    if query_length == 0 || query_length > MAX_DNS_QUERY_LEN {
        return STATUS_INVALID;
    }
    let Some(memory) = guest_memory(&mut caller) else { return STATUS_MEMORY };
    let Some(encoded) = read_guest(&memory, &caller, query_pointer.cast_unsigned(), query_length) else {
        return STATUS_MEMORY;
    };
    let Ok(query) = wire::decode_dns_query(&encoded) else { return STATUS_INVALID };
    let operation = operation.cast_unsigned();
    in_runtime(&caller.data().runtime, || match kind {
        DnsKind::Resolve => caller.data().reactor.start_dns_resolve(operation, query),
        DnsKind::Txt => caller.data().reactor.start_dns_txt(operation, query),
        DnsKind::Srv => caller.data().reactor.start_dns_srv(operation, query),
    })
}

/// The size probe leaves the finished lookup in place, so the retry with the capacity reported by
/// [`TakeOutcome::NeedsCapacity`] still finds it. The result is consumed only once it fits, and the
/// length returned is always the encoded length.
fn take_dns(
    mut caller: Caller<'_, HostState>,
    operation: i64,
    result_pointer: i32,
    result_capacity: i32,
    kind: DnsKind,
) -> i32 {
    let Some(memory) = guest_memory(&mut caller) else { return STATUS_MEMORY };
    let operation = operation.cast_unsigned();
    let reactor = Arc::clone(&caller.data().reactor);
    let capacity = result_capacity.cast_unsigned() as usize;
    let encoded = match kind {
        DnsKind::Resolve => match dns_outcome(reactor.take_dns_resolve(operation, capacity)) {
            Ok(addresses) => wire::encode_dns_addresses(&addresses),
            Err(status) => return status,
        },
        DnsKind::Txt => match dns_outcome(reactor.take_dns_txt(operation, capacity)) {
            Ok(text) => wire::encode_dns_txt(&text),
            Err(status) => return status,
        },
        DnsKind::Srv => match dns_outcome(reactor.take_dns_srv(operation, capacity)) {
            Ok(records) => wire::encode_dns_srv(&records),
            Err(status) => return status,
        },
    };
    if encoded.len() > MAX_DNS_RESULT_LEN {
        reactor.cancel_operation(operation);
        return STATUS_INVALID;
    }
    if memory.write(&mut caller, result_pointer.cast_unsigned() as usize, &encoded).is_err() {
        return STATUS_MEMORY;
    }
    i32::try_from(encoded.len()).unwrap_or(STATUS_INVALID)
}

/// The DNS slice of `take_*`: a resize hint or a pending poll becomes the matching status, and a
/// ready value (already claimed from the reactor) is handed to the caller. A hint past
/// [`MAX_DNS_RESULT_LEN`] is refused instead of asking the guest to allocate for it.
fn dns_outcome<T>(outcome: Result<TakeOutcome<T>, ReactorError>) -> Result<T, i32> {
    match outcome {
        Ok(TakeOutcome::Ready(value)) => Ok(value),
        Ok(TakeOutcome::Pending) => Err(STATUS_PENDING),
        Ok(TakeOutcome::NeedsCapacity(needed)) if needed <= MAX_DNS_RESULT_LEN => {
            Err(i32::try_from(needed).unwrap_or(STATUS_INVALID))
        }
        Ok(TakeOutcome::NeedsCapacity(_)) => Err(STATUS_INVALID),
        Err(error) => Err(operation_status(&error)),
    }
}

#[cfg(test)]
mod tests {
    use wasmtime::{Engine, Extern, Instance, Module, Store};

    use super::*;

    fn io_error(kind: ErrorKind) -> ReactorError {
        ReactorError::Io(std::io::Error::new(kind, "synthetic"))
    }

    #[test]
    fn operation_status_maps_every_reactor_error() {
        assert_eq!(operation_status(&ReactorError::AlreadyClaimed(1)), STATUS_INVALID);
        assert_eq!(operation_status(&ReactorError::UnknownOperation(1)), STATUS_INVALID);
        assert_eq!(
            operation_status(&ReactorError::WrongOperationKind(1, crate::reactor::OperationKind::Read)),
            STATUS_INVALID
        );
        assert_eq!(operation_status(&ReactorError::UnknownHandle(1)), STATUS_INVALID);
        assert_eq!(operation_status(&ReactorError::ManagementHandlerNotConfigured), STATUS_INVALID);
        assert_eq!(operation_status(&ReactorError::Cancelled(1)), STATUS_PENDING);
        assert_eq!(operation_status(&ReactorError::WouldBlock), STATUS_WOULD_BLOCK);
        assert_eq!(operation_status(&io_error(ErrorKind::BrokenPipe)), STATUS_IO_ERROR);
        assert_eq!(operation_status(&ReactorError::Other(anyhow::anyhow!("boom"))), STATUS_IO_ERROR);
    }

    #[test]
    fn connect_status_splits_the_four_connect_errnos() {
        assert_eq!(connect_status(&io_error(ErrorKind::ConnectionRefused)), STATUS_CONNECTION_REFUSED);
        assert_eq!(connect_status(&io_error(ErrorKind::ConnectionAborted)), STATUS_CONNECTION_ABORTED);
        assert_eq!(connect_status(&io_error(ErrorKind::ConnectionReset)), STATUS_CONNECTION_RESET);
        assert_eq!(connect_status(&io_error(ErrorKind::NotConnected)), STATUS_NOT_CONNECTED);
    }

    #[test]
    fn connect_status_keeps_the_shared_cases_and_falls_back() {
        assert_eq!(connect_status(&ReactorError::Cancelled(1)), STATUS_PENDING);
        assert_eq!(connect_status(&ReactorError::AlreadyClaimed(1)), STATUS_INVALID);
        // The connect status has no would-block case, so a full send queue is a plain I/O error.
        assert_eq!(connect_status(&ReactorError::WouldBlock), STATUS_IO_ERROR);
        assert_eq!(connect_status(&io_error(ErrorKind::TimedOut)), STATUS_IO_ERROR);
    }

    #[test]
    fn take_ready_collapses_pending_and_never_yields_a_resize_hint_for_simple_families() {
        let pending: Result<TakeOutcome<u8>, ReactorError> = Ok(TakeOutcome::Pending);
        assert_eq!(take_ready(pending, operation_status).err(), Some(STATUS_PENDING));

        let resized: Result<TakeOutcome<u8>, ReactorError> = Ok(TakeOutcome::NeedsCapacity(70));
        assert_eq!(take_ready(resized, operation_status).err(), Some(STATUS_IO_ERROR));

        let ready: Result<TakeOutcome<u8>, ReactorError> = Ok(TakeOutcome::Ready(7));
        assert_eq!(take_ready(ready, operation_status).ok(), Some(7));

        let failed: Result<TakeOutcome<u8>, ReactorError> = Err(io_error(ErrorKind::ConnectionRefused));
        assert_eq!(take_ready(failed, connect_status).err(), Some(STATUS_CONNECTION_REFUSED));
    }

    #[test]
    fn event_length_bounds_are_inclusive_and_capped() {
        assert!(event_lengths_valid(1, 1));
        assert!(event_lengths_valid(MAX_EVENT_KIND_LEN, MAX_EVENT_MESSAGE_LEN));
        assert!(!event_lengths_valid(0, 1));
        assert!(!event_lengths_valid(MAX_EVENT_KIND_LEN + 1, 1));
        assert!(!event_lengths_valid(1, 0));
        assert!(!event_lengths_valid(1, MAX_EVENT_MESSAGE_LEN + 1));
    }

    #[test]
    fn factory_options_ceiling_is_enforced_before_the_copy() {
        let (mut store, memory) = guest_memory(&Engine::default());
        assert!(read_options(&memory, &mut store, 0, MAX_FACTORY_OPTIONS_LEN).is_some());
        assert!(read_options(&memory, &mut store, 0, MAX_FACTORY_OPTIONS_LEN + 1).is_none());
    }

    #[test]
    fn valid_result_memory_rejects_wrong_length_and_bad_pointer() {
        let (store, memory) = guest_memory(&Engine::default());
        let size = memory.data_size(&store);
        assert!(valid_result_memory(&memory, &store, 0, 62, wire::TCP_SOCKET_RESULT_LEN));
        // A short result buffer is a malformed take, which the caller turns into a cancel.
        assert!(!valid_result_memory(&memory, &store, 0, 61, wire::TCP_SOCKET_RESULT_LEN));
        assert!(!valid_result_memory(&memory, &store, 0, 63, wire::TCP_SOCKET_RESULT_LEN));
        // In range as a length, out of range as a pointer.
        let too_far = u32::try_from(size).unwrap_or(u32::MAX);
        assert!(!valid_result_memory(&memory, &store, too_far, 62, wire::TCP_SOCKET_RESULT_LEN));
        assert!(!valid_result_memory(&memory, &store, size as u32 - 61, 62, wire::TCP_SOCKET_RESULT_LEN));
        assert!(valid_result_memory(&memory, &store, size as u32 - 62, 62, wire::TCP_SOCKET_RESULT_LEN));
    }

    /// A hand-assembled module with a single 4-page memory exported as `"memory"`: enough to
    /// exercise the guest-memory paths without the 6.8 MB artifact module.
    const MEMORY_MODULE: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // header
        0x05, 0x03, 0x01, 0x00, 0x04, // memory section: one memory, min 4 pages
        0x07, 0x0a, 0x01, 0x06, b'm', b'e', b'm', b'o', b'r', b'y', 0x02, 0x00, // export "memory"
    ];

    fn guest_memory(engine: &Engine) -> (Store<()>, Memory) {
        let module = Module::new(engine, MEMORY_MODULE).expect("memory-only module must validate");
        let mut store = Store::new(engine, ());
        let instance = Instance::new(&mut store, &module, &[]).expect("module has no imports");
        let memory =
            instance.get_export(&mut store, "memory").and_then(Extern::into_memory).expect("module exports its memory");
        (store, memory)
    }

    fn seal(store: &mut Store<()>, memory: &Memory, algorithm: i32, key: &[u8], nonce: &[u8], text_length: i32) -> i32 {
        aead_in_place(
            memory,
            store,
            AeadDirection::Seal,
            algorithm,
            0x10,
            i32::try_from(key.len()).unwrap_or(i32::MAX),
            0x40,
            i32::try_from(nonce.len()).unwrap_or(i32::MAX),
            0x80,
            0,
            0x100,
            text_length,
        )
    }

    fn open(store: &mut Store<()>, memory: &Memory, algorithm: i32, key: &[u8], nonce: &[u8], text_length: i32) -> i32 {
        aead_in_place(
            memory,
            store,
            AeadDirection::Open,
            algorithm,
            0x10,
            i32::try_from(key.len()).unwrap_or(i32::MAX),
            0x40,
            i32::try_from(nonce.len()).unwrap_or(i32::MAX),
            0x80,
            0,
            0x100,
            text_length,
        )
    }

    #[test]
    fn aead_seal_then_open_round_trips_in_guest_memory() {
        let (mut store, memory) = guest_memory(&Engine::default());
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        memory.write(&mut store, 0x10, &key).expect("key fits");
        memory.write(&mut store, 0x40, &nonce).expect("nonce fits");
        let plaintext = b"easytier host abi";
        memory.write(&mut store, 0x100, plaintext).expect("plaintext fits");

        assert_eq!(seal(&mut store, &memory, 2, &key, &nonce, plaintext.len() as i32), 0);
        let sealed = memory.data(&store)[0x100..0x100 + plaintext.len() + 16].to_vec();
        assert_ne!(&sealed[..plaintext.len()], plaintext, "seal must overwrite the plaintext in place");

        assert_eq!(open(&mut store, &memory, 2, &key, &nonce, plaintext.len() as i32), 0);
        assert_eq!(&memory.data(&store)[0x100..0x100 + plaintext.len()], plaintext);
    }

    #[test]
    fn aead_open_reports_a_tampered_tag_as_auth_failed() {
        let (mut store, memory) = guest_memory(&Engine::default());
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        memory.write(&mut store, 0x10, &key).expect("key fits");
        memory.write(&mut store, 0x40, &nonce).expect("nonce fits");
        memory.write(&mut store, 0x100, &[0u8; 16]).expect("plaintext fits");

        assert_eq!(seal(&mut store, &memory, 1, &key, &nonce, 16), 0);
        memory.data_mut(&mut store)[0x100] ^= 0xFF;
        assert_eq!(open(&mut store, &memory, 1, &key, &nonce, 16), STATUS_CRYPTO_AUTH_FAILED);
    }

    #[test]
    fn aead_falls_back_on_bad_algorithm_key_length_nonce_and_bad_pointers() {
        let (mut store, memory) = guest_memory(&Engine::default());
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        memory.write(&mut store, 0x10, &key).expect("key fits");
        memory.write(&mut store, 0x40, &nonce).expect("nonce fits");
        memory.write(&mut store, 0x100, &[0u8; 32]).expect("buffer fits");
        let size = i32::try_from(memory.data_size(&store)).expect("a 4-page memory fits in an i32");

        // AES-256 requested with a 16-byte key.
        assert_eq!(seal(&mut store, &memory, 2, &key, &nonce, 16), STATUS_CRYPTO_FALLBACK);
        // Unknown algorithm.
        assert_eq!(seal(&mut store, &memory, 7, &key, &nonce, 16), STATUS_CRYPTO_FALLBACK);
        // Nonce that is not GCM's 12 bytes.
        assert_eq!(seal(&mut store, &memory, 1, &key, &[0u8; 11], 16), STATUS_CRYPTO_FALLBACK);
        // Key pointer past the end of memory.
        assert_eq!(
            aead_in_place(&memory, &mut store, AeadDirection::Seal, 1, size, 16, 0x40, 12, 0x80, 0, 0x100, 16),
            STATUS_CRYPTO_FALLBACK
        );
        // Buffer that cannot hold `text_length + 16`.
        assert_eq!(
            aead_in_place(&memory, &mut store, AeadDirection::Seal, 1, 0x10, 16, 0x40, 12, 0x80, 0, size - 8, 16),
            STATUS_CRYPTO_FALLBACK
        );
        // A negative `text_length` reaches the guest as 0xFFFFFFFF, whose `+ 16` must not wrap.
        assert_eq!(
            aead_in_place(&memory, &mut store, AeadDirection::Seal, 1, 0x10, 16, 0x40, 12, 0x80, 0, 0x100, -1),
            STATUS_CRYPTO_FALLBACK
        );
    }
}
