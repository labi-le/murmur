// Test code is exempt from the production panic posture: the bans on `unwrap`,
// `expect`, `panic`, indexing and casts exist to keep a long-lived server process
// alive, and a failing test is supposed to abort. Style tiers are exempt for the
// same reason -- the scaffolding around an assertion is not product code.
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::string_slice,
        clippy::print_stdout,
        clippy::print_stderr,
        clippy::unreachable,
        clippy::todo,
        clippy::unimplemented,
        clippy::pedantic,
        clippy::nursery,
        reason = "test scaffolding is not product code, and a failing test should abort"
    )
)]

pub mod deadline;
pub mod packet;

pub mod addr;
pub mod bind;
pub mod bufconn;
pub mod bufconn_unsafe;
pub mod cached;
pub mod context;
pub mod earlyconn;
pub mod io;
pub mod listener;
pub mod packet_file;
pub mod refconn;
pub mod relay;
pub mod sing;
pub mod tcpip;
pub mod upstream;
pub mod websocket;

/// The re-exports keep the short module-name spelling used at the call sites.
pub use addr::new_custom_addr;
pub use bind::new_bind_packet_conn;
pub use bufconn::{
    is_bufio_error, new_buffered_conn, new_buffered_stream, warp_conn_with_bio_reader, BufferedConn, BufferedStream,
    BufioError, BufioReader, DEFAULT_BUF_SIZE,
};
pub use cached::{new_cached_conn, new_cached_conn_from_node, CachedConn};
pub use context::{relay_context, setup_context_for_conn, SetupContextDone};
pub use earlyconn::{new_early_conn, EarlyConnResponse, SharedError};
pub use io::{ReadOnlyReader, WriteOnlyWriter};
pub use listener::{new_handle_context_listener, HandleContextListener, HandleFn, PanicLogFn};
pub use packet::datagram::{
    enhance_datagram_as_old_enhance_packet_conn, new_enhance_datagram, new_enhance_named_datagram,
    old_enhance_packet_conn_as_enhance_datagram, wait_read_from_datagram, wait_read_from_named_datagram,
    EnhanceDatagram, EnhanceNamedDatagram, WaitReadFromDatagram, WaitReadFromNamedDatagram,
};
pub use packet_file::{
    new_deadline_enhance_packet_conn, new_deadline_enhance_sing_packet_conn, new_deadline_net_packet_conn,
    new_deadline_sing_packet_conn, new_enhance_packet_conn, new_ref_packet_conn, new_thread_safe_packet_conn,
    EnhancePacketConn, WaitReadFrom,
};
pub use refconn::{new_ref_conn, new_ref_extended_conn};
pub use sing::{
    calculate_front_headroom, calculate_mtu, calculate_rear_headroom, need_handshake, new_deadline_conn,
    new_extended_conn, new_extended_conn_from_node, new_extended_reader, new_extended_writer, new_read_wait_options,
    pipe, relay, relay_streams, unwrap_reader, unwrap_writer, write_buffer, CachedReader, CountFunc, EarlyConn,
    ExtendedConn, ExtendedReader, ExtendedWriter, ReaderWithUpstream, UpstreamNode, WithUpstream, WriterWithUpstream,
    DEFAULT_HEADROOM,
};
pub use tcpip::{split_host_port, split_network_type};
pub use upstream::find_upstream;
pub use websocket::{get_websocket_sec_accept, mask_websocket};
