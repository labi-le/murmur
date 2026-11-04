//! Congestion-control algorithms, a monotonic clock, and the `Conn`/`Stream`/`Config`/`Transport`/
//! `EarlyListener` surface that `transport/tuic`, `transport/hysteria` and
//! `transport/shadowquic` drive against (the JLS-forked variant of that surface is mirrored
//! under [`jls`]).
//!
//! The vendored congestion-control implementations are adapted through local interfaces, so the
//! QUIC side of those interfaces lives here.
//!
//! `hysteria` shares a QUIC connection handle across concurrent tasks (one task may cancel a
//! stream while another is mid-read on it), which pointer-receiver stream methods allow
//! directly; [`Conn::open_stream`]/[`Conn::accept_stream`] hand back an owned, `&mut`-accessed
//! [`Stream`] instead (`transport/tuic`'s and `transport/shadowquic`'s call shape), so
//! `transport/hysteria/core/client.rs` keeps its own `Arc`-shared, `&self`-polled stream trait
//! locally rather than reusing [`Stream`] here.
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
        clippy::nursery
    )
)]

pub mod monotime {
    use std::sync::LazyLock;
    use std::time::{Duration, Instant};

    use murmur_common::time::TimeDuration;

    static BASE: LazyLock<Instant> = LazyLock::new(Instant::now);

    #[must_use]
    pub fn base() -> Instant {
        *BASE
    }

    /// A monotonic instant; only differences between values are meaningful.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub struct Time(Instant);

    impl Time {
        #[must_use]
        pub fn sub(&self, other: &Self) -> Duration {
            self.0.saturating_duration_since(other.0)
        }

        #[must_use]
        pub fn add(&self, delta: Duration) -> Self {
            Self(self.0 + delta)
        }

        #[must_use]
        pub fn is_zero(&self) -> bool {
            self.0 == base()
        }

        #[must_use]
        #[expect(
            clippy::cast_possible_truncation,
            reason = "`TimeDuration` is a signed nanosecond count, so a monotonic duration above `i64::MAX` nanoseconds (292 years) has no representable value and truncates"
        )]
        pub fn as_nanos(&self) -> TimeDuration {
            self.0.saturating_duration_since(base()).as_nanos() as TimeDuration
        }

        #[must_use]
        pub fn as_secs(&self) -> i64 {
            self.as_nanos() / 1_000_000_000
        }
    }

    impl Default for Time {
        fn default() -> Self {
            Self(base())
        }
    }

    #[must_use]
    pub fn now() -> Time {
        Time(Instant::now())
    }

    #[must_use]
    pub fn since(t: Time) -> Duration {
        t.0.elapsed()
    }

    #[must_use]
    #[expect(
        clippy::cast_possible_truncation,
        reason = "`TimeDuration` is a signed nanosecond count, so a monotonic duration above `i64::MAX` nanoseconds (292 years) has no representable value and truncates"
    )]
    pub fn until(t: Time) -> TimeDuration {
        t.0.saturating_duration_since(Instant::now()).as_nanos() as TimeDuration
    }

    #[must_use]
    pub fn from_time(t: &chrono::DateTime<chrono::Utc>) -> Time {
        let elapsed =
            t.timestamp_nanos_opt().unwrap_or_default() - chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default();
        if elapsed >= 0 {
            Time(Instant::now() + Duration::from_nanos(elapsed.cast_unsigned()))
        } else {
            #[expect(
                clippy::unwrap_used,
                reason = "`checked_sub` only fails for a timestamp older than the monotonic clock's own epoch; a fallback instant would silently return a different time than the caller asked for"
            )]
            let past = Instant::now().checked_sub(Duration::from_nanos(elapsed.unsigned_abs())).unwrap();
            Time(past)
        }
    }
}

pub mod congestion {
    use std::sync::Arc;
    use std::time::Duration;

    use crate::monotime;

    pub type ByteCount = i64;
    pub type PacketNumber = i64;

    pub const INITIAL_PACKET_SIZE: ByteCount = 1280;
    pub const MAX_PACKET_BUFFER_SIZE: ByteCount = 1452;
    pub const MIN_INITIAL_PACKET_SIZE: ByteCount = 1200;
    pub const MAX_CONGESTION_WINDOW_PACKETS: ByteCount = 20000;
    pub const PACKETS_PER_CONNECTION_ID: ByteCount = 10000;
    pub const MIN_PACING_DELAY: Duration = Duration::from_millis(1);

    #[derive(Clone, Copy, Debug)]
    pub struct AckedPacketInfo {
        pub packet_number: PacketNumber,
        pub bytes_acked: ByteCount,
        pub received_time: monotime::Time,
    }

    #[derive(Clone, Copy, Debug)]
    pub struct LostPacketInfo {
        pub packet_number: PacketNumber,
        pub bytes_lost: ByteCount,
    }

    pub trait RttStatsProvider: Send + Sync {
        fn min_rtt(&self) -> Duration;
        fn latest_rtt(&self) -> Duration;
        fn smoothed_rtt(&self) -> Duration;
        fn mean_deviation(&self) -> Duration;
        fn max_ack_delay(&self) -> Duration;
        fn pto(&self, include_max_ack_delay: bool) -> Duration;
        fn update_rtt(&self, send_delta: Duration, ack_delay: Duration);
        fn set_max_ack_delay(&self, mad: Duration);
        fn set_initial_rtt(&self, t: Duration);
    }

    pub trait CongestionControl: Send + Sync {
        fn set_rtt_stats_provider(&mut self, provider: Arc<dyn RttStatsProvider>);
        fn time_until_send(&self, bytes_in_flight: ByteCount) -> monotime::Time;
        fn has_pacing_budget(&self, now: monotime::Time) -> bool;
        fn on_packet_sent(
            &mut self,
            sent_time: monotime::Time,
            bytes_in_flight: ByteCount,
            packet_number: PacketNumber,
            bytes: ByteCount,
            is_retransmittable: bool,
        );
        fn can_send(&self, bytes_in_flight: ByteCount) -> bool;
        fn maybe_exit_slow_start(&mut self);
        fn on_packet_acked(
            &mut self,
            number: PacketNumber,
            acked_bytes: ByteCount,
            prior_in_flight: ByteCount,
            event_time: monotime::Time,
        );
        fn on_congestion_event(&mut self, number: PacketNumber, lost_bytes: ByteCount, prior_in_flight: ByteCount);
        fn on_retransmission_timeout(&mut self, packets_retransmitted: bool);
        fn set_max_datagram_size(&mut self, size: ByteCount);
        fn in_slow_start(&self) -> bool;
        fn in_recovery(&self) -> bool;
        fn get_congestion_window(&self) -> ByteCount;
    }

    pub trait CongestionControlEx: CongestionControl {
        fn on_congestion_event_ex(
            &mut self,
            prior_in_flight: ByteCount,
            event_time: monotime::Time,
            acked_packets: &[AckedPacketInfo],
            lost_packets: &[LostPacketInfo],
        );
    }
}

use std::io;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::sync::CancellationToken;

use murmur_std_compat::net::{Addr, PacketConn, UdpAddr};

pub type ApplicationErrorCode = u64;
pub type StreamErrorCode = u64;
pub type StreamId = i64;
pub type Version = u32;

/// Version 1 (RFC 9000).
pub const VERSION1: Version = 0x0000_0001;
/// Version 2 (RFC 9369).
pub const VERSION2: Version = 0x6b33_43cf;

/// Returned from `Conn::send_datagram` when a DATAGRAM frame would exceed the maximum size.
#[derive(thiserror::Error, Debug, Clone, Copy)]
#[error("DATAGRAM frame too large (maximum: {max_datagram_payload_size} bytes)")]
pub struct DatagramTooLargeError {
    pub max_datagram_payload_size: congestion::ByteCount,
}

/// A `ShadowQUIC` JLS credential.
#[derive(Clone, Debug, Default)]
pub struct JlsUser {
    pub username: String,
    pub password: String,
}

/// Enables `ShadowQUIC` JLS authentication and camouflage. Carried on [`Config::jls`].
#[derive(Clone, Debug, Default)]
pub struct JlsConfig {
    pub enable: bool,
    pub user: JlsUser,
    pub users: Vec<JlsUser>,
    pub server_name: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum JlsStatus {
    #[default]
    Disabled,
    Unauthenticated,
    Authenticated,
}

#[derive(Clone, Debug, Default)]
pub struct JlsState {
    pub status: JlsStatus,
    pub user: String,
}

/// The QUIC configuration.
///
/// The JLS fork's own `Config` is this same struct plus one extra field, so [`Config::jls`]
/// carries that extension inline instead of a second `Config` type; callers that do not use JLS
/// leave it `None`.
#[expect(
    clippy::struct_excessive_bools,
    reason = "each flag is a distinct QUIC transport knob from the public configuration surface, so none can be folded into a state enum"
)]
#[derive(Clone, Debug, Default)]
pub struct Config {
    pub versions: Vec<Version>,
    pub jls: Option<JlsConfig>,
    pub handshake_idle_timeout: Duration,
    pub max_idle_timeout: Duration,
    pub initial_stream_receive_window: u64,
    pub max_stream_receive_window: u64,
    pub initial_connection_receive_window: u64,
    pub max_connection_receive_window: u64,
    pub max_incoming_streams: i64,
    pub max_incoming_uni_streams: i64,
    pub keep_alive_period: Duration,
    pub initial_packet_size: u16,
    pub disable_path_mtu_discovery: bool,
    pub allow_0rtt: bool,
    pub enable_datagrams: bool,
    pub max_datagram_frame_size: i64,
    /// quinn never migrates a connection to another path, so the intent already holds; no quinn
    /// knob expresses it (see `murmur_transport_tuic::quic`).
    pub disable_path_manager: bool,
}

/// The TLS configuration carried by the quic transport; the mirror owns the concrete type.
pub trait TlsConfig: Send + Sync {}

/// The JLS field of the TLS connection state.
#[derive(Clone, Debug, Default)]
pub struct TlsConnectionState {
    pub jls: JlsState,
}

#[derive(Clone, Debug, Default)]
pub struct ConnectionState {
    pub tls: TlsConnectionState,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ConnectionStats {
    pub packets_lost: u64,
    pub packets_sent: u64,
    pub smoothed_rtt: Duration,
    pub latest_rtt: Duration,
    pub current_mtu: u16,
}

pub trait SendStream: AsyncWrite + Send + Sync + Unpin {
    fn stream_id(&self) -> StreamId;
    fn cancel_write(&self, error_code: StreamErrorCode);
    fn close(&self) -> io::Result<()>;
    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()>;
}

pub trait ReceiveStream: AsyncRead + Send + Sync + Unpin {
    fn stream_id(&self) -> StreamId;
    fn cancel_read(&self, error_code: StreamErrorCode);
    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()>;
}

/// A stream handle.
///
/// `split` gives the read/write halves a concrete implementation would back with a real bilock,
/// matching the rule that a stream tolerates one concurrent reader and one concurrent writer,
/// never two of either.
pub trait Stream: AsyncRead + AsyncWrite + Send + Sync + Unpin {
    fn stream_id(&self) -> StreamId;
    fn cancel_read(&self, error_code: StreamErrorCode);
    fn cancel_write(&self, error_code: StreamErrorCode);
    /// Closes only the send direction.
    fn close(&self) -> io::Result<()>;
    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()>;
    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()>;
    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()>;
    fn split(self: Box<Self>) -> (Box<dyn StreamReadHalf>, Box<dyn StreamWriteHalf>);
    fn as_any(&self) -> &dyn std::any::Any;
}

/// The read half returned by [`Stream::split`].
pub trait StreamReadHalf: AsyncRead + Send + Sync + Unpin {
    fn cancel_read(&self, error_code: StreamErrorCode);
}

/// The write half returned by [`Stream::split`].
pub trait StreamWriteHalf: AsyncWrite + Send + Sync + Unpin {
    fn close(&self) -> io::Result<()>;
    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()>;
}

/// The `Arc`-shared, `&self`-polled flavor of the [`Stream`]/`Conn` surface
/// `transport/hysteria/core/client.rs` drives.
///
/// Hysteria shares one QUIC connection handle across concurrent tasks (one task may cancel a
/// stream while another is mid-read on it), which pointer-receiver stream/connection methods
/// allow directly; `Stream::poll_read`/`Stream::poll_write` take `&self` instead of
/// [`Stream`]'s `&mut self` `AsyncRead`/`AsyncWrite` bound so an `Arc`-shared handle stays usable
/// from more than one task, and [`Conn::open_stream_sync`]/`open_stream` drop the [`Conn`]
/// context parameter.
pub mod hysteria {
    use std::io;
    use std::sync::Arc;
    use std::task::{Context, Poll};

    use async_trait::async_trait;
    use tokio::io::ReadBuf;
    use tokio_util::sync::CancellationToken;

    use murmur_std_compat::net::Addr;

    pub trait Stream: Send + Sync {
        fn stream_id(&self) -> super::StreamId;
        fn poll_read(&self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>>;
        fn poll_write(&self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>>;
        fn cancel_read(&self, code: super::StreamErrorCode);
        fn cancel_write(&self, code: super::StreamErrorCode);
        fn close(&self) -> io::Result<()>;
        fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()>;
        fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()>;
        fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()>;
        fn context(&self) -> CancellationToken;
    }

    #[async_trait]
    pub trait Conn: Send + Sync {
        fn local_addr(&self) -> Box<dyn Addr>;
        fn remote_addr(&self) -> Box<dyn Addr>;
        async fn open_stream_sync(&self) -> anyhow::Result<Arc<dyn Stream>>;
        fn open_stream(&self) -> anyhow::Result<Arc<dyn Stream>>;
        /// The setter type-asserts the sender to the extended congestion-control interface so its
        /// ack/loss sampling hook runs, so the seam asks for that interface directly:
        /// `BrutalSender` is the only sender hysteria installs and it implements it.
        fn set_congestion_control(&self, cc: Box<dyn super::congestion::CongestionControlEx>);
        fn close_with_error(&self, code: super::ApplicationErrorCode, reason: &str) -> anyhow::Result<()>;
        async fn receive_datagram(&self) -> anyhow::Result<Vec<u8>>;
        fn send_datagram(&self, data: &[u8]) -> anyhow::Result<()>;
        fn as_any(&self) -> &dyn std::any::Any;
    }
}

/// The connection handle, as driven by `transport/tuic`.
#[async_trait]
pub trait Conn: Send + Sync {
    fn local_addr(&self) -> Box<dyn Addr>;
    fn remote_addr(&self) -> Box<dyn Addr>;
    fn close_with_error(&self, code: ApplicationErrorCode, reason: &str) -> anyhow::Result<()>;
    fn config(&self) -> Config;
    fn set_congestion_control(&self, cc: Box<dyn congestion::CongestionControl>);
    fn connection_stats(&self) -> ConnectionStats;
    fn connection_state(&self) -> ConnectionState;
    /// The connection's cancellation token, only ever used as a done signal.
    fn context(&self) -> CancellationToken;
    /// Resolves once the handshake completes; the signal may never fire.
    async fn handshake_complete(&self);
    fn open_stream(&self) -> anyhow::Result<Box<dyn Stream>>;
    async fn open_stream_sync(&self, ctx: &CancellationToken) -> anyhow::Result<Box<dyn Stream>>;
    fn open_uni_stream(&self) -> anyhow::Result<Box<dyn SendStream>>;
    async fn open_uni_stream_sync(&self, ctx: &CancellationToken) -> anyhow::Result<Box<dyn SendStream>>;
    async fn accept_stream(&self, ctx: &CancellationToken) -> anyhow::Result<Box<dyn Stream>>;
    async fn accept_uni_stream(&self, ctx: &CancellationToken) -> anyhow::Result<Box<dyn ReceiveStream>>;
    fn send_datagram(&self, data: &[u8]) -> anyhow::Result<()>;
    async fn receive_datagram(&self, ctx: &CancellationToken) -> anyhow::Result<Vec<u8>>;
}

/// The transport, with its dial and dial-early entry points.
#[async_trait]
pub trait Transport: Send + Sync {
    fn set_created_conn(&self, created_conn: bool);
    fn set_single_use(&self, single_use: bool);

    async fn dial(
        &self,
        ctx: &CancellationToken,
        addr: &UdpAddr,
        tls_conf: &dyn TlsConfig,
        conf: &Config,
    ) -> anyhow::Result<Arc<dyn Conn>>;

    async fn dial_early(
        &self,
        ctx: &CancellationToken,
        addr: &UdpAddr,
        tls_conf: &dyn TlsConfig,
        conf: &Config,
    ) -> anyhow::Result<Arc<dyn Conn>>;
}

/// Builds a transport over the packet conn the dialer created.
pub trait TransportFactory: Send + Sync {
    fn new_transport(&self, conn: Arc<dyn PacketConn>, connection_id_length: i32) -> Box<dyn Transport>;
}

/// The JLS-forked surface `transport/shadowquic` drives.
///
/// It goes beyond what it shares with the non-forked surface above (`Config`, `TlsConfig`,
/// `ConnectionState`, the `Stream` family, `ApplicationErrorCode`, …).
///
/// The fork ships its own `congestion`/`monotime` types rather than reusing the shared ones, so
/// those two, plus the `Conn`/`Transport`/`EarlyListener` surface that closes over the forked
/// congestion type, live here instead of at the top level.
pub mod jls {
    use std::io;
    use std::sync::Arc;

    use async_trait::async_trait;
    use tokio_util::sync::CancellationToken;

    use murmur_std_compat::net::{Addr, PacketConn, UdpAddr};

    /// The fork's congestion-control package.
    pub mod congestion {
        use std::sync::Arc;
        use std::time::Duration;

        use super::monotime;

        pub type ByteCount = i64;
        pub type PacketNumber = i64;

        #[derive(Clone, Copy, Debug)]
        pub struct AckedPacketInfo {
            pub packet_number: PacketNumber,
            pub bytes_acked: ByteCount,
            pub received_time: monotime::Time,
        }

        #[derive(Clone, Copy, Debug)]
        pub struct LostPacketInfo {
            pub packet_number: PacketNumber,
            pub bytes_lost: ByteCount,
        }

        pub trait RttStatsProvider: Send + Sync {
            fn min_rtt(&self) -> Duration;
            fn latest_rtt(&self) -> Duration;
            fn smoothed_rtt(&self) -> Duration;
            fn mean_deviation(&self) -> Duration;
            fn max_ack_delay(&self) -> Duration;
            fn pto(&self, include_max_ack_delay: bool) -> Duration;
            fn update_rtt(&self, send_delta: Duration, ack_delay: Duration);
            fn set_max_ack_delay(&self, mad: Duration);
            fn set_initial_rtt(&self, t: Duration);
        }

        pub trait CongestionControl: Send + Sync {
            fn set_rtt_stats_provider(&mut self, provider: Arc<dyn RttStatsProvider>);
            fn time_until_send(&self, bytes_in_flight: ByteCount) -> monotime::Time;
            fn has_pacing_budget(&self, now: monotime::Time) -> bool;
            fn on_packet_sent(
                &mut self,
                sent_time: monotime::Time,
                bytes_in_flight: ByteCount,
                packet_number: PacketNumber,
                bytes: ByteCount,
                is_retransmittable: bool,
            );
            fn can_send(&self, bytes_in_flight: ByteCount) -> bool;
            fn maybe_exit_slow_start(&mut self);
            fn on_packet_acked(
                &mut self,
                number: PacketNumber,
                acked_bytes: ByteCount,
                prior_in_flight: ByteCount,
                event_time: monotime::Time,
            );
            fn on_congestion_event(&mut self, number: PacketNumber, lost_bytes: ByteCount, prior_in_flight: ByteCount);
            fn on_retransmission_timeout(&mut self, packets_retransmitted: bool);
            fn set_max_datagram_size(&mut self, size: ByteCount);
            fn in_slow_start(&self) -> bool;
            fn in_recovery(&self) -> bool;
            fn get_congestion_window(&self) -> ByteCount;
        }

        pub trait CongestionControlEx: CongestionControl {
            fn on_congestion_event_ex(
                &mut self,
                prior_in_flight: ByteCount,
                event_time: monotime::Time,
                acked_packets: &[AckedPacketInfo],
                lost_packets: &[LostPacketInfo],
            );
        }
    }

    /// The fork's monotonic clock.
    ///
    /// Its `Time` has the same representation as the shared one, so this newtype wraps
    /// [`crate::monotime::Time`] directly instead of duplicating it.
    pub mod monotime {
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
        pub struct Time(pub crate::monotime::Time);
    }

    /// The connection handle, as driven by `transport/shadowquic`.
    #[async_trait]
    pub trait Conn: Send + Sync {
        /// The connection's cancellation token, only ever used as a done signal.
        fn closed(&self) -> CancellationToken;

        async fn open_stream_sync(&self, ctx: &CancellationToken) -> anyhow::Result<Box<dyn super::Stream>>;
        async fn open_uni_stream_sync(&self, ctx: &CancellationToken) -> anyhow::Result<Box<dyn super::SendStream>>;
        async fn accept_stream(&self, ctx: &CancellationToken) -> anyhow::Result<Box<dyn super::Stream>>;
        async fn accept_uni_stream(&self, ctx: &CancellationToken) -> anyhow::Result<Box<dyn super::ReceiveStream>>;

        fn local_addr(&self) -> Box<dyn Addr>;
        fn remote_addr(&self) -> Box<dyn Addr>;

        fn close_with_error(&self, code: super::ApplicationErrorCode, message: &str) -> io::Result<()>;

        fn config(&self) -> super::Config;
        fn set_congestion_control(&self, cc: Box<dyn congestion::CongestionControlEx>);
        fn connection_stats(&self) -> super::ConnectionStats;
        fn connection_state(&self) -> super::ConnectionState;

        async fn receive_datagram(&self, ctx: &CancellationToken) -> anyhow::Result<Vec<u8>>;
        fn send_datagram(&self, data: Vec<u8>) -> anyhow::Result<()>;
    }

    #[async_trait]
    pub trait EarlyListener: Send + Sync {
        async fn accept(&self, ctx: &CancellationToken) -> anyhow::Result<Arc<dyn Conn>>;
        fn close(&self) -> io::Result<()>;
    }

    /// The listen-early constructor, injected by the caller because no concrete implementation
    /// exists yet.
    ///
    /// It is synchronous: it only binds the listener, and the handshake itself happens per
    /// accepted connection.
    pub type ListenEarlyFn = Arc<
        dyn Fn(
                Box<dyn PacketConn>,
                Arc<dyn super::TlsConfig>,
                Arc<super::Config>,
            ) -> anyhow::Result<Arc<dyn EarlyListener>>
            + Send
            + Sync,
    >;

    /// The transport, with its dial and dial-early entry points.
    #[async_trait]
    pub trait Transport: Send + Sync {
        fn set_created_conn(&self, created_conn: bool);
        fn set_single_use(&self, single_use: bool);

        async fn dial(
            &self,
            ctx: &CancellationToken,
            addr: &UdpAddr,
            tls_conf: &dyn super::TlsConfig,
            conf: &super::Config,
        ) -> anyhow::Result<Arc<dyn Conn>>;

        async fn dial_early(
            &self,
            ctx: &CancellationToken,
            addr: &UdpAddr,
            tls_conf: &dyn super::TlsConfig,
            conf: &super::Config,
        ) -> anyhow::Result<Arc<dyn Conn>>;
    }

    /// Builds a transport over the packet conn the dialer created.
    pub trait TransportFactory: Send + Sync {
        fn new_transport(&self, conn: Arc<dyn PacketConn>, connection_id_length: i32) -> Box<dyn Transport>;
    }
}
