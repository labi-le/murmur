//! A swap-in congestion controller over `quinn`'s `ControllerFactory` hook.
//!
//! `quinn` creates every connection with CUBIC and, once the server's `ServerHello` carries
//! `recv_bps`, `core/client.rs` swaps in a Brutal sender on the live connection. `quinn` picks a
//! controller once, when the connection is created, and offers no way to swap it, so the
//! controller built here keeps CUBIC until the negotiated sender arrives and adopts it from then
//! on — the same visible transition, driven from the other end.
//!
//! What carries over is the congestion window: `BrutalSender::get_congestion_window` is
//! `bps * max(latest, smoothed) * 1.5 / ack_rate`, and `quinn` gates transmission on exactly the
//! value this controller returns from `window()`. The ack-rate feedback loop runs off the acked and
//! lost events, which `quinn` does report.
//!
//! Two boundaries are worth stating plainly. `quinn` derives its own token-bucket pacing from that
//! window and the smoothed RTT rather than exposing a pacing rate, so `BrutalSender`'s own pacer
//! (`time_until_send`/`has_pacing_budget`, no `quinn` hook) is inert here — the effective rate is
//! `window / rtt` instead. And `quinn`'s `Controller` callbacks carry no packet numbers and report
//! losses in bytes rather than in packets, so the sampling entries handed to
//! `on_congestion_event_ex` carry a zero packet number and count one loss per loss event. The
//! `BrutalSender` reads only the entry counts.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use quinn::congestion::{Controller, ControllerFactory, ControllerMetrics, Cubic, CubicConfig};
use quinn_proto::RttEstimator;

use murmur_quic::congestion::{
    AckedPacketInfo, ByteCount, CongestionControlEx, LostPacketInfo, PacketNumber, RttStatsProvider,
};
use murmur_quic::monotime;

/// Anchors the `std::time::Instant`s `quinn` hands out onto the monotonic clock, which exposes
/// only differences, so the sender's token bucket sees one consistent timeline.
static LOCAL_BASE: LazyLock<Instant> = LazyLock::new(Instant::now);

fn monotime_of(instant: Instant) -> monotime::Time {
    let mirror_offset = LOCAL_BASE.saturating_duration_since(monotime::base());
    monotime::Time::default().add(mirror_offset).add(instant.saturating_duration_since(*LOCAL_BASE))
}

/// The RTT statistics `quinn` publishes.
///
/// `quinn` owns RTT estimation and keeps the variance private to its recovery loop, so this is a
/// read-only projection: the values `RttEstimator` publishes are recorded verbatim, and the fields
/// derived from that private variance use the seed `RttEstimator::new` itself uses (half the
/// initial RTT). The mutators stay inert so a second estimator can never disagree with the one
/// `quinn` is actually pacing against.
struct RttStats {
    min: AtomicU64,
    smoothed: AtomicU64,
    /// `RttEstimator::conservative()`, i.e. `max(smoothed, latest)` — the value
    /// `BrutalSender::get_congestion_window` takes its maximum over.
    conservative: AtomicU64,
}

impl RttStats {
    fn new() -> Self {
        Self { min: AtomicU64::new(0), smoothed: AtomicU64::new(0), conservative: AtomicU64::new(0) }
    }

    fn record(&self, rtt: &RttEstimator) {
        self.min.store(duration_nanos(rtt.min()), Ordering::Relaxed);
        self.smoothed.store(duration_nanos(rtt.get()), Ordering::Relaxed);
        self.conservative.store(duration_nanos(rtt.conservative()), Ordering::Relaxed);
    }

    fn smoothed_duration(&self) -> Duration {
        nanos_duration(self.smoothed.load(Ordering::Relaxed))
    }
}

impl RttStatsProvider for RttStats {
    fn min_rtt(&self) -> Duration {
        nanos_duration(self.min.load(Ordering::Relaxed))
    }

    fn latest_rtt(&self) -> Duration {
        nanos_duration(self.conservative.load(Ordering::Relaxed))
    }

    fn smoothed_rtt(&self) -> Duration {
        self.smoothed_duration()
    }

    fn mean_deviation(&self) -> Duration {
        self.smoothed_duration() / 2
    }

    fn max_ack_delay(&self) -> Duration {
        // quinn's own `pto_base` carries no ack-delay term, so the delay it would bound is zero.
        Duration::ZERO
    }

    fn pto(&self, _include_max_ack_delay: bool) -> Duration {
        self.smoothed_duration() + 4 * self.mean_deviation()
    }

    fn update_rtt(&self, _send_delta: Duration, _ack_delay: Duration) {}

    fn set_max_ack_delay(&self, _mad: Duration) {}

    fn set_initial_rtt(&self, _t: Duration) {}
}

fn duration_nanos(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

fn nanos_duration(nanos: u64) -> Duration {
    Duration::from_nanos(nanos)
}

/// The transport's congestion slot, shared between the connection and the controller `quinn` builds
/// for it.
pub(super) struct HysteriaCongestion {
    pending: Mutex<Option<Box<dyn CongestionControlEx>>>,
    rtt: Arc<RttStats>,
}

impl HysteriaCongestion {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self { pending: Mutex::new(None), rtt: Arc::new(RttStats::new()) })
    }

    pub(super) fn install(&self, sender: Box<dyn CongestionControlEx>) {
        *self.pending.lock() = Some(sender);
    }
}

impl ControllerFactory for HysteriaCongestion {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(HysteriaController {
            owner: Arc::clone(&self),
            cubic: Cubic::new(Arc::new(CubicConfig::default()), now, current_mtu),
            sender: Mutex::new(None),
            mtu: current_mtu,
            acked: Vec::new(),
            lost: Vec::new(),
            bytes_in_flight: 0,
        })
    }
}

struct HysteriaController {
    owner: Arc<HysteriaCongestion>,
    /// CUBIC, in place until a Brutal sender is installed.
    cubic: Cubic,
    /// Empty until the control stream negotiates the rate.
    sender: Mutex<Option<Box<dyn CongestionControlEx>>>,
    mtu: u16,
    acked: Vec<AckedPacketInfo>,
    lost: Vec<LostPacketInfo>,
    bytes_in_flight: u64,
}

impl HysteriaController {
    fn adopt(&self) {
        let Some(mut sender) = self.owner.pending.lock().take() else { return };
        let rtt: Arc<dyn RttStatsProvider> = Arc::<RttStats>::clone(&self.owner.rtt);
        sender.set_rtt_stats_provider(rtt);
        sender.set_max_datagram_size(ByteCount::from(self.mtu));
        *self.sender.lock() = Some(sender);
    }

    fn sample(&self, now: Instant) {
        if self.acked.is_empty() && self.lost.is_empty() {
            return;
        }
        let bytes_in_flight = ByteCount::try_from(self.bytes_in_flight).unwrap_or_default();
        let event_time = monotime_of(now);
        let mut guard = self.sender.lock();
        if let Some(sender) = guard.as_mut() {
            sender.on_congestion_event_ex(bytes_in_flight, event_time, &self.acked, &self.lost);
        }
        drop(guard);
    }
}

impl Controller for HysteriaController {
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_add(bytes);
        self.adopt();
        let mut guard = self.sender.lock();
        if let Some(sender) = guard.as_mut() {
            sender.on_packet_sent(
                monotime_of(now),
                ByteCount::try_from(self.bytes_in_flight).unwrap_or_default(),
                PacketNumber::try_from(last_packet_number).unwrap_or_default(),
                ByteCount::try_from(bytes).unwrap_or_default(),
                true,
            );
            return;
        }
        drop(guard);
        self.cubic.on_sent(now, bytes, last_packet_number);
    }

    fn on_ack(&mut self, now: Instant, sent: Instant, bytes: u64, _app_limited: bool, rtt: &RttEstimator) {
        self.owner.rtt.record(rtt);
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes);
        self.acked.push(AckedPacketInfo {
            packet_number: 0,
            bytes_acked: ByteCount::try_from(bytes).unwrap_or_default(),
            received_time: monotime_of(sent),
        });
        self.adopt();
        let mut guard = self.sender.lock();
        if let Some(sender) = guard.as_mut() {
            sender.on_packet_acked(
                0,
                ByteCount::try_from(bytes).unwrap_or_default(),
                ByteCount::try_from(self.bytes_in_flight).unwrap_or_default(),
                monotime_of(now),
            );
            return;
        }
        drop(guard);
        self.cubic.on_ack(now, sent, bytes, false, rtt);
    }

    fn on_end_acks(&mut self, now: Instant, _in_flight: u64, app_limited: bool, largest_packet_num_acked: Option<u64>) {
        self.sample(now);
        self.acked.clear();
        self.lost.clear();
        self.cubic.on_end_acks(now, self.bytes_in_flight, app_limited, largest_packet_num_acked);
    }

    fn on_congestion_event(&mut self, now: Instant, sent: Instant, is_persistent_congestion: bool, lost_bytes: u64) {
        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(lost_bytes);
        if lost_bytes > 0 {
            self.lost.push(LostPacketInfo {
                packet_number: 0,
                bytes_lost: ByteCount::try_from(lost_bytes).unwrap_or_default(),
            });
        }
        let _ = sent;
        self.adopt();
        let mut guard = self.sender.lock();
        if let Some(sender) = guard.as_mut() {
            sender.on_congestion_event(
                0,
                ByteCount::try_from(lost_bytes).unwrap_or_default(),
                ByteCount::try_from(self.bytes_in_flight).unwrap_or_default(),
            );
            sender.on_retransmission_timeout(is_persistent_congestion);
            drop(guard);
            self.sample(now);
            return;
        }
        drop(guard);
        self.cubic.on_congestion_event(now, sent, is_persistent_congestion, lost_bytes);
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mtu = new_mtu;
        self.cubic.on_mtu_update(new_mtu);
        if let Some(sender) = self.sender.lock().as_mut() {
            sender.set_max_datagram_size(ByteCount::from(new_mtu));
        }
    }

    fn window(&self) -> u64 {
        let guard = self.sender.lock();
        match guard.as_ref() {
            Some(sender) => u64::try_from(sender.get_congestion_window()).unwrap_or_default(),
            None => self.cubic.window(),
        }
    }

    fn metrics(&self) -> ControllerMetrics {
        let mut metrics = ControllerMetrics::default();
        metrics.congestion_window = self.window();
        metrics
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        let mut guard = self.sender.lock();
        Box::new(Self {
            owner: Arc::clone(&self.owner),
            cubic: self.cubic.clone(),
            sender: Mutex::new(guard.take()),
            mtu: self.mtu,
            acked: Vec::new(),
            lost: Vec::new(),
            bytes_in_flight: 0,
        })
    }

    fn initial_window(&self) -> u64 {
        self.window()
    }

    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}
