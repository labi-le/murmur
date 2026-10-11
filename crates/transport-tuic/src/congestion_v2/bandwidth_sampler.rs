use std::time::Duration;

use murmur_quic::congestion::{AckedPacketInfo, ByteCount, LostPacketInfo, PacketNumber};
use murmur_quic::monotime;

use super::bandwidth::{bandwidth_from_delta, Bandwidth, INF_BANDWIDTH};
use super::bbr_sender::INVALID_PACKET_NUMBER;
use super::minmax::{max, min};
use super::packet_number_indexed_queue::{new_packet_number_indexed_queue, PacketNumberIndexedQueue};
use super::ringbuffer::RingBuffer;
use super::windowed_filter::{new_windowed_filter, WindowedFilter};

pub(crate) const INF_RTT: Duration = Duration::from_nanos(i64::MAX as u64);
const DEFAULT_CONNECTION_STATE_MAP_QUEUE_SIZE: usize = 256;
const DEFAULT_CANDIDATES_BUFFER_SIZE: usize = 256;

pub(crate) type RoundTripCount = u64;

/// `SendTimeState` is a subset of `ConnectionStateOnSentPacket` which is returned
/// to the caller when the packet is acked or lost.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct SendTimeState {
    /// Whether other states in this object is valid.
    pub(crate) is_valid: bool,
    /// Whether the sender is app limited at the time the packet was sent.
    /// App limited bandwidth sample might be artificially low because the sender
    /// did not have enough data to send in order to saturate the link.
    pub(crate) is_app_limited: bool,
    /// Total number of sent bytes at the time the packet was sent.
    /// Includes the packet itself.
    pub(crate) total_bytes_sent: ByteCount,
    /// Total number of acked bytes at the time the packet was sent.
    pub(crate) total_bytes_acked: ByteCount,

    /// Total number of inflight bytes at the time the packet was sent.
    /// Includes the packet itself.
    /// It should be equal to |`total_bytes_sent`| minus the sum of
    /// |`total_bytes_acked`| and total neutered bytes.
    pub(crate) bytes_in_flight: ByteCount,
}

pub(crate) const fn new_send_time_state(
    is_app_limited: bool,
    total_bytes_sent: ByteCount,
    total_bytes_acked: ByteCount,
    bytes_in_flight: ByteCount,
) -> SendTimeState {
    SendTimeState { is_valid: true, is_app_limited, total_bytes_sent, total_bytes_acked, bytes_in_flight }
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ExtraAckedEvent {
    /// The excess bytes acknowlwedged in the time delta for this event.
    pub(crate) extra_acked: ByteCount,

    /// The bytes acknowledged and time delta from the event.
    pub(crate) bytes_acked: ByteCount,
    pub(crate) time_delta: Duration,
    /// The round trip of the event.
    pub(crate) round: RoundTripCount,
}

pub(crate) const fn max_extra_acked_event_func(a: ExtraAckedEvent, b: ExtraAckedEvent) -> i32 {
    if a.extra_acked > b.extra_acked {
        1
    } else if a.extra_acked < b.extra_acked {
        -1
    } else {
        0
    }
}

/// `BandwidthSample`
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct BandwidthSample {
    /// The bandwidth at that particular sample. Zero if no valid bandwidth sample
    /// is available.
    pub(crate) bandwidth: Bandwidth,
    /// The RTT measurement at this particular sample.  Zero if no RTT sample is
    /// available.  Does not correct for delayed ack time.
    pub(crate) rtt: Duration,
    /// |`send_rate`| is computed from the current packet being acked('P') and an
    /// earlier packet that is acked before P was sent.
    pub(crate) send_rate: Bandwidth,
    /// States captured when the packet was sent.
    pub(crate) state_at_send: SendTimeState,
}

pub(crate) fn new_bandwidth_sample() -> BandwidthSample {
    BandwidthSample { send_rate: INF_BANDWIDTH, ..BandwidthSample::default() }
}

/// `MaxAckHeightTracker` is part of the `BandwidthSampler`. It is called after every
/// ack event to keep track the degree of ack aggregation(a.k.a "ack height").
#[derive(Debug)]
pub(crate) struct MaxAckHeightTracker {
    /// Tracks the maximum number of bytes acked faster than the estimated
    /// bandwidth.
    max_ack_height_filter: WindowedFilter<ExtraAckedEvent, RoundTripCount>,
    /// The time this aggregation started and the number of bytes acked during it.
    aggregation_epoch_start_time: Option<monotime::Time>,
    aggregation_epoch_bytes: ByteCount,
    /// The last sent packet number before the current aggregation epoch started.
    last_sent_packet_number_before_epoch: PacketNumber,

    ack_aggregation_bandwidth_threshold: f64,
    start_new_aggregation_epoch_after_full_round: bool,
    reduce_extra_acked_on_bandwidth_increase: bool,
}

pub(crate) fn new_max_ack_height_tracker(window_length: RoundTripCount) -> MaxAckHeightTracker {
    MaxAckHeightTracker {
        max_ack_height_filter: new_windowed_filter(window_length, max_extra_acked_event_func),
        aggregation_epoch_start_time: None,
        aggregation_epoch_bytes: 0,
        last_sent_packet_number_before_epoch: INVALID_PACKET_NUMBER,
        ack_aggregation_bandwidth_threshold: 1.0,
        start_new_aggregation_epoch_after_full_round: false,
        reduce_extra_acked_on_bandwidth_increase: false,
    }
}

// Exposed for the packet-number-indexed queue module.
impl MaxAckHeightTracker {
    pub(crate) fn get(&self) -> ByteCount {
        self.max_ack_height_filter.get_best().extra_acked
    }

    pub(crate) fn update(
        &mut self,
        bandwidth_estimate: Bandwidth,
        is_new_max_bandwidth: bool,
        round_trip_count: RoundTripCount,
        last_sent_packet_number: PacketNumber,
        last_acked_packet_number: PacketNumber,
        ack_time: Option<monotime::Time>,
        bytes_acked: ByteCount,
    ) -> ByteCount {
        let mut force_new_epoch = false;

        if self.reduce_extra_acked_on_bandwidth_increase && is_new_max_bandwidth {
            // Save and clear existing entries.
            let mut best = self.max_ack_height_filter.get_best();
            let mut second_best = self.max_ack_height_filter.get_second_best();
            let mut third_best = self.max_ack_height_filter.get_third_best();
            self.max_ack_height_filter.clear();

            // Reinsert the heights into the filter after recalculating.
            let mut expected_bytes_acked = bytes_from_bandwidth_and_time_delta(bandwidth_estimate, best.time_delta);
            if expected_bytes_acked < best.bytes_acked {
                best.extra_acked = best.bytes_acked - expected_bytes_acked;
                self.max_ack_height_filter.update(best, best.round);
            }
            expected_bytes_acked = bytes_from_bandwidth_and_time_delta(bandwidth_estimate, second_best.time_delta);
            if expected_bytes_acked < second_best.bytes_acked {
                second_best.extra_acked = second_best.bytes_acked - expected_bytes_acked;
                self.max_ack_height_filter.update(second_best, second_best.round);
            }
            expected_bytes_acked = bytes_from_bandwidth_and_time_delta(bandwidth_estimate, third_best.time_delta);
            if expected_bytes_acked < third_best.bytes_acked {
                third_best.extra_acked = third_best.bytes_acked - expected_bytes_acked;
                self.max_ack_height_filter.update(third_best, third_best.round);
            }
        }

        // If any packet sent after the start of the epoch has been acked, start a new
        // epoch.
        if self.start_new_aggregation_epoch_after_full_round
            && self.last_sent_packet_number_before_epoch != INVALID_PACKET_NUMBER
            && last_acked_packet_number != INVALID_PACKET_NUMBER
            && last_acked_packet_number > self.last_sent_packet_number_before_epoch
        {
            force_new_epoch = true;
        }
        if self.aggregation_epoch_start_time.is_none() || force_new_epoch {
            self.aggregation_epoch_bytes = bytes_acked;
            self.aggregation_epoch_start_time = ack_time;
            self.last_sent_packet_number_before_epoch = last_sent_packet_number;
            return 0;
        }

        // Compute how many bytes are expected to be delivered, assuming max bandwidth
        // is correct.
        let Some(aggregation_epoch_start_time) = self.aggregation_epoch_start_time else {
            // A missing epoch start is taken above; the zero time is no more
            // usable as a time base than that.
            return 0;
        };
        let aggregation_delta =
            ack_time.map(|ack_time| ack_time.sub(&aggregation_epoch_start_time)).unwrap_or_default();
        let expected_bytes_acked = bytes_from_bandwidth_and_time_delta(bandwidth_estimate, aggregation_delta);
        // Reset the current aggregation epoch as soon as the ack arrival rate is less
        // than or equal to the max bandwidth.
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_precision_loss,
            reason = "the max-bandwidth comparison scales a byte count by a fractional threshold in `f64` and truncates the product back to a byte count, which is how the aggregation epoch is measured"
        )]
        if self.aggregation_epoch_bytes
            <= (self.ack_aggregation_bandwidth_threshold * expected_bytes_acked as f64) as ByteCount
        {
            // Reset to start measuring a new aggregation epoch.
            self.aggregation_epoch_bytes = bytes_acked;
            self.aggregation_epoch_start_time = ack_time;
            self.last_sent_packet_number_before_epoch = last_sent_packet_number;
            return 0;
        }

        self.aggregation_epoch_bytes += bytes_acked;

        // Compute how many extra bytes were delivered vs max bandwidth.
        let extra_bytes_acked = self.aggregation_epoch_bytes - expected_bytes_acked;
        let new_event = ExtraAckedEvent {
            extra_acked: extra_bytes_acked,
            bytes_acked: self.aggregation_epoch_bytes,
            time_delta: aggregation_delta,
            round: 0,
        };
        self.max_ack_height_filter.update(new_event, round_trip_count);
        extra_bytes_acked
    }

    pub(crate) fn reset(&mut self, new_height: ByteCount, new_time: RoundTripCount) {
        let new_event = ExtraAckedEvent { extra_acked: new_height, round: new_time, ..ExtraAckedEvent::default() };
        self.max_ack_height_filter.reset(new_event, new_time);
    }

    pub(crate) const fn set_ack_aggregation_bandwidth_threshold(&mut self, threshold: f64) {
        self.ack_aggregation_bandwidth_threshold = threshold;
    }

    pub(crate) const fn set_reduce_extra_acked_on_bandwidth_increase(&mut self, value: bool) {
        self.reduce_extra_acked_on_bandwidth_increase = value;
    }
}

/// `AckPoint` represents a point on the ack line.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct AckPoint {
    pub(crate) ack_time: Option<monotime::Time>,
    pub(crate) total_bytes_acked: ByteCount,
}

/// `RecentAckPoints` maintains the most recent 2 ack points at distinct times.
#[derive(Debug, Default)]
pub(crate) struct RecentAckPoints {
    ack_points: [AckPoint; 2],
}

impl RecentAckPoints {
    pub(crate) fn update(&mut self, ack_time: monotime::Time, total_bytes_acked: ByteCount) {
        match self.ack_points[1].ack_time {
            Some(previous) if ack_time < previous => {
                self.ack_points[1].ack_time = Some(ack_time);
            }
            Some(previous) if ack_time > previous => {
                self.ack_points[0] = self.ack_points[1];
                self.ack_points[1].ack_time = Some(ack_time);
            }
            // the zero time precedes every real sample, so a fresh ack point
            // takes the place of the unset one.
            None => {
                self.ack_points[0] = self.ack_points[1];
                self.ack_points[1].ack_time = Some(ack_time);
            }
            _ => {}
        }

        self.ack_points[1].total_bytes_acked = total_bytes_acked;
    }

    pub(crate) fn clear(&mut self) {
        self.ack_points[0] = AckPoint::default();
        self.ack_points[1] = AckPoint::default();
    }

    pub(crate) const fn most_recent_point(&self) -> &AckPoint {
        &self.ack_points[1]
    }

    pub(crate) const fn less_recent_point(&self) -> &AckPoint {
        if self.ack_points[0].total_bytes_acked != 0 {
            return &self.ack_points[0];
        }

        &self.ack_points[1]
    }
}

/// `ConnectionStateOnSentPacket` represents the information about a sent packet
/// and the state of the connection at the moment the packet was sent,
/// specifically the information about the most recently acknowledged packet at
/// that moment.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ConnectionStateOnSentPacket {
    /// Time at which the packet is sent.
    pub(crate) sent_time: monotime::Time,
    /// Size of the packet.
    pub(crate) size: ByteCount,
    /// The value of |totalBytesSentAtLastAckedPacket| at the time the
    /// packet was sent.
    pub(crate) total_bytes_sent_at_last_acked_packet: ByteCount,
    /// The value of |lastAckedPacketSentTime| at the time the packet was
    /// sent.
    pub(crate) last_acked_packet_sent_time: Option<monotime::Time>,
    /// The value of |lastAckedPacketAckTime| at the time the packet was
    /// sent.
    pub(crate) last_acked_packet_ack_time: Option<monotime::Time>,
    /// Send time states that are returned to the congestion controller when the
    /// packet is acked or lost.
    pub(crate) send_time_state: SendTimeState,
}

/// The queue uses these entries to fill the gaps between packet numbers; no
/// reader inspects one, and monotime has no zero instant for the zero time.
impl Default for ConnectionStateOnSentPacket {
    fn default() -> Self {
        Self {
            sent_time: monotime::now(),
            size: 0,
            total_bytes_sent_at_last_acked_packet: 0,
            last_acked_packet_sent_time: None,
            last_acked_packet_ack_time: None,
            send_time_state: SendTimeState::default(),
        }
    }
}

/// Snapshot constructor. Records the current state of the bandwidth
/// sampler.
/// |`bytes_in_flight`| is the bytes in flight right after the packet is sent.
pub(crate) fn new_connection_state_on_sent_packet(
    sent_time: monotime::Time,
    size: ByteCount,
    bytes_in_flight: ByteCount,
    sampler: &BandwidthSampler,
) -> ConnectionStateOnSentPacket {
    ConnectionStateOnSentPacket {
        sent_time,
        size,
        total_bytes_sent_at_last_acked_packet: sampler.total_bytes_sent_at_last_acked_packet,
        last_acked_packet_sent_time: sampler.last_acked_packet_sent_time,
        last_acked_packet_ack_time: sampler.last_acked_packet_ack_time,
        send_time_state: new_send_time_state(
            sampler.is_app_limited,
            sampler.total_bytes_sent,
            sampler.total_bytes_acked,
            bytes_in_flight,
        ),
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct CongestionEventSample {
    /// The maximum bandwidth sample from all acked packets.
    /// zero if no samples are available.
    pub(crate) sample_max_bandwidth: Bandwidth,
    /// Whether `sample_max_bandwidth` is from an app-limited sample.
    pub(crate) sample_is_app_limited: bool,
    /// The minimum rtt sample from all acked packets.
    /// an infinite delta if no samples are available.
    pub(crate) sample_rtt: Duration,
    /// For each packet p in acked packets, this is the max value of INFLIGHT(p),
    /// where INFLIGHT(p) is the number of bytes acked while p is inflight.
    pub(crate) sample_max_inflight: ByteCount,
    /// The send state of the largest packet in `acked_packets`, unless it is
    /// empty. If `acked_packets` is empty, it's the send state of the largest
    /// packet in `lost_packets`.
    pub(crate) last_packet_send_state: SendTimeState,
    /// The number of extra bytes acked from this ack event, compared to what is
    /// expected from the flow's bandwidth. Larger value means more ack
    /// aggregation.
    pub(crate) extra_acked: ByteCount,
}

pub(crate) fn new_congestion_event_sample() -> CongestionEventSample {
    CongestionEventSample { sample_rtt: INF_RTT, ..CongestionEventSample::default() }
}

/// `BandwidthSampler` keeps track of sent and acknowledged packets and outputs a
/// bandwidth sample for every packet acknowledged. The samples are taken for
/// individual packets, and are not filtered; the consumer has to filter the
/// bandwidth samples itself. In certain cases, the sampler will locally severely
/// underestimate the bandwidth, hence a maximum filter with a size of at least
/// one RTT is recommended.
///
/// This class bases its samples on the slope of two curves: the number of bytes
/// sent over time, and the number of bytes acknowledged as received over time.
/// It produces a sample of both slopes for every packet that gets acknowledged,
/// based on a slope between two points on each of the corresponding curves. Note
/// that due to the packet loss, the number of bytes on each curve might get
/// further and further away from each other, meaning that it is not feasible to
/// compare byte values coming from different curves with each other.
///
/// The obvious points for measuring slope sample are the ones corresponding to
/// the packet that was just acknowledged. Let us denote them as `S_1` (point at
/// which the current packet was sent) and `A_1` (point at which the current packet
/// was acknowledged). However, taking a slope requires two points on each line,
/// so estimating bandwidth requires picking a packet in the past with respect to
/// which the slope is measured.
///
/// For that purpose, `BandwidthSampler` always keeps track of the most recently
/// acknowledged packet, and records it together with every outgoing packet.
/// When a packet gets acknowledged (`A_1`), it has not only information about when
/// it itself was sent (`S_1`), but also the information about the latest
/// acknowledged packet right before it was sent (`S_0` and `A_0`).
///
/// Based on that data, send and ack rate are estimated as:
///
///    `send_rate` = (`bytes(S_1)` - `bytes(S_0)`) / (`time(S_1)` - `time(S_0)`)
///    `ack_rate` = (`bytes(A_1)` - `bytes(A_0)`) / (`time(A_1)` - `time(A_0)`)
///
/// Here, the ack rate is intuitively the rate we want to treat as bandwidth.
/// However, in certain cases (e.g. ack compression) the ack rate at a point may
/// end up higher than the rate at which the data was originally sent, which is
/// not indicative of the real bandwidth. Hence, we use the send rate as an upper
/// bound, and the sample value is
///
///    `rate_sample` = `min(send_rate`, `ack_rate`)
///
/// An important edge case handled by the sampler is tracking the app-limited
/// samples. There are multiple meaning of "app-limited" used interchangeably,
/// hence it is important to understand and to be able to distinguish between
/// them.
///
/// Meaning 1: connection state. The connection is said to be app-limited when
/// there is no outstanding data to send. This means that certain bandwidth
/// samples in the future would not be an accurate indication of the link
/// capacity, and it is important to inform consumer about that. Whenever
/// connection becomes app-limited, the sampler is notified through its
/// app-limited hook.
///
/// Meaning 2: a phase in the bandwidth sampler. As soon as the bandwidth
/// sampler becomes notified about the connection being app-limited, it enters
/// app-limited phase. In that phase, all *sent* packets are marked as
/// app-limited. Note that the connection itself does not have to be
/// app-limited during the app-limited phase, and in fact it will not be
/// (otherwise how would it send packets?). The boolean flag below indicates
/// whether the sampler is in that phase.
///
/// Meaning 3: a flag on the sent packet and on the sample. If a sent packet is
/// sent during the app-limited phase, the resulting sample related to the
/// packet will be marked as app-limited.
///
/// With the terminology issue out of the way, let us consider the question of
/// what kind of situation it addresses.
///
/// Consider a scenario where we first send packets 1 to 20 at a regular
/// bandwidth, and then immediately run out of data. After a few seconds, we send
/// packets 21 to 60, and only receive ack for 21 between sending packets 40 and
/// 41. In this case, when we sample bandwidth for packets 21 to 40, the `S_0/A_0`
/// we use to compute the slope is going to be packet 20, a few seconds apart
/// from the current packet, hence the resulting estimate would be extremely low
/// and not indicative of anything. Only at packet 41 the `S_0/A_0` will become 21,
/// meaning that the bandwidth sample would exclude the quiescence.
///
/// Based on the analysis of that scenario, we implement the following rule: once
/// the app-limited hook is called, all sent packets will produce app-limited samples
/// up until an ack for a packet that was sent after that hook was called.
/// Note that while the scenario above is not the only scenario when the
/// connection is app-limited, the approach works in other cases too.
#[derive(Debug)]
pub(crate) struct BandwidthSampler {
    /// The total number of congestion controlled bytes sent during the connection.
    total_bytes_sent: ByteCount,

    /// The total number of congestion controlled bytes which were acknowledged.
    total_bytes_acked: ByteCount,

    /// The total number of congestion controlled bytes which were lost.
    total_bytes_lost: ByteCount,

    /// The value of `total_bytes_sent` at the time the last acknowledged packet
    /// was sent. Valid only when `last_acked_packet_sent_time` is valid.
    total_bytes_sent_at_last_acked_packet: ByteCount,

    /// The time at which the last acknowledged packet was sent. Set to
    /// zero if no valid timestamp is available.
    last_acked_packet_sent_time: Option<monotime::Time>,

    /// The time at which the most recent packet was acknowledged.
    last_acked_packet_ack_time: Option<monotime::Time>,

    /// The most recently sent packet.
    last_sent_packet: PacketNumber,

    /// The most recently acked packet.
    last_acked_packet: PacketNumber,

    /// Indicates whether the bandwidth sampler is currently in an app-limited
    /// phase.
    is_app_limited: bool,

    /// The packet that will be acknowledged after this one will cause the sampler
    /// to exit the app-limited phase.
    end_of_app_limited_phase: PacketNumber,

    /// Record of the connection state at the point where each packet in flight was
    /// sent, indexed by the packet number.
    connection_state_map: PacketNumberIndexedQueue<ConnectionStateOnSentPacket>,

    recent_ack_points: RecentAckPoints,
    a0_candidates: RingBuffer<AckPoint>,

    max_ack_height_tracker: MaxAckHeightTracker,
    total_bytes_acked_after_last_ack_event: ByteCount,

    /// True if connection option 'BSAO' is set.
    overestimate_avoidance: bool,

    /// True if connection option 'BBRB' is set.
    limit_max_ack_height_tracker_by_send_rate: bool,
}

pub(crate) fn new_bandwidth_sampler(max_ack_height_tracker_window_length: RoundTripCount) -> BandwidthSampler {
    let mut b = BandwidthSampler {
        total_bytes_sent: 0,
        total_bytes_acked: 0,
        total_bytes_lost: 0,
        total_bytes_sent_at_last_acked_packet: 0,
        last_acked_packet_sent_time: None,
        last_acked_packet_ack_time: None,
        last_sent_packet: INVALID_PACKET_NUMBER,
        last_acked_packet: INVALID_PACKET_NUMBER,
        is_app_limited: false,
        end_of_app_limited_phase: INVALID_PACKET_NUMBER,
        connection_state_map: new_packet_number_indexed_queue(DEFAULT_CONNECTION_STATE_MAP_QUEUE_SIZE),
        recent_ack_points: RecentAckPoints::default(),
        a0_candidates: RingBuffer::default(),
        max_ack_height_tracker: new_max_ack_height_tracker(max_ack_height_tracker_window_length),
        total_bytes_acked_after_last_ack_event: 0,
        overestimate_avoidance: false,
        limit_max_ack_height_tracker_by_send_rate: false,
    };

    b.a0_candidates.init(DEFAULT_CANDIDATES_BUFFER_SIZE);

    b
}

impl BandwidthSampler {
    pub(crate) fn max_ack_height(&self) -> ByteCount {
        self.max_ack_height_tracker.get()
    }

    pub(crate) fn reset_max_ack_height_tracker(&mut self, new_height: ByteCount, new_time: RoundTripCount) {
        self.max_ack_height_tracker.reset(new_height, new_time);
    }

    pub(crate) fn set_reduce_extra_acked_on_bandwidth_increase(&mut self, value: bool) {
        self.max_ack_height_tracker.set_reduce_extra_acked_on_bandwidth_increase(value);
    }

    pub(crate) fn enable_overestimate_avoidance(&mut self) {
        if self.overestimate_avoidance {
            return;
        }

        self.overestimate_avoidance = true;
        self.max_ack_height_tracker.set_ack_aggregation_bandwidth_threshold(2.0);
    }

    pub(crate) fn on_packet_sent(
        &mut self,
        sent_time: monotime::Time,
        packet_number: PacketNumber,
        bytes: ByteCount,
        bytes_in_flight: ByteCount,
        is_retransmittable: bool,
    ) {
        self.last_sent_packet = packet_number;

        if !is_retransmittable {
            return;
        }

        self.total_bytes_sent += bytes;

        // If there are no packets in flight, the time at which the new transmission
        // opens can be treated as the A_0 point for the purpose of bandwidth
        // sampling. This underestimates bandwidth to some extent, and produces some
        // artificially low samples for most packets in flight, but it provides with
        // samples at important points where we would not have them otherwise, most
        // importantly at the beginning of the connection.
        if bytes_in_flight == 0 {
            self.last_acked_packet_ack_time = Some(sent_time);
            if self.overestimate_avoidance {
                self.recent_ack_points.clear();
                self.recent_ack_points.update(sent_time, self.total_bytes_acked);
                self.a0_candidates.clear();
                let most_recent_point = *self.recent_ack_points.most_recent_point();
                self.a0_candidates.push_back(most_recent_point);
            }
            self.total_bytes_sent_at_last_acked_packet = self.total_bytes_sent;

            // In this situation ack compression is not a concern, set send rate to
            // effectively infinite.
            self.last_acked_packet_sent_time = Some(sent_time);
        }

        let state = new_connection_state_on_sent_packet(sent_time, bytes, bytes_in_flight + bytes, self);
        self.connection_state_map.emplace(packet_number, &state);
    }

    pub(crate) fn on_congestion_event(
        &mut self,
        ack_time: monotime::Time,
        acked_packets: &[AckedPacketInfo],
        lost_packets: &[LostPacketInfo],
        max_bandwidth: Bandwidth,
        est_bandwidth_upper_bound: Bandwidth,
        round_trip_count: RoundTripCount,
    ) -> CongestionEventSample {
        let mut event_sample = new_congestion_event_sample();

        let mut last_lost_packet_send_state = SendTimeState::default();

        for p in lost_packets {
            let send_state = self.on_packet_lost(p.packet_number, p.bytes_lost);
            if send_state.is_valid {
                last_lost_packet_send_state = send_state;
            }
        }

        if acked_packets.is_empty() {
            // Only populate send state for a loss-only event.
            event_sample.last_packet_send_state = last_lost_packet_send_state;
            return event_sample;
        }

        let mut last_acked_packet_send_state = SendTimeState::default();
        let mut max_send_rate: Bandwidth = 0;

        for p in acked_packets {
            let sample = self.on_packet_acknowledged(ack_time, p.packet_number);
            if !sample.state_at_send.is_valid {
                continue;
            }

            last_acked_packet_send_state = sample.state_at_send;

            if !sample.rtt.is_zero() {
                event_sample.sample_rtt = min(event_sample.sample_rtt, sample.rtt);
            }
            if sample.bandwidth > event_sample.sample_max_bandwidth {
                event_sample.sample_max_bandwidth = sample.bandwidth;
                event_sample.sample_is_app_limited = sample.state_at_send.is_app_limited;
            }
            if sample.send_rate != INF_BANDWIDTH {
                max_send_rate = max(max_send_rate, sample.send_rate);
            }
            let inflight_sample = self.total_bytes_acked - last_acked_packet_send_state.total_bytes_acked;
            if inflight_sample > event_sample.sample_max_inflight {
                event_sample.sample_max_inflight = inflight_sample;
            }
        }

        if !last_lost_packet_send_state.is_valid {
            event_sample.last_packet_send_state = last_acked_packet_send_state;
        } else if !last_acked_packet_send_state.is_valid {
            event_sample.last_packet_send_state = last_lost_packet_send_state;
        } else {
            // If two packets are inflight and an alarm is armed to lose a packet and it
            // wakes up late, then the first of two in flight packets could have been
            // acknowledged before the wakeup, which re-evaluates loss detection, and
            // could declare the later of the two lost.
            let lost_after_acked = match (lost_packets.last(), acked_packets.last()) {
                (Some(lost), Some(acked)) => lost.packet_number > acked.packet_number,
                (Some(_) | None, None) | (None, Some(_)) => false,
            };
            if lost_after_acked {
                event_sample.last_packet_send_state = last_lost_packet_send_state;
            } else {
                event_sample.last_packet_send_state = last_acked_packet_send_state;
            }
        }

        let is_new_max_bandwidth = event_sample.sample_max_bandwidth > max_bandwidth;
        let mut max_bandwidth = max(max_bandwidth, event_sample.sample_max_bandwidth);
        if self.limit_max_ack_height_tracker_by_send_rate {
            max_bandwidth = max(max_bandwidth, max_send_rate);
        }

        event_sample.extra_acked = self.on_ack_event_end(
            min(est_bandwidth_upper_bound, max_bandwidth),
            is_new_max_bandwidth,
            round_trip_count,
        );

        event_sample
    }

    pub(crate) fn on_packet_lost(&mut self, packet_number: PacketNumber, bytes_lost: ByteCount) -> SendTimeState {
        let mut s = SendTimeState::default();
        self.total_bytes_lost += bytes_lost;
        if let Some(sent_packet_pointer) = self.connection_state_map.get_entry(packet_number) {
            sent_packet_to_send_time_state(sent_packet_pointer, &mut s);
        }
        s
    }

    pub(crate) const fn on_app_limited(&mut self) {
        self.is_app_limited = true;
        self.end_of_app_limited_phase = self.last_sent_packet;
    }

    pub(crate) fn remove_obsolete_packets(&mut self, least_unacked: PacketNumber) {
        // A packet can become obsolete when it is removed from the sent-packet
        // map's view of inflight before it is acked or marked as lost. For example,
        // when a crypto packet is retransmitted, the packet is removed from that
        // map's inflight, but is not marked as acked or lost in the BandwidthSampler.
        self.connection_state_map.remove_up_to(least_unacked);
    }

    pub(crate) const fn total_bytes_lost(&self) -> ByteCount {
        self.total_bytes_lost
    }

    pub(crate) const fn total_bytes_acked(&self) -> ByteCount {
        self.total_bytes_acked
    }

    pub(crate) fn choose_a0_point(&mut self, total_bytes_acked: ByteCount, a0: &mut AckPoint) -> bool {
        if self.a0_candidates.empty() {
            return false;
        }

        if self.a0_candidates.len() == 1 {
            *a0 = *self.a0_candidates.front();
            return true;
        }

        for i in 1..self.a0_candidates.len() {
            if self.a0_candidates.offset(i).total_bytes_acked > total_bytes_acked {
                *a0 = *self.a0_candidates.offset(i - 1);
                if i > 1 {
                    for _ in 0..i - 1 {
                        self.a0_candidates.pop_front();
                    }
                }
                return true;
            }
        }

        *a0 = *self.a0_candidates.back();
        for _ in 0..self.a0_candidates.len() - 1 {
            self.a0_candidates.pop_front();
        }
        true
    }

    pub(crate) fn on_packet_acknowledged(
        &mut self,
        ack_time: monotime::Time,
        packet_number: PacketNumber,
    ) -> BandwidthSample {
        let mut sample = new_bandwidth_sample();
        self.last_acked_packet = packet_number;
        let Some(sent_packet) = self.connection_state_map.get_entry(packet_number).copied() else {
            return sample;
        };

        // OnPacketAcknowledgedInner
        self.total_bytes_acked += sent_packet.size;
        self.total_bytes_sent_at_last_acked_packet = sent_packet.send_time_state.total_bytes_sent;
        self.last_acked_packet_sent_time = Some(sent_packet.sent_time);
        self.last_acked_packet_ack_time = Some(ack_time);
        if self.overestimate_avoidance {
            self.recent_ack_points.update(ack_time, self.total_bytes_acked);
        }

        if self.is_app_limited {
            // Exit app-limited phase in two cases:
            // (1) end_of_app_limited_phase_ is not initialized, i.e., so far all
            // packets are sent while there are buffered packets or pending data.
            // (2) The current acked packet is after the sent packet marked as the end
            // of the app limit phase.
            if self.end_of_app_limited_phase == INVALID_PACKET_NUMBER || packet_number > self.end_of_app_limited_phase {
                self.is_app_limited = false;
            }
        }

        // There might have been no packets acknowledged at the moment when the
        // current packet was sent. In that case, there is no bandwidth sample to
        // make.
        let Some(last_acked_packet_sent_time) = sent_packet.last_acked_packet_sent_time else {
            return sample;
        };

        // Infinite rate indicates that the sampler is supposed to discard the
        // current send rate sample and use only the ack rate.
        let send_rate = if sent_packet.sent_time > last_acked_packet_sent_time {
            bandwidth_from_delta(
                sent_packet.send_time_state.total_bytes_sent - sent_packet.total_bytes_sent_at_last_acked_packet,
                sent_packet.sent_time.sub(&last_acked_packet_sent_time),
            )
        } else {
            INF_BANDWIDTH
        };

        let mut a0 = AckPoint::default();
        let chose_a0 =
            self.overestimate_avoidance && self.choose_a0_point(sent_packet.send_time_state.total_bytes_acked, &mut a0);
        if !chose_a0 {
            a0.ack_time = sent_packet.last_acked_packet_ack_time;
            a0.total_bytes_acked = sent_packet.send_time_state.total_bytes_acked;
        }

        let ack_rate = match a0.ack_time {
            Some(a0_ack_time) => {
                // During the slope calculation, ensure that ack time of the current packet is
                // always larger than the time of the previous packet, otherwise division by
                // zero or integer underflow can occur.
                if ack_time <= a0_ack_time {
                    return sample;
                }
                bandwidth_from_delta(self.total_bytes_acked - a0.total_bytes_acked, ack_time.sub(&a0_ack_time))
            }
            // Subtracting the zero time, i.e. the whole uptime, drives the
            // rate to the bottom of the scale.
            None => 0,
        };

        sample.bandwidth = min(send_rate, ack_rate);
        // Note: this sample does not account for delayed acknowledgement time.  This
        // means that the RTT measurements here can be artificially high, especially
        // on low bandwidth connections.
        sample.rtt = ack_time.sub(&sent_packet.sent_time);
        sample.send_rate = send_rate;
        sent_packet_to_send_time_state(&sent_packet, &mut sample.state_at_send);

        sample
    }

    pub(crate) fn on_ack_event_end(
        &mut self,
        bandwidth_estimate: Bandwidth,
        is_new_max_bandwidth: bool,
        round_trip_count: RoundTripCount,
    ) -> ByteCount {
        let newly_acked_bytes = self.total_bytes_acked - self.total_bytes_acked_after_last_ack_event;
        if newly_acked_bytes == 0 {
            return 0;
        }
        self.total_bytes_acked_after_last_ack_event = self.total_bytes_acked;
        let extra_acked = self.max_ack_height_tracker.update(
            bandwidth_estimate,
            is_new_max_bandwidth,
            round_trip_count,
            self.last_sent_packet,
            self.last_acked_packet,
            self.last_acked_packet_ack_time,
            newly_acked_bytes,
        );
        // If |extra_acked| is zero, i.e. this ack event marks the start of a new ack
        // aggregation epoch, save LessRecentPoint, which is the last ack point of the
        // previous epoch, as a A0 candidate.
        if self.overestimate_avoidance && extra_acked == 0 {
            let less_recent_point = *self.recent_ack_points.less_recent_point();
            self.a0_candidates.push_back(less_recent_point);
        }
        extra_acked
    }
}

pub(crate) const fn sent_packet_to_send_time_state(
    sent_packet: &ConnectionStateOnSentPacket,
    send_time_state: &mut SendTimeState,
) {
    *send_time_state = sent_packet.send_time_state;
    send_time_state.is_valid = true;
}

/// Calculates the bytes from a bandwidth(bits per second) and a time delta
#[must_use]
#[expect(
    clippy::cast_possible_truncation,
    reason = "`Duration::as_nanos` yields a `u128` while a byte count is an `i64`; the nanosecond span is bounded by the sub-second deltas the sampler is fed, so the narrowing matches the arithmetic"
)]
pub const fn bytes_from_bandwidth_and_time_delta(bandwidth: Bandwidth, delta: Duration) -> ByteCount {
    bandwidth.cast_signed().wrapping_mul(delta.as_nanos() as ByteCount)
        / ((Duration::from_secs(1).as_nanos() as ByteCount) * 8)
}
