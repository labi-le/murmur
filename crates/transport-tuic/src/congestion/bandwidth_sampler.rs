use std::collections::HashMap;
use std::time::Duration;

use murmur_quic::{congestion, monotime};

use super::bandwidth::{bandwidth_from_delta, Bandwidth};
use super::bbr_sender::{min_bandwidth, INFINITE_RTT};

pub static INFINITE_BANDWIDTH: Bandwidth = u64::MAX;

/// `SendTimeState` is a subset of `ConnectionStateOnSentPacket` which is returned
/// to the caller when the packet is acked or lost.
#[derive(Debug, Clone, Copy, Default)]
pub struct SendTimeState {
    /// Whether other states in this object is valid.
    pub(crate) is_valid: bool,
    /// Whether the sender is app limited at the time the packet was sent.
    /// App limited bandwidth sample might be artificially low because the sender
    /// did not have enough data to send in order to saturate the link.
    pub(crate) is_app_limited: bool,
    /// Total number of sent bytes at the time the packet was sent.
    /// Includes the packet itself.
    pub(crate) total_bytes_sent: congestion::ByteCount,
    /// Total number of acked bytes at the time the packet was sent.
    pub(crate) total_bytes_acked: congestion::ByteCount,
    /// Total number of lost bytes at the time the packet was sent.
    pub(crate) total_bytes_lost: congestion::ByteCount,
}

/// `ConnectionStateOnSentPacket` represents the information about a sent packet.
///
/// It also carries the state of the connection at the moment the packet was sent,
/// specifically the information about the most recently acknowledged packet at
/// that moment.
#[derive(Debug, Clone, Copy)]
pub struct ConnectionStateOnSentPacket {
    /// Time at which the packet is sent.
    pub(crate) send_time: monotime::Time,
    /// Size of the packet.
    pub(crate) size: congestion::ByteCount,
    /// The value of |totalBytesSentAtLastAckedPacket| at the time the
    /// packet was sent.
    pub(crate) total_bytes_sent_at_last_acked_packet: congestion::ByteCount,
    /// The value of |lastAckedPacketSentTime| at the time the packet was sent.
    pub(crate) last_acked_packet_sent_time: monotime::Time,
    /// The value of |lastAckedPacketAckTime| at the time the packet was sent.
    pub(crate) last_acked_packet_ack_time: monotime::Time,
    /// Send time states that are returned to the congestion controller when the
    /// packet is acked or lost.
    pub(crate) send_time_state: SendTimeState,
}

/// `BandwidthSample`
#[derive(Debug, Clone, Copy)]
pub struct BandwidthSample {
    /// The bandwidth at that particular sample. Zero if no valid bandwidth sample
    /// is available.
    pub(crate) bandwidth: Bandwidth,
    /// The RTT measurement at this particular sample.  Zero if no RTT sample is
    /// available.  Does not correct for delayed ack time.
    pub(crate) rtt: Duration,
    /// States captured when the packet was sent.
    pub(crate) state_at_send: SendTimeState,
}

#[must_use]
pub fn new_bandwidth_sample() -> BandwidthSample {
    BandwidthSample { bandwidth: 0, rtt: INFINITE_RTT, state_at_send: SendTimeState::default() }
}

/// `BandwidthSampler` keeps track of sent and acknowledged packets.
///
/// It outputs a bandwidth sample for every packet acknowledged, taken as
/// `min(send_rate, ack_rate)` over the slope between the packet and the last
/// acknowledged packet that was in flight when it was sent. The samples are not
/// filtered; the consumer has to filter them itself. Once `on_app_limited` is
/// called, every sent packet produces app-limited samples up to the ack of a
/// packet sent after that call.
#[derive(Debug)]
pub struct BandwidthSampler {
    /// The total number of congestion controlled bytes sent during the connection.
    pub(crate) total_bytes_sent: congestion::ByteCount,
    /// The total number of congestion controlled bytes which were acknowledged.
    pub(crate) total_bytes_acked: congestion::ByteCount,
    /// The total number of congestion controlled bytes which were lost.
    pub(crate) total_bytes_lost: congestion::ByteCount,
    /// The value of |`total_bytes_sent`| at the time the last acknowledged packet
    /// was sent. Valid only when |`last_acked_packet_sent_time`| is valid.
    total_bytes_sent_at_last_acked_packet: congestion::ByteCount,
    /// The time at which the last acknowledged packet was sent; Valid only when it is
    /// not the zero time.
    last_acked_packet_sent_time: monotime::Time,
    /// The time at which the most recent packet was acknowledged.
    last_acked_packet_ack_time: monotime::Time,
    /// The most recently sent packet.
    last_send_packet: congestion::PacketNumber,
    /// Indicates whether the bandwidth sampler is currently in an app-limited
    /// phase.
    pub(crate) is_app_limited: bool,
    /// The packet that will be acknowledged after this one will cause the sampler
    /// to exit the app-limited phase.
    end_of_app_limited_phase: congestion::PacketNumber,
    /// Record of the connection state at the point where each packet in flight was
    /// sent, indexed by the packet number.
    connection_stats: ConnectionStates,
}

#[must_use]
pub fn new_bandwidth_sampler() -> BandwidthSampler {
    BandwidthSampler {
        total_bytes_sent: 0,
        total_bytes_acked: 0,
        total_bytes_lost: 0,
        total_bytes_sent_at_last_acked_packet: 0,
        last_acked_packet_sent_time: monotime::Time::default(),
        last_acked_packet_ack_time: monotime::Time::default(),
        last_send_packet: 0,
        is_app_limited: false,
        end_of_app_limited_phase: 0,
        connection_stats: ConnectionStates { stats: HashMap::new() },
    }
}

impl BandwidthSampler {
    /// Inputs the sent packet information into the sampler. Assumes that all
    /// packets are sent in order. The information about the packet will not be
    /// released from the sampler until it the packet is either acknowledged or
    /// declared lost.
    pub fn on_packet_sent(
        &mut self,
        sent_time: monotime::Time,
        last_sent_packet: congestion::PacketNumber,
        sent_bytes: congestion::ByteCount,
        bytes_in_flight: congestion::ByteCount,
        has_retransmittable_data: bool,
    ) {
        self.last_send_packet = last_sent_packet;

        if !has_retransmittable_data {
            return;
        }

        self.total_bytes_sent = self.total_bytes_sent.wrapping_add(sent_bytes);

        // If there are no packets in flight, the time at which the new transmission
        // opens can be treated as the A_0 point for the purpose of bandwidth
        // sampling. This underestimates bandwidth to some extent, and produces some
        // artificially low samples for most packets in flight, but it provides with
        // samples at important points where we would not have them otherwise, most
        // importantly at the beginning of the connection.
        if bytes_in_flight == 0 {
            self.last_acked_packet_ack_time = sent_time;
            self.total_bytes_sent_at_last_acked_packet = self.total_bytes_sent;

            // In this situation ack compression is not a concern, set send rate to
            // effectively infinite.
            self.last_acked_packet_sent_time = sent_time;
        }

        let state = new_connection_state_on_sent_packet(sent_time, sent_bytes, self);
        self.connection_stats.insert(last_sent_packet, state);
    }

    /// Notifies the sampler that the last acked packet is acknowledged. Returns a
    /// bandwidth sample. If no bandwidth sample is available,
    /// zero bandwidth is returned.
    pub fn on_packet_acked(
        &mut self,
        ack_time: monotime::Time,
        last_acked_packet: congestion::PacketNumber,
    ) -> BandwidthSample {
        let Some(sent_packet_state) = self.connection_stats.get(last_acked_packet).copied() else {
            return new_bandwidth_sample();
        };

        let sample = self.on_packet_acked_inner(ack_time, last_acked_packet, &sent_packet_state);
        self.connection_stats.remove(last_acked_packet);

        sample
    }

    /// onPacketAckedInner Handles the actual bandwidth calculations, whereas the outer method handles
    /// retrieving and removing |sentPacket|.
    fn on_packet_acked_inner(
        &mut self,
        ack_time: monotime::Time,
        last_acked_packet: congestion::PacketNumber,
        sent_packet: &ConnectionStateOnSentPacket,
    ) -> BandwidthSample {
        self.total_bytes_acked = self.total_bytes_acked.wrapping_add(sent_packet.size);

        self.total_bytes_sent_at_last_acked_packet = sent_packet.send_time_state.total_bytes_sent;
        self.last_acked_packet_sent_time = sent_packet.send_time;
        self.last_acked_packet_ack_time = ack_time;

        // Exit app-limited phase once a packet that was sent while the connection is
        // not app-limited is acknowledged.
        if self.is_app_limited && last_acked_packet > self.end_of_app_limited_phase {
            self.is_app_limited = false;
        }

        // There might have been no packets acknowledged at the moment when the
        // current packet was sent. In that case, there is no bandwidth sample to
        // make.
        if sent_packet.last_acked_packet_sent_time.is_zero() {
            return new_bandwidth_sample();
        }

        // Infinite rate indicates that the sampler is supposed to discard the
        // current send rate sample and use only the ack rate.
        let send_rate = if sent_packet.send_time > sent_packet.last_acked_packet_sent_time {
            bandwidth_from_delta(
                sent_packet.send_time_state.total_bytes_sent - sent_packet.total_bytes_sent_at_last_acked_packet,
                sent_packet.send_time.sub(&sent_packet.last_acked_packet_sent_time),
            )
        } else {
            INFINITE_BANDWIDTH
        };

        // During the slope calculation, ensure that ack time of the current packet is
        // always larger than the time of the previous packet, otherwise division by
        // zero or integer underflow can occur.
        if ack_time <= sent_packet.last_acked_packet_ack_time {
            return new_bandwidth_sample();
        }

        let ack_rate = bandwidth_from_delta(
            self.total_bytes_acked - sent_packet.send_time_state.total_bytes_acked,
            ack_time.sub(&sent_packet.last_acked_packet_ack_time),
        );

        // Note: this sample does not account for delayed acknowledgement time.  This
        // means that the RTT measurements here can be artificially high, especially
        // on low bandwidth connections.
        let mut sample = BandwidthSample {
            bandwidth: min_bandwidth(send_rate, ack_rate),
            rtt: ack_time.sub(&sent_packet.send_time),
            state_at_send: SendTimeState::default(),
        };

        sent_packet_to_send_time_state(sent_packet, &mut sample.state_at_send);
        sample
    }

    /// Informs the sampler that a packet is considered lost and it should no
    /// longer keep track of it.
    pub fn on_congestion_event(&mut self, packet_number: congestion::PacketNumber) -> SendTimeState {
        let (ok, sent_packet) = self.connection_stats.remove(packet_number);
        let SendTimeState { is_app_limited, total_bytes_sent, total_bytes_acked, total_bytes_lost, .. } =
            SendTimeState::default();
        let mut send_time_state =
            SendTimeState { is_valid: ok, is_app_limited, total_bytes_sent, total_bytes_acked, total_bytes_lost };
        if let Some(sent_packet) = sent_packet {
            self.total_bytes_lost = self.total_bytes_lost.wrapping_add(sent_packet.size);
            sent_packet_to_send_time_state(&sent_packet, &mut send_time_state);
        }

        send_time_state
    }

    /// Informs the sampler that the connection is currently app-limited, causing
    /// the sampler to enter the app-limited phase.  The phase will expire by
    /// itself.
    pub const fn on_app_limited(&mut self) {
        self.is_app_limited = true;
        self.end_of_app_limited_phase = self.last_send_packet;
    }
}

/// Copies a subset of the private `ConnectionStateOnSentPacket` to the public
/// `SendTimeState`, always marking it valid.
pub const fn sent_packet_to_send_time_state(
    sent_packet: &ConnectionStateOnSentPacket,
    send_time_state: &mut SendTimeState,
) {
    send_time_state.is_app_limited = sent_packet.send_time_state.is_app_limited;
    send_time_state.total_bytes_sent = sent_packet.send_time_state.total_bytes_sent;
    send_time_state.total_bytes_acked = sent_packet.send_time_state.total_bytes_acked;
    send_time_state.total_bytes_lost = sent_packet.send_time_state.total_bytes_lost;
    send_time_state.is_valid = true;
}

/// Record of the connection state at the point where each packet in flight was
/// sent, indexed by the packet number.
#[derive(Debug)]
pub struct ConnectionStates {
    stats: HashMap<congestion::PacketNumber, ConnectionStateOnSentPacket>,
}

impl ConnectionStates {
    pub fn insert(
        &mut self,
        packet_number: congestion::PacketNumber,
        sent_packet: ConnectionStateOnSentPacket,
    ) -> bool {
        if self.stats.contains_key(&packet_number) {
            return false;
        }

        self.stats.insert(packet_number, sent_packet);
        true
    }

    #[must_use]
    pub fn get(&self, packet_number: congestion::PacketNumber) -> Option<&ConnectionStateOnSentPacket> {
        self.stats.get(&packet_number)
    }

    pub fn remove(&mut self, packet_number: congestion::PacketNumber) -> (bool, Option<ConnectionStateOnSentPacket>) {
        let state = self.stats.remove(&packet_number);
        (state.is_some(), state)
    }
}

#[must_use]
pub const fn new_connection_state_on_sent_packet(
    sent_time: monotime::Time,
    bytes: congestion::ByteCount,
    sampler: &BandwidthSampler,
) -> ConnectionStateOnSentPacket {
    ConnectionStateOnSentPacket {
        send_time: sent_time,
        size: bytes,
        last_acked_packet_sent_time: sampler.last_acked_packet_sent_time,
        last_acked_packet_ack_time: sampler.last_acked_packet_ack_time,
        total_bytes_sent_at_last_acked_packet: sampler.total_bytes_sent_at_last_acked_packet,
        send_time_state: SendTimeState {
            is_valid: true,
            is_app_limited: sampler.is_app_limited,
            total_bytes_sent: sampler.total_bytes_sent,
            total_bytes_acked: sampler.total_bytes_acked,
            total_bytes_lost: sampler.total_bytes_lost,
        },
    }
}
