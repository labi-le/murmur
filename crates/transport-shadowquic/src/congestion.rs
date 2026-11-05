use std::sync::Arc;
use std::time::Duration;

use murmur_quic::congestion as oldcongestion;
use murmur_quic::jls::congestion as jcongestion;
use murmur_quic::jls::monotime as jmonotime;
use murmur_quic::jls::Conn as JlsConn;
use murmur_transport_tuic::congestion;
use murmur_transport_tuic::congestion_v2 as congestionv2;

pub fn set_congestion_controller(quic_conn: &dyn JlsConn, cc: &str, cwnd: i32, profile: &str) {
    let cwnd = if cwnd == 0 { 32 } else { cwnd };
    let initial_packet_size = oldcongestion::ByteCount::from(quic_conn.config().initial_packet_size);
    match cc {
        "cubic" => {
            quic_conn.set_congestion_control(new_congestion_adapter(Box::new(
                congestion::cubic_sender::new_cubic_sender(initial_packet_size, false),
            )));
        }
        "new_reno" => {
            quic_conn.set_congestion_control(new_congestion_adapter(Box::new(
                congestion::cubic_sender::new_cubic_sender(initial_packet_size, true),
            )));
        }
        "bbr_meta_v1" => {
            quic_conn.set_congestion_control(new_congestion_adapter(Box::new(congestion::bbr_sender::new_bbr_sender(
                initial_packet_size,
                oldcongestion::ByteCount::from(cwnd) * congestion::bbr_sender::INITIAL_MAX_DATAGRAM_SIZE,
                congestion::bbr_sender::DEFAULT_BBR_MAX_CONGESTION_WINDOW
                    * congestion::bbr_sender::INITIAL_MAX_DATAGRAM_SIZE,
            ))));
        }
        "bbr_meta_v2" | "bbr" => {
            quic_conn.set_congestion_control(new_congestion_adapter(Box::new(
                congestionv2::bbr_sender::new_bbr_sender(
                    initial_packet_size,
                    oldcongestion::ByteCount::from(cwnd),
                    parse_profile(profile),
                ),
            )));
        }
        _ => {}
    }
}

pub(crate) fn set_brutal_congestion_controller(quic_conn: &dyn JlsConn, bps: u64) {
    if bps == 0 {
        return;
    }
    quic_conn.set_congestion_control(new_congestion_adapter(Box::new(congestionv2::brutal::new_brutal_sender(bps))));
}

/// Maps an option string onto `congestionv2::Profile`; the BBR sender defaults any unrecognized
/// value to `ProfileStandard`.
fn parse_profile(profile: &str) -> congestionv2::bbr_sender::Profile {
    match profile {
        congestionv2::bbr_sender::PROFILE_CONSERVATIVE => congestionv2::bbr_sender::Profile::ProfileConservative,
        congestionv2::bbr_sender::PROFILE_AGGRESSIVE => congestionv2::bbr_sender::Profile::ProfileAggressive,
        _ => congestionv2::bbr_sender::Profile::ProfileStandard,
    }
}

fn new_congestion_adapter(
    cc: Box<dyn oldcongestion::CongestionControlEx>,
) -> Box<dyn jcongestion::CongestionControlEx> {
    Box::new(CongestionAdapter { cc })
}

///
/// `murmur_quic::congestion::CongestionControl` has no `as_any`/downcast support, so the
/// adapter stores the concrete congestion control as `Box<dyn CongestionControlEx>` directly instead
/// of performing a runtime type assertion; every concrete sender constructed in this file implements
/// `CongestionControlEx`, so the assertion always succeeded in practice.
struct CongestionAdapter {
    cc: Box<dyn oldcongestion::CongestionControlEx>,
}

impl jcongestion::CongestionControl for CongestionAdapter {
    fn set_rtt_stats_provider(&mut self, provider: Arc<dyn jcongestion::RttStatsProvider>) {
        self.cc.set_rtt_stats_provider(Arc::new(RttStatsProviderAdapter { provider }));
    }

    fn time_until_send(&self, bytes_in_flight: jcongestion::ByteCount) -> jmonotime::Time {
        jmonotime::Time(self.cc.time_until_send(bytes_in_flight))
    }

    fn has_pacing_budget(&self, now: jmonotime::Time) -> bool {
        self.cc.has_pacing_budget(now.0)
    }

    fn on_packet_sent(
        &mut self,
        sent_time: jmonotime::Time,
        bytes_in_flight: jcongestion::ByteCount,
        packet_number: jcongestion::PacketNumber,
        bytes: jcongestion::ByteCount,
        is_retransmittable: bool,
    ) {
        self.cc.on_packet_sent(sent_time.0, bytes_in_flight, packet_number, bytes, is_retransmittable);
    }

    fn can_send(&self, bytes_in_flight: jcongestion::ByteCount) -> bool {
        self.cc.can_send(bytes_in_flight)
    }

    fn maybe_exit_slow_start(&mut self) {
        self.cc.maybe_exit_slow_start();
    }

    fn on_packet_acked(
        &mut self,
        number: jcongestion::PacketNumber,
        acked_bytes: jcongestion::ByteCount,
        prior_in_flight: jcongestion::ByteCount,
        event_time: jmonotime::Time,
    ) {
        self.cc.on_packet_acked(number, acked_bytes, prior_in_flight, event_time.0);
    }

    fn on_congestion_event(
        &mut self,
        number: jcongestion::PacketNumber,
        lost_bytes: jcongestion::ByteCount,
        prior_in_flight: jcongestion::ByteCount,
    ) {
        self.cc.on_congestion_event(number, lost_bytes, prior_in_flight);
    }

    fn on_retransmission_timeout(&mut self, packets_retransmitted: bool) {
        self.cc.on_retransmission_timeout(packets_retransmitted);
    }

    fn set_max_datagram_size(&mut self, size: jcongestion::ByteCount) {
        self.cc.set_max_datagram_size(size);
    }

    fn in_slow_start(&self) -> bool {
        self.cc.in_slow_start()
    }

    fn in_recovery(&self) -> bool {
        self.cc.in_recovery()
    }

    fn get_congestion_window(&self) -> jcongestion::ByteCount {
        self.cc.get_congestion_window()
    }
}

impl jcongestion::CongestionControlEx for CongestionAdapter {
    fn on_congestion_event_ex(
        &mut self,
        prior_in_flight: jcongestion::ByteCount,
        event_time: jmonotime::Time,
        acked_packets: &[jcongestion::AckedPacketInfo],
        lost_packets: &[jcongestion::LostPacketInfo],
    ) {
        self.cc.on_congestion_event_ex(
            prior_in_flight,
            event_time.0,
            &adapt_acked_packet_info(acked_packets),
            &adapt_lost_packet_info(lost_packets),
        );
    }
}

fn adapt_acked_packet_info(packets: &[jcongestion::AckedPacketInfo]) -> Vec<oldcongestion::AckedPacketInfo> {
    packets
        .iter()
        .map(|packet| oldcongestion::AckedPacketInfo {
            packet_number: packet.packet_number,
            bytes_acked: packet.bytes_acked,
            received_time: packet.received_time.0,
        })
        .collect()
}

fn adapt_lost_packet_info(packets: &[jcongestion::LostPacketInfo]) -> Vec<oldcongestion::LostPacketInfo> {
    packets
        .iter()
        .map(|packet| oldcongestion::LostPacketInfo {
            packet_number: packet.packet_number,
            bytes_lost: packet.bytes_lost,
        })
        .collect()
}

struct RttStatsProviderAdapter {
    provider: Arc<dyn jcongestion::RttStatsProvider>,
}

impl oldcongestion::RttStatsProvider for RttStatsProviderAdapter {
    fn min_rtt(&self) -> Duration {
        self.provider.min_rtt()
    }

    fn latest_rtt(&self) -> Duration {
        self.provider.latest_rtt()
    }

    fn smoothed_rtt(&self) -> Duration {
        self.provider.smoothed_rtt()
    }

    fn mean_deviation(&self) -> Duration {
        self.provider.mean_deviation()
    }

    fn max_ack_delay(&self) -> Duration {
        self.provider.max_ack_delay()
    }

    fn pto(&self, include_max_ack_delay: bool) -> Duration {
        self.provider.pto(include_max_ack_delay)
    }

    fn update_rtt(&self, send_delta: Duration, ack_delay: Duration) {
        self.provider.update_rtt(send_delta, ack_delay);
    }

    fn set_max_ack_delay(&self, mad: Duration) {
        self.provider.set_max_ack_delay(mad);
    }

    fn set_initial_rtt(&self, t: Duration) {
        self.provider.set_initial_rtt(t);
    }
}
