//! NTP client service: exchanges SNTP packets with the configured server, applies the measured
//! clock offset, and optionally writes the server time to the system wall clock.
//!
//! The NTP client wire protocol (RFC 5905 SNTP) is small and fully specified, so the exchange is
//! implemented here on top of the sing dialer instead of depending on a dedicated crate.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use chrono::{DateTime, Local, Utc};
use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use crate::time::set_offset;
use murmur_common::time::TimeDuration;
use murmur_common_net::io::{Datagram, Stream};
use murmur_component::dialer;
use murmur_component_proxydialer as proxydialer;
use murmur_component_proxydialer::sing::SingDialer;
use murmur_constant::adapters::Dialer as ConstantDialer;
use murmur_constant::tunnel::Tunnel as ConstantTunnel;
use murmur_log::{errorln, infoln, warnln};
use murmur_sing::metadata::{parse_socksaddr, Socksaddr};

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
use super::time_stub::set_system_time;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use super::time_unix::set_system_time;
#[cfg(target_os = "windows")]
use super::time_windows::set_system_time;

/// Timestamp layout of the system-time sync log line.
const TIME_LAYOUT: &str = "%Y-%m-%d %H:%M:%S %z";

static GLOBAL_SRV: Mutex<Option<Arc<Service>>> = Mutex::new(None);

pub struct Service {
    server: Socksaddr,
    dialer: Arc<dyn SingDialer>,
    ticker_interval: Duration,
    ctx: CancellationToken,
    sync_system_time: Mutex<bool>,
}

impl fmt::Debug for Service {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Service")
            .field("server", &self.server)
            .field("ticker_interval", &self.ticker_interval)
            .field("ctx", &self.ctx)
            .field("sync_system_time", &self.sync_system_time)
            .finish_non_exhaustive()
    }
}

/// Adapter giving `dialer::dialer::Dialer` the `constant::adapters::Dialer` vocabulary that
/// `proxydialer::sing::new_sing_dialer` needs; that dialer only exposes inherent methods.
#[derive(Debug)]
struct DefaultDialer(dialer::dialer::Dialer);

#[async_trait]
impl ConstantDialer for DefaultDialer {
    async fn dial_context(&self, ctx: &CancellationToken, network: &str, address: &str) -> Result<Box<dyn Stream>> {
        self.0.dial_context(ctx, network, address).await
    }

    /// No reachable caller: the NTP client only dials a connected UDP socket, so the full
    /// `constant::adapters::PacketConn` vocabulary (`EnhancePacketConn` + `Connection`, for
    /// statistics tracking) would be dead machinery here.
    async fn listen_packet(
        &self,
        _ctx: &CancellationToken,
        _network: &str,
        _address: &str,
        _r_addr_port: Option<SocketAddr>,
    ) -> Result<Box<dyn Datagram>> {
        Err(anyhow!("ntp: ListenPacket is not reachable from the NTP client dialer"))
    }
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "public entry point: the configuration call site owns the string and the signature is load-bearing"
)]
pub fn re_create_ntp_service(
    server: String,
    interval: Duration,
    dialer_proxy: String,
    tunnel: Arc<dyn ConstantTunnel>,
    sync_system_time: bool,
) {
    if server.is_empty() || interval.is_zero() {
        let old = GLOBAL_SRV.lock().take();
        if let Some(old) = old {
            old.stop();
        }
        return;
    }
    let ctx = CancellationToken::new();
    let c_dialer: Arc<dyn ConstantDialer> = if dialer_proxy.is_empty() {
        Arc::new(DefaultDialer(dialer::dialer::new_dialer(Vec::new())))
    } else {
        proxydialer::byname::new_by_name(dialer_proxy, tunnel)
    };

    let srv = Arc::new(Service {
        server: parse_socksaddr(&server),
        dialer: proxydialer::sing::new_sing_dialer(c_dialer),
        ticker_interval: Duration::from_secs(u64::try_from(interval.as_nanos()).unwrap_or(u64::MAX).saturating_mul(60)),
        ctx,
        sync_system_time: Mutex::new(sync_system_time),
    });
    let old = GLOBAL_SRV.lock().replace(Arc::clone(&srv));
    if let Some(old) = old {
        old.stop();
    }
    srv.start();
}

impl Service {
    fn start(self: &Arc<Self>) {
        let sync_system_time = *self.sync_system_time.lock();
        infoln!("NTP service start, sync system time is {sync_system_time}");
        let srv = Arc::clone(self);
        tokio::spawn(async move { srv.loop_update().await });
    }

    fn stop(&self) {
        infoln!("NTP service stop");
        self.ctx.cancel();
    }

    // cancel-safe: the only suspension point is the exchange, and every write that follows it runs
    // without awaiting, so a dropped future leaves no half-applied offset.
    async fn update(&self) -> Result<()> {
        let mut last_err = None;
        for _ in 0..3 {
            match exchange(&self.ctx, self.dialer.as_ref(), self.server.clone()).await {
                Ok(response) => {
                    let offset = response.clock_offset;
                    if offset > 0 {
                        infoln!("System clock is ahead of NTP time by {offset}ns");
                    } else if offset < 0 {
                        infoln!("System clock is behind NTP time by {}ns", -offset);
                    }
                    set_offset(offset);
                    let sync_system_time = *self.sync_system_time.lock();
                    if sync_system_time {
                        let time_now = response.time;
                        match set_system_time(time_now) {
                            Ok(()) => {
                                infoln!(
                                    "Sync system time success: {}",
                                    time_now.with_timezone(&Local).format(TIME_LAYOUT)
                                );
                            }
                            Err(sync_err) => {
                                errorln!("Write time to system: {sync_err}");
                                *self.sync_system_time.lock() = false;
                            }
                        }
                    }
                    return Ok(());
                }
                Err(err) => {
                    if self.ctx.is_cancelled() {
                        return Ok(());
                    }
                    last_err = Some(err);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| anyhow!("ntp: exchange failed")))
    }

    // NOT cancel-safe: an external drop skips the trailing `set_offset(0)`, so the last measured
    // offset stays in effect; the token path always reaches it.
    async fn loop_update(&self) {
        let mut ticker =
            tokio::time::interval_at(tokio::time::Instant::now() + self.ticker_interval, self.ticker_interval);
        loop {
            if let Err(err) = self.update().await {
                warnln!("Sync time failed: {err}");
            }
            tokio::select! {
                () = self.ctx.cancelled() => break,
                _ = ticker.tick() => {}
            }
        }
        set_offset(0);
    }
}

/// Server response, narrowed to the fields the update path reads.
#[derive(Debug)]
struct NtpResponse {
    time: DateTime<Utc>,
    clock_offset: TimeDuration,
}

/// Seconds between the NTP epoch (1900-01-01T00:00:00Z) and the Unix epoch.
const NTP_EPOCH_UNIX_OFFSET_SECS: i64 = 2_208_988_800;

/// The SNTP version this client speaks and requires in the reply (RFC 5905 §7.3).
const NTP_VERSION: u8 = 4;
/// The reply mode that identifies a server response (RFC 5905 §7.3).
const MODE_SERVER: u8 = 4;

/// The checks that bind a reply to this request (RFC 5905 §8): the reply must come from a server,
/// speak the requested version, and echo the transmit timestamp this client sent in the originate
/// field. Without the echo check any datagram from any peer is accepted as the answer.
fn validate_reply(response: &[u8; 48], expected_originate: u64) -> Result<()> {
    let mode = response[0] & 0x07;
    if mode != MODE_SERVER {
        return Err(anyhow!("ntp: reply mode {mode} is not server ({MODE_SERVER})"));
    }
    let version = (response[0] >> 3) & 0x07;
    if version != NTP_VERSION {
        return Err(anyhow!("ntp: reply version {version} does not match request version {NTP_VERSION}"));
    }
    let originate_raw: [u8; 8] = response[24..32].try_into().map_err(|_| anyhow!("ntp: response too short"))?;
    let originate = u64::from_be_bytes(originate_raw);
    if originate != expected_originate {
        return Err(anyhow!(
            "ntp: reply originate stamp {originate:#018x} does not echo request transmit stamp {expected_originate:#018x}"
        ));
    }
    Ok(())
}

fn ntp_time_to_datetime(raw: u64) -> DateTime<Utc> {
    let sec = (raw >> 32).cast_signed() - NTP_EPOCH_UNIX_OFFSET_SECS;
    let frac = raw & 0xffff_ffff;
    let nanos = u32::try_from((u128::from(frac) * 1_000_000_000u128) >> 32).unwrap_or_default();
    DateTime::from_timestamp(sec, nanos).unwrap_or(DateTime::UNIX_EPOCH)
}

/// One SNTP exchange with the server.
// cancel-safe: the future owns the socket it dialled and the request buffer, so a drop leaves no
// shared state behind.
async fn exchange(ctx: &CancellationToken, dialer: &dyn SingDialer, server: Socksaddr) -> Result<NtpResponse> {
    let mut conn = dialer.dial_context(ctx, "udp", server).await?;
    let _ = conn.set_deadline(Some(tokio::time::Instant::now() + Duration::from_secs(5)));

    let mut request = [0u8; 48];
    // LI = 3 (not in sync, RFC 5905), VN = NTP_VERSION, Mode = 3 (client).
    request[0] = (3 << 6) | (NTP_VERSION << 3) | 3;
    let random_bits: u64 = rand::random();
    request[40..48].copy_from_slice(&random_bits.to_be_bytes());

    let xmit_time = Utc::now();

    let exchanged = tokio::time::timeout(Duration::from_secs(5), async {
        conn.write_all(&request).await?;
        let mut response = [0u8; 48];
        conn.read_exact(&mut response).await?;
        Ok::<[u8; 48], std::io::Error>(response)
    })
    .await;

    let response = match exchanged {
        Ok(Ok(response)) => response,
        Ok(Err(err)) => return Err(err.into()),
        Err(_) => return Err(anyhow!("i/o timeout")),
    };
    let recv_time = Utc::now();

    validate_reply(&response, random_bits)?;

    let (_, timestamps) = response.split_at(32);
    let (receive_bytes, transmit_bytes) = timestamps.split_at(8);
    let receive_raw: [u8; 8] = receive_bytes.try_into().map_err(|_| anyhow!("ntp: response too short"))?;
    let transmit_raw: [u8; 8] = transmit_bytes.try_into().map_err(|_| anyhow!("ntp: response too short"))?;
    let receive_time = ntp_time_to_datetime(u64::from_be_bytes(receive_raw));
    let transmit_time = ntp_time_to_datetime(u64::from_be_bytes(transmit_raw));

    let a = receive_time - xmit_time;
    let b = transmit_time - recv_time;
    let offset = (a + b) / 2;

    Ok(NtpResponse { time: transmit_time, clock_offset: offset.num_nanoseconds().unwrap_or(0) })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local_sing_dialer() -> Arc<dyn SingDialer> {
        let c_dialer: Arc<dyn ConstantDialer> = Arc::new(DefaultDialer(dialer::dialer::new_dialer(Vec::new())));
        proxydialer::sing::new_sing_dialer(c_dialer)
    }

    /// RFC 5905 §8: the originate field must echo the transmit field this client sent. A reply
    /// that leaves it zero belongs to some other exchange (or to nobody) and must be rejected.
    #[tokio::test]
    async fn a_reply_that_does_not_echo_the_request_stamp_is_rejected() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let addr = server.local_addr().expect("local addr");

        tokio::spawn(async move {
            let mut request = [0u8; 48];
            let (_, peer) = server.recv_from(&mut request).await.expect("recv");
            let mut reply = [0u8; 48];
            reply[0] = (3 << 6) | (NTP_VERSION << 3) | MODE_SERVER;
            server.send_to(&reply, peer).await.expect("send");
        });

        let dialer = local_sing_dialer();
        let ctx = CancellationToken::new();
        let err = exchange(&ctx, dialer.as_ref(), parse_socksaddr(&addr.to_string()))
            .await
            .expect_err("a reply that does not echo the request stamp is rejected");
        assert!(err.to_string().contains("originate"), "{err}");
    }

    /// The echo check must not reject a genuine reply: one that copies the request's transmit
    /// stamp back is accepted and its timestamps drive the offset.
    #[tokio::test]
    async fn a_reply_that_echoes_the_request_stamp_is_accepted() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let addr = server.local_addr().expect("local addr");

        tokio::spawn(async move {
            let mut request = [0u8; 48];
            let (_, peer) = server.recv_from(&mut request).await.expect("recv");
            let mut reply = [0u8; 48];
            reply[0] = (3 << 6) | (NTP_VERSION << 3) | MODE_SERVER;
            reply[24..32].copy_from_slice(&request[40..48]);
            server.send_to(&reply, peer).await.expect("send");
        });

        let dialer = local_sing_dialer();
        let ctx = CancellationToken::new();
        exchange(&ctx, dialer.as_ref(), parse_socksaddr(&addr.to_string())).await.expect("an echoed reply is accepted");
    }

    /// A datagram that is not a server response, or that speaks another version, is not the reply
    /// to this request either.
    #[test]
    fn a_reply_from_a_client_or_with_the_wrong_version_is_rejected() {
        let mut reply = [0u8; 48];
        reply[0] = (3 << 6) | (NTP_VERSION << 3) | 3;
        let err = validate_reply(&reply, 0).expect_err("a client-mode reply is not a server response");
        assert!(err.to_string().contains("mode"), "{err}");

        reply[0] = (3 << 6) | (3 << 3) | MODE_SERVER;
        let err = validate_reply(&reply, 0).expect_err("a reply in another version is rejected");
        assert!(err.to_string().contains("version"), "{err}");
    }
}
