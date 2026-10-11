use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use parking_lot::RwLock;
use tokio::sync::{mpsc, Mutex as TokioMutex};
use tokio_util::sync::CancellationToken;

use murmur_common_net::io::Stream;
use murmur_component::dialer::bind::unmap_addr;
use murmur_constant::adapters::{PacketAdapter, PacketConn, PacketSender, UDPPacket, WriteBack, WriteBackProxy};
use murmur_constant::metadata::Metadata;
use murmur_log::{debugln, warnln};
use murmur_std_compat::net::UdpAddr;

use super::tunnel::{nat_table, pre_handle_metadata, SENDER_CAPACITY, UDP_TIMEOUT};

pub(crate) struct PacketSenderImpl {
    cancel: CancellationToken,
    tx: mpsc::Sender<Arc<dyn PacketAdapter>>,
    rx: TokioMutex<mpsc::Receiver<Arc<dyn PacketAdapter>>>,
    origin_to_target: RwLock<HashMap<String, Option<IpAddr>>>,
    target_to_origin: RwLock<HashMap<IpAddr, IpAddr>>,
}

/// Returns a channel-backed packet sender, ensuring packets are sent
/// sequentially and without blocking.
pub(crate) fn new_packet_sender() -> Arc<dyn PacketSender> {
    let (tx, rx) = mpsc::channel(SENDER_CAPACITY);
    Arc::new(PacketSenderImpl {
        cancel: CancellationToken::new(),
        tx,
        rx: TokioMutex::new(rx),
        origin_to_target: RwLock::new(HashMap::new()),
        target_to_origin: RwLock::new(HashMap::new()),
    })
}

impl PacketSenderImpl {
    // NOT cancel-safe: a cancel after the mapping update skips the packet's write.
    async fn process_packet(&self, pc: &Arc<dyn PacketConn>, packet: &Arc<dyn PacketAdapter>) {
        let metadata = packet.metadata();

        let mut addr: Option<UdpAddr> = None;

        let target_addr = {
            let origin_to_target = self.origin_to_target.read();
            origin_to_target.get(&metadata.string()).copied().flatten()
        };

        if let Some(target_addr) = target_addr {
            addr = Some(UdpAddr::new(target_addr, metadata.dst_port));
        }

        if addr.is_none() {
            let origin_metadata = metadata.clone();
            let mut metadata = metadata.clone();

            let _ = pre_handle_metadata(&mut metadata).await;
            let mut metadata = metadata.pure();
            if !metadata.host.is_empty() {
                if let Err(err) = pc.resolve_udp(&self.cancel, &mut metadata).await {
                    warnln!("[UDP] Resolve Ip error: {err}");
                    return;
                }
            }

            if metadata.dst_ip.is_none() {
                warnln!("[UDP] Destination ip not valid: {metadata:?}");
                return;
            }
            self.add_mapping(&origin_metadata, &metadata);
            addr = metadata.udp_addr();
        }
        let _ = handle_udp_to_remote(packet.as_ref(), pc.as_ref(), addr).await;
    }
}

#[async_trait]
impl PacketSender for PacketSenderImpl {
    // cancel-safe: the packet is either queued or dropped, never half-written.
    async fn send(&self, packet: Arc<dyn PacketAdapter>) {
        if self.cancel.is_cancelled() {
            packet.drop_();
            return;
        }

        match self.tx.try_send(packet) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(packet) | mpsc::error::TrySendError::Closed(packet)) => packet.drop_(),
        }
    }

    // NOT cancel-safe: the loop owns the write-back proxy's packet stream.
    #[expect(
        clippy::significant_drop_tightening,
        reason = "the receiver lock has to stay held for every select iteration"
    )]
    async fn process(&self, conn: Arc<dyn PacketConn>, proxy: Arc<dyn WriteBackProxy>) {
        let mut rx = self.rx.lock().await;
        loop {
            tokio::select! {
                () = self.cancel.cancelled() => return,
                packet = rx.recv() => {
                    let Some(packet) = packet else { return };
                    // Unannotated on purpose: the parameter of `update_write_back`
                    // is the trait object, and an annotation here would force
                    // `Arc::clone` to resolve its parameter from the target type.
                    let write_back = Arc::clone(&packet);
                    proxy.update_write_back(write_back);
                    self.process_packet(&conn, &packet).await;
                }
            }
        }
    }

    fn close(&self) {
        self.cancel.cancel();
        if let Ok(mut rx) = self.rx.try_lock() {
            while let Ok(packet) = rx.try_recv() {
                packet.drop_();
            }
        }
    }

    // cancel-safe: it awaits nothing and holds no state.
    async fn do_sniff(&self, _metadata: &mut Metadata) -> Result<()> {
        Ok(())
    }

    fn add_mapping(&self, origin_metadata: &Metadata, metadata: &Metadata) {
        let origin_key = origin_metadata.string();
        let origin_addr = origin_metadata.dst_ip;
        let target_addr = metadata.dst_ip;

        {
            let mut origin_to_target = self.origin_to_target.write();
            if origin_to_target.get(&origin_key).copied().flatten().is_none() {
                origin_to_target.insert(origin_key, target_addr);
            }
        }
        if let Some(target_addr) = target_addr {
            let mut target_to_origin = self.target_to_origin.write();
            if let std::collections::hash_map::Entry::Vacant(e) = target_to_origin.entry(target_addr) {
                if let Some(origin_addr) = origin_addr {
                    e.insert(origin_addr);
                }
            }
        }
    }

    fn restore_read_from(&self, addr: IpAddr) -> IpAddr {
        self.target_to_origin.read().get(&addr).copied().unwrap_or(addr)
    }
}

// cancel-safe: it forwards a single datagram and keeps no state of its own.
async fn handle_udp_to_remote(packet: &dyn UDPPacket, pc: &dyn PacketConn, addr: Option<UdpAddr>) -> Result<()> {
    let Some(addr) = addr else {
        return Err(anyhow!("udp addr invalid"));
    };

    pc.write_to(packet.data(), &addr).await?;
    let _ = pc.set_read_deadline(Some(tokio::time::Instant::now() + UDP_TIMEOUT));

    Ok(())
}

// NOT cancel-safe: a cancel skips the sender close and nat-table cleanup at the end.
pub(crate) async fn handle_udp_to_local(
    write_back: Arc<dyn WriteBack>,
    pc: Arc<dyn PacketConn>,
    sender: Arc<dyn PacketSender>,
    key: String,
    o_addr_port: SocketAddr,
) {
    loop {
        let _ = pc.set_read_deadline(Some(tokio::time::Instant::now() + UDP_TIMEOUT));
        let (data, put, from, result) = pc.wait_read_from().await;
        if result.is_err() {
            break;
        }

        let from_udp_addr = match from.as_deref().and_then(murmur_std_compat::net::sock_addr_of) {
            Some(murmur_std_compat::net::SockAddr::Udp(addr)) => addr,
            Some(murmur_std_compat::net::SockAddr::Tcp(_)) | None => {
                warnln!(
                    "[UDP] server return a [{}] which isn't a UDP address, force replace to ({o_addr_port}), this may be caused by a wrongly implemented server",
                    from.as_ref().map_or_else(|| "<nil>".to_owned(), |addr| addr.string()),
                );
                UdpAddr::from(o_addr_port)
            }
        };

        let from_addr_port = SocketAddr::new(from_udp_addr.ip, from_udp_addr.port);
        let from_addr = unmap(from_addr_port.ip());

        let from_addr = unmap(sender.restore_read_from(from_addr));

        let from_addr_port = SocketAddr::new(from_addr, from_addr_port.port());

        let result = write_back.write_back(&data, Some(from_addr_port)).await;
        if let Some(put) = put {
            put();
        } else {
            let _ = murmur_common_pool::put(data);
        }
        if result.is_err() {
            break;
        }
    }

    sender.close();
    let _ = pc.close();
    close_all_local_conn(&key);
    nat_table().delete(&key);
}

fn unmap(ip: IpAddr) -> IpAddr {
    unmap_addr(Some(ip)).unwrap_or(ip)
}

fn close_all_local_conn(l_addr: &str) {
    nat_table().range_for_local_conn(l_addr, &mut |key, _conn| {
        debugln!("Closing TProxy local conn... lAddr={l_addr} rAddr={key}");
        true
    });
}

// NOT cancel-safe: a cancel drops the half-forwarded byte stream.
pub(crate) async fn handle_socket(inbound: &mut dyn Stream, outbound: &mut dyn Stream) {
    murmur_common_net::relay_streams(inbound, outbound).await;
}
