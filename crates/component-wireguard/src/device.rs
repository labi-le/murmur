//! The WireGuard device: peers, allowed-IPs routing, handshake initiation and response, retries,
//! rekeying, keepalives and the transport data path.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use ipnet::IpNet;
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use murmur_log::{debugln, errorln, warnln};

use crate::bind::ReservedBind;
use crate::cookie::{address_bytes, CookieChecker, CookieGenerator, MessageCookieReply, MESSAGE_COOKIE_REPLY_SIZE};
use crate::crypto::{self, Aead};
use crate::handshake::{
    responder::Responder, Initiator, MESSAGE_CONTENT_MAX_SIZE, MESSAGE_INITIATION_SIZE, MESSAGE_MAX_SIZE,
    MESSAGE_MIN_SIZE, MESSAGE_RESPONSE_SIZE, MESSAGE_TRANSPORT_HEADER_SIZE, MESSAGE_TRANSPORT_SIZE,
    TRANSPORT_OFFSET_CONTENT, TRANSPORT_OFFSET_COUNTER, TRANSPORT_OFFSET_RECEIVER, TYPE_COOKIE_REPLY, TYPE_INITIATION,
    TYPE_RESPONSE, TYPE_TRANSPORT,
};
use crate::keys::{PresharedKey, PublicKey, StaticKey};
use crate::replay::ReplayFilter;
use crate::stack::Events;

pub const QUEUE_HANDSHAKE_SIZE: usize = 1024;
pub const UNDER_LOAD_AFTER_TIME: Duration = Duration::from_secs(1);
/// The under-load threshold, queue size divided by 8.
const UNDER_LOAD_THRESHOLD: usize = QUEUE_HANDSHAKE_SIZE / 8;

const REJECT_AFTER_MESSAGES: u64 = u64::MAX - (1 << 13) - 1;
const REKEY_AFTER_MESSAGES: u64 = 1 << 60;
const REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
/// The interval between handshake retransmits.
const REKEY_TIMEOUT: Duration = Duration::from_secs(5);
const REKEY_TIMEOUT_JITTER_MS: u64 = 334;
const REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_TIMER_HANDSHAKES: u32 = 18;
/// The floor between two consumed initiations from one peer.
const HANDSHAKE_INITIATION_RATE: Duration = Duration::from_millis(200);
const PADDING_MULTIPLE: usize = 16;
const STAGED_QUEUE_SIZE: usize = 1024;
const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const MAX_PEERS: usize = 1 << 16;
/// The tun channel bound, matching the capacity the inbound/outbound queues give.
const TUN_QUEUE_SIZE: usize = 256;

type PeerId = usize;

#[derive(Clone, Debug)]
pub struct PeerConfig {
    pub public_key: PublicKey,
    /// `preshared_key`; zeroed when the configuration omits it.
    pub preshared_key: PresharedKey,
    /// `endpoint`, already resolved by the caller.
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<IpNet>,
    /// `persistent_keepalive_interval`, in seconds; `0` disables it.
    pub persistent_keepalive: u16,
}

impl PeerConfig {
    /// A peer before an IPC set fills the rest in.
    #[must_use]
    pub fn new(public_key: PublicKey) -> Self {
        Self {
            public_key,
            preshared_key: PresharedKey::zeroed(),
            endpoint: None,
            allowed_ips: Vec::new(),
            persistent_keepalive: 0,
        }
    }
}

/// Device configuration: the UAPI `private_key` plus the peer list.
///
/// The `workers` argument only sizes the encryption, decryption and handshake worker pools; it
/// selects no protocol constant, message layout or timer. This device runs in one async task, so
/// `adapter::outbound::wireguard`'s `workers` option is accepted and unused.
#[derive(Clone, Debug)]
pub struct DeviceConfig {
    pub private_key: StaticKey,
    pub peers: Vec<PeerConfig>,
    /// The tun MTU, which bounds the transport padding and the content size check.
    pub mtu: u16,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Slot {
    Current,
    Previous,
    /// The next slot: the responder parks a new session here until the initiator
    /// proves it holds it by sending under it.
    Next,
}

#[derive(Clone, Copy)]
enum IndexEntry {
    Handshake(PeerId),
    Keypair(PeerId, Slot),
}

struct Keypair {
    local_index: u32,
    remote_index: u32,
    send: Aead,
    receive: Aead,
    send_counter: u64,
    replay: ReplayFilter,
    created: Instant,
}

#[derive(Default, Clone)]
struct Timers {
    retransmit_handshake: Option<Instant>,
    send_keepalive: Option<Instant>,
    new_handshake: Option<Instant>,
    zero_key_material: Option<Instant>,
    persistent_keepalive: Option<Instant>,
    need_another_keepalive: bool,
}

struct Peer {
    config: PeerConfig,
    endpoint: Option<SocketAddr>,
    current: Option<Keypair>,
    previous: Option<Keypair>,
    next: Option<Keypair>,
    /// The peer's cookie generator, keyed by its static public key.
    cookie_generator: CookieGenerator,
    initiator: Option<Initiator>,
    /// The responder half of a handshake this device is answering. `Responder` carries the
    /// last accepted TAI64N stamp, so it outlives any single message.
    responder: Option<Responder>,
    staged: VecDeque<Vec<u8>>,
    last_handshake: Option<Instant>,
    last_sent_handshake: Option<Instant>,
    last_initiation: Option<Instant>,
    sent_minute_handshake: bool,
    handshake_attempts: u32,
    timers: Timers,
}

enum Command {
    UpdatePeers(Vec<PeerConfig>),
}

/// A packet device, as a pair of channels between the IP stack and the device.
pub struct Tun {
    to_device: mpsc::Sender<Vec<u8>>,
    from_device: mpsc::Receiver<Vec<u8>>,
    events: Events,
}

impl core::fmt::Debug for Tun {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Tun").finish_non_exhaustive()
    }
}

impl Tun {
    /// The device's event stream, which the IP stack waits on before reading the device.
    #[must_use]
    pub fn events(&self) -> Events {
        self.events.clone()
    }

    /// hand one packet to the device. A full channel drops
    pub fn write(&self, packet: Vec<u8>) {
        match self.to_device.try_send(packet) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {}
            Err(err) => errorln!("[WireGuard] failed to queue packet for the device: {err}"),
        }
    }

    /// A non-blocking read from the tun. `smoltcp`'s `Device::receive` is
    /// synchronous, so a full tun cannot be awaited here.
    pub fn try_receive(&mut self) -> Option<Vec<u8>> {
        self.from_device.try_recv().ok()
    }
}

/// The running device. Configuration changes go through [`Device::update_peers`], which is
/// An IPC set with `update_only`.
pub struct Device {
    bind: Arc<ReservedBind>,
    command_tx: mpsc::UnboundedSender<Command>,
    closed: CancellationToken,
    is_up: AtomicBool,
}

impl core::fmt::Debug for Device {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Device").field("is_up", &self.is_up()).finish_non_exhaustive()
    }
}

impl Device {
    /// Device construction, configuration and bring-up. The
    /// returned [`Tun`] is the IP stack's end of the device.
    pub fn new(name: String, bind: Arc<ReservedBind>, config: DeviceConfig) -> Result<(Arc<Self>, Tun)> {
        let (to_device_tx, to_device_rx) = mpsc::channel(TUN_QUEUE_SIZE);
        let (from_device_tx, from_device_rx) = mpsc::channel(TUN_QUEUE_SIZE);
        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let closed = CancellationToken::new();
        let events = Events::default();
        let state = State::new(config)?;

        let device = Arc::new(Self {
            bind: Arc::clone(&bind),
            command_tx,
            closed: closed.clone(),
            is_up: AtomicBool::new(true),
        });
        tokio::spawn(
            DeviceRun {
                name,
                bind,
                tun_tx: from_device_tx,
                tun_rx: to_device_rx,
                events: events.clone(),
                state,
                load: Load::default(),
                command_rx,
                closed,
            }
            .run(),
        );

        Ok((device, Tun { to_device: to_device_tx, from_device: from_device_rx, events }))
    }

    /// Applies a peer update: refresh endpoints, keepalives, allowed
    /// IPs and pre-shared keys of the named peers, add the new ones, drop the rest.
    #[expect(clippy::unused_async, reason = "the caller awaits this along with the rest of the device API")]
    pub async fn update_peers(&self, peers: Vec<PeerConfig>) -> Result<()> {
        self.command_tx.send(Command::UpdatePeers(peers)).map_err(|_| anyhow!("wireguard device is closed"))
    }

    pub fn close(&self) -> Result<()> {
        self.is_up.store(false, Ordering::Relaxed);
        self.closed.cancel();
        let _ = self.bind.close();
        Ok(())
    }

    #[must_use]
    pub fn is_up(&self) -> bool {
        self.is_up.load(Ordering::Relaxed) && !self.closed.is_cancelled()
    }
}

struct State {
    static_key: StaticKey,
    /// The device's cookie checker, keyed by its own static public key.
    cookie_checker: CookieChecker,
    mtu: usize,
    peers: Vec<Peer>,
    by_public: HashMap<PublicKey, PeerId>,
    index: HashMap<u32, IndexEntry>,
}

impl State {
    fn new(config: DeviceConfig) -> Result<Self> {
        if config.peers.len() > MAX_PEERS {
            return Err(anyhow!("too many peers: {}", config.peers.len()));
        }
        let cookie_checker = CookieChecker::new(config.private_key.public_key().as_bytes());
        let mut state = Self {
            static_key: config.private_key,
            cookie_checker,
            mtu: usize::from(config.mtu.max(1)),
            peers: Vec::new(),
            by_public: HashMap::new(),
            index: HashMap::new(),
        };
        state.update_peers(&config.peers);
        Ok(state)
    }

    /// A peer update: a known public key updates in place, an unknown one
    /// is added, and a peer missing from the request is removed.
    fn update_peers(&mut self, configs: &[PeerConfig]) {
        let mut keep = vec![false; self.peers.len()];
        for config in configs {
            if let Some(id) = self.by_public.get(&config.public_key).copied() {
                if let Some(kept) = keep.get_mut(id) {
                    *kept = true;
                }
                let Some(peer) = self.peers.get_mut(id) else {
                    continue;
                };
                peer.config.preshared_key = config.preshared_key;
                peer.config.allowed_ips.clone_from(&config.allowed_ips);
                peer.config.persistent_keepalive = config.persistent_keepalive;
                peer.config.endpoint = config.endpoint;
                peer.endpoint = config.endpoint;
            } else {
                let id = self.peers.len();
                let cookie_generator = CookieGenerator::new(config.public_key.as_bytes());
                self.peers.push(Peer {
                    config: config.clone(),
                    endpoint: config.endpoint,
                    current: None,
                    previous: None,
                    next: None,
                    cookie_generator,
                    initiator: None,
                    responder: None,
                    staged: VecDeque::new(),
                    last_handshake: None,
                    last_sent_handshake: None,
                    last_initiation: None,
                    sent_minute_handshake: false,
                    handshake_attempts: 0,
                    timers: Timers::default(),
                });
                self.by_public.insert(config.public_key, id);
                keep.push(true);
            }
        }
        self.remove_peers(&keep);
    }

    fn remove_peers(&mut self, keep: &[bool]) {
        if keep.iter().all(|kept| *kept) {
            return;
        }
        let mut retained: HashMap<PeerId, PeerId> = HashMap::new();
        let previous = std::mem::take(&mut self.peers);
        for (id, peer) in previous.into_iter().enumerate() {
            if !keep.get(id).copied().unwrap_or(false) {
                continue;
            }
            retained.insert(id, self.peers.len());
            self.peers.push(peer);
        }
        self.index.retain(|_, entry| {
            let id = match *entry {
                IndexEntry::Handshake(id) | IndexEntry::Keypair(id, _) => id,
            };
            retained.contains_key(&id)
        });
        self.by_public = self.peers.iter().enumerate().map(|(id, peer)| (peer.config.public_key, id)).collect();
    }

    /// The peer whose allowed IPs hold `address` by the longest matching prefix.
    fn lookup_peer(&self, address: IpAddr) -> Option<PeerId> {
        let mut best: Option<(u8, PeerId)> = None;
        for (id, peer) in self.peers.iter().enumerate() {
            for allowed in &peer.config.allowed_ips {
                if allowed.contains(&address) && best.is_none_or(|(len, _)| allowed.prefix_len() > len) {
                    best = Some((allowed.prefix_len(), id));
                }
            }
        }
        best.map(|(_, id)| id)
    }

    /// The initiator branch of a symmetric-session handoff: the new keypair becomes
    /// `current` at once, anything parked in `next` becomes `previous`, and the keypairs
    /// before those are forgotten.
    fn install_initiator_keypair(&mut self, peer_id: PeerId, keypair: Keypair) {
        {
            let Some(peer) = self.peers.get_mut(peer_id) else {
                return;
            };
            let previous = peer.previous.take();
            let current = peer.current.take();
            let next = peer.next.take();
            peer.previous = next.or(current);
            peer.current = Some(keypair);
            drop(previous);
        }
        self.reindex_keypairs(peer_id);
    }

    /// The responder branch of a symmetric-session handoff: the new keypair waits in
    /// `next` until `promote_next_keypair` sees traffic under it, while `current` keeps
    /// carrying this peer's own sends.
    fn install_responder_keypair(&mut self, peer_id: PeerId, keypair: Keypair) {
        {
            let Some(peer) = self.peers.get_mut(peer_id) else {
                return;
            };
            let previous = peer.previous.take();
            let next = peer.next.take();
            peer.next = Some(keypair);
            drop((previous, next));
        }
        self.reindex_keypairs(peer_id);
    }

    /// the initiator has proved it derived the parked
    /// session, so the peer starts sending under it and the keypair it replaces becomes
    /// `previous`.
    fn promote_next_keypair(&mut self, peer_id: PeerId) {
        let promoted = {
            let Some(peer) = self.peers.get_mut(peer_id) else {
                return;
            };
            match peer.next.take() {
                Some(next) => {
                    let previous = peer.previous.take();
                    peer.previous = peer.current.take();
                    peer.current = Some(next);
                    drop(previous);
                    true
                }
                None => false,
            }
        };
        if promoted {
            self.reindex_keypairs(peer_id);
        }
    }

    /// Re-indexes the keypairs after a rotation: the
    /// index names the peer for every local index it still holds, and nothing else.
    fn reindex_keypairs(&mut self, peer_id: PeerId) {
        let slots = {
            let Some(peer) = self.peers.get(peer_id) else {
                return;
            };
            [
                (Slot::Current, peer.current.as_ref().map(|keypair| keypair.local_index)),
                (Slot::Previous, peer.previous.as_ref().map(|keypair| keypair.local_index)),
                (Slot::Next, peer.next.as_ref().map(|keypair| keypair.local_index)),
            ]
        };
        self.index.retain(|_, entry| !matches!(*entry, IndexEntry::Keypair(id, _) if id == peer_id));
        for (slot, local_index) in slots {
            if let Some(local_index) = local_index {
                self.index.insert(local_index, IndexEntry::Keypair(peer_id, slot));
            }
        }
    }

    /// Allocates a random index for a new handshake, which must not collide.
    fn new_index(&self) -> u32 {
        loop {
            let candidate = rand::random::<u32>();
            if candidate != 0 && !self.index.contains_key(&candidate) {
                return candidate;
            }
        }
    }
}

struct DeviceRun {
    name: String,
    bind: Arc<ReservedBind>,
    tun_tx: mpsc::Sender<Vec<u8>>,
    tun_rx: mpsc::Receiver<Vec<u8>>,
    events: Events,
    state: State,
    load: Load,
    command_rx: mpsc::UnboundedReceiver<Command>,
    closed: CancellationToken,
}

/// Whether the device is under load, which a handshake-queue depth would otherwise show: a burst
/// of handshakes leaves a backlog. This device handles each datagram inline in one task, so no
/// such queue exists; the arrival rate of handshake messages stands in for its depth, with
/// a queue-size/8 threshold and a hold-off.
///
/// A per-source token bucket (20 packets a second with a burst of 5) is not implemented: a peer
/// whose `mac2` verifies is served without that second limit. Only a device that answers
/// handshakes is exposed, and this project's own WireGuard outbound only ever initiates.
#[derive(Default)]
struct Load {
    window_start: Option<Instant>,
    messages: usize,
    under_load_until: Option<Instant>,
}

impl Load {
    fn note_handshake(&mut self, now: Instant) {
        match self.window_start {
            Some(start) if now.duration_since(start) < UNDER_LOAD_AFTER_TIME => self.messages += 1,
            _ => {
                self.window_start = Some(now);
                self.messages = 1;
            }
        }
        if self.messages >= UNDER_LOAD_THRESHOLD {
            self.under_load_until = Some(now + UNDER_LOAD_AFTER_TIME);
        }
    }

    fn is_under_load(&self, now: Instant) -> bool {
        self.under_load_until.is_some_and(|until| until > now)
    }
}

impl DeviceRun {
    async fn run(mut self) {
        let mut buffer = vec![0u8; MESSAGE_MAX_SIZE];
        loop {
            let deadline = self.next_deadline();
            let timer = async {
                match deadline {
                    Some(at) => tokio::time::sleep_until(at).await,
                    None => std::future::pending::<()>().await,
                }
            };
            tokio::select! {
                biased;
                () = self.closed.cancelled() => break,
                command = self.command_rx.recv() => match command {
                    Some(Command::UpdatePeers(peers)) => self.state.update_peers(&peers),
                    None => break,
                },
                received = self.bind.recv_from(&mut buffer) => match received {
                    Ok((size, source)) => self.handle_incoming(buffer.get(..size).unwrap_or_default(), source).await,
                    Err(err) => {
                        errorln!("[WireGuard]({}) failed to read packet: {err}", self.name);
                        tokio::time::sleep(Duration::from_millis(300)).await;
                    }
                },
                packet = self.tun_rx.recv() => {
                    if let Some(packet) = packet {
                        self.handle_tunnel_packet(packet).await;
                    }
                }
                () = timer => self.handle_timers().await,
            }
        }
        let _ = self.bind.close();
        debugln!("[WireGuard]({}) device stopped", self.name);
    }

    fn next_deadline(&self) -> Option<Instant> {
        let mut earliest: Option<Instant> = None;
        for peer in &self.state.peers {
            for at in [
                peer.timers.retransmit_handshake,
                peer.timers.send_keepalive,
                peer.timers.new_handshake,
                peer.timers.zero_key_material,
                peer.timers.persistent_keepalive,
                peer.current.as_ref().map(|keypair| keypair.created + REKEY_AFTER_TIME),
            ]
            .into_iter()
            .flatten()
            {
                earliest = Some(earliest.map_or(at, |current: Instant| current.min(at)));
            }
        }
        earliest
    }

    async fn handle_tunnel_packet(&mut self, packet: Vec<u8>) {
        if packet.is_empty() {
            return;
        }
        let Some(destination) = ip_destination(&packet) else {
            debugln!("[WireGuard]({}) received packet with unknown IP version", self.name);
            return;
        };
        let Some(peer_id) = self.state.lookup_peer(destination) else {
            debugln!("[WireGuard]({}) no peer for destination {destination}", self.name);
            return;
        };
        self.stage(peer_id, packet);
        self.send_staged(peer_id).await;
    }

    /// Stages a packet, dropping the oldest when the queue is full.
    fn stage(&mut self, peer_id: PeerId, packet: Vec<u8>) {
        let Some(peer) = self.state.peers.get_mut(peer_id) else {
            return;
        };
        if peer.staged.len() >= STAGED_QUEUE_SIZE {
            peer.staged.pop_front();
        }
        peer.staged.push_back(packet);
    }

    /// staged packets leave under the current keypair, or the
    /// peer starts a handshake and the queue waits for it.
    async fn send_staged(&mut self, peer_id: PeerId) {
        loop {
            if !self.keypair_is_fresh(peer_id) {
                self.send_handshake_initiation(peer_id, false).await;
                return;
            }
            let Some(packet) = self.state.peers.get_mut(peer_id).and_then(|peer| peer.staged.pop_front()) else {
                return;
            };
            let Some((endpoint, message)) = self.encrypt(peer_id, &packet) else {
                return;
            };
            if let Err(err) = self.transmit(endpoint, &message).await {
                errorln!("[WireGuard]({}) failed to send packet to {endpoint}: {err}", self.name);
                return;
            }
            self.timers_data_sent(peer_id);
        }
    }

    /// The staleness test before staged packets are sent.
    fn keypair_is_fresh(&self, peer_id: PeerId) -> bool {
        let Some(peer) = self.state.peers.get(peer_id) else {
            return false;
        };
        match &peer.current {
            Some(keypair) => {
                keypair.send_counter < REJECT_AFTER_MESSAGES
                    && Instant::now().duration_since(keypair.created) < REJECT_AFTER_TIME
            }
            None => false,
        }
    }

    /// Encrypts one packet.
    fn encrypt(&mut self, peer_id: PeerId, packet: &[u8]) -> Option<(SocketAddr, Vec<u8>)> {
        if packet.len() > MESSAGE_CONTENT_MAX_SIZE {
            debugln!("[WireGuard]({}) dropping oversized packet of {} bytes", self.name, packet.len());
            return None;
        }
        let peer = self.state.peers.get_mut(peer_id)?;
        let endpoint = peer.endpoint?;
        let keypair = peer.current.as_mut()?;
        let counter = keypair.send_counter;
        keypair.send_counter += 1;

        let mut content = Vec::with_capacity(packet.len() + PADDING_MULTIPLE);
        content.extend_from_slice(packet);
        content.resize(content.len() + padding_size(packet.len(), self.state.mtu), 0);

        let mut message = Vec::with_capacity(MESSAGE_TRANSPORT_HEADER_SIZE + content.len() + crypto::TAG_SIZE);
        message.extend_from_slice(&TYPE_TRANSPORT.to_le_bytes());
        message.extend_from_slice(&keypair.remote_index.to_le_bytes());
        message.extend_from_slice(&counter.to_le_bytes());
        match keypair.send.seal(&crypto::transport_nonce(counter), &[], &content) {
            Ok(sealed) => message.extend_from_slice(&sealed),
            Err(err) => {
                errorln!("[WireGuard]({}) failed to seal packet for {endpoint}: {err}", self.name);
                return None;
            }
        }
        Some((endpoint, message))
    }

    async fn transmit(&self, endpoint: SocketAddr, packet: &[u8]) -> Result<()> {
        self.bind.send_to(packet, endpoint).await.map_err(anyhow::Error::from)
    }

    async fn send_handshake_initiation(&mut self, peer_id: PeerId, is_retry: bool) {
        if !is_retry {
            if let Some(peer) = self.state.peers.get_mut(peer_id) {
                peer.handshake_attempts = 0;
            }
        }
        let now = Instant::now();
        {
            let Some(peer) = self.state.peers.get_mut(peer_id) else {
                return;
            };
            if peer.last_sent_handshake.is_some_and(|last| now.duration_since(last) < REKEY_TIMEOUT) {
                return;
            }
            peer.last_sent_handshake = Some(now);
        }

        let local_index = self.state.new_index();
        let (initiator, mut packet) = {
            let Some(peer) = self.state.peers.get(peer_id) else {
                return;
            };
            match Initiator::create_message_initiation(&self.state.static_key, &peer.config.public_key, local_index) {
                Ok(created) => created,
                Err(err) => {
                    errorln!("[WireGuard]({}) failed to create initiation message: {err}", self.name);
                    return;
                }
            }
        };
        self.state.index.insert(local_index, IndexEntry::Handshake(peer_id));
        let endpoint = {
            let Some(peer) = self.state.peers.get_mut(peer_id) else {
                return;
            };
            peer.initiator = Some(initiator);
            peer.cookie_generator.add_macs(&mut packet);
            peer.endpoint
        };

        let Some(endpoint) = endpoint else {
            return;
        };
        if let Err(err) = self.transmit(endpoint, &packet).await {
            errorln!("[WireGuard]({}) failed to send handshake initiation: {err}", self.name);
        }
        let jitter = Duration::from_millis(rand::random::<u64>() % REKEY_TIMEOUT_JITTER_MS);
        if let Some(peer) = self.state.peers.get_mut(peer_id) {
            peer.timers.retransmit_handshake = Some(now + REKEY_TIMEOUT + jitter);
        }
        self.timers_any_authenticated_packet_sent(peer_id);
        self.timers_any_authenticated_packet_traversal(peer_id);
    }

    /// an empty transport message.
    async fn send_keepalive(&mut self, peer_id: PeerId) {
        let Some((endpoint, message)) = self.encrypt(peer_id, &[]) else {
            return;
        };
        if let Err(err) = self.transmit(endpoint, &message).await {
            errorln!("[WireGuard]({}) failed to send keepalive: {err}", self.name);
        }
        self.timers_any_authenticated_packet_sent(peer_id);
        self.timers_any_authenticated_packet_traversal(peer_id);
    }

    /// Handles one incoming datagram: handshake or transport.
    // NOT cancel-safe: the packet is already consumed from the socket and the handler writes replies and mutates handshake state as it runs, so a dropped call cannot be retried.
    async fn handle_incoming(&mut self, packet: &[u8], source: SocketAddr) {
        if packet.len() < MESSAGE_MIN_SIZE {
            return;
        }
        let message_type = u32_at(packet, 0);
        match message_type {
            TYPE_INITIATION if packet.len() == MESSAGE_INITIATION_SIZE => {
                self.handle_handshake(packet, source, true).await;
            }
            TYPE_RESPONSE if packet.len() == MESSAGE_RESPONSE_SIZE => {
                self.handle_handshake(packet, source, false).await;
            }
            TYPE_COOKIE_REPLY if packet.len() == MESSAGE_COOKIE_REPLY_SIZE => self.handle_cookie_reply(packet),
            TYPE_TRANSPORT if packet.len() >= MESSAGE_TRANSPORT_SIZE => self.handle_transport(packet, source).await,
            _ => debugln!("[WireGuard]({}) received message with unknown type", self.name),
        }
    }

    /// The `mac1` check and the under-load branch, which runs
    /// before either handshake message is consumed.
    async fn handle_handshake(&mut self, packet: &[u8], source: SocketAddr, is_initiation: bool) {
        let now = Instant::now();
        self.load.note_handshake(now);
        if !self.state.cookie_checker.check_mac1(packet) {
            debugln!("[WireGuard]({}) received packet with invalid mac1", self.name);
            return;
        }
        if self.load.is_under_load(now) && !self.state.cookie_checker.check_mac2(packet, &address_bytes(source.ip())) {
            self.send_cookie_reply(packet, source).await;
            return;
        }
        if is_initiation {
            self.handle_initiation(packet, source).await;
        } else {
            self.handle_response(packet, source).await;
        }
    }

    async fn send_cookie_reply(&mut self, packet: &[u8], source: SocketAddr) {
        debugln!("[WireGuard]({}) sending cookie response for denied handshake message for {source}", self.name);
        let receiver = u32_at(packet, 4);
        let reply = match self.state.cookie_checker.create_reply(packet, receiver, &address_bytes(source.ip())) {
            Ok(reply) => reply,
            Err(err) => {
                errorln!("[WireGuard]({}) failed to create cookie reply: {err}", self.name);
                return;
            }
        };
        if let Err(err) = self.transmit(source, &reply.marshal()).await {
            errorln!("[WireGuard]({}) failed to send cookie reply to {source}: {err}", self.name);
        }
    }

    /// The cookie-reply branch: the reply is
    /// addressed by the handshake index it answers, and only that peer's generator can open
    /// it, since the cookie is sealed against the `mac1` of the message it denied.
    fn handle_cookie_reply(&mut self, packet: &[u8]) {
        let reply = match MessageCookieReply::unmarshal(packet) {
            Ok(reply) => reply,
            Err(err) => {
                debugln!("[WireGuard]({}) failed to decode cookie reply: {err}", self.name);
                return;
            }
        };
        let Some(IndexEntry::Handshake(peer_id) | IndexEntry::Keypair(peer_id, _)) =
            self.state.index.get(&reply.receiver).copied()
        else {
            return;
        };
        let Some(peer) = self.state.peers.get_mut(peer_id) else {
            return;
        };
        if peer.cookie_generator.consume_reply(&reply) {
            debugln!("[WireGuard]({}) receiving cookie response", self.name);
        } else {
            debugln!("[WireGuard]({}) could not decrypt invalid cookie response", self.name);
        }
    }

    /// Consumes a handshake response, installs the session and sends a keepalive.
    async fn handle_response(&mut self, packet: &[u8], source: SocketAddr) {
        let receiver = u32_at(packet, 8);
        let Some(IndexEntry::Handshake(peer_id)) = self.state.index.get(&receiver).copied() else {
            debugln!("[WireGuard]({}) received response for an unknown handshake", self.name);
            return;
        };
        let session = {
            let Some(peer) = self.state.peers.get(peer_id) else {
                return;
            };
            let Some(initiator) = peer.initiator.as_ref() else {
                return;
            };
            if let Ok(session) =
                initiator.consume_message_response(&self.state.static_key, &peer.config.preshared_key, packet)
            {
                session
            } else {
                debugln!("[WireGuard]({}) received invalid response from {source}", self.name);
                return;
            }
        };

        let now = Instant::now();
        self.state.install_initiator_keypair(
            peer_id,
            Keypair {
                local_index: session.local_index,
                remote_index: session.remote_index,
                send: Aead::new(&session.send_key),
                receive: Aead::new(&session.recv_key),
                send_counter: 0,
                replay: ReplayFilter::default(),
                created: now,
            },
        );
        {
            let Some(peer) = self.state.peers.get_mut(peer_id) else {
                return;
            };
            peer.initiator = None;
            peer.last_handshake = Some(now);
            peer.sent_minute_handshake = false;
            peer.handshake_attempts = 0;
            peer.timers.retransmit_handshake = None;
            peer.timers.zero_key_material = Some(now + REJECT_AFTER_TIME * 3);
            set_endpoint(&mut peer.endpoint, source);
        }

        debugln!("[WireGuard]({}) received handshake response from {source}", self.name);
        self.send_keepalive(peer_id).await;
        self.send_staged(peer_id).await;
    }

    /// The responder branch: consume the initiation, build the response and install the session,
    /// which parks the new keypair in the next slot until `handle_transport` sees traffic under it.
    async fn handle_initiation(&mut self, packet: &[u8], source: SocketAddr) {
        let mut responder = Responder::new();
        let Ok(remote_static) = responder.consume_static(&self.state.static_key, packet) else {
            return;
        };
        let Some(peer_id) = self.state.by_public.get(&remote_static).copied() else {
            return;
        };
        let now = Instant::now();
        {
            let Some(peer) = self.state.peers.get_mut(peer_id) else {
                return;
            };
            if peer.last_initiation.is_some_and(|last| now.duration_since(last) <= HANDSHAKE_INITIATION_RATE) {
                return;
            }
            responder.carry_replay_stamp(peer.responder.as_ref());
            if responder.consume_timestamp(&self.state.static_key, &peer.config.preshared_key, packet).is_err() {
                peer.responder = Some(responder);
                return;
            }
            peer.last_initiation = Some(now);
            peer.responder = Some(responder);
        }

        let local_index = self.state.new_index();
        let (mut response, session) = {
            let Some(peer) = self.state.peers.get(peer_id) else {
                return;
            };
            match peer.responder.as_ref().map(|it| it.create_message_response(local_index)) {
                Some(Ok(created)) => created,
                _ => return,
            }
        };
        if let Some(peer) = self.state.peers.get_mut(peer_id) {
            peer.cookie_generator.add_macs(&mut response);
        }
        self.state.install_responder_keypair(
            peer_id,
            Keypair {
                local_index: session.local_index,
                remote_index: session.remote_index,
                send: Aead::new(&session.send_key),
                receive: Aead::new(&session.recv_key),
                send_counter: 0,
                replay: ReplayFilter::default(),
                created: now,
            },
        );
        {
            let Some(peer) = self.state.peers.get_mut(peer_id) else {
                return;
            };
            peer.last_handshake = Some(now);
            peer.handshake_attempts = 0;
            peer.timers.retransmit_handshake = None;
            peer.timers.zero_key_material = Some(now + REJECT_AFTER_TIME * 3);
            peer.endpoint = Some(source);
        }

        debugln!("[WireGuard]({}) received handshake initiation from {source}", self.name);
        if let Err(err) = self.transmit(source, &response).await {
            errorln!("[WireGuard]({}) failed to send handshake response to {source}: {err}", self.name);
            return;
        }
        self.timers_any_authenticated_packet_sent(peer_id);
        self.timers_any_authenticated_packet_traversal(peer_id);
    }

    /// Handles one authenticated transport message.
    async fn handle_transport(&mut self, packet: &[u8], source: SocketAddr) {
        let receiver = u32_at(packet, TRANSPORT_OFFSET_RECEIVER);
        let Some(IndexEntry::Keypair(peer_id, slot)) = self.state.index.get(&receiver).copied() else {
            return;
        };
        let counter = u64_at(packet, TRANSPORT_OFFSET_COUNTER);
        if counter >= REJECT_AFTER_MESSAGES {
            return;
        }

        let plaintext = {
            let Some(peer) = self.state.peers.get_mut(peer_id) else {
                return;
            };
            let keypair = match slot {
                Slot::Current => peer.current.as_mut(),
                Slot::Previous => peer.previous.as_mut(),
                Slot::Next => peer.next.as_mut(),
            };
            let Some(keypair) = keypair else {
                return;
            };
            if Instant::now().duration_since(keypair.created) >= REJECT_AFTER_TIME {
                return;
            }
            let content = packet.get(TRANSPORT_OFFSET_CONTENT..).unwrap_or_default();
            match keypair.receive.open(&crypto::transport_nonce(counter), &[], content) {
                Ok(plaintext) if keypair.replay.validate_counter(counter) => plaintext,
                _ => return,
            }
        };

        if slot == Slot::Next {
            self.state.promote_next_keypair(peer_id);
            self.send_staged(peer_id).await;
        }
        if let Some(peer) = self.state.peers.get_mut(peer_id) {
            set_endpoint(&mut peer.endpoint, source);
        }
        if plaintext.is_empty() {
            debugln!("[WireGuard]({}) receiving keepalive packet from {source}", self.name);
            self.timers_authenticated_received(peer_id);
            self.timers_data_received(peer_id);
            self.keep_key_fresh_receiving(peer_id).await;
            return;
        }
        let Some(trimmed) = trim_to_ip_length(&plaintext) else {
            return;
        };
        let Some(source_address) = ip_source(&trimmed) else {
            return;
        };
        if self.state.lookup_peer(source_address) != Some(peer_id) {
            debugln!("[WireGuard]({}) packet with disallowed source address {source_address}", self.name);
            return;
        }
        self.timers_authenticated_received(peer_id);
        self.timers_data_received(peer_id);
        self.keep_key_fresh_receiving(peer_id).await;
        match self.tun_tx.try_send(trimmed) {
            Ok(()) => self.events.notify(),
            Err(mpsc::error::TrySendError::Full(_)) => {}
            Err(err) => errorln!("[WireGuard]({}) failed to write packet to the tun device: {err}", self.name),
        }
    }

    fn timers_data_sent(&mut self, peer_id: PeerId) {
        let Some(peer) = self.state.peers.get_mut(peer_id) else {
            return;
        };
        if peer.timers.new_handshake.is_none() {
            let jitter = Duration::from_millis(rand::random::<u64>() % REKEY_TIMEOUT_JITTER_MS);
            peer.timers.new_handshake = Some(Instant::now() + KEEPALIVE_TIMEOUT + REKEY_TIMEOUT + jitter);
        }
        self.timers_any_authenticated_packet_traversal(peer_id);
    }

    fn timers_data_received(&mut self, peer_id: PeerId) {
        let Some(peer) = self.state.peers.get_mut(peer_id) else {
            return;
        };
        match peer.timers.send_keepalive {
            None => peer.timers.send_keepalive = Some(Instant::now() + KEEPALIVE_TIMEOUT),
            Some(_) => peer.timers.need_another_keepalive = true,
        }
        self.timers_any_authenticated_packet_traversal(peer_id);
    }

    fn timers_any_authenticated_packet_sent(&mut self, peer_id: PeerId) {
        if let Some(peer) = self.state.peers.get_mut(peer_id) {
            peer.timers.send_keepalive = None;
        }
    }

    fn timers_authenticated_received(&mut self, peer_id: PeerId) {
        if let Some(peer) = self.state.peers.get_mut(peer_id) {
            peer.timers.new_handshake = None;
        }
    }

    fn timers_any_authenticated_packet_traversal(&mut self, peer_id: PeerId) {
        let Some(peer) = self.state.peers.get_mut(peer_id) else {
            return;
        };
        let keepalive = peer.config.persistent_keepalive;
        if keepalive > 0 {
            let at = Instant::now() + Duration::from_secs(u64::from(keepalive));
            peer.timers.persistent_keepalive = Some(at);
        }
    }

    async fn keep_key_fresh_sending(&mut self, peer_id: PeerId) {
        let now = Instant::now();
        let Some(peer) = self.state.peers.get(peer_id) else {
            return;
        };
        let rekey = match &peer.current {
            Some(keypair) => {
                keypair.send_counter > REKEY_AFTER_MESSAGES || now.duration_since(keypair.created) > REKEY_AFTER_TIME
            }
            None => false,
        };
        if rekey {
            self.send_handshake_initiation(peer_id, false).await;
        }
    }

    async fn keep_key_fresh_receiving(&mut self, peer_id: PeerId) {
        let now = Instant::now();
        let Some(peer) = self.state.peers.get(peer_id) else {
            return;
        };
        let stale = match &peer.current {
            Some(keypair) => {
                let stale_after = REJECT_AFTER_TIME.saturating_sub(KEEPALIVE_TIMEOUT).saturating_sub(REKEY_TIMEOUT);
                now.duration_since(keypair.created) > stale_after
                    && peer.last_handshake.is_none_or(|at| now.duration_since(at) >= Duration::from_secs(60))
            }
            None => false,
        };
        let minute_handshake_sent = peer.sent_minute_handshake;
        if stale && !minute_handshake_sent {
            if let Some(peer) = self.state.peers.get_mut(peer_id) {
                peer.sent_minute_handshake = true;
            }
            self.send_handshake_initiation(peer_id, false).await;
        }
    }

    /// Runs the peer timer checks: keepalive, handshake retransmit and the rest.
    async fn handle_timers(&mut self) {
        let now = Instant::now();
        for peer_id in 0..self.state.peers.len() {
            let Some(timers) = self.state.peers.get(peer_id).map(|peer| peer.timers.clone()) else {
                continue;
            };
            if timers.persistent_keepalive.is_some_and(|at| at <= now) {
                self.expire_persistent_keepalive(peer_id).await;
            }
            if timers.retransmit_handshake.is_some_and(|at| at <= now) {
                self.expire_retransmit_handshake(peer_id, now).await;
            }
            if timers.new_handshake.is_some_and(|at| at <= now) {
                self.expire_new_handshake(peer_id).await;
            }
            if timers.send_keepalive.is_some_and(|at| at <= now) {
                self.expire_send_keepalive(peer_id).await;
            }
            if timers.zero_key_material.is_some_and(|at| at <= now) {
                self.expire_zero_key_material(peer_id);
            }
            self.keep_key_fresh_sending(peer_id).await;
        }
    }

    /// The persistent-keepalive interval passed, so a keepalive goes out when configured.
    async fn expire_persistent_keepalive(&mut self, peer_id: PeerId) {
        let keepalive = {
            let Some(peer) = self.state.peers.get_mut(peer_id) else {
                return;
            };
            peer.timers.persistent_keepalive = None;
            peer.config.persistent_keepalive
        };
        if keepalive > 0 {
            self.send_keepalive(peer_id).await;
        }
    }

    /// The handshake retransmit is due: retry, or give up once the attempts ran out.
    async fn expire_retransmit_handshake(&mut self, peer_id: PeerId, now: Instant) {
        let (gave_up, attempts) = {
            let Some(peer) = self.state.peers.get_mut(peer_id) else {
                return;
            };
            peer.timers.retransmit_handshake = None;
            if peer.handshake_attempts > MAX_TIMER_HANDSHAKES {
                if peer.staged.is_empty() {
                    peer.timers.zero_key_material = Some(now + REJECT_AFTER_TIME * 3);
                } else {
                    peer.handshake_attempts = 0;
                }
                (true, peer.handshake_attempts)
            } else {
                peer.handshake_attempts += 1;
                (false, peer.handshake_attempts)
            }
        };
        if gave_up {
            debugln!(
                "[WireGuard]({}) handshake did not complete after {} attempts, giving up",
                self.name,
                MAX_TIMER_HANDSHAKES + 2
            );
        } else {
            warnln!(
                "[WireGuard]({}) handshake did not complete in {}s, retrying (try {})",
                self.name,
                REKEY_TIMEOUT.as_secs(),
                attempts + 1
            );
            self.send_handshake_initiation(peer_id, true).await;
        }
    }

    /// The new-handshake timer expired: nothing was heard back, so the handshake is retried.
    async fn expire_new_handshake(&mut self, peer_id: PeerId) {
        if let Some(peer) = self.state.peers.get_mut(peer_id) {
            peer.timers.new_handshake = None;
        }
        warnln!(
            "[WireGuard]({}) retrying handshake because we stopped hearing back after {}s",
            self.name,
            (KEEPALIVE_TIMEOUT + REKEY_TIMEOUT).as_secs()
        );
        self.send_handshake_initiation(peer_id, false).await;
    }

    /// The keepalive timer expired, including the follow-up a peer that already asked for one gets.
    async fn expire_send_keepalive(&mut self, peer_id: PeerId) {
        if let Some(peer) = self.state.peers.get_mut(peer_id) {
            peer.timers.send_keepalive = None;
        }
        self.send_keepalive(peer_id).await;
        if self.state.peers.get(peer_id).is_some_and(|peer| peer.timers.need_another_keepalive) {
            if let Some(peer) = self.state.peers.get_mut(peer_id) {
                peer.timers.need_another_keepalive = false;
                peer.timers.send_keepalive = Some(Instant::now() + KEEPALIVE_TIMEOUT);
            }
        }
    }

    /// The zero-key-material timer expired: the session went too long without a new one, so
    /// every keypair goes.
    fn expire_zero_key_material(&mut self, peer_id: PeerId) {
        if let Some(peer) = self.state.peers.get_mut(peer_id) {
            peer.timers.zero_key_material = None;
        }
        warnln!(
            "[WireGuard]({}) removing all keys, since we haven't received a new one in {}s",
            self.name,
            (REJECT_AFTER_TIME * 3).as_secs()
        );
        if let Some(peer) = self.state.peers.get_mut(peer_id) {
            peer.current = None;
            peer.previous = None;
            peer.next = None;
            peer.initiator = None;
        }
        self.state.reindex_keypairs(peer_id);
    }
}

/// an authenticated packet may move the peer to the
/// address it came from, which is how a roaming NAT rebinding is picked up.
fn set_endpoint(current: &mut Option<SocketAddr>, source: SocketAddr) {
    if *current != Some(source) {
        *current = Some(source);
    }
}

fn padding_size(packet_size: usize, mtu: usize) -> usize {
    let unit = if packet_size > mtu { packet_size % mtu } else { packet_size };
    unit.div_ceil(PADDING_MULTIPLE).saturating_mul(PADDING_MULTIPLE).saturating_sub(unit)
}

/// The little-endian `u32` at `offset`; zeroes when the message stops short of it.
fn u32_at(packet: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(packet.get(offset..offset + 4).and_then(|bytes| bytes.try_into().ok()).unwrap_or_default())
}

/// The little-endian `u64` at `offset`; zeroes when the message stops short of it.
fn u64_at(packet: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(packet.get(offset..offset + 8).and_then(|bytes| bytes.try_into().ok()).unwrap_or_default())
}

/// The big-endian `u16` at `offset`, or `None` when the packet stops short of it.
fn u16_at(packet: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes(packet.get(offset..offset + 2)?.try_into().ok()?))
}

fn ip_header_len(packet: &[u8]) -> Option<usize> {
    let first = *packet.first()?;
    match first >> 4 {
        4 => {
            let header_len = usize::from(first & 0x0f) * 4;
            (header_len >= IPV4_HEADER_LEN).then_some(header_len)
        }
        6 => Some(IPV6_HEADER_LEN),
        _ => None,
    }
}

/// The packet's destination address.
fn ip_destination(packet: &[u8]) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        4 => Some(IpAddr::from(<[u8; 4]>::try_from(packet.get(16..20)?).ok()?)),
        6 => Some(IpAddr::from(<[u8; 16]>::try_from(packet.get(24..40)?).ok()?)),
        _ => None,
    }
}

fn ip_source(packet: &[u8]) -> Option<IpAddr> {
    match packet.first()? >> 4 {
        4 => Some(IpAddr::from(<[u8; 4]>::try_from(packet.get(12..16)?).ok()?)),
        6 => Some(IpAddr::from(<[u8; 16]>::try_from(packet.get(8..24)?).ok()?)),
        _ => None,
    }
}

/// Trims a transport payload to the IP packet's own length.
fn trim_to_ip_length(packet: &[u8]) -> Option<Vec<u8>> {
    let header_len = ip_header_len(packet)?;
    if packet.len() < header_len {
        return None;
    }
    let total = match packet.first()? >> 4 {
        4 => usize::from(u16_at(packet, 2)?),
        _ => IPV6_HEADER_LEN + usize::from(u16_at(packet, 4)?),
    };
    if total < header_len || total > packet.len() {
        return None;
    }
    Some(packet.get(..total)?.to_vec())
}
