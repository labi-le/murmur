use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;

use crate::packet::Association;
use crate::protocol::{decode_datagram, read_uint16, NetAddr};
use murmur_common_net::deadline::pipe::CloseSignal;
use murmur_quic::jls::Conn as JlsConn;
use murmur_quic::{ApplicationErrorCode, ReceiveStream};
use murmur_transport::socks5::socks5;

pub(crate) const MAX_PENDING_PACKETS_PER_ID: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UdpMode {
    Datagram,
    Stream,
}

#[derive(Clone)]
pub(crate) struct ReceivedPacket {
    pub(crate) data: Vec<u8>,
    pub(crate) addr: NetAddr,
    pub(crate) socks_addr: socks5::Addr,
}

pub(crate) struct RecvTarget {
    pub(crate) assoc: Arc<Association>,
    pub(crate) addr: socks5::Addr,
    pub(crate) net: NetAddr,
}

struct RecvSlot {
    ready: Arc<CloseSignal>,
    target: Option<Arc<RecvTarget>>,
    pending: Vec<Vec<u8>>,
}

impl RecvSlot {
    fn new() -> Self {
        Self { ready: Arc::new(CloseSignal::default()), target: None, pending: Vec::new() }
    }
}

struct ConnStateInner {
    next_id: u16,
    active_send: HashSet<u16>,
    recv: HashMap<u16, RecvSlot>,
}

pub(crate) struct ConnState {
    pub(crate) quic_conn: Arc<dyn JlsConn>,
    pub(crate) ctx: CancellationToken,

    inner: Mutex<ConnStateInner>,
}

pub(crate) fn new_conn_state(quic_conn: Arc<dyn JlsConn>) -> Arc<ConnState> {
    // Linking the child context to the parent connection's lifetime is what
    // `CancellationToken::child_token` already does.
    let ctx = quic_conn.closed().child_token();
    let state = Arc::new(ConnState {
        quic_conn,
        ctx,
        inner: Mutex::new(ConnStateInner { next_id: 0, active_send: HashSet::new(), recv: HashMap::new() }),
    });

    tokio::spawn({
        let state = Arc::clone(&state);
        async move { state.handle_datagrams().await }
    });
    tokio::spawn({
        let state = Arc::clone(&state);
        async move { state.handle_uni_streams().await }
    });

    state
}

impl ConnState {
    pub(crate) fn closed(&self) -> bool {
        self.ctx.is_cancelled()
    }

    pub(crate) fn close_with_error(&self, code: ApplicationErrorCode, message: &str) -> std::io::Result<()> {
        self.ctx.cancel();
        self.quic_conn.close_with_error(code, message)
    }

    async fn handle_datagrams(self: Arc<Self>) {
        loop {
            let Ok(message) = self.quic_conn.receive_datagram(&self.ctx).await else {
                self.ctx.cancel();
                return;
            };
            let Ok((id, payload)) = decode_datagram(&message) else {
                continue;
            };
            self.feed_datagram(id, payload);
        }
    }

    async fn handle_uni_streams(self: Arc<Self>) {
        loop {
            let Ok(stream) = self.quic_conn.accept_uni_stream(&self.ctx).await else {
                self.ctx.cancel();
                return;
            };
            tokio::spawn({
                let state = Arc::clone(&self);
                async move { state.handle_uni_stream(stream).await }
            });
        }
    }

    async fn handle_uni_stream(&self, mut stream: Box<dyn ReceiveStream>) {
        let _ = self.handle_uni_stream_inner(&mut stream).await;
        stream.cancel_read(0);
    }

    async fn handle_uni_stream_inner(&self, stream: &mut Box<dyn ReceiveStream>) -> anyhow::Result<()> {
        let id = read_uint16(stream).await?;
        let target = self.wait_recv_target(id).await?;

        loop {
            let length = read_uint16(stream).await?;
            let mut payload = vec![0u8; length as usize];
            stream.read_exact(&mut payload).await?;
            target.assoc.deliver(ReceivedPacket {
                data: payload,
                addr: target.net.clone(),
                socks_addr: target.addr.clone(),
            });
        }
    }

    fn feed_datagram(&self, id: u16, payload: &[u8]) {
        let mut inner = self.inner.lock();
        if let Some(slot) = inner.recv.get(&id) {
            if let Some(target) = slot.target.clone() {
                drop(inner);
                target.assoc.deliver(ReceivedPacket {
                    data: payload.to_vec(),
                    addr: target.net.clone(),
                    socks_addr: target.addr.clone(),
                });
                return;
            }
        }
        let slot = inner.recv.entry(id).or_insert_with(RecvSlot::new);
        if slot.pending.len() < MAX_PENDING_PACKETS_PER_ID {
            slot.pending.push(payload.to_vec());
        }
        drop(inner);
    }

    // cancel-safe: each iteration re-reads the slot, so a drop simply stops waiting.
    async fn wait_recv_target(&self, id: u16) -> anyhow::Result<Arc<RecvTarget>> {
        loop {
            let ready = {
                let mut inner = self.inner.lock();
                let slot = inner.recv.entry(id).or_insert_with(RecvSlot::new);
                if let Some(target) = slot.target.clone() {
                    return Ok(target);
                }
                let ready = Arc::clone(&slot.ready);
                drop(inner);
                ready
            };

            tokio::select! {
                () = ready.wait() => {}
                () = self.ctx.cancelled() => return Err(anyhow::anyhow!("use of closed network connection")),
            }
        }
    }

    pub(crate) fn store_recv(&self, id: u16, assoc: &Arc<Association>, addr: &socks5::Addr) {
        let net_addr = crate::protocol::addr_to_net_addr(addr);

        let pending = {
            let mut inner = self.inner.lock();
            let slot = inner.recv.entry(id).or_insert_with(RecvSlot::new);
            let was_pending = slot.target.is_none();
            slot.target =
                Some(Arc::new(RecvTarget { assoc: Arc::clone(assoc), addr: addr.clone(), net: net_addr.clone() }));
            let pending = std::mem::take(&mut slot.pending);
            if was_pending {
                slot.ready.close();
            }
            drop(inner);
            pending
        };

        for packet in pending {
            assoc.deliver(ReceivedPacket { data: packet, addr: net_addr.clone(), socks_addr: addr.clone() });
        }
    }

    pub(crate) fn remove_recv_ids(&self, assoc: &Arc<Association>, ids: &HashSet<u16>) {
        let mut inner = self.inner.lock();
        for id in ids {
            let remove = match inner.recv.get(id) {
                Some(slot) => match &slot.target {
                    Some(target) => Arc::ptr_eq(&target.assoc, assoc),
                    None => false,
                },
                None => false,
            };
            if remove {
                inner.recv.remove(id);
            }
        }
    }

    pub(crate) fn alloc_send_id(&self) -> anyhow::Result<u16> {
        let mut inner = self.inner.lock();
        let start = inner.next_id;
        loop {
            let id = inner.next_id;
            inner.next_id = inner.next_id.wrapping_add(1);
            if inner.active_send.insert(id) {
                return Ok(id);
            }
            if inner.next_id == start {
                return Err(ErrorsTooManyUdpContexts.into());
            }
        }
    }

    pub(crate) fn release_send_ids(&self, ids: &HashSet<u16>) {
        let mut inner = self.inner.lock();
        for id in ids {
            inner.active_send.remove(id);
        }
    }
}

#[derive(thiserror::Error, Debug, Clone, Copy)]
#[error("shadowquic: too many udp contexts")]
pub(crate) struct ErrorsTooManyUdpContexts;
