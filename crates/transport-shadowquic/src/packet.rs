use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::{Arc, Weak};

use async_trait::async_trait;
use parking_lot::Mutex as SyncMutex;
use tokio::sync::{mpsc, Mutex as AsyncMutex};

use crate::protocol::{
    addr_from_net_addr, encode_datagram, read_udp_control, write_packet_stream_header, write_packet_stream_payload,
    write_udp_control, ErrPacketTooLarge, MAX_UDP_PACKET_SIZE,
};
use crate::state::{ConnState, ReceivedPacket, UdpMode};
use murmur_common_net::deadline::pipe::{make_pipe_deadline, CloseSignal, PipeDeadline};
use murmur_common_net::WaitReadFrom;
use murmur_quic::{SendStream, Stream, StreamReadHalf, StreamWriteHalf};
use murmur_std_compat::net::deadline_time;
use murmur_std_compat::net::{Addr, PacketConn};

pub(crate) const PACKET_INPUT_QUEUE: usize = 128;

fn err_net_closed() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "use of closed network connection")
}

fn err_deadline_exceeded() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "i/o timeout")
}

struct AssociationInner {
    send_ids: HashMap<Vec<u8>, u16>,
    send_id_set: HashSet<u16>,
    recv_id_set: HashSet<u16>,
    uni_streams: HashMap<Vec<u8>, Box<dyn SendStream>>,
    control_write: Box<dyn StreamWriteHalf>,
}

pub(crate) struct Association {
    self_weak: Weak<Self>,
    parent: Arc<ConnState>,
    mode: UdpMode,

    input_tx: mpsc::Sender<ReceivedPacket>,
    input_rx: AsyncMutex<mpsc::Receiver<ReceivedPacket>>,

    inner: AsyncMutex<AssociationInner>,

    closed: Arc<CloseSignal>,
    close_started: std::sync::atomic::AtomicBool,
    close_err: SyncMutex<Option<io::Error>>,

    read_deadline: PipeDeadline,
    write_deadline: PipeDeadline,
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "the crate-internal constructor takes the caller's owned `Arc` handle; its signature is the interface `client.rs` and `server.rs` build against"
)]
pub(crate) fn new_association(parent: Arc<ConnState>, control: Box<dyn Stream>, mode: UdpMode) -> Arc<Association> {
    let (control_read, control_write) = control.split();
    let (input_tx, input_rx) = mpsc::channel(PACKET_INPUT_QUEUE);

    let assoc = Arc::new_cyclic(|self_weak| Association {
        self_weak: Weak::clone(self_weak),
        parent: Arc::clone(&parent),
        mode,
        input_tx,
        input_rx: AsyncMutex::new(input_rx),
        inner: AsyncMutex::new(AssociationInner {
            send_ids: HashMap::new(),
            send_id_set: HashSet::new(),
            recv_id_set: HashSet::new(),
            uni_streams: HashMap::new(),
            control_write,
        }),
        closed: Arc::new(CloseSignal::default()),
        close_started: std::sync::atomic::AtomicBool::new(false),
        close_err: SyncMutex::new(None),
        read_deadline: make_pipe_deadline(),
        write_deadline: make_pipe_deadline(),
    });

    tokio::spawn(read_control(Arc::clone(&assoc), control_read));
    tokio::spawn({
        let assoc = Arc::clone(&assoc);
        let parent_ctx = parent.ctx.clone();
        async move {
            parent_ctx.cancelled().await;
            let _ = assoc.close().await;
        }
    });

    assoc
}

// NOT cancel-safe: a dropped future skips the trailing `cancel_read`/`close` cleanup, but the
// spawned task is never aborted, so the loop always reaches it.
async fn read_control(assoc: Arc<Association>, mut control_read: Box<dyn StreamReadHalf>) {
    loop {
        tokio::select! {
            result = read_udp_control(&mut control_read) => {
                match result {
                    Ok((addr, id)) => {
                        {
                            let mut inner = assoc.inner.lock().await;
                            inner.recv_id_set.insert(id);
                        }
                        assoc.parent.store_recv(id, &assoc, &addr);
                    }
                    Err(_) => break,
                }
            }
            () = assoc.closed.wait() => break,
        }
    }
    control_read.cancel_read(0);
    let _ = assoc.close().await;
}

impl Association {
    #[expect(
        clippy::expect_used,
        reason = "an `Association` is only ever reached through an `Arc`, and the caller's own handle is alive for the whole call, so the weak self-reference always upgrades"
    )]
    fn arc(&self) -> Arc<Self> {
        self.self_weak.upgrade().expect("association dropped while still in use")
    }

    pub(crate) fn deliver(&self, packet: ReceivedPacket) {
        if self.closed.is_closed() {
            return;
        }
        let _ = self.input_tx.try_send(packet);
    }

    /// Closes the association, folding the one-shot guard into an atomic.
    pub(crate) async fn close(self: &Arc<Self>) -> io::Result<()> {
        self.closed.close();
        if self
            .close_started
            .compare_exchange(false, true, std::sync::atomic::Ordering::SeqCst, std::sync::atomic::Ordering::SeqCst)
            .is_ok()
        {
            let result = self.close_inner().await;
            *self.close_err.lock() = result.err();
        }
        match &*self.close_err.lock() {
            Some(err) => Err(io::Error::new(err.kind(), err.to_string())),
            None => Ok(()),
        }
    }

    async fn close_inner(self: &Arc<Self>) -> io::Result<()> {
        let (send_id_set, recv_id_set, uni_streams, close_result) = {
            let mut inner = self.inner.lock().await;
            let _ = inner.control_write.set_write_deadline(Some(tokio::time::Instant::now()));

            let send_id_set = inner.send_id_set.clone();
            let recv_id_set = inner.recv_id_set.clone();
            let uni_streams = std::mem::take(&mut inner.uni_streams);
            let close_result = inner.control_write.close();
            drop(inner);
            (send_id_set, recv_id_set, uni_streams, close_result)
        };

        for (_, stream) in uni_streams {
            let _ = stream.close();
        }

        self.parent.release_send_ids(&send_id_set);
        self.parent.remove_recv_ids(self, &recv_id_set);

        close_result
    }

    pub(crate) fn local_addr(&self) -> Box<dyn Addr> {
        self.parent.quic_conn.local_addr()
    }

    /// The select over the incoming queue and the closed signal, used directly by
    /// `Server::handle_association` (the server drives an association's packets internally instead
    /// of exposing its own read surfaces to an external caller).
    // cancel-safe: the queue keeps any packet a cancelled receive had not taken, and the lock
    // guard is released with the future.
    pub(crate) async fn recv_for_server(&self) -> Option<ReceivedPacket> {
        let mut rx = self.input_rx.lock().await;
        let packet = tokio::select! {
            packet = rx.recv() => packet,
            () = self.closed.wait() => None,
        };
        drop(rx);
        packet
    }

    /// Writes a packet, shared by the packet-conn and write-back call sites.
    async fn write_to_addr(&self, p: &[u8], addr: Option<&dyn Addr>) -> anyhow::Result<usize> {
        if p.len() > MAX_UDP_PACKET_SIZE {
            return Err(ErrPacketTooLarge.into());
        }
        if self.closed.is_closed() {
            return Err(err_net_closed().into());
        }
        if self.write_deadline.wait().is_closed() {
            return Err(err_deadline_exceeded().into());
        }

        let socks_addr = addr_from_net_addr(addr)?;
        let key = socks_addr.to_vec();

        let mut inner = self.inner.lock().await;

        let id = if let Some(id) = inner.send_ids.get(&key).copied() {
            id
        } else {
            let id = self.parent.alloc_send_id()?;
            if let Err(err) = write_udp_control(&mut inner.control_write, &socks_addr, id).await {
                drop(inner);
                self.parent.release_send_ids(&HashSet::from([id]));
                return Err(err);
            }
            inner.send_ids.insert(key.clone(), id);
            inner.send_id_set.insert(id);
            id
        };

        match self.mode {
            UdpMode::Stream => {
                if !inner.uni_streams.contains_key(&key) {
                    let mut stream = self.parent.quic_conn.open_uni_stream_sync(&self.parent.ctx).await?;
                    if let Err(err) = write_packet_stream_header(&mut stream, id).await {
                        let _ = stream.close();
                        return Err(err.into());
                    }
                    inner.uni_streams.insert(key.clone(), stream);
                }
                if let Some(stream) = inner.uni_streams.get_mut(&key) {
                    write_packet_stream_payload(stream, p).await?;
                }
            }
            UdpMode::Datagram => {
                let packet = encode_datagram(id, p)?;
                self.parent.quic_conn.send_datagram(packet)?;
            }
        }
        drop(inner);

        Ok(p.len())
    }
}

#[async_trait]
impl PacketConn for Association {
    // cancel-safe: an unread packet stays queued, and dropping the future releases the input lock.
    async fn read_from(&self, buf: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        let mut rx = self.input_rx.lock().await;
        let read_deadline = self.read_deadline.wait();
        let result = tokio::select! {
            packet = rx.recv() => match packet {
                Some(packet) => {
                    let n = packet.data.len().min(buf.len());
                    if let (Some(dst), Some(src)) = (buf.get_mut(..n), packet.data.get(..n)) {
                        dst.copy_from_slice(src);
                    }
                    let addr: Box<dyn Addr> = Box::new(packet.addr);
                    Ok((n, addr))
                }
                None => Err(err_net_closed()),
            },
            () = self.closed.wait() => Err(err_net_closed()),
            () = read_deadline.wait() => Err(err_deadline_exceeded()),
        };
        drop(rx);
        result
    }

    async fn write_to(&self, buf: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        self.write_to_addr(buf, Some(addr)).await.map_err(|err| match err.downcast::<io::Error>() {
            Ok(io_err) => io_err,
            Err(err) => io::Error::other(err),
        })
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        Ok(Self::local_addr(self))
    }

    fn close(&self) -> io::Result<()> {
        let assoc = self.arc();
        tokio::spawn(async move {
            let _ = assoc.close().await;
        });
        Ok(())
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        let t = deadline_time(deadline);
        self.read_deadline.set(t);
        self.write_deadline.set(t);
        Ok(())
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.read_deadline.set(deadline_time(deadline));
        Ok(())
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.write_deadline.set(deadline_time(deadline));
        Ok(())
    }
}

#[async_trait]
impl WaitReadFrom for Association {
    // cancel-safe: as `read_from`.
    async fn wait_read_from(
        &self,
    ) -> (Vec<u8>, Option<Box<dyn FnOnce() + Send>>, Option<Box<dyn Addr>>, io::Result<()>) {
        let mut rx = self.input_rx.lock().await;
        let read_deadline = self.read_deadline.wait();
        let result = tokio::select! {
            packet = rx.recv() => match packet {
                Some(packet) => {
                    let addr: Box<dyn Addr> = Box::new(packet.addr);
                    (packet.data, None, Some(addr), Ok(()))
                }
                None => (Vec::new(), None, None, Err(err_net_closed())),
            },
            () = self.closed.wait() => (Vec::new(), None, None, Err(err_net_closed())),
            () = read_deadline.wait() => (Vec::new(), None, None, Err(err_deadline_exceeded())),
        };
        drop(rx);
        result
    }
}

/// A boxable packet-conn handle over a shared association. A direct
/// `impl PacketConn for Arc<Association>` would shadow `Association`'s own
/// inherent methods (`local_addr`, `close`) at existing `Arc<Association>` call
/// sites elsewhere in this crate, so the delegation lives on this distinct
/// newtype instead.
pub(crate) struct AssociationHandle(pub(crate) Arc<Association>);

#[async_trait]
impl PacketConn for AssociationHandle {
    async fn read_from(&self, buf: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        PacketConn::read_from(&*self.0, buf).await
    }

    async fn write_to(&self, buf: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        PacketConn::write_to(&*self.0, buf, addr).await
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        Ok(self.0.local_addr())
    }

    fn close(&self) -> io::Result<()> {
        let assoc = Arc::clone(&self.0);
        tokio::spawn(async move {
            let _ = assoc.close().await;
        });
        Ok(())
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        PacketConn::set_deadline(&*self.0, deadline)
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        PacketConn::set_read_deadline(&*self.0, deadline)
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        PacketConn::set_write_deadline(&*self.0, deadline)
    }
}

#[async_trait]
impl WaitReadFrom for AssociationHandle {
    // NOT cancel-safe: a dropped call has already consumed datagram framing from the socket, so a later read would start mid-frame; every `select!` arm that awaits it drops it only while the connection is being torn down.
    async fn wait_read_from(
        &self,
    ) -> (Vec<u8>, Option<Box<dyn FnOnce() + Send>>, Option<Box<dyn Addr>>, io::Result<()>) {
        WaitReadFrom::wait_read_from(&*self.0).await
    }
}

/// The write-back surface a server UDP packet exposes.
pub(crate) async fn write_back(
    assoc: &Association,
    b: &[u8],
    addr: Option<std::net::SocketAddr>,
) -> anyhow::Result<usize> {
    let addr_owned = addr.map(murmur_common_net::io::udp_addr_from_socket_addr);
    let addr: Option<&dyn Addr> = match &addr_owned {
        Some(a) => Some(a),
        None => None,
    };
    assoc.write_to_addr(b, addr).await
}
