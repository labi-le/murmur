use std::any::Any;
use std::fmt;
use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use murmur_common::atomic::type_::{new_int64, Int64};
use murmur_common::utils::uuid::new_uuid_v4;
use murmur_common_net::sing::{ExtendedConn, UpstreamNode};
use murmur_common_net::{ReaderWithUpstream, WaitReadFrom, WithUpstream, WriterWithUpstream};
use murmur_compat::sing_buf::Buffer;
use murmur_constant::adapters::{
    Chain, Conn as ConstantConn, Connection, PacketConn as ConstantPacketConn, ProxyAdapter,
};
use murmur_constant::metadata::Metadata;
use murmur_constant::rule::Rule;
use murmur_std_compat::net::{Addr, Conn, PacketConn};

use super::manager::Manager;

pub trait Tracker: Connection {
    fn id(&self) -> String;

    fn close(&self) -> io::Result<()>;

    fn info(&self) -> Arc<TrackerInfo>;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TrackerInfo {
    #[serde(rename = "id", with = "uuid_json")]
    pub uuid: Uuid,
    #[serde(rename = "metadata", with = "metadata_json")]
    pub metadata: Arc<Metadata>,
    #[serde(rename = "upload")]
    pub upload_total: Int64,
    #[serde(rename = "download")]
    pub download_total: Int64,
    #[serde(rename = "start", with = "murmur_common::time_rfc3339")]
    pub start: DateTime<Utc>,
    #[serde(rename = "chains", with = "chain_json")]
    pub chain: Chain,
    #[serde(rename = "providerChains", with = "chain_json")]
    pub provider_chain: Chain,
    #[serde(rename = "rule")]
    pub rule: String,
    #[serde(rename = "rulePayload")]
    pub rule_payload: String,
}

/// The caller and the manager's connection list share one handle.
///
/// A `&mut` conn cannot come out of a shared `Arc`, so the conn lives behind a lock in
/// [`TcpTrackerInner`] and this handle gives the caller its `&mut` view.
pub struct TcpTracker {
    inner: Arc<TcpTrackerInner>,
    close_view: TcpTrackerCloseView,
}

struct TcpTrackerInner {
    conn: Mutex<Box<dyn ConstantConn>>,
    tracker_info: Arc<TrackerInfo>,
    manager: Arc<Manager>,
    push_to_manager: bool,
}

impl TcpTracker {
    #[must_use]
    pub fn id(&self) -> String {
        self.inner.id()
    }

    #[must_use]
    pub fn info(&self) -> Arc<TrackerInfo> {
        Arc::clone(&self.inner.tracker_info)
    }
}

impl fmt::Debug for TcpTracker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpTracker").field("uuid", &self.inner.tracker_info.uuid).finish_non_exhaustive()
    }
}

impl AsyncRead for TcpTracker {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = {
            let mut conn = this.inner.conn.lock();
            Pin::new(&mut **conn).poll_read(cx, buf)
        };
        #[expect(clippy::cast_possible_wrap, reason = "a read count is bounded by the buffer length")]
        let download = (buf.filled().len() - before) as i64;
        if download != 0 {
            if this.inner.push_to_manager {
                this.inner.manager.push_downloaded(download);
            }
            this.inner.tracker_info.download_total.add(download);
        }
        result
    }
}

impl AsyncWrite for TcpTracker {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = {
            let mut conn = this.inner.conn.lock();
            Pin::new(&mut **conn).poll_write(cx, buf)
        };
        if let Poll::Ready(Ok(n)) = &result {
            #[expect(clippy::cast_possible_wrap, reason = "a write count is bounded by the buffer length")]
            let upload = *n as i64;
            if this.inner.push_to_manager {
                this.inner.manager.push_uploaded(upload);
            }
            this.inner.tracker_info.upload_total.add(upload);
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut conn = this.inner.conn.lock();
        Pin::new(&mut **conn).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let mut conn = this.inner.conn.lock();
        Pin::new(&mut **conn).poll_shutdown(cx)
    }
}

/// Close-only view of [`TcpTrackerInner`], the `Stream::old_conn` target below (the same pattern
/// the H2 transport in `transport-vmess` uses):
///
/// `TcpTracker` itself never implements the old [`Conn`], so this is the only place production and
/// test code can still reach it directly.
struct TcpTrackerCloseView(Arc<TcpTrackerInner>);

/// Never actually polled: forwards to the same locked conn `TcpTracker`'s own `AsyncRead`/
/// `AsyncWrite` use, purely to satisfy `Conn: AsyncRead + AsyncWrite`.
impl AsyncRead for TcpTrackerCloseView {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let mut conn = self.get_mut().0.conn.lock();
        Pin::new(&mut **conn).poll_read(cx, buf)
    }
}

impl AsyncWrite for TcpTrackerCloseView {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let mut conn = self.get_mut().0.conn.lock();
        Pin::new(&mut **conn).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut conn = self.get_mut().0.conn.lock();
        Pin::new(&mut **conn).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut conn = self.get_mut().0.conn.lock();
        Pin::new(&mut **conn).poll_shutdown(cx)
    }
}

impl Conn for TcpTrackerCloseView {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.0
            .conn
            .lock()
            .local_addr()
            .map(|addr| -> Box<dyn Addr> { Box::new(murmur_std_compat::net::TcpAddr::from(addr)) })
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.0
            .conn
            .lock()
            .peer_addr()
            .map(|addr| -> Box<dyn Addr> { Box::new(murmur_std_compat::net::TcpAddr::from(addr)) })
    }

    /// Reaches [`Tracker::close`] on the shared [`TcpTrackerInner`], deregistering from the
    /// manager exactly once regardless of how many `dyn Conn`/`Stream` handles this is called
    /// through.
    fn close(&self) -> io::Result<()> {
        self.0.close()
    }

    fn close_read(&self) -> io::Result<()> {
        self.0.conn.lock().shutdown_read()
    }

    fn close_write(&self) -> io::Result<()> {
        self.0.conn.lock().shutdown_write()
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        match self.0.conn.lock().old_conn() {
            Some(inner) => inner.set_deadline(deadline),
            None => Ok(()),
        }
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        match self.0.conn.lock().old_conn() {
            Some(inner) => inner.set_read_deadline(deadline),
            None => Ok(()),
        }
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        match self.0.conn.lock().old_conn() {
            Some(inner) => inner.set_write_deadline(deadline),
            None => Ok(()),
        }
    }
}

impl murmur_common_net::io::Stream for TcpTracker {
    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.conn.lock().local_addr()
    }

    fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.conn.lock().peer_addr()
    }

    fn shutdown_read(&self) -> io::Result<()> {
        self.inner.conn.lock().shutdown_read()
    }

    fn shutdown_write(&self) -> io::Result<()> {
        self.inner.conn.lock().shutdown_write()
    }

    fn as_socket(&self) -> Option<socket2::SockRef<'_>> {
        None
    }

    fn old_conn(&self) -> Option<&dyn Conn> {
        Some(&self.close_view)
    }
}

impl murmur_common_net::io::ExtendedStream for TcpTracker {
    fn reader_replaceable(&self) -> bool {
        self.inner.conn.lock().reader_replaceable()
    }

    fn writer_replaceable(&self) -> bool {
        self.inner.conn.lock().writer_replaceable()
    }
}

impl UpstreamNode for TcpTracker {
    fn reader_replaceable(&self) -> Option<bool> {
        Some(murmur_common_net::io::ExtendedStream::reader_replaceable(self))
    }

    fn writer_replaceable(&self) -> Option<bool> {
        Some(murmur_common_net::io::ExtendedStream::writer_replaceable(self))
    }
}

#[async_trait]
impl ExtendedConn for TcpTracker {
    // cancel-safe: the only await completes the read before any counter is updated.
    async fn read_buffer(&mut self, buffer: &mut Buffer) -> io::Result<()> {
        let result = poll_fn(|cx| {
            let mut conn = self.inner.conn.lock();
            let mut read_buf = ReadBuf::new(buffer.free_bytes());
            match Pin::new(&mut **conn).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            }
        })
        .await;
        match result {
            Ok(n) => buffer.truncate(n),
            Err(_) => buffer.truncate(0),
        }
        #[expect(clippy::cast_possible_wrap, reason = "a buffer length is bounded by the buffer")]
        let download = buffer.len() as i64;
        if download != 0 {
            if self.inner.push_to_manager {
                self.inner.manager.push_downloaded(download);
            }
            self.inner.tracker_info.download_total.add(download);
        }
        result.map(|_| ())
    }

    // cancel-safe: the write completes before the counters are updated.
    async fn write_buffer(&mut self, buffer: &mut Buffer) -> io::Result<()> {
        let len = buffer.len();
        #[expect(clippy::cast_possible_wrap, reason = "a buffer length is bounded by the buffer")]
        let upload = len as i64;
        let mut written = 0;
        let result = poll_fn(|cx| {
            let mut conn = self.inner.conn.lock();
            while written < len {
                let Some(remaining) = buffer.bytes().get(written..) else {
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                };
                match Pin::new(&mut **conn).poll_write(cx, remaining) {
                    Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                    Poll::Ready(Ok(n)) => written += n,
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                }
            }
            Poll::Ready(Ok(()))
        })
        .await;
        buffer.release();
        if self.inner.push_to_manager {
            self.inner.manager.push_uploaded(upload);
        }
        self.inner.tracker_info.upload_total.add(upload);
        result
    }
}

impl Connection for TcpTracker {
    fn chains(&self) -> Chain {
        self.inner.conn.lock().chains()
    }

    fn provider_chains(&self) -> Chain {
        self.inner.conn.lock().provider_chains()
    }

    fn append_to_chains(&self, adapter: Arc<dyn ProxyAdapter>) {
        self.inner.conn.lock().append_to_chains(adapter);
    }

    fn remote_destination(&self) -> String {
        self.inner.conn.lock().remote_destination()
    }
}

impl Tracker for TcpTrackerInner {
    fn id(&self) -> String {
        self.tracker_info.uuid.to_string()
    }

    fn close(&self) -> io::Result<()> {
        self.manager.leave(self);
        murmur_common_net::io::close_stream(&**self.conn.lock())
    }

    fn info(&self) -> Arc<TrackerInfo> {
        Arc::clone(&self.tracker_info)
    }
}

impl Connection for TcpTrackerInner {
    fn chains(&self) -> Chain {
        self.conn.lock().chains()
    }

    fn provider_chains(&self) -> Chain {
        self.conn.lock().provider_chains()
    }

    fn append_to_chains(&self, adapter: Arc<dyn ProxyAdapter>) {
        self.conn.lock().append_to_chains(adapter);
    }

    fn remote_destination(&self) -> String {
        self.conn.lock().remote_destination()
    }
}

impl TcpTracker {
    pub fn new(
        conn: Box<dyn ConstantConn>,
        manager: &Arc<Manager>,
        metadata: &mut Metadata,
        rule: Option<Arc<dyn Rule>>,
        upload_total: i64,
        download_total: i64,
        push_to_manager: bool,
    ) -> Self {
        metadata.remote_dst = conn.remote_destination();
        let chain = conn.chains();
        let provider_chain = conn.provider_chains();
        let (rule_type, rule_payload) = match rule {
            Some(rule) => (rule.rule_type().string(), rule.payload()),
            None => (String::new(), String::new()),
        };

        let inner = Arc::new(TcpTrackerInner {
            conn: Mutex::new(conn),
            tracker_info: Arc::new(TrackerInfo {
                uuid: new_uuid_v4(),
                start: Utc::now(),
                metadata: Arc::new(metadata.clone()),
                chain,
                provider_chain,
                rule: rule_type,
                rule_payload,
                upload_total: new_int64(upload_total),
                download_total: new_int64(download_total),
            }),
            manager: Arc::clone(manager),
            push_to_manager,
        });

        if push_to_manager {
            if upload_total > 0 {
                manager.push_uploaded(upload_total);
            }
            if download_total > 0 {
                manager.push_downloaded(download_total);
            }
        }

        let registered = Arc::clone(&inner);
        manager.join(registered);
        Self { close_view: TcpTrackerCloseView(Arc::clone(&inner)), inner }
    }
}

/// Every packet-conn method takes `&self`, so the registered tracker is the value the caller uses.
pub struct UdpTracker {
    packet_conn: Arc<dyn ConstantPacketConn>,
    tracker_info: Arc<TrackerInfo>,
    manager: Arc<Manager>,
    push_to_manager: bool,
}

impl fmt::Debug for UdpTracker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpTracker").field("uuid", &self.tracker_info.uuid).finish_non_exhaustive()
    }
}

#[async_trait]
impl PacketConn for UdpTracker {
    // cancel-safe: the packet is read before the download counter is updated.
    async fn read_from(&self, buf: &mut [u8]) -> io::Result<(usize, Box<dyn Addr>)> {
        let result = self.packet_conn.read_from(buf).await;
        #[expect(clippy::cast_possible_wrap, reason = "a datagram read count is bounded by the caller's buffer")]
        let download = match &result {
            Ok((n, _)) => *n as i64,
            Err(_) => 0,
        };
        if self.push_to_manager {
            self.manager.push_downloaded(download);
        }
        self.tracker_info.download_total.add(download);
        result
    }

    // cancel-safe: the packet is written before the upload counter is updated.
    async fn write_to(&self, buf: &[u8], addr: &dyn Addr) -> io::Result<usize> {
        let result = self.packet_conn.write_to(buf, addr).await;
        #[expect(clippy::cast_possible_wrap, reason = "a datagram write count is bounded by the caller's buffer")]
        let upload = match &result {
            Ok(n) => *n as i64,
            Err(_) => 0,
        };
        if self.push_to_manager {
            self.manager.push_uploaded(upload);
        }
        self.tracker_info.upload_total.add(upload);
        result
    }

    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.packet_conn.local_addr()
    }

    fn close(&self) -> io::Result<()> {
        self.manager.leave(self);
        self.packet_conn.close()
    }

    fn set_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.packet_conn.set_deadline(deadline)
    }

    fn set_read_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.packet_conn.set_read_deadline(deadline)
    }

    fn set_write_deadline(&self, deadline: Option<tokio::time::Instant>) -> io::Result<()> {
        self.packet_conn.set_write_deadline(deadline)
    }
}

#[async_trait]
impl WaitReadFrom for UdpTracker {
    // cancel-safe: the datagram is read before the download counter is updated.
    async fn wait_read_from(
        &self,
    ) -> (Vec<u8>, Option<Box<dyn FnOnce() + Send>>, Option<Box<dyn Addr>>, io::Result<()>) {
        let (data, put, addr, err) = self.packet_conn.wait_read_from().await;
        #[expect(clippy::cast_possible_wrap, reason = "a datagram length is bounded by the read buffer")]
        let download = data.len() as i64;
        if self.push_to_manager {
            self.manager.push_downloaded(download);
        }
        self.tracker_info.download_total.add(download);
        (data, put, addr, err)
    }
}

#[async_trait]
impl ConstantPacketConn for UdpTracker {
    /// Forwards the resolve to the wrapped packet conn.
    // cancel-safe: it forwards the resolve to the wrapped packet conn.
    async fn resolve_udp(&self, ctx: &CancellationToken, metadata: &mut Metadata) -> anyhow::Result<()> {
        self.packet_conn.resolve_udp(ctx, metadata).await
    }
}

impl Connection for UdpTracker {
    fn chains(&self) -> Chain {
        self.packet_conn.chains()
    }

    fn provider_chains(&self) -> Chain {
        self.packet_conn.provider_chains()
    }

    fn append_to_chains(&self, adapter: Arc<dyn ProxyAdapter>) {
        self.packet_conn.append_to_chains(adapter);
    }

    fn remote_destination(&self) -> String {
        self.packet_conn.remote_destination()
    }
}

impl WithUpstream for UdpTracker {
    fn upstream(&self) -> Option<&dyn Any> {
        Some(self.packet_conn.as_packet_conn())
    }
}

impl ReaderWithUpstream for UdpTracker {
    /// The inner conn's flag is promoted; an erased packet conn cannot be asked, so this answers
    /// the value this adapter's packet conns report.
    fn reader_replaceable(&self) -> bool {
        true
    }
}

impl WriterWithUpstream for UdpTracker {
    /// See [`ReaderWithUpstream::reader_replaceable`].
    fn writer_replaceable(&self) -> bool {
        true
    }
}

impl Tracker for UdpTracker {
    fn id(&self) -> String {
        self.tracker_info.uuid.to_string()
    }

    fn close(&self) -> io::Result<()> {
        self.manager.leave(self);
        self.packet_conn.close()
    }

    fn info(&self) -> Arc<TrackerInfo> {
        Arc::clone(&self.tracker_info)
    }
}

impl UdpTracker {
    pub fn new(
        conn: Arc<dyn ConstantPacketConn>,
        manager: &Arc<Manager>,
        metadata: &mut Metadata,
        rule: Option<Arc<dyn Rule>>,
        upload_total: i64,
        download_total: i64,
        push_to_manager: bool,
    ) -> Arc<Self> {
        metadata.remote_dst = conn.remote_destination();
        let chain = conn.chains();
        let provider_chain = conn.provider_chains();
        let (rule_type, rule_payload) = match rule {
            Some(rule) => (rule.rule_type().string(), rule.payload()),
            None => (String::new(), String::new()),
        };

        let ut = Arc::new(Self {
            tracker_info: Arc::new(TrackerInfo {
                uuid: new_uuid_v4(),
                start: Utc::now(),
                metadata: Arc::new(metadata.clone()),
                chain,
                provider_chain,
                rule: rule_type,
                rule_payload,
                upload_total: new_int64(upload_total),
                download_total: new_int64(download_total),
            }),
            packet_conn: conn,
            manager: Arc::clone(manager),
            push_to_manager,
        });

        if push_to_manager {
            if upload_total > 0 {
                manager.push_uploaded(upload_total);
            }
            if download_total > 0 {
                manager.push_downloaded(download_total);
            }
        }

        let registered = Arc::clone(&ut);
        manager.join(registered);
        ut
    }
}

/// `serde`'s `rc` feature is off, so a `[]*TrackerInfo` keeps its own serializer.
pub(crate) mod tracker_infos_json {
    use std::sync::Arc;

    use serde::{Deserialize, Deserializer, Serializer};

    use super::TrackerInfo;

    /// The connections field is a slice the manager only appends to, so it stays empty — and
    /// `null` on the wire — until a tracker is registered.
    pub(crate) fn serialize<S: Serializer>(infos: &[Arc<TrackerInfo>], serializer: S) -> Result<S::Ok, S::Error> {
        if infos.is_empty() {
            return serializer.serialize_none();
        }
        serializer.collect_seq(infos.iter().map(|info| &**info))
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<Arc<TrackerInfo>>, D::Error> {
        let infos = Option::<Vec<TrackerInfo>>::deserialize(deserializer)?.unwrap_or_default();
        Ok(infos.into_iter().map(Arc::new).collect())
    }
}

/// `serde`'s `rc` feature is off, so an `Arc<Metadata>` keeps its own serializer.
mod metadata_json {
    use std::sync::Arc;

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use murmur_constant::metadata::Metadata;

    pub(super) fn serialize<S: Serializer>(metadata: &Arc<Metadata>, serializer: S) -> Result<S::Ok, S::Error> {
        (**metadata).serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Arc<Metadata>, D::Error> {
        Ok(Arc::new(Metadata::deserialize(deserializer)?))
    }
}

/// the `gofrs/uuid.UUID` JSON form: the canonical hyphenated string.
mod uuid_json {
    use serde::{Deserialize, Deserializer, Serializer};
    use uuid::Uuid;

    pub(super) fn serialize<S: Serializer>(uuid: &Uuid, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&uuid.to_string())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Uuid, D::Error> {
        let text = String::deserialize(deserializer)?;
        Uuid::parse_str(&text).map_err(serde::de::Error::custom)
    }
}

/// `C.Chain` is a `[]string`, which `murmur_constant::adapters::Chain` does not serialize itself.
mod chain_json {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use murmur_constant::adapters::Chain;

    pub(super) fn serialize<S: Serializer>(chain: &Chain, serializer: S) -> Result<S::Ok, S::Error> {
        chain.0.serialize(serializer)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Chain, D::Error> {
        Ok(Chain(Vec::<String>::deserialize(deserializer)?))
    }
}
