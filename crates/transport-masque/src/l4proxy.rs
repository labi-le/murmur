use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::anyhow;
use async_trait::async_trait;
use futures::future::BoxFuture;
use http::HeaderMap;
use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use crate::masque::{context_canceled, h3};
use murmur_common::contextutils::after_func;
use murmur_component::dialer::options::NetDialer;
use murmur_std_compat::net::{Addr, Conn, PacketConn, UdpAddr};

pub const L4_CONNECT_SNI: &str = "consumer-masque-proxy.cloudflareclient.com";

pub type DialQuicFn = Arc<
    dyn Fn(CancellationToken) -> BoxFuture<'static, anyhow::Result<(Box<dyn PacketConn>, quinn::Connection)>>
        + Send
        + Sync,
>;

pub struct L4Client {
    dial_fn: DialQuicFn,
    run_lock: Semaphore,
    run_ctx: CancellationToken,
    client_conn: Mutex<Option<Arc<h3::ClientConn>>>,
    /// The QUIC connection does not expose the local port here, so the local address is
    /// snapshotted from the dialed packet conn instead.
    local_addr: Mutex<Option<SocketAddr>>,
}

impl std::fmt::Debug for L4Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("L4Client").field("local_addr", &*self.local_addr.lock()).finish_non_exhaustive()
    }
}

impl L4Client {
    pub fn new(run_ctx: CancellationToken, dial_fn: DialQuicFn) -> Self {
        Self {
            dial_fn,
            run_lock: Semaphore::new(1),
            run_ctx,
            client_conn: Mutex::new(None),
            local_addr: Mutex::new(None),
        }
    }

    ///
    /// The caller should cancel `run_ctx` before calling it.
    pub async fn close(&self) -> anyhow::Result<()> {
        self.close_conn(None).await
    }

    pub async fn close_conn(&self, client_conn: Option<&Arc<h3::ClientConn>>) -> anyhow::Result<()> {
        // The background context never returns an error.
        let permit = self.run_lock.acquire().await?;
        let client_conn = {
            let mut current = self.client_conn.lock();
            let client_conn = match client_conn {
                Some(client_conn) => Some(Arc::clone(client_conn)),
                None => current.clone(),
            };
            let same_conn = match (current.as_ref(), client_conn.as_ref()) {
                (Some(current), Some(target)) => Arc::ptr_eq(current, target),
                _ => false,
            };
            if same_conn {
                *current = None;
            }
            client_conn
        };
        drop(permit);

        if let Some(client_conn) = client_conn {
            client_conn.close_with_error(0, "client closed");
        }
        Ok(())
    }

    pub async fn dial_conn(&self, ctx: CancellationToken) -> anyhow::Result<Arc<h3::ClientConn>> {
        let _permit = tokio::select! {
            permit = self.run_lock.acquire() => permit?,
            () = ctx.cancelled() => return Err(context_canceled()),
        };
        let cached = self.client_conn.lock().clone();
        if let Some(client_conn) = cached {
            return Ok(client_conn);
        }

        if self.run_ctx.is_cancelled() {
            return Err(context_canceled());
        }

        // `dial_ctx` must be cancelled when either `ctx` or `run_ctx` is done.
        let dial_ctx = ctx.child_token();
        let stop = after_func(&self.run_ctx, {
            let dial_ctx = dial_ctx.clone();
            move || dial_ctx.cancel()
        });
        let dialed = (*self.dial_fn)(dial_ctx.clone()).await;
        let _ = stop();
        dial_ctx.cancel();

        // The packet conn is needed only for its local address; it is not retained.
        let (packet_conn, quic_conn) = dialed?;
        if let Ok(addr) = packet_conn.local_addr() {
            if let Some(murmur_std_compat::net::SockAddr::Udp(addr)) =
                murmur_std_compat::net::sock_addr_of(addr.as_ref())
            {
                *self.local_addr.lock() = Some(SocketAddr::new(addr.ip, addr.port));
            }
        }

        let transport = h3::Transport::new(false, Vec::new());
        let client_conn = transport.new_client_conn(quic_conn).await?;
        *self.client_conn.lock() = Some(Arc::clone(&client_conn));
        Ok(client_conn)
    }

    pub async fn dial_context(
        &self,
        ctx: CancellationToken,
        _network: &str,
        address: &str,
    ) -> anyhow::Result<Box<dyn Conn>> {
        let client_conn = self.dial_conn(ctx.clone()).await?;
        let mut stream = match client_conn.open_request_stream(Some(&ctx)).await {
            Ok(stream) => stream,
            Err(err) => {
                // Close the underlay connection if we failed to open a stream.
                let _ = self.close_conn(Some(&client_conn)).await;
                return Err(err);
            }
        };

        let head = h3::RequestHead {
            method: http::Method::CONNECT,
            proto: String::new(),
            host: address.to_owned(),
            header: HeaderMap::new(),
            url: http::Uri::try_from(format!("https://{address}")).map_err(|err| anyhow!("{err}"))?,
        };
        stream.send_request_header(&head).await?;
        let response = stream.read_response().await?;
        if response.status_code < 200 || response.status_code > 299 {
            return Err(anyhow!("CONNECT rejected with status {}", response.status_code));
        }

        let (send, recv, _datagrams) = stream.split();
        Ok(Box::new(L4StreamConn {
            send: Mutex::new(send),
            recv: Mutex::new(recv),
            client_conn,
            local_addr: *self.local_addr.lock(),
        }))
    }
}

/// [`L4Client`] as the net dialer for the proxied connections.
#[async_trait]
impl NetDialer for L4Client {
    async fn dial_context(
        &self,
        ctx: &CancellationToken,
        network: &str,
        address: &str,
    ) -> anyhow::Result<Box<dyn murmur_common_net::io::Stream>> {
        let conn = Self::dial_context(self, ctx.clone(), network, address).await?;
        Ok(Box::new(murmur_common_net::io::OldConnAsStream(conn)))
    }
}

pub(crate) struct L4StreamConn {
    send: Mutex<h3::StreamSend>,
    recv: Mutex<h3::StreamRecv>,
    client_conn: Arc<h3::ClientConn>,
    local_addr: Option<SocketAddr>,
}

impl L4StreamConn {
    /// The QUIC connection, stored explicitly instead of being read
    /// out of the first field of an HTTP/3 client connection.
    pub(crate) fn quic_conn(&self) -> &quinn::Connection {
        self.client_conn.quic_conn()
    }

    pub(crate) fn close_conn(&self) -> io::Result<()> {
        self.recv.lock().stop(0);
        self.send.lock().finish().map_err(io::Error::other)
    }

    fn read_local_addr(&self) -> io::Result<Box<dyn Addr>> {
        match self.local_addr {
            Some(addr) => Ok(Box::new(UdpAddr::new(addr.ip(), addr.port()))),
            None => match self.quic_conn().local_ip() {
                Some(ip) => Ok(Box::new(UdpAddr::new(ip, 0))),
                None => Err(io::Error::other("no local address")),
            },
        }
    }
}

impl Conn for L4StreamConn {
    fn local_addr(&self) -> io::Result<Box<dyn Addr>> {
        self.read_local_addr()
    }

    fn remote_addr(&self) -> io::Result<Box<dyn Addr>> {
        let addr = self.quic_conn().remote_address();
        Ok(Box::new(UdpAddr::new(addr.ip(), addr.port())))
    }

    fn close(&self) -> io::Result<()> {
        self.close_conn()
    }
}

impl AsyncRead for L4StreamConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // The framed read takes a plain slice, so one staging buffer copy is unavoidable here.
        let mut scratch = [0u8; 16 * 1024];
        let len = buf.remaining().min(scratch.len());
        if len == 0 {
            return Poll::Ready(Ok(()));
        }
        let (stage, _rest) = scratch.split_at_mut(len);
        let read = this.recv.lock().poll_read(cx, stage);
        match read {
            Poll::Ready(Ok(0)) => Poll::Ready(Ok(())),
            Poll::Ready(Ok(n)) => {
                let (filled, _rest) = scratch.split_at(n);
                buf.put_slice(filled);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for L4StreamConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.get_mut().send.lock().poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().send.lock().finish().map_err(io::Error::other)?;
        Poll::Ready(Ok(()))
    }
}

impl std::fmt::Debug for L4StreamConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("L4StreamConn").field("stream_id", &self.send.lock().stream_id()).finish_non_exhaustive()
    }
}
