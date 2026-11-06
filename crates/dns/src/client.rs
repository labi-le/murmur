use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use hickory_proto::op::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use murmur_component::dialer::bind::join_host_port;
use murmur_component::resolver::resolver::SharedResolver;
use murmur_constant::adapters::ProxyAdapter;
use murmur_log::debugln;
use murmur_std_compat::net::Conn;

use super::dialer::DnsDialer;
use super::resolver::DnsClient;

/// The client timeout, five seconds.
const CLIENT_TIMEOUT: Duration = Duration::from_secs(5);
/// The client UDP payload size, 4096.
const CLIENT_UDP_SIZE: usize = 4096;

pub(crate) struct Client {
    port: String,
    host: String,
    dialer: DnsDialer,
    schema: String,
}

pub(crate) fn new_client(
    addr: &str,
    r: Option<SharedResolver>,
    is_tcp: bool,
    params: &HashMap<String, String>,
    proxy_adapter: Option<Arc<dyn ProxyAdapter>>,
    proxy_name: &str,
) -> Arc<dyn DnsClient> {
    let (host, port) =
        murmur_common::net_addr::split_host_port(addr).unwrap_or_else(|_| (addr.to_owned(), String::new()));
    let _ = params;
    let schema = if is_tcp { "tcp" } else { "udp" }.to_owned();
    Arc::new(Client { port, host, dialer: DnsDialer::new(r, proxy_adapter, proxy_name.to_owned()), schema })
}

#[async_trait]
impl DnsClient for Client {
    fn address(&self) -> String {
        format!("{}://{}", self.schema, join_host_port(&self.host, &self.port))
    }

    // cancel-safe: it only races the inner exchange against the context, and the inner future owns its
    // connection.
    async fn exchange_context(&self, ctx: &CancellationToken, m: &Message) -> Result<Message> {
        tokio::select! {
            () = ctx.cancelled() => Err(anyhow!("context canceled")),
            result = self.exchange(ctx, m) => result,
        }
    }

    fn reset_connection(&self) {}
}

impl Client {
    // cancel-safe: the connection it dials is owned by this future, so a cancelled exchange drops it and
    // leaves no shared state behind.
    async fn exchange(&self, ctx: &CancellationToken, m: &Message) -> Result<Message> {
        let mut network = if self.schema == "udp" { "udp" } else { "tcp" };
        let addr = join_host_port(&self.host, &self.port);

        let mut conn = self.dialer.dial_context(ctx, network, &addr).await?;
        let mut msg = exchange_with_conn(conn.as_mut(), m, network == "udp").await;

        if let Ok(response) = &msg {
            if response.metadata.truncation && network == "udp" {
                network = "tcp";
                debugln!(
                    "[DNS] Truncated reply from {}:{} for {} over UDP, retrying over TCP",
                    self.host,
                    self.port,
                    m.queries.first().map_or_else(String::new, |q| q.name().to_string()),
                );
                match self.dialer.dial_context(ctx, network, &addr).await {
                    Ok(mut tcp_conn) => {
                        msg = exchange_with_conn(tcp_conn.as_mut(), m, false).await;
                        let _ = tcp_conn.close();
                    }
                    Err(err) => {
                        let _ = conn.close();
                        return Err(err);
                    }
                }
            }
        }
        let _ = conn.close();
        msg
    }
}

/// Exchanges over a caller-supplied connection; shared with `dot.rs`, which
/// always exchanges over an already-established TCP connection.
// NOT cancel-safe: a drop between the timed write and the timed read leaves a partially sent or partially
// consumed DNS frame; every caller closes the connection instead of reusing it.
pub(crate) async fn exchange_with_conn(conn: &mut dyn Conn, m: &Message, is_udp: bool) -> Result<Message> {
    let payload = m.to_vec()?;
    tokio::time::timeout(CLIENT_TIMEOUT, write_dns_message(conn, &payload, is_udp))
        .await
        .map_err(|_| anyhow!("i/o timeout"))??;
    let response = tokio::time::timeout(CLIENT_TIMEOUT, read_dns_message(conn, is_udp))
        .await
        .map_err(|_| anyhow!("i/o timeout"))??;
    Ok(response)
}

// NOT cancel-safe: a timeout can drop it mid-frame, leaving the stream desynchronized for the caller to
// close.
async fn write_dns_message(conn: &mut dyn Conn, payload: &[u8], is_udp: bool) -> Result<()> {
    if !is_udp {
        let len = u16::try_from(payload.len())
            .map_err(|_| anyhow!("dns: message of {} bytes is too large", payload.len()))?;
        conn.write_all(&len.to_be_bytes()).await?;
    }
    conn.write_all(payload).await?;
    conn.flush().await?;
    Ok(())
}

// NOT cancel-safe: a timeout can drop it between the length prefix and the body, desynchronizing the TCP
// stream for the caller.
async fn read_dns_message(conn: &mut dyn Conn, is_udp: bool) -> Result<Message> {
    if is_udp {
        let mut buf = vec![0u8; CLIENT_UDP_SIZE];
        let n = conn.read(&mut buf).await?;
        buf.truncate(n);
        Ok(Message::from_vec(&buf)?)
    } else {
        let mut len_buf = [0u8; 2];
        conn.read_exact(&mut len_buf).await?;
        let len = usize::from(u16::from_be_bytes(len_buf));
        let mut buf = vec![0u8; len];
        conn.read_exact(&mut buf).await?;
        Ok(Message::from_vec(&buf)?)
    }
}
