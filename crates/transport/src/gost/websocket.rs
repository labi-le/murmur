//! Gost websocket transport with optional smux multiplexing.
//!
//! The mux option multiplexes the websocket stream through the smux implementation, implemented as
//! the `murmur-smux` crate; the crate boundary is bridged by
//! `murmur_common_net::io::{OldConnAsStream, StreamAsOldConn}`.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::CancellationToken;

use murmur_common_net::io::{OldConnAsStream, Stream, StreamAsOldConn};
use murmur_component_ca as ca;
use murmur_component_ech as ech;
use murmur_std_compat::net::Conn as NetConn;
use murmur_transport_vmess::websocket::{stream_websocket_conn_public, WebsocketConfig};

#[derive(Clone, Debug, Default)]
pub struct Option {
    pub host: String,
    pub port: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub tls: bool,
    pub ech_config: std::option::Option<Arc<ech::Config>>,
    pub skip_cert_verify: bool,
    pub name_cert_verify: String,
    pub fingerprint: String,
    pub certificate: String,
    pub private_key: String,
    pub mux: bool,
}

/// Wraps a mux stream and also closes the session when closed.
pub(crate) struct MuxConn {
    stream: Box<dyn murmur_smux::Stream>,
    session: Box<dyn murmur_smux::Session>,
}

impl MuxConn {
    pub(crate) fn new(stream: Box<dyn murmur_smux::Stream>, session: Box<dyn murmur_smux::Session>) -> Self {
        Self { stream, session }
    }
}

impl AsyncRead for MuxConn {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for MuxConn {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut *self.get_mut().stream).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().stream).poll_shutdown(cx)
    }
}

impl Stream for MuxConn {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.stream.local_addr()
    }

    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.stream.peer_addr()
    }

    fn shutdown_read(&self) -> io::Result<()> {
        self.stream.shutdown_read()
    }

    fn shutdown_write(&self) -> io::Result<()> {
        let stream_err = self.stream.shutdown_write();
        let session_err = self.session.close();
        stream_err?;
        session_err
    }
}

fn header_get<'a>(headers: &'a [(String, String)], name: &str) -> std::option::Option<&'a str> {
    headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

pub async fn new_gost_websocket(
    ctx: &CancellationToken,
    conn: Box<dyn NetConn>,
    option: &Option,
) -> Result<Box<dyn NetConn>> {
    let headers: Vec<(String, String)> = option.headers.iter().map(|(k, v)| (k.clone(), v.clone())).collect();

    let WebsocketConfig {
        tls,
        tls_config,
        max_early_data,
        early_data_header_name,
        client_fingerprint,
        v2ray_http_upgrade,
        v2ray_http_upgrade_fast_open,
        ..
    } = WebsocketConfig::default();
    let mut config = WebsocketConfig {
        host: option.host.clone(),
        port: option.port.clone(),
        path: option.path.clone(),
        headers,
        tls,
        tls_config,
        ech_config: option.ech_config.clone(),
        max_early_data,
        early_data_header_name,
        client_fingerprint,
        v2ray_http_upgrade,
        v2ray_http_upgrade_fast_open,
    };

    if option.tls {
        config.tls = true;
        let mut tls_config = ca::config::get_tls_config(ca::config::Option {
            tls_config: Some(crate::websocket_tls::http_upgrade_tls_config(&option.host, option.skip_cert_verify)),
            fingerprint: option.fingerprint.clone(),
            name_cert_verify: option.name_cert_verify.clone(),
            zero_trust: false,
            certificate: option.certificate.clone(),
            private_key: option.private_key.clone(),
        })?;

        if let Some(host) = header_get(&config.headers, "Host") {
            if !host.is_empty() {
                host.clone_into(&mut tls_config.server_name);
            }
        }

        config.tls_config = Some(Arc::new(tls_config));
    }

    let conn = stream_websocket_conn_public(ctx, conn, config).await?;

    if !option.mux {
        return Ok(conn);
    }

    let mut mux_config = murmur_smux::default_config();
    mux_config.keep_alive_disabled = true;

    let session = murmur_smux::client(Box::new(OldConnAsStream(conn)), &mux_config)?;
    let stream = match session.open_stream().await {
        Ok(stream) => stream,
        Err(err) => {
            let _ = session.close();
            return Err(err);
        }
    };

    Ok(Box::new(StreamAsOldConn::new(MuxConn::new(stream, session))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_get_is_case_insensitive() {
        let headers = vec![("X-Custom".to_owned(), "1".to_owned()), ("host".to_owned(), "example.com".to_owned())];
        assert_eq!(header_get(&headers, "Host"), Some("example.com"));
        assert_eq!(header_get(&headers, "Missing"), None);
    }
}
