//! Deviation: like `tunnel_ws.rs`, this crate has no mirror of the WebSocket upgrader, so the
//! server-side opening handshake is answered directly.
//!
//! The upgrader re-parses the raw HTTP request bytes it is handed (it is oblivious to the
//! caller's own header parsing); the raw request bytes would be replayed in front of the raw
//! conn, while this crate already has the parsed request in `req`, so only `buffered`
//! (bytes read past the header, e.g. pipelined WS frames) needs replaying onto the wrapped
//! connection.

use std::collections::HashMap;

use anyhow::Result;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use url::Url;

use murmur_common_net::io::{close_stream, Stream};
use murmur_ws::STATE_SERVER_SIDE;

use super::conn_helpers::write_full;
use super::early_handshake::PreparedServerEarlyHandshake;
use super::pathroot::strip_path_root;
use super::tunnel_api::{HandleResult, TunnelMode};
use super::tunnel_dial::{parse_early_data_query, TUNNEL_EARLY_DATA_HEADER};
use super::tunnel_server::{new_pre_buffered_conn, HttpRequestHeader, TunnelServer};
use super::tunnel_ws::compute_ws_accept;
use super::ws_auth::TUNNEL_AUTH_QUERY_KEY;
use super::ws_stream_conn::new_ws_stream_conn;

pub(crate) fn looks_like_web_socket_upgrade(headers: &HashMap<String, String>) -> bool {
    let upgrade = headers.get("upgrade").map(String::as_str).unwrap_or_default();
    if !upgrade.trim().eq_ignore_ascii_case("websocket") {
        return false;
    }
    let connection = headers.get("connection").map(String::as_str).unwrap_or_default();
    connection.split(',').any(|part| part.trim().eq_ignore_ascii_case("upgrade"))
}

fn ensure_leading_slash(target: &str) -> String {
    if target.starts_with('/') {
        target.to_owned()
    } else {
        format!("/{target}")
    }
}

impl TunnelServer {
    pub(crate) async fn handle_ws(
        &self,
        mut raw_conn: Box<dyn Stream>,
        req: &HttpRequestHeader,
        header_bytes: &[u8],
        buffered: &[u8],
    ) -> Result<(HandleResult, Option<Box<dyn Stream>>)> {
        let Ok(u) = Url::parse(&format!("http://placeholder{}", ensure_leading_slash(&req.target))) else {
            return self.reject_or_reply(raw_conn, header_bytes, buffered, 400, "bad request").await;
        };

        let (path, ok) = strip_path_root(&self.path_root, u.path());
        if !ok || path != "/ws" {
            return self.reject_or_reply(raw_conn, header_bytes, buffered, 404, "not found").await;
        }
        if req.method.trim().to_uppercase() != "GET" {
            return self.reject_or_reply(raw_conn, header_bytes, buffered, 400, "bad request").await;
        }
        if !looks_like_web_socket_upgrade(&req.headers) {
            return self.reject_or_reply(raw_conn, header_bytes, buffered, 400, "bad request").await;
        }

        let mut auth_val = req.headers.get("authorization").cloned().unwrap_or_default();
        if auth_val.is_empty() {
            auth_val = u
                .query_pairs()
                .find(|(k, _)| k == TUNNEL_AUTH_QUERY_KEY)
                .map(|(_, v)| v.into_owned())
                .unwrap_or_default();
        }
        let auth_ok = match &self.auth {
            Some(auth) => auth.verify_value(&auth_val, TunnelMode::Ws, &req.method, &path, chrono::Utc::now()),
            None => true,
        };
        if !auth_ok {
            return self.reject_or_reply(raw_conn, header_bytes, buffered, 404, "not found").await;
        }

        let Ok(early_payload) = parse_early_data_query(&u) else {
            return self.reject_or_reply(raw_conn, header_bytes, buffered, 400, "bad request").await;
        };
        let mut prepared: Option<PreparedServerEarlyHandshake> = None;
        if !early_payload.is_empty() {
            if let Some(early_handshake) = &self.early_handshake {
                match (early_handshake.prepare)(&early_payload) {
                    Ok(p) => prepared = Some(p),
                    Err(_) => return self.reject_or_reply(raw_conn, header_bytes, buffered, 404, "not found").await,
                }
            }
        }

        let Some(ws_key) = req.headers.get("sec-websocket-key").cloned() else {
            return self.reject_or_reply(raw_conn, header_bytes, buffered, 400, "bad request").await;
        };
        let accept = compute_ws_accept(&ws_key);

        let mut response = Vec::with_capacity(256);
        response.extend_from_slice(b"HTTP/1.1 101 Switching Protocols\r\n");
        response.extend_from_slice(b"Upgrade: websocket\r\n");
        response.extend_from_slice(b"Connection: Upgrade\r\n");
        response.extend_from_slice(b"Sec-WebSocket-Accept: ");
        response.extend_from_slice(accept.as_bytes());
        response.extend_from_slice(b"\r\n");
        if let Some(prepared) = &prepared {
            if !prepared.response_payload.is_empty() {
                response.extend_from_slice(TUNNEL_EARLY_DATA_HEADER.as_bytes());
                response.extend_from_slice(b": ");
                response.extend_from_slice(URL_SAFE_NO_PAD.encode(&prepared.response_payload).as_bytes());
                response.extend_from_slice(b"\r\n");
            }
        }
        response.extend_from_slice(b"\r\n");

        if write_full(&mut raw_conn, &response).await.is_err() {
            let _ = close_stream(&*raw_conn);
            return Ok((HandleResult::Done, None));
        }

        let ws_conn_raw: Box<dyn Stream> =
            if buffered.is_empty() { raw_conn } else { new_pre_buffered_conn(raw_conn, buffered.to_vec()) };

        let mut out_conn: Box<dyn Stream> = new_ws_stream_conn(ws_conn_raw, STATE_SERVER_SIDE);
        let mut early_user_hash: Option<String> = None;
        if let Some(prepared) = prepared {
            if let Some(wrap_conn) = &prepared.wrap_conn {
                match wrap_conn(out_conn).await {
                    Ok(wrapped) => {
                        out_conn = wrapped;
                        early_user_hash = Some(prepared.user_hash);
                    }
                    Err(_) => return Ok((HandleResult::Done, None)),
                }
            }
        }
        Ok((HandleResult::StartTunnel(early_user_hash), Some(out_conn)))
    }
}
