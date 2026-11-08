use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use hickory_proto::op::Message;
use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;

use murmur_common::deque::Deque;
use murmur_component::dialer::bind::join_host_port;
use murmur_component::resolver::resolver::SharedResolver;
use murmur_component_ca as ca;
use murmur_component_tls::utls;
use murmur_constant::adapters::ProxyAdapter;
use murmur_std_compat::net::Conn;

use super::client::exchange_with_conn;
use super::dialer::DnsDialer;
use super::resolver::DnsClient;

const MAX_OLD_DOT_CONNS: usize = 8;

pub(crate) struct DnsOverTls {
    port: String,
    host: String,
    dialer: DnsDialer,
    skip_cert_verify: bool,
    name_cert_verify: String,
    disable_reuse: bool,

    connections: Mutex<Deque<Box<dyn Conn>>>,
}

pub(crate) fn new_dot_client(
    addr: &str,
    r: Option<SharedResolver>,
    params: &HashMap<String, String>,
    proxy_adapter: Option<Arc<dyn ProxyAdapter>>,
    proxy_name: &str,
) -> Arc<dyn DnsClient> {
    let (host, port) =
        murmur_common::net_addr::split_host_port(addr).unwrap_or_else(|_| (addr.to_owned(), String::new()));

    let mut connections = Deque::default();
    connections.set_base_cap(MAX_OLD_DOT_CONNS);

    let t = DnsOverTls {
        port,
        host,
        dialer: DnsDialer::new(r, proxy_adapter, proxy_name.to_owned()),
        skip_cert_verify: params.get("skip-cert-verify").is_some_and(|v| v == "true"),
        name_cert_verify: params.get("name-cert-verify").cloned().unwrap_or_default(),
        disable_reuse: params.get("disable-reuse").is_some_and(|v| v == "true"),
        connections: Mutex::new(connections),
    };
    Arc::new(t)
}

#[async_trait]
impl DnsClient for DnsOverTls {
    fn address(&self) -> String {
        format!("tls://{}", join_host_port(&self.host, &self.port))
    }

    // cancel-safe: it only races the inner exchange against the context.
    async fn exchange_context(&self, ctx: &CancellationToken, m: &Message) -> Result<Message> {
        tokio::select! {
            () = ctx.cancelled() => Err(anyhow!("context canceled")),
            result = self.exchange(ctx, m) => result,
        }
    }

    fn reset_connection(&self) {
        if self.disable_reuse {
            return;
        }
        let mut old_conns: Vec<Box<dyn Conn>> = Vec::new();
        {
            let mut connections = self.connections.lock();
            while !connections.is_empty() {
                old_conns.push(connections.pop_front());
            }
            drop(connections);
        }
        for old_conn in old_conns {
            tokio::spawn(async move {
                let _ = old_conn.close();
            });
        }
    }
}

impl DnsOverTls {
    /// Retries only when reusing an old connection.
    // cancel-safe: a cancelled exchange drops the connection it took from the pool rather than returning
    // it, so the pool never holds a half-used connection.
    async fn exchange(&self, ctx: &CancellationToken, m: &Message) -> Result<Message> {
        loop {
            if ctx.is_cancelled() {
                return Err(anyhow!("context canceled"));
            }

            let mut is_old_conn = true;
            let mut conn: Option<Box<dyn Conn>> = None;
            if !self.disable_reuse {
                let mut connections = self.connections.lock();
                if !connections.is_empty() {
                    conn = Some(connections.pop_back());
                }
            }

            let mut conn = if let Some(conn) = conn {
                conn
            } else {
                is_old_conn = false;
                self.dial_context(ctx).await?
            };

            match exchange_with_conn(conn.as_mut(), m, false).await {
                Ok(msg) => {
                    if self.disable_reuse {
                        let _ = conn.close();
                    } else {
                        let mut connections = self.connections.lock();
                        if connections.len() >= MAX_OLD_DOT_CONNS {
                            let old_conn = connections.pop_front();
                            tokio::spawn(async move {
                                let _ = old_conn.close();
                            });
                        }
                        connections.push_back(conn);
                    }
                    return Ok(msg);
                }
                Err(err) => {
                    let _ = conn.close();
                    if is_old_conn {
                        continue;
                    }
                    return Err(err);
                }
            }
        }
    }

    async fn dial_context(&self, ctx: &CancellationToken) -> Result<Box<dyn Conn>> {
        let conn = self.dialer.dial_context(ctx, "tcp", &join_host_port(&self.host, &self.port)).await?;

        let utls::Config {
            rand,
            time,
            certificates,
            get_certificate,
            get_client_certificate,
            verify_peer_certificate,
            verify_connection,
            root_cas,
            next_protos,
            client_auth,
            client_cas,
            cipher_suites,
            session_tickets_disabled,
            min_version,
            max_version,
            curve_preferences,
            renegotiation,
            key_log_writer,
            encrypted_client_hello_config_list,
            encrypted_client_hello_rejection_verify,
            encrypted_client_hello_keys,
            get_encrypted_client_hello_keys,
            session_id_generator,
            ..
        } = utls::Config::default();
        let tls_config = ca::config::get_tls_config(ca::config::Option {
            tls_config: Some(utls::Config {
                rand,
                time,
                certificates,
                get_certificate,
                get_client_certificate,
                verify_peer_certificate,
                verify_connection,
                root_cas,
                next_protos,
                server_name: self.host.clone(),
                client_auth,
                client_cas,
                insecure_skip_verify: self.skip_cert_verify,
                cipher_suites,
                session_tickets_disabled,
                min_version,
                max_version,
                curve_preferences,
                renegotiation,
                key_log_writer,
                encrypted_client_hello_config_list,
                encrypted_client_hello_rejection_verify,
                encrypted_client_hello_keys,
                get_encrypted_client_hello_keys,
                session_id_generator,
            }),
            fingerprint: String::new(),
            name_cert_verify: self.name_cert_verify.clone(),
            zero_trust: false,
            certificate: String::new(),
            private_key: String::new(),
        });
        let tls_config = match tls_config {
            Ok(config) => config,
            Err(err) => {
                let _ = conn.close();
                return Err(err);
            }
        };

        let tls_conn = utls::client(Box::new(murmur_common_net::io::OldConnAsStream(conn)), Arc::new(tls_config));
        if let Err(err) = tls_conn.handshake_context(ctx).await {
            let _ = murmur_common_net::io::close_stream(&tls_conn);
            return Err(err);
        }

        Ok(Box::new(murmur_common_net::io::StreamAsOldConn::new(tls_conn)))
    }
}

#[cfg(all(test, target_os = "linux"))]
mod blackhole_probe {
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::Duration;

    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};
    use tokio::net::TcpListener;
    use tokio_util::sync::CancellationToken;

    use super::new_dot_client;

    /// A peer that accepts and then never writes is what a filtered `:853` looks like: the TLS
    /// handshake never completes. Every dial must end on the resolver's timeout and release its
    /// descriptor, whether the queries arrive one at a time or all at once.
    fn open_fds() -> usize {
        std::fs::read_dir("/proc/self/fd").map_or(0, Iterator::count)
    }

    fn a_query() -> Message {
        let mut m = Message::new(0, MessageType::Query, OpCode::Query);
        m.add_query(Query::query("example.com.".parse::<Name>().expect("name"), RecordType::A));
        m
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_blackholed_dot_peer_leaves_no_sockets_behind() {
        probe(8, false).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_blackholed_dot_dials_leave_no_sockets_behind() {
        probe(8, true).await;
    }

    async fn probe(dials: usize, concurrent: bool) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind the blackhole");
        let addr = listener.local_addr().expect("local addr");
        let server = tokio::spawn(async move {
            let mut held = Vec::new();
            while held.len() < dials {
                let Ok((socket, _)) = listener.accept().await else { break };
                held.push(socket);
            }
            // Holding them past the client's cancellation means a client that forgot to close its
            // side is still visible in /proc/self/fd below.
            tokio::time::sleep(Duration::from_secs(1)).await;
            drop(held);
        });

        let client = new_dot_client(&addr.to_string(), None, &HashMap::new(), None, "");
        let baseline = open_fds();
        let mut spawned = Vec::new();
        for _ in 0..dials {
            let ctx = CancellationToken::new();
            let sleeper = ctx.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(300)).await;
                sleeper.cancel();
            });
            let client = Arc::clone(&client);
            let call = async move {
                let _ = tokio::time::timeout(Duration::from_secs(2), client.exchange_context(&ctx, &a_query())).await;
            };
            if concurrent {
                spawned.push(tokio::spawn(call));
            } else {
                call.await;
            }
        }
        for task in spawned {
            let _ = task.await;
        }
        let _ = tokio::time::timeout(Duration::from_secs(10), server).await;
        // Other tests in this binary may open descriptors of their own while this one runs, so
        // settle rather than sample once: a leak never comes back down.
        let mut after = open_fds();
        for _ in 0..50 {
            if after <= baseline + 4 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            after = open_fds();
        }
        assert!(after <= baseline + 4, "descriptors grew from {baseline} to {after} over {dials} blackholed dials");
    }
}
