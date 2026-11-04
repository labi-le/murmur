use std::any::Any;
use std::collections::VecDeque;
use std::sync::Arc;

use chrono::Utc;
use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;

use crate::types::type_::{DialFunc, Error as ClientError};
use murmur_constant::metadata::Metadata;
use murmur_std_compat::net::Conn;

use super::tuic::{new_client_v4, new_client_v5, Client, ClientOptionV4, ClientOptionV5};

/// The idle-eviction window for a pooled client.
const IDLE_EVICTION: chrono::Duration = chrono::Duration::minutes(30);

fn is_too_many_open_streams(err: &anyhow::Error) -> bool {
    matches!(err.downcast_ref::<ClientError>(), Some(ClientError::TooManyOpenStreams))
}

/// The per-backend factory, split because the
/// two option types differ. `DialFunc` is shared: both clients dial the one QUIC session
/// [`crate::quic`] provides.
enum ClientFactory {
    V4 { option: Arc<ClientOptionV4>, dial_fn: DialFunc },
    V5 { option: ClientOptionV5, dial_fn: DialFunc },
}

impl ClientFactory {
    fn new_client(&self, udp: bool) -> Client {
        match self {
            Self::V4 { option, dial_fn } => new_client_v4(Arc::clone(option), udp, Arc::clone(dial_fn)),
            Self::V5 { option, dial_fn } => new_client_v5(option.clone(), udp, Arc::clone(dial_fn)),
        }
    }
}

/// `PoolClient`, the shared client pool behind `new_pool_client_v4`/`new_pool_client_v5`.
///
/// The TCP and UDP client lists each become one
/// `Mutex<VecDeque<..>>`; a list entry is `Option<Client>` to keep the
/// front-of-list check expressible even though this crate's own code never pushes `None`.
pub struct PoolClient {
    factory: ClientFactory,
    tcp_clients: Mutex<VecDeque<Option<Client>>>,
    udp_clients: Mutex<VecDeque<Option<Client>>>,
}

impl core::fmt::Debug for PoolClient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PoolClient").finish_non_exhaustive()
    }
}

impl PoolClient {
    pub async fn dial_context(
        self: &Arc<Self>,
        ctx: &CancellationToken,
        metadata: &mut Metadata,
    ) -> anyhow::Result<Box<dyn Conn>> {
        let mut result = self.get_client(false).dial_context(ctx, metadata).await;
        if matches!(&result, Err(err) if is_too_many_open_streams(err)) {
            result = self.new_client(false).dial_context(ctx, metadata).await;
        }
        let conn = result?;
        let this = Arc::clone(self);
        let ref_: Arc<dyn Any + Send + Sync> = this;
        // S11: remove in U5, once Client::dial_context returns Stream.
        Ok(Box::new(murmur_common_net::io::StreamAsOldConn::new(murmur_common_net::new_ref_conn(
            murmur_common_net::io::OldConnAsStream(conn),
            ref_,
        ))))
    }

    pub async fn listen_packet(
        self: &Arc<Self>,
        ctx: &CancellationToken,
        metadata: &mut Metadata,
    ) -> anyhow::Result<Arc<dyn murmur_common_net::EnhancePacketConn>> {
        let mut result = self.get_client(true).listen_packet(ctx, metadata).await;
        if matches!(&result, Err(err) if is_too_many_open_streams(err)) {
            result = self.new_client(true).listen_packet(ctx, metadata).await;
        }
        let pc = result?;
        let this = Arc::clone(self);
        let ref_: Arc<dyn Any + Send + Sync> = this;
        Ok(murmur_common_net::new_ref_packet_conn(pc, ref_))
    }

    fn new_client(self: &Arc<Self>, udp: bool) -> Client {
        let clients_mutex = if udp { &self.udp_clients } else { &self.tcp_clients };
        let mut clients = clients_mutex.lock();
        let client = self.factory.new_client(udp);
        client.set_last_visited(Utc::now());
        clients.push_front(Some(client.clone()));
        client
    }

    fn get_client(self: &Arc<Self>, udp: bool) -> Client {
        let clients_mutex = if udp { &self.udp_clients } else { &self.tcp_clients };
        let best_client = {
            let mut clients = clients_mutex.lock();

            let mut best: Option<Client> = None;
            let mut i = 0;
            while i < clients.len() {
                match clients.get_mut(i).and_then(Option::take) {
                    None => {
                        clients.remove(i);
                    }
                    Some(client) => {
                        let replace = best.as_ref().is_none_or(|b| client.open_streams() < b.open_streams());
                        if replace {
                            best = Some(client.clone());
                        }
                        if let Some(slot) = clients.get_mut(i) {
                            *slot = Some(client);
                        }
                        i += 1;
                    }
                }
            }

            let mut i = 0;
            while i < clients.len() {
                let evict = match clients.get(i).and_then(Option::as_ref) {
                    Some(client) => {
                        let is_best = best.as_ref().is_some_and(|b| Client::ptr_eq(client, b));
                        !is_best
                            && client.open_streams() == 0
                            && client.last_visited().is_none_or(|t| Utc::now().signed_duration_since(t) > IDLE_EVICTION)
                    }
                    None => false,
                };
                if evict {
                    if let Some(client) = clients.remove(i).flatten() {
                        client.close();
                    }
                } else {
                    i += 1;
                }
            }

            best
        };

        match best_client {
            None => self.new_client(udp),
            Some(client) => {
                client.set_last_visited(Utc::now());
                client
            }
        }
    }
}

/// Builds the v4 pool. `v4::client::ClientOption` has no `Clone` impl, so the option
/// copy is a field-by-field reconstruction instead (every field is `Copy`).
pub fn new_pool_client_v4(client_option: &ClientOptionV4, dial_fn: DialFunc) -> Arc<PoolClient> {
    let option = ClientOptionV4 {
        token: client_option.token,
        udp_relay_mode: client_option.udp_relay_mode,
        request_timeout: client_option.request_timeout,
        max_udp_relay_packet_size: client_option.max_udp_relay_packet_size,
        fast_open: client_option.fast_open,
        max_open_streams: client_option.max_open_streams,
    };
    Arc::new(PoolClient {
        factory: ClientFactory::V4 { option: Arc::new(option), dial_fn },
        tcp_clients: Mutex::new(VecDeque::new()),
        udp_clients: Mutex::new(VecDeque::new()),
    })
}

pub fn new_pool_client_v5(client_option: &ClientOptionV5, dial_fn: DialFunc) -> Arc<PoolClient> {
    Arc::new(PoolClient {
        factory: ClientFactory::V5 { option: client_option.clone(), dial_fn },
        tcp_clients: Mutex::new(VecDeque::new()),
        udp_clients: Mutex::new(VecDeque::new()),
    })
}
