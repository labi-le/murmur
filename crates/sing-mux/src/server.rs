//! The service drives one carrier's stream handlers together inside a single call.
//!
//! `tokio::spawn` would need `H: 'static` and therefore an `Arc<H>`, which would force every
//! `MuxService` caller in this tree to hold its handler behind `Arc` even when it doesn't
//! otherwise need to (several call sites in `listener-sing` currently own their `ListenerHandler`
//! by value). Interleaving all of one mux carrier's stream handlers on a
//! `futures::stream::FuturesUnordered` inside this one call instead gives the same
//! run-concurrently-with-each-other behaviour without that requirement: the handler is borrowed
//! for exactly the lifetime of [`Service::new_connection`]'s own call, and every accepted stream's
//! processing still overlaps the others' I/O waits.

use futures::stream::FuturesUnordered;
use futures::StreamExt;
use tokio::io::AsyncWriteExt;

use crate::brutal::{
    read_brutal_request, set_brutal_options, write_brutal_response, RawSocket, BRUTAL_AVAILABLE, BRUTAL_EXCHANGE_DOMAIN,
};
use crate::client::BrutalOptions;
use crate::padding::new_padding_conn;
use crate::protocol::{read_request, read_stream_request, StreamNetwork};
use crate::server_conn::{new_server_conn, new_server_packet_conn};
use crate::session::{new_server_session, MuxConn, MuxStream};
use murmur_log::warnln;
pub use murmur_sing::metadata::Metadata;
use murmur_sing::metadata::Socksaddr;
use murmur_sing::network::PacketConn as SingPacketConn;

#[async_trait::async_trait]
pub trait ServiceHandler: Send + Sync {
    async fn new_connection(&self, conn: Box<dyn MuxConn>, metadata: Metadata) -> anyhow::Result<()>;
    async fn new_packet_connection(&self, conn: Box<dyn SingPacketConn>, metadata: Metadata) -> anyhow::Result<()>;
}

/// The `ServiceOptions` this build exposes.
///
/// This build's callers pass the handler and log through their own errors per call (see the module
/// doc for why the handler moved off the struct), and the stream-context constructor has exactly one real caller
/// in this tree (`listener-sing`'s identity closure), so it is not reproduced as a configurable
/// field.
#[derive(Debug)]
pub struct ServiceOptions {
    pub padding: bool,
    pub brutal: BrutalOptions,
}

#[derive(Debug)]
pub struct Service {
    padding: bool,
    brutal: BrutalOptions,
}

pub fn new_service(options: ServiceOptions) -> anyhow::Result<Service> {
    if options.brutal.enabled && !BRUTAL_AVAILABLE {
        return Err(anyhow::anyhow!("TCP Brutal is only supported on Linux"));
    }
    Ok(Service { padding: options.padding, brutal: options.brutal })
}

impl Service {
    /// Runs the accept loop for one mux carrier connection to completion; the caller task is
    /// what actually runs concurrently with everything else in the listener.
    // NOT cancel-safe: the stream handlers are owned by this call rather than spawned, so dropping
    // the future drops every stream still in flight on the carrier -- which is what a listener
    // shutdown means.
    pub async fn new_connection<H: ServiceHandler>(
        &self,
        handler: &H,
        mut conn: Box<dyn MuxConn>,
        socket: RawSocket,
        metadata: Metadata,
    ) -> anyhow::Result<()> {
        let request = read_request(&mut conn).await?;
        if request.padding {
            conn = new_padding_conn(conn);
        } else if self.padding {
            return Err(anyhow::anyhow!("non-padded connection rejected"));
        }
        let session = new_server_session(conn, request.protocol).await?;
        let mut in_flight = FuturesUnordered::new();
        loop {
            tokio::select! {
                accepted = session.accept() => {
                    match accepted {
                        Ok(stream) => {
                            in_flight.push(Self::handle_stream(
                                handler, &self.brutal, socket, stream, metadata.clone(),
                            ));
                        }
                        Err(_) => break,
                    }
                }
                Some(result) = in_flight.next(), if !in_flight.is_empty() => {
                    if let Err(err) = result {
                        warnln!("sing-mux: handle connection: {err:?}");
                    }
                }
            }
        }
        while let Some(result) = in_flight.next().await {
            if let Err(err) = result {
                warnln!("sing-mux: handle connection: {err:?}");
            }
        }
        let _ = session.close().await;
        Ok(())
    }

    async fn handle_stream<H: ServiceHandler>(
        handler: &H,
        brutal: &BrutalOptions,
        socket: RawSocket,
        stream: Box<dyn MuxStream>,
        mut metadata: Metadata,
    ) -> anyhow::Result<()> {
        let mut stream = crate::error::wrap_stream(stream);
        let request = read_stream_request(&mut stream)
            .await
            .map_err(|err| anyhow::anyhow!("read multiplex stream request: {err}"))?;
        metadata.destination = request.destination.clone();
        match request.network {
            StreamNetwork::Tcp => {
                let mut conn = new_server_conn(stream);
                if request.destination.fqdn == BRUTAL_EXCHANGE_DOMAIN {
                    let client_receive_bps = read_brutal_request(&mut conn)
                        .await
                        .map_err(|err| anyhow::anyhow!("read brutal request: {err}"))?;
                    if brutal.enabled {
                        let send_bps = brutal.send_bps.min(client_receive_bps);
                        match set_brutal_options(socket, send_bps) {
                            Ok(()) => {
                                write_brutal_response(&mut conn, brutal.receive_bps, true, "")
                                    .await
                                    .map_err(|err| anyhow::anyhow!("write brutal response: {err}"))?;
                            }
                            Err(err) => {
                                write_brutal_response(&mut conn, 0, false, &format!("enable TCP Brutal: {err}"))
                                    .await
                                    .map_err(|err| anyhow::anyhow!("write brutal response: {err}"))?;
                            }
                        }
                    } else {
                        write_brutal_response(&mut conn, 0, false, "brutal is not enabled by the server")
                            .await
                            .map_err(|err| anyhow::anyhow!("write brutal response: {err}"))?;
                    }
                    let _ = conn.shutdown().await;
                    return Ok(());
                }
                handler.new_connection(Box::new(conn), metadata).await
            }
            StreamNetwork::Udp => {
                let packet_conn: Box<dyn SingPacketConn> = if request.packet_addr {
                    Box::new(new_server_packet_conn(stream, Socksaddr::default(), true))
                } else {
                    Box::new(new_server_packet_conn(stream, request.destination.clone(), false))
                };
                handler.new_packet_connection(packet_conn, metadata).await
            }
        }
    }
}
