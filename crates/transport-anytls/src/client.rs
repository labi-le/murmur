use std::future::Future;
use std::sync::{Arc, Weak};
use std::time::Duration;

use arc_swap::ArcSwapOption;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio_util::sync::CancellationToken;

use crate::padding::padding::{self as padding_mod, PaddingFactory, DEFAULT_PADDING_SCHEME};
use crate::session::client::{new_client as new_session_client, Client as SessionClient};
use murmur_common_net::io::{close_stream, OldConnAsStream, Stream as NetStream, StreamAsOldConn};
use murmur_compat::sing_buf;
use murmur_component_proxydialer::sing::SingDialer;
use murmur_sing::metadata::{Socksaddr, SOCKSADDR_SERIALIZER};
use murmur_std_compat::net::Conn as NetConn;
use murmur_transport_vmess::tls::{stream_tls_conn, TlsConfig};

pub struct ClientConfig {
    pub password: String,
    pub client_metadata: String,
    pub idle_session_check_interval: Duration,
    pub idle_session_timeout: Duration,
    pub min_idle_session: i32,
    pub disable_reuse: bool,
    pub server: Socksaddr,
    pub dialer: Arc<dyn SingDialer>,
    pub tls_config: TlsConfig,
}

impl std::fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientConfig")
            .field("idle_session_check_interval", &self.idle_session_check_interval)
            .field("idle_session_timeout", &self.idle_session_timeout)
            .field("min_idle_session", &self.min_idle_session)
            .field("disable_reuse", &self.disable_reuse)
            .field("server", &self.server)
            .finish_non_exhaustive()
    }
}

pub struct Client {
    password_sha256: Vec<u8>,
    tls_config: TlsConfig,
    dialer: Arc<dyn SingDialer>,
    server: Socksaddr,
    session: Arc<SessionClient>,
    padding: Arc<ArcSwapOption<PaddingFactory>>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client").field("server", &self.server).finish_non_exhaustive()
    }
}

/// Builds the client. It is shared with the caller the same way (as `Arc<Client>`) so
/// the outbound TLS connection can be handed to the session client as a closure that outlives
/// the client.
#[must_use]
pub fn new_client(ctx: &CancellationToken, config: ClientConfig) -> Arc<Client> {
    let password_sha256 = Sha256::digest(config.password.as_bytes()).to_vec();
    let padding: Arc<ArcSwapOption<PaddingFactory>> = Arc::new(ArcSwapOption::default());
    padding_mod::update_padding_scheme(DEFAULT_PADDING_SCHEME, &padding);

    let client = Arc::new_cyclic(|weak: &Weak<Client>| {
        let weak = Weak::clone(weak);
        let session_padding = Arc::clone(&padding);
        let dial_out = Box::new(move |ctx: &CancellationToken| {
            let ctx = ctx.clone();
            let weak = Weak::clone(&weak);
            let fut: std::pin::Pin<Box<dyn Future<Output = anyhow::Result<Box<dyn NetConn>>> + Send>> =
                Box::pin(async move {
                    let Some(client) = weak.upgrade() else {
                        return Err(anyhow::anyhow!("anytls client dropped while dialing"));
                    };
                    client.create_outbound_tls_connection(&ctx).await
                });
            fut
        });

        let session = new_session_client(
            ctx,
            dial_out,
            session_padding,
            config.client_metadata,
            config.idle_session_check_interval,
            config.idle_session_timeout,
            config.min_idle_session,
            config.disable_reuse,
        );

        Client {
            password_sha256,
            tls_config: config.tls_config,
            dialer: config.dialer,
            server: config.server,
            session,
            padding,
        }
    });

    client
}

impl Client {
    pub async fn create_proxy(
        &self,
        ctx: &CancellationToken,
        destination: Socksaddr,
    ) -> anyhow::Result<Box<dyn NetConn>> {
        let mut conn = self.session.create_stream(ctx).await?;
        if let Err(err) = write_socksaddr(conn.as_mut(), &destination).await {
            let _ = close_stream(conn.as_ref());
            return Err(err);
        }
        Ok(Box::new(StreamAsOldConn::new(conn)))
    }

    async fn create_outbound_tls_connection(&self, ctx: &CancellationToken) -> anyhow::Result<Box<dyn NetConn>> {
        let conn = self.dialer.dial_context(ctx, "tcp", self.server.clone()).await?;

        let mut b = sing_buf::new_packet();

        if let Err(err) = b.write_bytes(&self.password_sha256) {
            b.release();
            return Err(err.into());
        }
        let padding_len = self
            .padding
            .load_full()
            .and_then(|factory| factory.generate_record_payload_sizes(0).first().copied())
            .unwrap_or(0);
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "the padding length travels as a 16-bit big-endian field, and the scheme's entries truncate the same way"
        )]
        let padding_len_wire = padding_len as u16;
        b.extend(2).copy_from_slice(&padding_len_wire.to_be_bytes());
        if padding_len > 0 {
            if let Err(err) = b.write_zero_n(usize::from(padding_len_wire)) {
                b.release();
                return Err(err.into());
            }
        }

        let mut tls_conn = match stream_tls_conn(ctx, Box::new(OldConnAsStream(conn)), &self.tls_config).await {
            Ok(tls_conn) => tls_conn,
            Err(err) => {
                b.release();
                return Err(err);
            }
        };

        if let Err(err) = b.write_to(&mut tls_conn).await {
            b.release();
            let _ = close_stream(tls_conn.as_ref());
            return Err(err.into());
        }
        if let Err(err) = tls_conn.flush().await {
            b.release();
            let _ = close_stream(tls_conn.as_ref());
            return Err(err.into());
        }
        b.release();
        Ok(Box::new(StreamAsOldConn::new(tls_conn)))
    }

    pub fn close(&self) -> std::io::Result<()> {
        self.session.close()
    }
}

/// Serializes `destination` as a SOCKS address followed by its port, via `SOCKSADDR_SERIALIZER`.
async fn write_socksaddr(conn: &mut dyn NetStream, destination: &Socksaddr) -> anyhow::Result<()> {
    let mut out = Vec::with_capacity(19);
    SOCKSADDR_SERIALIZER.write_addr_port(&mut out, destination)?;
    conn.write_all(&out).await?;
    Ok(())
}
