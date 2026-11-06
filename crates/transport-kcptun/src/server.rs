use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;

use murmur_common_net::io::{OldPacketConnAsDatagram, Stream, StreamAsOldConn};
use murmur_std_compat::net::{Conn, PacketConn};

use super::common::{kcp, smux, Config};
use super::comp::new_comp_stream;

pub struct Server {
    config: Config,
    block: Option<Arc<dyn kcp::BlockCrypt>>,
}

/// The per-connection handler, called once per accepted smux stream.
pub type HandlerFn = Arc<dyn Fn(Box<dyn Conn>) + Send + Sync>;

impl fmt::Debug for Server {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Server").field("config", &self.config).finish_non_exhaustive()
    }
}

impl Server {
    #[must_use]
    pub fn new(mut config: Config) -> Self {
        config.fill_defaults();
        let block = config.new_block();
        Self { config, block }
    }

    /// cancel-safe: the accept loop hands each connection to a spawned task before awaiting
    /// again, so dropping this future loses only the listener's own state.
    pub async fn serve(&self, pc: Box<dyn PacketConn>, handler: HandlerFn) -> Result<()> {
        let lis = kcp::serve_conn(
            self.block.clone(),
            self.config.data_shard,
            self.config.parity_shard,
            Box::new(OldPacketConnAsDatagram(pc)),
        )?;
        let _ = lis.set_dscp(self.config.dscp);
        let _ = lis.set_read_buffer(self.config.sock_buf);
        let _ = lis.set_write_buffer(self.config.sock_buf);
        loop {
            let conn = match lis.accept_kcp().await {
                Ok(conn) => conn,
                Err(err) => {
                    let _ = lis.close();
                    return Err(err);
                }
            };
            conn.set_stream_mode(true);
            conn.set_write_delay(false);
            conn.set_no_delay(
                self.config.no_delay,
                self.config.interval,
                self.config.resend,
                self.config.no_congestion,
            );
            conn.set_mtu(self.config.mtu);
            conn.set_window_size(self.config.snd_wnd, self.config.rcv_wnd);
            conn.set_ack_no_delay(self.config.ack_nodelay);
            conn.set_rate_limit(self.config.rate_limit.cast_unsigned());

            let mut net_conn: Box<dyn Stream> = conn;
            if !self.config.no_comp {
                net_conn = Box::new(new_comp_stream(net_conn));
            }

            let config = self.config.clone();
            let handler = Arc::clone(&handler);
            tokio::spawn(async move {
                let mut smux_config = smux::default_config();
                smux_config.version = config.smux_ver;
                smux_config.max_receive_buffer = i64::from(config.smux_buf);
                smux_config.max_stream_buffer = i64::from(config.stream_buf);
                smux_config.max_frame_size = config.frame_size;
                smux_config.keep_alive_interval = Duration::from_secs(i64::from(config.keep_alive).cast_unsigned());
                if smux_config.keep_alive_interval >= smux_config.keep_alive_timeout {
                    smux_config.keep_alive_timeout = 3 * smux_config.keep_alive_interval;
                }

                let Ok(mux) = smux::server(net_conn, &smux_config) else { return };
                loop {
                    let Ok(stream) = smux::accept(mux.as_ref()).await else { break };
                    let stream: Box<dyn Conn> = Box::new(StreamAsOldConn::new(stream));
                    let handler = Arc::clone(&handler);
                    tokio::spawn(async move {
                        handler(stream);
                    });
                }
                let _ = mux.close();
            });
        }
    }
}
