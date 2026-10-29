use murmur_adapter_inbound::addition::{apply_additions, Addition};
use murmur_adapter_inbound::socket::new_socket;
use murmur_common::shared_conn::SharedConn;
use murmur_common_net::io::{CancellableStream, Stream};
use murmur_transport::socks5::socks5;

use super::context::{with_additions, SingContext};
use super::sing::{convert_metadata, ListenerHandler};

impl ListenerHandler {
    /// Combines socket construction with `Tunnel::handle_tcp_conn`, but also handles a special
    /// FQDN destination.
    pub async fn handle_socket(&self, target: &socks5::Addr, conn: Box<dyn Stream>, additions: &[Addition]) {
        let (conn, mut metadata) = new_socket(target, conn, self.config.type_, self.config.additions.as_slice());
        if self.is_special_fqdn(&metadata.host) {
            let shared = SharedConn::new(CancellableStream::new(conn));
            let ctx = with_additions(&SingContext::default(), additions.to_vec());
            let sing_metadata = convert_metadata(&metadata);
            if self.parse_special_fqdn(ctx, Box::new(shared.clone()), sing_metadata).await.is_err() {
                let _ = shared.close();
            }
        } else {
            apply_additions(&mut metadata, additions);
            self.config.tunnel.handle_tcp_conn(conn, metadata).await;
        }
    }
}
