use std::sync::Arc;

use tokio::sync::Mutex;
use uuid::Uuid;

use murmur_common::utils::uuid::new_uuid_v4;
use murmur_common_net::io::Stream;
use murmur_common_net::{new_buffered_conn, new_extended_conn, BufferedConn};
use murmur_constant::context::PlainContext;
use murmur_constant::metadata::Metadata;

#[derive(Debug)]
pub struct ConnContext {
    id: Uuid,
    metadata: Metadata,
    conn: Arc<Mutex<BufferedConn>>,
}

#[must_use]
pub fn new_conn_context(conn: Box<dyn Stream>, metadata: Metadata) -> ConnContext {
    let conn = new_extended_conn(conn);
    ConnContext { id: new_uuid_v4(), metadata, conn: Arc::new(Mutex::new(new_buffered_conn(conn))) }
}

impl PlainContext for ConnContext {
    fn id(&self) -> Uuid {
        self.id
    }
}

impl murmur_constant::context::ConnContext for ConnContext {
    fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    fn metadata_mut(&mut self) -> &mut Metadata {
        &mut self.metadata
    }

    fn conn(&self) -> Arc<Mutex<BufferedConn>> {
        Arc::clone(&self.conn)
    }
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::time::Duration;

    use murmur_constant::context::ConnContext as _;
    use murmur_std_compat::net::Conn as _;
    use tokio::net::{TcpListener, TcpStream};

    use super::*;

    #[tokio::test]
    async fn silent_tcp_peer_does_not_hold_tunnel_peek_lock_past_deadline() -> io::Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let client = TcpStream::connect(listener.local_addr()?).await?;
        let (server, _) = listener.accept().await?;
        let context = new_conn_context(Box::new(server), Metadata::default());
        let shared = context.conn();
        let peek_conn = Arc::clone(&shared);
        let (locked, ready) = tokio::sync::oneshot::channel();
        let peek = tokio::spawn(async move {
            let mut conn = peek_conn.lock().await;
            let _ = locked.send(());
            conn.set_read_deadline(Some(tokio::time::Instant::now() + Duration::from_millis(40)))?;
            let (_, result) = conn.peek(1).await;
            Ok::<_, io::Error>(result.unwrap_err().kind())
        });
        let _keep_silent_peer_open = client;
        ready.await.expect("peek task must acquire lock");
        let _guard = tokio::time::timeout(Duration::from_secs(2), shared.lock())
            .await
            .expect("tunnel peek must release the connection lock");
        let result = tokio::time::timeout(Duration::from_secs(2), peek).await.expect("peek must finish")??;
        assert_eq!(result, io::ErrorKind::TimedOut);
        Ok(())
    }
}
