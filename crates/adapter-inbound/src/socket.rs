use std::net::SocketAddr;

use murmur_common_net::io::Stream;
use murmur_constant::metadata::{Metadata, NetWork, Type};
use murmur_std_compat::net::{Addr, TcpAddr};
use murmur_transport::socks5::socks5;

use super::addition::{apply_additions, with_in_addr, with_src_addr, Addition};
use super::util::parse_socks_addr;

fn boxed_addr(addr: SocketAddr) -> Box<dyn Addr> {
    Box::new(TcpAddr::from(addr))
}

pub fn new_socket(
    target: &socks5::Addr,
    conn: Box<dyn Stream>,
    source: Type,
    additions: &[Addition],
) -> (Box<dyn Stream>, Metadata) {
    let mut metadata = parse_socks_addr(target);
    metadata.network = NetWork::TCP;
    metadata.type_ = source;
    let remote_addr = conn.peer_addr().ok().map(boxed_addr);
    let local_addr = conn.local_addr().ok().map(boxed_addr);
    apply_additions(&mut metadata, &[with_src_addr(remote_addr), with_in_addr(local_addr)]);
    apply_additions(&mut metadata, additions);
    (conn, metadata)
}

#[cfg(test)]
mod tests {
    use tokio::net::{TcpListener, TcpStream};

    use super::*;

    #[tokio::test]
    async fn new_socket_populates_metadata_from_a_real_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let server_addr = listener.local_addr().expect("server addr");
        let client = TcpStream::connect(server_addr).await.expect("connect");
        let (server, _) = listener.accept().await.expect("accept");
        let client_addr = client.local_addr().expect("client addr");

        let target = socks5::parse_addr("192.0.2.1:80").expect("valid target");
        let (conn, metadata): (Box<dyn Stream>, Metadata) = new_socket(&target, Box::new(server), Type::SOCKS5, &[]);

        assert_eq!(conn.local_addr().expect("conn local addr"), server_addr);
        assert_eq!(metadata.src_ip, Some(client_addr.ip()));
        assert_eq!(metadata.src_port, client_addr.port());
        assert_eq!(metadata.in_ip, Some(server_addr.ip()));
        assert_eq!(metadata.in_port, server_addr.port());
        assert_eq!(metadata.network, NetWork::TCP);
        assert_eq!(metadata.type_, Type::SOCKS5);
    }
}
