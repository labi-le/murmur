use std::sync::Arc;

use murmur_constant::metadata::{Metadata, NetWork, Type};
use murmur_std_compat::net::Conn;
use murmur_transport::socks5::socks5;

use super::addition::{apply_additions, with_in_addr, with_src_addr, Addition};
use super::util::parse_socks_addr;

pub fn new_http(
    target: &socks5::Addr,
    src_conn: &dyn Conn,
    conn: Box<dyn Conn>,
    additions: &[Addition],
) -> (Box<dyn Conn>, Metadata) {
    let mut metadata = parse_socks_addr(target);
    metadata.network = NetWork::TCP;
    metadata.type_ = Type::HTTP;
    metadata.raw_src_addr = src_conn.remote_addr().ok().map(Arc::from);
    metadata.raw_dst_addr = src_conn.local_addr().ok().map(Arc::from);
    let src_remote_addr = src_conn.remote_addr().ok();
    let src_local_addr = src_conn.local_addr().ok();
    apply_additions(&mut metadata, &[with_src_addr(src_remote_addr), with_in_addr(src_local_addr)]);
    apply_additions(&mut metadata, additions);
    (conn, metadata)
}
