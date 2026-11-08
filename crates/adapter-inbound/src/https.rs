use std::sync::Arc;

use murmur_constant::metadata::{Metadata, Type};
use murmur_std_compat::net::Conn;

use super::addition::{apply_additions, with_in_addr, with_src_addr, Addition};
use super::util::parse_http_addr;

/// Takes the CONNECT authority as a raw string; see `parse_http_addr`'s doc for why.
pub fn new_https(authority: &str, conn: Box<dyn Conn>, additions: &[Addition]) -> (Box<dyn Conn>, Metadata) {
    let mut metadata = parse_http_addr(authority);
    metadata.type_ = Type::HTTPS;
    metadata.raw_src_addr = conn.remote_addr().ok().map(Arc::from);
    metadata.raw_dst_addr = conn.local_addr().ok().map(Arc::from);
    let remote_addr = conn.remote_addr().ok();
    let local_addr = conn.local_addr().ok();
    apply_additions(&mut metadata, &[with_src_addr(remote_addr), with_in_addr(local_addr)]);
    apply_additions(&mut metadata, additions);
    (conn, metadata)
}
