use bytes::BytesMut;
use rand::RngCore;

pub fn append_rand_bytes(buf: &mut BytesMut, length: usize) {
    let offset = buf.len();
    buf.resize(offset + length, 0);
    if let Some(appended) = buf.get_mut(offset..) {
        rand::rng().fill_bytes(appended);
    }
}
