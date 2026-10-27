use std::sync::Arc;

use tokio::sync::Mutex;
use uuid::Uuid;

use murmur_common_net::BufferedConn;
use murmur_std_compat::net::PacketConn;

use super::metadata::Metadata;

pub trait PlainContext: Send + Sync {
    fn id(&self) -> Uuid;
}

/// `ConnContext`. One `Metadata` and one `BufferedConn` are shared with every holder: the context
/// keeps both and hands out a shared conn handle plus a borrow of the metadata.
///
/// A caller that needs both must take `conn()` first: the returned handle is owned, so the borrow
/// of the context ends before `metadata_mut()` starts.
pub trait ConnContext: PlainContext {
    fn metadata(&self) -> &Metadata;

    fn metadata_mut(&mut self) -> &mut Metadata;

    fn conn(&self) -> Arc<Mutex<BufferedConn>>;
}

pub trait PacketConnContext: PlainContext {
    fn metadata(&self) -> &Metadata;

    fn metadata_mut(&mut self) -> &mut Metadata;

    fn packet_conn(&self) -> Option<Arc<dyn PacketConn>>;
}
