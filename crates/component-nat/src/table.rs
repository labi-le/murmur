use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::Notify;

use murmur_common::xsync::map::Map;
use murmur_constant::adapters::{NatTable, PacketSender};

#[derive(Default)]
pub struct Table {
    mapping: Map<String, Arc<Entry>>,
}

impl std::fmt::Debug for Table {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Table").finish_non_exhaustive()
    }
}

pub(crate) struct Entry {
    pub packet_sender: Arc<dyn PacketSender>,
    pub local_udp_conn_map: Map<String, Arc<UdpSocket>>,
    pub local_lock_map: Map<String, Arc<Notify>>,
}

impl NatTable for Table {
    fn get_or_create(
        &self,
        key: &str,
        maker: Box<dyn FnOnce() -> Arc<dyn PacketSender> + Send>,
    ) -> (Arc<dyn PacketSender>, bool) {
        let mut maker = Some(maker);
        let (item, loaded) = self.mapping.load_or_store_fn(key.to_owned(), || {
            #[expect(
                clippy::expect_used,
                reason = "`load_or_store_fn` runs its constructor at most once, and only on a miss, so the maker is still present here"
            )]
            let make = maker.take().expect("the maker runs only on a miss");
            Arc::new(Entry {
                packet_sender: make(),
                local_udp_conn_map: Map::default(),
                local_lock_map: Map::default(),
            })
        });
        (Arc::clone(&item.packet_sender), loaded)
    }

    fn delete(&self, key: &str) {
        self.mapping.delete(key.to_owned());
    }

    fn get_for_local_conn(&self, l_addr: &str, r_addr: &str) -> Option<Arc<UdpSocket>> {
        self.get_entry(l_addr)?.local_udp_conn_map.load(&r_addr.to_owned())
    }

    fn add_for_local_conn(&self, l_addr: &str, r_addr: &str, conn: Arc<UdpSocket>) -> bool {
        let Some(entry) = self.get_entry(l_addr) else {
            return false;
        };
        entry.local_udp_conn_map.store(r_addr.to_owned(), conn);
        true
    }

    fn range_for_local_conn(&self, l_addr: &str, f: &mut dyn FnMut(&str, &Arc<UdpSocket>) -> bool) {
        let Some(entry) = self.get_entry(l_addr) else {
            return;
        };
        entry.local_udp_conn_map.range(|key, value| f(key, value));
    }

    fn get_or_create_lock_for_local_conn(&self, l_addr: &str, key: &str) -> (Arc<Notify>, bool) {
        let Some(entry) = self.get_entry(l_addr) else {
            // The return type has no absent value, so the `loaded` flag is what tells the caller the
            // entry is missing.
            return (Arc::new(Notify::new()), false);
        };
        entry.local_lock_map.load_or_store_fn(key.to_owned(), make_lock)
    }

    fn delete_for_local_conn(&self, l_addr: &str, key: &str) {
        let Some(entry) = self.get_entry(l_addr) else {
            return;
        };
        entry.local_udp_conn_map.delete(key.to_owned());
    }

    fn delete_lock_for_local_conn(&self, l_addr: &str, key: &str) {
        let Some(entry) = self.get_entry(l_addr) else {
            return;
        };
        entry.local_lock_map.delete(key.to_owned());
    }
}

impl Table {
    fn get_entry(&self, key: &str) -> Option<Arc<Entry>> {
        self.mapping.load(&key.to_owned())
    }
}

fn make_lock() -> Arc<Notify> {
    Arc::new(Notify::new())
}

#[must_use]
pub fn new() -> Table {
    Table::default()
}
