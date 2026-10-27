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
    fn get(&self, key: &str) -> Option<Arc<dyn PacketSender>> {
        self.get_entry(key).map(|entry| Arc::clone(&entry.packet_sender))
    }

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
        self.get_entry(l_addr)?.local_udp_conn_map.load(r_addr)
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
        self.mapping.load(key)
    }
}

fn make_lock() -> Arc<Notify> {
    Arc::new(Notify::new())
}

#[must_use]
pub fn new() -> Table {
    Table::default()
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Barrier;

    use murmur_constant::adapters::{PacketAdapter, PacketConn, WriteBackProxy};
    use murmur_constant::metadata::Metadata;

    use super::*;

    struct NoopSender;

    #[async_trait::async_trait]
    impl PacketSender for NoopSender {
        async fn send(&self, _packet: Arc<dyn PacketAdapter>) {}

        async fn process(&self, _conn: Arc<dyn PacketConn>, _proxy: Arc<dyn WriteBackProxy>) {}

        fn close(&self) {}

        async fn do_sniff(&self, _metadata: &mut Metadata) -> anyhow::Result<()> {
            Ok(())
        }

        fn add_mapping(&self, _origin_metadata: &Metadata, _metadata: &Metadata) {}

        fn restore_read_from(&self, addr: IpAddr) -> IpAddr {
            addr
        }
    }

    /// Every table lookup runs with a borrowed key; the entry stored under the owned `String` has
    /// to stay reachable through it, both in the outer mapping and in a local conn map.
    #[tokio::test]
    async fn local_conns_are_reachable_through_a_borrowed_key() {
        let table = Table::default();
        let send: Box<dyn FnOnce() -> Arc<dyn PacketSender> + Send> = Box::new(|| Arc::new(NoopSender));

        let (sender, loaded) = table.get_or_create("entry.example:1", send);
        assert!(!loaded, "the first get_or_create stores the entry");
        let (again, loaded) = table.get_or_create("entry.example:1", Box::new(|| Arc::new(NoopSender)));
        assert!(loaded, "the borrowed lookup did not find the stored entry");
        assert!(Arc::ptr_eq(&sender, &again), "the second call built a second entry");

        let sock = Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.expect("bind udp socket"));
        assert!(table.add_for_local_conn("entry.example:1", "192.0.2.9:5353", Arc::clone(&sock)));

        let found = table.get_for_local_conn("entry.example:1", "192.0.2.9:5353").expect("the local conn is stored");
        assert!(Arc::ptr_eq(&found, &sock), "the borrowed local conn lookup found another socket");
        assert!(
            table.get_for_local_conn("entry.example:1", "192.0.2.10:5353").is_none(),
            "an unstored remote address was found"
        );
    }

    #[tokio::test]
    async fn an_established_entry_is_visible_to_the_borrowed_lookup_until_deleted() {
        let table = Table::default();
        assert!(table.get("lookup.example:1").is_none(), "an absent key produced a sender");

        let (sender, loaded) = table.get_or_create("lookup.example:1", Box::new(|| Arc::new(NoopSender)));
        assert!(!loaded, "the first get_or_create stores the entry");

        let found = table.get("lookup.example:1").expect("the established key is not visible to the fast lookup");
        assert!(Arc::ptr_eq(&sender, &found), "the fast lookup built or found another sender");

        table.delete("lookup.example:1");
        assert!(table.get("lookup.example:1").is_none(), "a deleted key remains visible to the fast lookup");
    }

    /// The established fast path misses first and then falls back to `get_or_create`, which is what
    /// the UDP loop does. Concurrent misses on one key must still run one maker and hand every
    /// caller the same sender.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_fast_path_misses_build_one_sender() {
        const THREADS: usize = 8;
        let table = Arc::new(Table::default());
        let made = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(Barrier::new(THREADS));
        let mut handles = Vec::with_capacity(THREADS);
        for _ in 0..THREADS {
            let table = Arc::clone(&table);
            let made = Arc::clone(&made);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                // The fast lookup may miss or may observe another thread's entry; either way the
                // create below is the only path that can build a sender.
                let _ = table.get("race.example:1");
                let (sender, _) = table.get_or_create(
                    "race.example:1",
                    Box::new(move || {
                        made.fetch_add(1, Ordering::SeqCst);
                        Arc::new(NoopSender)
                    }),
                );
                sender
            }));
        }
        let senders: Vec<_> =
            handles.into_iter().map(|handle| handle.join().expect("a racing thread panicked")).collect();

        assert_eq!(made.load(Ordering::SeqCst), 1, "the maker ran more than once for one key");
        let first = table.get("race.example:1").expect("the winning entry is stored");
        assert!(senders.iter().all(|sender| Arc::ptr_eq(sender, &first)), "callers saw different senders");
    }

    #[tokio::test]
    async fn deleting_and_recreating_a_key_produces_a_new_sender() {
        let table = Table::default();
        let made = Arc::new(AtomicUsize::new(0));

        let count = Arc::clone(&made);
        let (first, loaded) = table.get_or_create(
            "recreate.example:1",
            Box::new(move || {
                count.fetch_add(1, Ordering::SeqCst);
                Arc::new(NoopSender)
            }),
        );
        assert!(!loaded, "the first get_or_create stores the entry");

        table.delete("recreate.example:1");
        assert!(table.get("recreate.example:1").is_none(), "a deleted key remains visible to the fast lookup");

        let count = Arc::clone(&made);
        let (second, loaded) = table.get_or_create(
            "recreate.example:1",
            Box::new(move || {
                count.fetch_add(1, Ordering::SeqCst);
                Arc::new(NoopSender)
            }),
        );
        assert!(!loaded, "the deleted entry was reused");
        assert_eq!(made.load(Ordering::SeqCst), 2, "the deleted entry did not require a second maker");
        assert!(!Arc::ptr_eq(&first, &second), "recreation returned the deleted sender");
        let found = table.get("recreate.example:1").expect("the recreated key is not visible to the fast lookup");
        assert!(Arc::ptr_eq(&second, &found), "the fast lookup returned the deleted sender");
    }
}
