use std::hash::{BuildHasher, RandomState};
use std::sync::LazyLock;

static GLOBAL_SEED: LazyLock<RandomState> = LazyLock::new(RandomState::new);

#[must_use]
pub fn global_id(material: &str) -> [u8; 8] {
    // The uint64 is stored into the array through a pointer, so native byte order.
    map_hash(material).to_ne_bytes()
}

pub fn map_hash(material: &str) -> u64 {
    GLOBAL_SEED.hash_one(material)
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn test_global_id_stable_and_distinct() {
        assert_eq!(global_id("10.0.0.1:1234"), global_id("10.0.0.1:1234"));

        let ids: HashSet<[u8; 8]> = (0..1000).map(|i| global_id(&format!("192.168.1.{i}:5555"))).collect();
        assert_eq!(ids.len(), 1000, "distinct materials collided");
    }
}
