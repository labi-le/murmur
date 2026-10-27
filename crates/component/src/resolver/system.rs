use std::collections::HashSet;
use std::sync::LazyLock;

use parking_lot::Mutex;

static BLACKLIST: LazyLock<Mutex<HashSet<String>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

pub fn add_system_dns_blacklist<S: AsRef<str>>(names: &[S]) {
    let mut blacklist = BLACKLIST.lock();
    for name in names {
        blacklist.insert(name.as_ref().to_owned());
    }
}

pub fn remove_system_dns_blacklist<S: AsRef<str>>(names: &[S]) {
    let mut blacklist = BLACKLIST.lock();
    for name in names {
        blacklist.remove(name.as_ref());
    }
}

pub fn is_system_dns_blacklisted<S: AsRef<str>>(names: &[S]) -> bool {
    let blacklist = BLACKLIST.lock();
    names.iter().any(|name| blacklist.contains(name.as_ref()))
}
