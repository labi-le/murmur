//! Persistent node state: the trait a node persists identity, peer-cache, and
//! per-network configuration objects through.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

/// Reports a failed state operation.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("invalid ZeroTier state object name")]
    InvalidName,
    #[error("ZeroTier state I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Persists opaque node state under a relative object-name namespace.
///
/// A node serializes store calls and treats persistence mutations as best
/// effort, matching the official core, so a failed [`StateStore::put`] never
/// fails the protocol operation that produced the state. The same store must
/// not be shared by concurrently active nodes without its own synchronization.
pub trait StateStore {
    /// An independently owned copy of `name`, or `None` when it is absent. A
    /// failed read also reports absence, as the official state callback does.
    fn get(&self, name: &str) -> Option<Vec<u8>>;
    /// Stores an independently owned copy of `value`.
    fn put(&mut self, name: &str, value: &[u8]) -> Result<(), StoreError>;
    /// Removes `name`, succeeding when it is already absent.
    fn delete(&mut self, name: &str) -> Result<(), StoreError>;
}

/// An unsynchronized in-memory store for one active node.
#[derive(Debug, Default, Clone)]
pub struct MemoryStore {
    data: BTreeMap<String, Vec<u8>>,
}

impl MemoryStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl StateStore for MemoryStore {
    fn get(&self, name: &str) -> Option<Vec<u8>> {
        self.data.get(name).cloned()
    }

    fn put(&mut self, name: &str, value: &[u8]) -> Result<(), StoreError> {
        self.data.insert(name.to_owned(), value.to_vec());
        Ok(())
    }

    fn delete(&mut self, name: &str) -> Result<(), StoreError> {
        self.data.remove(name);
        Ok(())
    }
}

/// Persists state as files below a root directory, creating parent
/// directories on demand and writing state objects with owner-only access.
#[derive(Debug, Clone)]
pub struct FileStore {
    root: PathBuf,
}

impl FileStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The absolute or relative path one state object name resolves to.
    pub fn path_for(&self, name: &str) -> Result<PathBuf, StoreError> {
        validate_state_name(name)?;
        Ok(self.root.join(name))
    }
}

impl StateStore for FileStore {
    fn get(&self, name: &str) -> Option<Vec<u8>> {
        let path = self.path_for(name).ok()?;
        fs::read(path).ok()
    }

    fn put(&mut self, name: &str, value: &[u8]) -> Result<(), StoreError> {
        let path = self.path_for(name)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        write_owner_only(&path, value)
    }

    fn delete(&mut self, name: &str) -> Result<(), StoreError> {
        let path = self.path_for(name)?;
        match fs::remove_file(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            other => other.map_err(StoreError::Io),
        }
    }
}

fn write_owner_only(path: &std::path::Path, value: &[u8]) -> Result<(), StoreError> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
        file.write_all(value)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        fs::write(path, value).map_err(StoreError::Io)
    }
}

/// Rejects names outside the relative state namespace.
fn validate_state_name(name: &str) -> Result<(), StoreError> {
    if name.is_empty() || name.starts_with('/') || name.contains('\\') {
        return Err(StoreError::InvalidName);
    }
    if name.split('/').any(|segment| segment.is_empty() || segment == "." || segment == "..") {
        return Err(StoreError::InvalidName);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_store_owns_its_values() {
        let mut store = MemoryStore::new();
        assert_eq!(store.get("networks.d/x.conf"), None);
        let mut value = vec![1u8, 2, 3];
        store.put("networks.d/x.conf", &value).unwrap();
        value[0] = 9;
        assert_eq!(store.get("networks.d/x.conf"), Some(vec![1, 2, 3]));
        store.delete("networks.d/x.conf").unwrap();
        store.delete("networks.d/x.conf").unwrap();
        assert_eq!(store.get("networks.d/x.conf"), None);
    }

    #[test]
    fn file_store_round_trips_and_tolerates_absence() {
        let root = std::env::temp_dir().join(format!("murmur-zerotier-store-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let mut store = FileStore::new(&root);
        let name = "networks.d/0123456789abcdef.conf";
        assert_eq!(store.get(name), None);
        store.delete(name).unwrap();
        store.put(name, b"configuration").unwrap();
        assert_eq!(store.get(name), Some(b"configuration".to_vec()));
        store.put(name, b"replacement").unwrap();
        assert_eq!(store.get(name), Some(b"replacement".to_vec()));
        assert!(matches!(store.put("../escape", b"x"), Err(StoreError::InvalidName)));
        store.delete(name).unwrap();
        assert_eq!(store.get(name), None);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn rejects_names_outside_the_state_namespace() {
        assert!(matches!(validate_state_name(""), Err(StoreError::InvalidName)));
        assert!(matches!(validate_state_name("/etc/passwd"), Err(StoreError::InvalidName)));
        assert!(matches!(validate_state_name("a/../b"), Err(StoreError::InvalidName)));
        assert!(matches!(validate_state_name("a//b"), Err(StoreError::InvalidName)));
        assert!(matches!(validate_state_name("a\\b"), Err(StoreError::InvalidName)));
        assert!(validate_state_name("networks.d/0123456789abcdef.conf").is_ok());
    }
}
