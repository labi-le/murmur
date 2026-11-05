use std::collections::HashMap;
use std::sync::{Arc, LazyLock};

pub trait Authenticator: Send + Sync {
    fn verify(&self, user: &str, pass: &str) -> bool;
    fn users(&self) -> Vec<String>;
}

pub trait AuthStore: Send + Sync {
    fn authenticator(&self) -> Option<Arc<dyn Authenticator>>;
    fn set_authenticator(&self, authenticator: Option<Arc<dyn Authenticator>>);
}

#[derive(Clone, Debug)]
pub struct AuthUser {
    pub user: String,
    pub pass: String,
}

struct InMemoryAuthenticator {
    storage: HashMap<String, String>,
    usernames: Vec<String>,
}

impl Authenticator for InMemoryAuthenticator {
    fn verify(&self, user: &str, pass: &str) -> bool {
        self.storage.get(user).is_some_and(|real_pass| real_pass == pass)
    }

    fn users(&self) -> Vec<String> {
        self.usernames.clone()
    }
}

#[must_use]
pub fn new_authenticator(users: &[AuthUser]) -> Option<Arc<dyn Authenticator>> {
    if users.is_empty() {
        return None;
    }
    let mut storage = HashMap::new();
    let mut usernames = Vec::with_capacity(users.len());
    for user in users {
        storage.insert(user.user.clone(), user.pass.clone());
        usernames.push(user.user.clone());
    }
    Some(Arc::new(InMemoryAuthenticator { storage, usernames }))
}

pub static ALWAYS_VALID: LazyLock<Arc<dyn Authenticator>> = LazyLock::new(|| Arc::new(AlwaysValid));

struct AlwaysValid;

impl Authenticator for AlwaysValid {
    fn verify(&self, _user: &str, _pass: &str) -> bool {
        true
    }

    fn users(&self) -> Vec<String> {
        Vec::new()
    }
}
