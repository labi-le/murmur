use std::sync::{Arc, LazyLock};

use parking_lot::RwLock;

use murmur_component::auth::auth::{AuthStore as AuthStoreTrait, Authenticator};

struct AuthStore {
    authenticator: RwLock<Option<Arc<dyn Authenticator>>>,
}

impl AuthStoreTrait for AuthStore {
    fn authenticator(&self) -> Option<Arc<dyn Authenticator>> {
        self.authenticator.read().clone()
    }

    fn set_authenticator(&self, authenticator: Option<Arc<dyn Authenticator>>) {
        *self.authenticator.write() = authenticator;
    }
}

#[must_use]
pub fn new_auth_store(authenticator: Option<Arc<dyn Authenticator>>) -> Arc<dyn AuthStoreTrait> {
    Arc::new(AuthStore { authenticator: RwLock::new(authenticator) })
}

pub static DEFAULT: LazyLock<Arc<dyn AuthStoreTrait>> = LazyLock::new(|| new_auth_store(None));

/// The empty store always returns `None`, even after an authenticator is set.
struct NilAuthStore;

impl AuthStoreTrait for NilAuthStore {
    fn authenticator(&self) -> Option<Arc<dyn Authenticator>> {
        None
    }

    fn set_authenticator(&self, _authenticator: Option<Arc<dyn Authenticator>>) {}
}

pub static NIL: LazyLock<Arc<dyn AuthStoreTrait>> = LazyLock::new(|| Arc::new(NilAuthStore));
