use std::sync::Arc;

use crate::auth::auth as auth_store;
use murmur_component::auth::auth::{AuthStore, AuthUser as ComponentAuthUser};

#[derive(Clone, Debug, Default, serde::Serialize)]
pub struct AuthUser {
    pub username: String,
    pub password: String,
}

pub type AuthUsers = Option<Vec<AuthUser>>;

pub fn get_auth_store(users: &AuthUsers) -> Arc<dyn AuthStore> {
    if let Some(users) = users {
        if users.is_empty() {
            return auth_store::NIL.clone();
        }
        let component_users: Vec<ComponentAuthUser> = users
            .iter()
            .map(|user| ComponentAuthUser { user: user.username.clone(), pass: user.password.clone() })
            .collect();
        let authenticator = murmur_component::auth::auth::new_authenticator(&component_users);
        return auth_store::new_auth_store(authenticator);
    }
    auth_store::DEFAULT.clone()
}
