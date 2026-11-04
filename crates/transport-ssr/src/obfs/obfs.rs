use std::collections::HashMap;
use std::sync::LazyLock;

use anyhow::{anyhow, Result};

use murmur_common_net::io::Stream;

use super::base::Base;
#[derive(Debug, thiserror::Error)]
#[error("tls1.2_ticket_auth incorrect magic number")]
pub(crate) struct ErrTLS12TicketAuthIncorrectMagicNumber;
#[derive(Debug, thiserror::Error)]
#[error("tls1.2_ticket_auth too short data")]
pub(crate) struct ErrTLS12TicketAuthTooShortData;
#[derive(Debug, thiserror::Error)]
#[error("tls1.2_ticket_auth hmac verifying failed")]
pub(crate) struct ErrTLS12TicketAuthHMACError;
#[derive(Clone, Debug, Default)]
pub(crate) struct AuthData {
    pub(crate) client_id: [u8; 32],
}
pub trait Obfs: Send + Sync {
    fn stream_conn(&self, c: Box<dyn Stream>) -> Box<dyn Stream>;
}
pub type ObfsCreator = fn(b: &Base) -> Box<dyn Obfs>;

/// The registry entry for one obfs: its overhead and its constructor.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ObfsEntry {
    pub(crate) overhead: i32,
    pub(crate) new: ObfsCreator,
}

/// The map type of the obfs registry.
pub(crate) type ObfsList = HashMap<String, ObfsEntry>;

/// The obfs registry, filled by each module's `init`.
static OBFS_LIST: LazyLock<ObfsList> = LazyLock::new(|| {
    let mut list = ObfsList::new();
    super::http_post::init(&mut list);
    super::http_simple::init(&mut list);
    super::plain::init(&mut list);
    super::random_head::init(&mut list);
    super::tls1_2_ticket_auth::init(&mut list);
    list
});

/// `register`; the registry is passed in rather than reached through a global.
pub(crate) fn register(list: &mut ObfsList, name: &str, c: ObfsCreator, o: i32) {
    list.insert(name.to_owned(), ObfsEntry { overhead: o, new: c });
}

///
/// # Errors
/// Returns an error when no obfs is registered under `name`.
pub fn pick_obfs(name: &str, b: &Base) -> Result<(Box<dyn Obfs>, i32)> {
    let choice = OBFS_LIST.get(name).copied();
    match choice {
        Some(choice) => Ok(((choice.new)(b), choice.overhead)),
        None => Err(anyhow!("Obfs {name} not supported")),
    }
}
