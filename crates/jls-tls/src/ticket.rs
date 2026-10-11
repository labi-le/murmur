//! The server-side state a resumed handshake needs, sealed into the opaque
//! ticket label the client echoes back, plus the ticket-age rule of RFC 8446
//! §4.2.11.
//!
//! The values are sealed into the ticket with the endpoint's ticket key, so
//! nothing about the resumed session has to be remembered between connections.
//! The encoding here is private to this crate: only this server ever writes or
//! reads a ticket it issued.

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit};
use rand::RngCore;

use crate::cursor::{Reader, Writer};
use crate::error::{Result, TlsError};

/// RFC 8446 §4.2.10: the server compares the age the client obfuscated against
/// the time since the ticket was issued and rejects 0-RTT when the difference
/// is larger than a "small tolerance", which is left to the implementation.
pub(crate) const TICKET_AGE_TOLERANCE_MS: u64 = 10_000;

const TICKET_FORMAT_VERSION: u8 = 1;
const NONCE_LEN: usize = 12;

/// The session fields that a resumption depends on.
pub(crate) struct TicketState {
    /// The resumption PSK, RFC 8446 §4.6.1.
    pub psk: [u8; 32],
    /// Creation time, seconds since the Unix epoch.
    pub created_at: u64,
    pub lifetime: u32,
    pub age_add: u32,
    pub max_early_data: u32,
    /// The negotiated ALPN protocol; only recorded when the ticket permits
    /// 0-RTT, because only then does the resume need it.
    pub alpn: Option<String>,
    /// The JLS identity the ticket was issued to, checked on resume against the
    /// identity of the connection attempting it.
    pub username: String,
}

fn encode(state: &TicketState) -> Result<Vec<u8>> {
    let mut w = Writer::new();
    w.u8(TICKET_FORMAT_VERSION);
    w.bytes(&state.psk);
    let created_at = state.created_at.to_be_bytes();
    w.bytes(&created_at);
    w.u32(state.lifetime);
    w.u32(state.age_add);
    w.u32(state.max_early_data);
    w.vec8(state.alpn.as_deref().unwrap_or_default().as_bytes())?;
    w.vec8(state.username.as_bytes())?;
    Ok(w.buf)
}

fn decode(plaintext: &[u8]) -> Result<TicketState> {
    let invalid = || TlsError::protocol("ticket: malformed session state");
    let mut r = Reader::new(plaintext);
    if r.u8().map_err(|_| invalid())? != TICKET_FORMAT_VERSION {
        return Err(invalid());
    }
    let psk = r.take_array::<32>().map_err(|_| invalid())?;
    let created_at = (u64::from(r.u32().map_err(|_| invalid())?) << 32) | u64::from(r.u32().map_err(|_| invalid())?);
    let lifetime = r.u32().map_err(|_| invalid())?;
    let age_add = r.u32().map_err(|_| invalid())?;
    let max_early_data = r.u32().map_err(|_| invalid())?;
    let alpn = r.vec8().map_err(|_| invalid())?;
    let username = r.vec8().map_err(|_| invalid())?;
    if !r.is_empty() {
        return Err(invalid());
    }
    let alpn = if alpn.is_empty() { None } else { Some(String::from_utf8(alpn.to_vec()).map_err(|_| invalid())?) };
    Ok(TicketState {
        psk,
        created_at,
        lifetime,
        age_add,
        max_early_data,
        alpn,
        username: String::from_utf8(username.to_vec()).map_err(|_| invalid())?,
    })
}

/// Seals `state` as `<nonce><ciphertext||tag>`, the shape of the ticket field of a
/// NewSessionTicket message.
pub(crate) fn seal(key: &[u8; 32], state: &TicketState, rng: &mut impl RngCore) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| TlsError::protocol("ticket: bad ticket key"))?;
    let mut ticket = nonce.to_vec();
    let mut ciphertext = cipher
        .encrypt(&nonce.into(), Payload { msg: &encode(state)?, aad: &[] })
        .map_err(|_| TlsError::protocol("ticket: sealing failed"))?;
    ticket.append(&mut ciphertext);
    Ok(ticket)
}

/// Opens a ticket this server sealed. An unopenable ticket is not an error the
/// handshake has to fail on: RFC 8446 §4.2.11 says a PSK the server cannot
/// account for is ignored, and the handshake falls back to a certificate one.
pub(crate) fn open(key: &[u8; 32], ticket: &[u8]) -> Result<TicketState> {
    let invalid = || TlsError::protocol("ticket: cannot open session ticket");
    let (nonce, ciphertext) = ticket.split_at_checked(NONCE_LEN).ok_or_else(invalid)?;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| invalid())?;
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| invalid())?;
    let plaintext = cipher.decrypt(&nonce.into(), Payload { msg: ciphertext, aad: &[] }).map_err(|_| invalid())?;
    decode(&plaintext)
}

/// RFC 8446 §4.2.11: `age = obfuscated_ticket_age - ticket_age_add mod 2^32`,
/// in milliseconds, against the time this server believes has passed since it
/// issued the ticket.
pub(crate) fn age_is_plausible(state: &TicketState, obfuscated_ticket_age: u32, now_unix: u64) -> bool {
    let sent_ms = u64::from(obfuscated_ticket_age.wrapping_sub(state.age_add));
    let elapsed_ms = now_unix.saturating_sub(state.created_at) * 1000;
    sent_ms.abs_diff(elapsed_ms) <= TICKET_AGE_TOLERANCE_MS
}

/// A ticket is usable while `created_at + lifetime` is in the future; RFC 8446
/// §4.2.11 also forbids clients from offering an older one, and §4.6.1 caps the
/// lifetime at seven days.
pub(crate) fn is_valid(state: &TicketState, now_unix: u64) -> bool {
    state.lifetime != 0
        && state.lifetime <= crate::messages::MAX_SESSION_TICKET_LIFETIME_SECS
        && now_unix < state.created_at + u64::from(state.lifetime)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> TicketState {
        TicketState {
            psk: [7u8; 32],
            created_at: 1_700_000_000,
            lifetime: 600,
            age_add: 0x1234_5678,
            max_early_data: crate::messages::MAX_EARLY_DATA_SIZE_QUIC,
            alpn: Some("h3".to_owned()),
            username: "alice".to_owned(),
        }
    }

    #[test]
    fn sealed_tickets_round_trip_and_reject_a_wrong_key() {
        let state = state();
        let ticket = seal(&[3u8; 32], &state, &mut rand::rng()).expect("seal");
        let opened = open(&[3u8; 32], &ticket).expect("open");
        assert_eq!(opened.psk, state.psk);
        assert_eq!(opened.created_at, state.created_at);
        assert_eq!(opened.lifetime, state.lifetime);
        assert_eq!(opened.age_add, state.age_add);
        assert_eq!(opened.max_early_data, state.max_early_data);
        assert_eq!(opened.alpn.as_deref(), Some("h3"));
        assert_eq!(opened.username, "alice");
        assert!(open(&[4u8; 32], &ticket).is_err(), "a ticket sealed under another key must not open");
        assert!(open(&[3u8; 32], &ticket[..NONCE_LEN]).is_err(), "a truncated ticket must not open");
        let mut tampered = ticket.clone();
        *tampered.last_mut().expect("non-empty") ^= 1;
        assert!(open(&[3u8; 32], &tampered).is_err(), "a modified ticket must not open");
    }

    /// The client sends `ticket_age_ms + ticket_age_add mod 2^32`.
    #[test]
    fn ticket_age_is_accepted_inside_the_tolerance_and_rejected_outside() {
        let state = state();
        let now = state.created_at + 5;
        let obfuscated = (5_000u32).wrapping_add(state.age_add);
        assert!(age_is_plausible(&state, obfuscated, now));
        assert!(age_is_plausible(&state, (15_000u32).wrapping_add(state.age_add), now));
        assert!(!age_is_plausible(&state, (30_000u32).wrapping_add(state.age_add), now));
        // The same obfuscated age against a `now` far from the ticket's creation.
        assert!(!age_is_plausible(&state, state.age_add, now + 30));
    }

    /// The obfuscated age wraps modulo 2^32, so a large `age_add` must not turn
    /// a fresh ticket into an implausible one.
    #[test]
    fn ticket_age_wraps_modulo_two_to_the_thirty_two() {
        let mut state = state();
        state.age_add = u32::MAX - 100;
        let now = state.created_at + 1;
        let obfuscated = (1_000u32).wrapping_add(state.age_add);
        assert!(obfuscated < 1_000, "the addition wrapped");
        assert!(age_is_plausible(&state, obfuscated, now));
    }

    #[test]
    fn expiry_is_the_lifetime_and_the_seven_day_cap() {
        let ticket = state();
        assert!(is_valid(&ticket, ticket.created_at));
        assert!(is_valid(&ticket, ticket.created_at + 599));
        assert!(!is_valid(&ticket, ticket.created_at + 600));
        let mut zero = state();
        zero.lifetime = 0;
        assert!(!is_valid(&zero, zero.created_at));
        let mut too_long = state();
        too_long.lifetime = crate::messages::MAX_SESSION_TICKET_LIFETIME_SECS + 1;
        assert!(!is_valid(&too_long, too_long.created_at));
    }
}
