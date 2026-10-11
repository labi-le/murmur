//! ZeroTier's protocol-specific cryptographic primitives.

pub mod gmac_siv;
pub mod salsa;

pub use gmac_siv::{GmacSivKeys, InvalidGmacSiv};
pub use salsa::salsa20_12_xor_key_stream;
