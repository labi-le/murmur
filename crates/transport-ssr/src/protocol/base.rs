use aes::cipher::{BlockCipherEncrypt as _, KeyInit as _};
use aes::Aes128;
use anyhow::{anyhow, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use bytes::{BufMut, BytesMut};
use parking_lot::Mutex;
use rand::rngs::OsRng;
use rand::TryRngCore;

use murmur_log::warnln;
use murmur_ntp::time;
use murmur_transport_shadowsocks::core::cipher::kdf;
#[derive(Clone, Debug, Default)]
pub struct Base {
    pub key: Vec<u8>,
    pub overhead: i32,
    pub param: String,
}
#[derive(Clone, Debug, Default)]
pub(crate) struct UserData {
    pub(crate) user_key: Vec<u8>,
    pub(crate) user_id: [u8; 4],
}

/// The client id and connection id are guarded together, so the pair
/// stays in one lock instead of beside a bare mutex.
#[derive(Debug, Default)]
struct AuthDataState {
    client_id: [u8; 4],
    connection_id: u32,
}
#[derive(Debug, Default)]
pub(crate) struct AuthData {
    state: Mutex<AuthDataState>,
}

/// The low 32 bits of `value`, the width of the protocol's timestamp field.
fn low_u32(value: i64) -> u32 {
    let [b0, b1, b2, b3, ..] = value.to_le_bytes();
    u32::from_le_bytes([b0, b1, b2, b3])
}

/// The low 16 bits of `value`, the width of the protocol's padding fields.
fn low_u16(value: i32) -> u16 {
    let [b0, b1, ..] = value.to_le_bytes();
    u16::from_le_bytes([b0, b1])
}

impl AuthData {
    pub(crate) fn next(&self) -> Self {
        let mut state = self.state.lock();
        if state.connection_id > 0xff00_0000 || state.connection_id == 0 {
            let _ = OsRng.try_fill_bytes(&mut state.client_id);
            state.connection_id = rand::random::<u32>() & 0xff_ffff;
        }
        state.connection_id += 1;

        Self { state: Mutex::new(AuthDataState { client_id: state.client_id, connection_id: state.connection_id }) }
    }

    pub(crate) fn put_auth_data(&self, buf: &mut BytesMut) {
        let state = self.state.lock();
        buf.put_u32_le(low_u32(time::now().timestamp()));
        buf.put_slice(&state.client_id);
        buf.put_u32_le(state.connection_id);
    }

    pub(crate) fn put_encrypted_data(
        &self,
        b: &mut BytesMut,
        user_key: &[u8],
        paddings: [i32; 2],
        salt: &str,
    ) -> Result<()> {
        let (client_id, connection_id) = {
            let state = self.state.lock();
            let ids = (state.client_id, state.connection_id);
            drop(state);
            ids
        };

        let mut plain = [0u8; 16];
        let (timestamp, rest) = plain.split_at_mut(4);
        timestamp.copy_from_slice(&low_u32(time::now().timestamp()).to_le_bytes());
        let (client, rest) = rest.split_at_mut(4);
        client.copy_from_slice(&client_id);
        let (connection, rest) = rest.split_at_mut(4);
        connection.copy_from_slice(&connection_id.to_le_bytes());
        for (slot, padding) in rest.chunks_exact_mut(2).zip(paddings) {
            slot.copy_from_slice(&low_u16(padding).to_le_bytes());
        }

        let cipher_key = kdf(&format!("{}{salt}", STANDARD.encode(user_key)), 16);
        let Ok(cipher) = Aes128::new_from_slice(&cipher_key) else {
            let err = anyhow!("invalid AES key size {}", cipher_key.len());
            warnln!("New cipher error: {}", err);
            return Err(err);
        };

        // the `cipher.NewCBCEncrypter(block, iv)` over a single block: with an all-zero IV the
        // CBC chaining step is the identity, so one ECB block is the same bytes.
        let mut block = aes::Block::from(plain);
        cipher.encrypt_block(&mut block);

        b.put_slice(block.as_slice());
        Ok(())
    }
}
