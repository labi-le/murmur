use anyhow::{anyhow, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

use super::client::ClientInstance;
use super::key::{MLKEM768_CLIENT_LENGTH, MLKEM768_SEED_LENGTH, X25519_PASSWORD_SIZE, X25519_PRIVATE_KEY_SIZE};
use super::server::ServerInstance;

/// Returns `None` without an error when the caller does not need to encrypt.
pub fn new_client(encryption: &str) -> Result<Option<ClientInstance>> {
    // An empty string is not rejected, because we need to ensure compatibility
    if encryption.is_empty() || encryption == "none" {
        return Ok(None);
    }
    let invalid = || anyhow!("invaild vless encryption value: {encryption}");
    let parts: Vec<&str> = encryption.split('.').collect();
    let [scheme, xor_mode, seconds, keys @ ..] = parts.as_slice() else {
        return Err(invalid());
    };
    if *scheme != "mlkem768x25519plus" || keys.is_empty() {
        return Err(invalid());
    }
    let xor_mode = match *xor_mode {
        "native" => 0,
        "xorpub" => 1,
        "random" => 2,
        _ => return Err(invalid()),
    };
    let seconds = match *seconds {
        "1rtt" => 0,
        "0rtt" => 1,
        _ => return Err(invalid()),
    };
    let mut nfs_p_keys_bytes: Vec<Vec<u8>> = Vec::new();
    let mut paddings: Vec<&str> = Vec::new();
    for r in keys.iter().copied() {
        if r.len() < 20 {
            paddings.push(r);
            continue;
        }
        let Ok(b) = URL_SAFE_NO_PAD.decode(r) else {
            return Err(invalid());
        };
        if b.len() != X25519_PASSWORD_SIZE && b.len() != MLKEM768_CLIENT_LENGTH {
            return Err(invalid());
        }
        nfs_p_keys_bytes.push(b);
    }
    let padding = paddings.join(".");
    let mut client = ClientInstance::default();
    if let Err(err) = client.init(nfs_p_keys_bytes, xor_mode, seconds, &padding) {
        return Err(anyhow!("failed to use encryption: {err}"));
    }
    Ok(Some(client))
}

/// Returns `None` without an error when the caller does not need to decrypt.
pub fn new_server(decryption: &str) -> Result<Option<ServerInstance>> {
    // An empty string is not rejected, because we need to ensure compatibility
    if decryption.is_empty() || decryption == "none" {
        return Ok(None);
    }
    let invalid = || anyhow!("invaild vless decryption value: {decryption}");
    let parts: Vec<&str> = decryption.split('.').collect();
    let [scheme, xor_mode, seconds, keys @ ..] = parts.as_slice() else {
        return Err(invalid());
    };
    if *scheme != "mlkem768x25519plus" || keys.is_empty() {
        return Err(invalid());
    }
    let xor_mode = match *xor_mode {
        "native" => 0,
        "xorpub" => 1,
        "random" => 2,
        _ => return Err(invalid()),
    };
    let seconds = seconds.strip_suffix('s').unwrap_or(seconds);
    let Ok(seconds_from) = seconds.split('-').next().unwrap_or_default().parse::<i64>() else {
        return Err(invalid());
    };
    let seconds_to = match seconds.split_once('-') {
        Some((_, to)) => {
            let Ok(i) = to.parse::<i64>() else {
                return Err(invalid());
            };
            i
        }
        None => 0i64,
    };
    let mut nfs_s_keys_bytes: Vec<Vec<u8>> = Vec::new();
    let mut paddings: Vec<&str> = Vec::new();
    for r in keys.iter().copied() {
        if r.len() < 20 {
            paddings.push(r);
            continue;
        }
        let Ok(b) = URL_SAFE_NO_PAD.decode(r) else {
            return Err(invalid());
        };
        if b.len() != X25519_PRIVATE_KEY_SIZE && b.len() != MLKEM768_SEED_LENGTH {
            return Err(invalid());
        }
        nfs_s_keys_bytes.push(b);
    }
    let padding = paddings.join(".");
    let mut server = ServerInstance::default();
    if let Err(err) = server.init(nfs_s_keys_bytes, xor_mode, seconds_from, seconds_to, &padding) {
        return Err(anyhow!("failed to use decryption: {err}"));
    }
    Ok(Some(server))
}
