use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use chrono::Utc;
use dashmap::DashMap;
use parking_lot::RwLock;
use rand::rngs::OsRng;
use rand::TryRngCore;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::sleep;

use murmur_common::time::duration_from_nanos;
use murmur_common_net::io::Stream;

use super::common::{
    copy_prefix, creat_padding, decode_header, decode_length, encode_length, format_byte_slice, parse_padding,
    rand_between, x25519_diffie_hellman, CommonConn, AEAD, MAX_NONCE,
};
use super::key::mlkem;
use super::xor::AesCtrStream;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Debug)]
pub struct ServerSession {
    pub pfs_key: Vec<u8>,
    pub nfs_keys: DashMap<[u8; 32], bool>,
}

impl ServerSession {
    pub(crate) fn new(pfs_key: Vec<u8>) -> Self {
        Self { pfs_key, nfs_keys: DashMap::new() }
    }
}

/// The server's NFS key, either X25519 or ML-KEM-768.
#[derive(Clone)]
pub enum NfsSKey {
    X25519(StaticSecret),
    MlKem768(mlkem::DecapsulationKey768),
}

/// Both variants hold private key material, so only the variant name is printed.
impl core::fmt::Debug for NfsSKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let kind = match self {
            Self::X25519(_) => "X25519",
            Self::MlKem768(_) => "MlKem768",
        };
        f.debug_struct("NfsSKey").field("kind", &kind).finish_non_exhaustive()
    }
}

/// The lock-guarded closed flag, last-seen map, tickets and sessions.
#[derive(Default)]
pub struct ServerState {
    pub closed: bool,
    pub lasts: HashMap<i64, [u8; 16]>,
    pub tickets: Vec<[u8; 16]>,
    pub sessions: HashMap<[u8; 16], Arc<ServerSession>>,
}

/// Tickets and sessions are key material, so only the bookkeeping sizes are printed.
impl core::fmt::Debug for ServerState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ServerState")
            .field("closed", &self.closed)
            .field("lasts", &self.lasts.len())
            .field("tickets", &self.tickets.len())
            .field("sessions", &self.sessions.len())
            .finish_non_exhaustive()
    }
}

impl ServerState {
    /// Drops the sessions whose ticket minute has passed; `init`'s task calls this once a minute.
    fn sweep_expired(&mut self) {
        let minute = Utc::now().timestamp() / 60;
        let last = self.lasts.remove(&minute).unwrap_or([0u8; 16]);
        self.lasts.remove(&(minute - 1)); // for insurance
        if last != [0u8; 16] {
            let mut cut = None;
            for (j, ticket) in self.tickets.iter().enumerate() {
                self.sessions.remove(ticket);
                if *ticket == last {
                    cut = Some(j + 1);
                    break;
                }
            }
            if let Some(cut) = cut {
                self.tickets.drain(..cut);
            }
        }
    }
}

#[derive(Default)]
pub struct ServerInstance {
    pub nfs_s_keys: Vec<NfsSKey>,
    pub nfs_p_keys_bytes: Vec<Vec<u8>>,
    pub hash32s: Vec<[u8; 32]>,
    pub relays_length: i64,
    pub xor_mode: u32,
    pub seconds_from: i64,
    pub seconds_to: i64,
    pub padding_lens: Vec<[i64; 3]>,
    pub padding_gaps: Vec<[i64; 3]>,
    /// The lock, shared with the ticket sweep task that `init` starts.
    pub rw_lock: Arc<RwLock<ServerState>>,
}

/// The key vectors are private key material, so only their counts and the configuration are printed.
impl core::fmt::Debug for ServerInstance {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ServerInstance")
            .field("nfs_s_keys", &self.nfs_s_keys.len())
            .field("nfs_p_keys_bytes", &self.nfs_p_keys_bytes.len())
            .field("hash32s", &self.hash32s.len())
            .field("relays_length", &self.relays_length)
            .field("xor_mode", &self.xor_mode)
            .field("seconds_from", &self.seconds_from)
            .field("seconds_to", &self.seconds_to)
            .field("padding_lens", &self.padding_lens)
            .field("padding_gaps", &self.padding_gaps)
            .field("rw_lock", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl ServerInstance {
    #[expect(
        clippy::needless_pass_by_value,
        reason = "the public configuration entry point owns the parsed key list; `pub fn` signature is fixed"
    )]
    pub fn init(
        &mut self,
        nfs_s_keys_bytes: Vec<Vec<u8>>,
        xor_mode: u32,
        seconds_from: i64,
        seconds_to: i64,
        padding: &str,
    ) -> Result<()> {
        if !self.nfs_s_keys.is_empty() {
            return Err(anyhow!("already initialized"));
        }
        let l = nfs_s_keys_bytes.len();
        if l == 0 {
            return Err(anyhow!("empty nfsSKeysBytes"));
        }
        let mut nfs_s_keys = Vec::with_capacity(l);
        let mut relay_public_keys: Vec<Vec<u8>> = Vec::with_capacity(l);
        let mut hash32s: Vec<[u8; 32]> = Vec::with_capacity(l);
        let mut relays_length: i64 = 0;
        for k in &nfs_s_keys_bytes {
            let relay_public_key = if k.len() == 32 {
                let key_bytes: [u8; 32] = k.as_slice().try_into().map_err(|_| anyhow!("checked 32-byte key"))?;
                let key = StaticSecret::from(key_bytes);
                let public_key = PublicKey::from(&key).to_bytes().to_vec();
                nfs_s_keys.push(NfsSKey::X25519(key));
                relays_length += 32 + 32;
                public_key
            } else {
                let key = mlkem::new_decapsulation_key_768(k)?;
                let public_key = key.encapsulation_key()?.bytes();
                nfs_s_keys.push(NfsSKey::MlKem768(key));
                relays_length += 1088 + 32;
                public_key
            };
            hash32s.push(*blake3::hash(&relay_public_key).as_bytes());
            relay_public_keys.push(relay_public_key);
        }
        relays_length -= 32;
        self.nfs_s_keys = nfs_s_keys;
        self.nfs_p_keys_bytes = relay_public_keys;
        self.hash32s = hash32s;
        self.relays_length = relays_length;
        self.xor_mode = xor_mode;
        self.seconds_from = seconds_from;
        self.seconds_to = seconds_to;
        parse_padding(padding, &mut self.padding_lens, &mut self.padding_gaps)?;
        if self.seconds_from > 0 || self.seconds_to > 0 {
            {
                let mut state = self.rw_lock.write();
                state.lasts = HashMap::new();
                state.tickets = Vec::with_capacity(1024);
                state.sessions = HashMap::new();
            }
            let rw_lock = Arc::clone(&self.rw_lock);
            tokio::spawn(async move {
                loop {
                    sleep(Duration::from_secs(60)).await;
                    let mut state = rw_lock.write();
                    if state.closed {
                        return;
                    }
                    state.sweep_expired();
                }
            });
        }
        Ok(())
    }

    pub fn close(&self) {
        self.rw_lock.write().closed = true;
    }

    // NOT cancel-safe: the handshake writes its preamble and messages to the socket before it completes, so a dropped call leaves the connection mid-exchange; the arms that await it drop it only when the connection is being torn down.
    pub async fn handshake(&self, conn: Box<dyn Stream>, mut fallback: Option<&mut Vec<u8>>) -> Result<CommonConn> {
        if self.nfs_s_keys.is_empty() {
            return Err(anyhow!("uninitialized"));
        }
        let mut c = CommonConn::new(conn, true);

        let (iv, nfs_key, mut nfs_aead) = self.negotiate_nfs_key(&mut c, &mut fallback).await?;

        let mut encrypted_length = vec![0u8; 18];
        c.conn.read_exact(&mut encrypted_length).await?;
        if let Some(fallback) = fallback.as_deref_mut() {
            fallback.extend_from_slice(&encrypted_length);
        }
        let mut decrypted_length = [0u8; 2];
        if nfs_aead.open_into(&mut decrypted_length, None, &encrypted_length, &[]).is_err() {
            c.use_aes = !c.use_aes;
            nfs_aead = AEAD::new(&iv, &nfs_key, c.use_aes);
            nfs_aead.open_into(&mut decrypted_length, None, &encrypted_length, &[])?;
        }
        if let Some(fallback) = fallback {
            fallback.clear();
        }
        let length = decode_length(&decrypted_length);

        if length == 32 {
            return self.resume_ticket(c, &iv, &nfs_key, &mut nfs_aead).await;
        }
        if length < 1184 + 32 + 16 {
            // client may send more public keys in the future's version
            return Err(anyhow!("too short length"));
        }
        let (ticket, pfs_public_key) = self.establish_pfs_key(&mut c, &nfs_key, &mut nfs_aead, length).await?;
        self.write_server_hello(&mut c, &mut nfs_aead, &pfs_public_key, &ticket).await?;

        // important: allows client sends padding slowly, eliminating 1-RTT's traffic pattern
        c.conn.read_exact(&mut encrypted_length).await?;
        let encrypted_length_len = encrypted_length.len();
        nfs_aead.open_in_place(&mut encrypted_length, None, encrypted_length_len, &[])?;
        let Some(declared_length) = encrypted_length.get(..2) else {
            return Err(anyhow!("too short length"));
        };
        let mut encrypted_padding = vec![0u8; decode_length(declared_length)];
        c.conn.read_exact(&mut encrypted_padding).await?;
        let encrypted_padding_len = encrypted_padding.len();
        nfs_aead.open_in_place(&mut encrypted_padding, None, encrypted_padding_len, &[])?;

        if self.xor_mode == 2 {
            let out_ctr = AesCtrStream::new(&c.united_key, &ticket);
            let in_ctr = AesCtrStream::new(&c.united_key, &iv);
            c = c.with_xor(out_ctr, Some(in_ctr), 0, 0);
        }
        Ok(c)
    }

    /// Reads the client's IV and relay chain and recovers the connection's NFS key.
    async fn negotiate_nfs_key(
        &self,
        c: &mut CommonConn,
        fallback: &mut Option<&mut Vec<u8>>,
    ) -> Result<([u8; 16], Vec<u8>, AEAD)> {
        let relays_length = usize::try_from(self.relays_length).map_err(|_| anyhow!("invalid relays length"))?;
        let mut iv_and_relays = vec![0u8; 16 + relays_length];
        c.conn.read_exact(&mut iv_and_relays).await?;
        if let Some(fallback) = fallback.as_deref_mut() {
            fallback.extend_from_slice(&iv_and_relays);
        }
        let mut iv = [0u8; 16];
        let (iv_bytes, mut rest) = split_mut_at(&mut iv_and_relays, 16)?;
        iv.copy_from_slice(iv_bytes);

        let mut nfs_key: Vec<u8> = Vec::new();
        let mut last_ctr: Option<AesCtrStream> = None;
        let key_count = self.nfs_s_keys.len();
        for (j, (k, relay_public_key)) in self.nfs_s_keys.iter().zip(&self.nfs_p_keys_bytes).enumerate() {
            let index = if matches!(k, NfsSKey::MlKem768(_)) { 1088 } else { 32 };
            if let Some(last_ctr) = last_ctr.as_mut() {
                let (relay, _) = split_mut_at(rest, 32)?;
                last_ctr.xor_key_stream(relay);
                // recover this relay
            }
            if self.xor_mode > 0 {
                // we don't use buggy elligator2, because we have PSK :)
                let (relay, _) = split_mut_at(rest, index)?;
                let mut ctr = AesCtrStream::new(relay_public_key, &iv);
                ctr.xor_key_stream(relay);
            }
            let (key_bytes, _) = split_mut_at(rest, index)?;
            match k {
                NfsSKey::X25519(k) => {
                    let pub_bytes: [u8; 32] = key_bytes.try_into().map_err(|_| anyhow!("checked 32-byte slice"))?;
                    if pub_bytes[31] > 127 {
                        // we just don't want the observer can change even one bit without breaking the
                        // connection, though it has nothing to do with security
                        return Err(anyhow!(
                            "the highest bit of the last byte of the peer-sent X25519 public key is not 0"
                        ));
                    }
                    nfs_key = x25519_diffie_hellman(k, &PublicKey::from(pub_bytes))?;
                }
                NfsSKey::MlKem768(k) => nfs_key = k.decapsulate(key_bytes)?,
            }
            if j == key_count - 1 {
                break;
            }
            let hash32 = self.hash32s.get(j + 1).ok_or_else(|| anyhow!("missing hash32"))?;
            let (_, after_key) = split_mut_at(rest, index)?;
            let (hash_bytes, tail) = split_mut_at(after_key, 32)?;
            let mut ctr = AesCtrStream::new(&nfs_key, &iv);
            ctr.xor_key_stream(hash_bytes);
            if hash_bytes != hash32.as_slice() {
                return Err(anyhow!("unexpected hash32: {}", format_byte_slice(hash_bytes)));
            }
            last_ctr = Some(ctr);
            rest = tail;
        }
        let nfs_aead = AEAD::new(&iv, &nfs_key, c.use_aes);
        Ok((iv, nfs_key, nfs_aead))
    }

    /// The 0-RTT path: resumes the session the client's ticket names.
    async fn resume_ticket(
        &self,
        mut c: CommonConn,
        iv: &[u8; 16],
        nfs_key: &[u8],
        nfs_aead: &mut AEAD,
    ) -> Result<CommonConn> {
        if self.seconds_from == 0 && self.seconds_to == 0 {
            return Err(anyhow!("0-RTT is not allowed"));
        }
        let mut encrypted_ticket = vec![0u8; 32];
        c.conn.read_exact(&mut encrypted_ticket).await?;
        let ticket = nfs_aead.open_alloc(None, &encrypted_ticket, &[])?;
        let ticket_key: [u8; 16] =
            ticket.get(..16).and_then(|b| b.try_into().ok()).ok_or_else(|| anyhow!("16-byte ticket"))?;
        let session = {
            let state = self.rw_lock.read();
            state.sessions.get(&ticket_key).cloned()
        };
        let Some(session) = session else {
            // matches 1-RTT's server hello length for "random", though it is not important, just
            // for example
            let noises_length =
                usize::try_from(rand_between(1279, 2279)).map_err(|_| anyhow!("invalid noise length"))?;
            let mut noises = vec![0u8; noises_length];
            let mut err = None;
            while err.is_none() {
                OsRng.try_fill_bytes(&mut noises)?;
                err = decode_header(&noises).1;
            }
            let _ = c.conn.write_all(&noises).await; // make client do new handshake
            return Err(anyhow!("expired ticket"));
        };
        let nfs_keys_key: [u8; 32] =
            nfs_key.get(..32).and_then(|b| b.try_into().ok()).ok_or_else(|| anyhow!("32-byte nfs key"))?;
        if session.nfs_keys.insert(nfs_keys_key, true).is_some() {
            // prevents bad client also
            return Err(anyhow!("replay detected"));
        }
        // the same nfsKey links the upload & download (prevents server -> client's another request)
        let mut united_key = Vec::with_capacity(session.pfs_key.len() + nfs_key.len());
        united_key.extend_from_slice(&session.pfs_key);
        united_key.extend_from_slice(nfs_key);
        c.united_key = united_key;
        let mut pre_write = vec![0u8; 16];
        // always trust yourself, not the client (also prevents being parsed as TLS thus causing
        // false interruption for "native" and "xorpub")
        OsRng.try_fill_bytes(&mut pre_write)?;
        c.aead = Some(AEAD::new(&pre_write, &c.united_key, c.use_aes));
        // unchangeable ctx (prevents server -> server), and different ctx length for upload /
        // download (prevents client -> client)
        c.peer_aead = Some(AEAD::new(&encrypted_ticket, &c.united_key, c.use_aes));
        c.pre_write = Some(pre_write);
        if self.xor_mode == 2 {
            let pre_write = c.pre_write.as_ref().ok_or_else(|| anyhow!("pre write is set"))?;
            let out_ctr = AesCtrStream::new(&c.united_key, pre_write);
            let in_ctr = AesCtrStream::new(&c.united_key, iv);
            // it doesn't matter if the attacker sends client's iv back to the client
            c = c.with_xor(out_ctr, Some(in_ctr), 16, 0);
        }
        Ok(c)
    }

    /// Reads the client's PFS public key, derives the united key and stores the new session.
    async fn establish_pfs_key(
        &self,
        c: &mut CommonConn,
        nfs_key: &[u8],
        nfs_aead: &mut AEAD,
        length: usize,
    ) -> Result<([u8; 16], Vec<u8>)> {
        let mut encrypted_pfs_public_key = vec![0u8; length];
        c.conn.read_exact(&mut encrypted_pfs_public_key).await?;
        let encrypted_pfs_public_key_len = encrypted_pfs_public_key.len();
        nfs_aead.open_in_place(&mut encrypted_pfs_public_key, None, encrypted_pfs_public_key_len, &[])?;
        let (peer_public_key, _) =
            encrypted_pfs_public_key.split_at_checked(1184 + 32).ok_or_else(|| anyhow!("too short length"))?;
        let mlkem768_e_key = mlkem::new_encapsulation_key_768(
            encrypted_pfs_public_key.get(..1184).ok_or_else(|| anyhow!("too short length"))?,
        )?;
        let (mlkem768_key, encapsulated_pfs_key) = mlkem768_e_key.encapsulate()?;
        let peer_x25519_p_key = PublicKey::from(
            <[u8; 32]>::try_from(
                encrypted_pfs_public_key.get(1184..1184 + 32).ok_or_else(|| anyhow!("too short length"))?,
            )
            .map_err(|_| anyhow!("checked 32-byte slice"))?,
        );
        let mut x25519_s_bytes = [0u8; 32];
        OsRng.try_fill_bytes(&mut x25519_s_bytes)?;
        let x25519_s_key = StaticSecret::from(x25519_s_bytes);
        let x25519_key = x25519_diffie_hellman(&x25519_s_key, &peer_x25519_p_key)?;
        // the UnitedKey append must leave pfsKey itself at 64 bytes
        let mut pfs_key = Vec::with_capacity(32 + 32);
        pfs_key.extend_from_slice(&mlkem768_key);
        pfs_key.extend_from_slice(&x25519_key);
        let mut pfs_public_key = encapsulated_pfs_key;
        pfs_public_key.extend_from_slice(PublicKey::from(&x25519_s_key).as_bytes());
        let mut united_key = Vec::with_capacity(pfs_key.len() + nfs_key.len());
        united_key.extend_from_slice(&pfs_key);
        united_key.extend_from_slice(nfs_key);
        c.united_key = united_key;
        c.aead = Some(AEAD::new(&pfs_public_key, &c.united_key, c.use_aes));
        c.peer_aead = Some(AEAD::new(peer_public_key, &c.united_key, c.use_aes));

        let mut ticket = [0u8; 16];
        OsRng.try_fill_bytes(&mut ticket)?;
        let seconds = if self.seconds_to == 0 {
            self.seconds_from * rand_between(50, 100) / 100
        } else {
            rand_between(self.seconds_from, self.seconds_to)
        };
        // the ticket's TTL is the wire's 2-byte length field
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "the ticket TTL field is uint16 on the wire, so the cast keeps its low 16 bits"
        )]
        copy_prefix(&mut ticket, &encode_length(seconds as usize));
        if seconds > 0 {
            let mut state = self.rw_lock.write();
            state.lasts.insert((Utc::now().timestamp() + self.seconds_from.max(self.seconds_to)) / 60 + 2, ticket);
            state.tickets.push(ticket);
            state.sessions.insert(ticket, Arc::new(ServerSession::new(pfs_key)));
        }
        Ok((ticket, pfs_public_key))
    }

    /// Seals and sends the server hello in the configured fragments.
    async fn write_server_hello(
        &self,
        c: &mut CommonConn,
        nfs_aead: &mut AEAD,
        pfs_public_key: &[u8],
        ticket: &[u8; 16],
    ) -> Result<()> {
        let pfs_key_exchange_length = 1088 + 32 + 16;
        let encrypted_ticket_length = 32;
        let (padding_length, mut padding_lens, padding_gaps) = creat_padding(&self.padding_lens, &self.padding_gaps);
        let padding_length = usize::try_from(padding_length).map_err(|_| anyhow!("invalid padding length"))?;
        let mut server_hello = vec![0u8; pfs_key_exchange_length + encrypted_ticket_length + padding_length];
        let (pfs_key_exchange, rest) = split_mut_at(&mut server_hello, pfs_key_exchange_length)?;
        nfs_aead.seal(pfs_key_exchange, Some(&MAX_NONCE), pfs_public_key, &[])?;
        let (encrypted_ticket, rest) = split_mut_at(rest, encrypted_ticket_length)?;
        let aead = c.aead.as_mut().ok_or_else(|| anyhow!("AEAD is set by this handshake"))?;
        aead.seal(encrypted_ticket, None, ticket, &[])?;
        let (encrypted_length, padding) = split_mut_at(rest, 18)?;
        aead.seal(encrypted_length, None, &encode_length(padding_length - 18), &[])?;
        aead.seal_in_place(padding, None, padding_length - 18 - 16, &[])?;

        let hello_fixed_length = i64::try_from(pfs_key_exchange_length + encrypted_ticket_length)
            .map_err(|_| anyhow!("too long server hello"))?;
        let first_padding_len = padding_lens.first_mut().ok_or_else(|| anyhow!("empty padding"))?;
        *first_padding_len += hello_fixed_length;
        // sends padding in a fragmented way, to create variable traffic pattern, before inner VLESS
        // flow takes control
        let mut written = 0;
        for (i, l) in padding_lens.iter().enumerate() {
            if *l > 0 {
                let len = usize::try_from(*l).map_err(|_| anyhow!("invalid padding length"))?;
                let fragment =
                    server_hello.get(written..written + len).ok_or_else(|| anyhow!("invalid padding length"))?;
                c.conn.write_all(fragment).await?;
                c.conn.flush().await?;
                written += len;
            }
            if let Some(gap) = padding_gaps.get(i) {
                sleep(duration_from_nanos(*gap)).await;
            }
        }
        Ok(())
    }
}

/// Splits `buf` at `mid`, reporting a short buffer instead of panicking.
fn split_mut_at(buf: &mut [u8], mid: usize) -> Result<(&mut [u8], &mut [u8])> {
    buf.split_at_mut_checked(mid).ok_or_else(|| anyhow!("short relay buffer"))
}
