use md5::{Digest, Md5};
use uuid::Uuid;

pub const ID_BYTES_LEN: usize = 16;

#[derive(Clone, Debug)]
pub struct Id {
    pub uuid: Uuid,
    pub cmd_key: Vec<u8>,
}

pub(crate) fn new_id(uuid: &Uuid) -> Id {
    let mut hash = Md5::new();
    hash.update(uuid.as_bytes());
    hash.update(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    let cmd_key = hash.finalize().to_vec();
    Id { uuid: *uuid, cmd_key }
}

/// Generates the next ID. The running digest is peeked non-destructively and more input is only
/// appended on a collision, so the hasher keeps accumulating across retries instead of restarting
/// from the UUID bytes each time; the implementation clones the hasher to peek the same way.
pub(crate) fn next_id(u: &Uuid) -> Uuid {
    let mut hash = Md5::new();
    hash.update(u.as_bytes());
    hash.update(b"16167dc8-16b6-4e6d-b8bb-65dd68113a81");
    loop {
        let digest: [u8; 16] = hash.clone().finalize().into();
        let candidate = Uuid::from_bytes(digest);
        if candidate.as_bytes() != u.as_bytes() {
            return candidate;
        }
        hash.update(b"533eff8a-4113-4b10-b5ce-0f5d76b98cd2");
    }
}

pub(crate) fn new_alter_ids(primary: &Id, alter_id_count: u16) -> Vec<Id> {
    let mut alter_ids = Vec::with_capacity(alter_id_count as usize + 1);
    let mut prev_id = primary.uuid;
    for _ in 0..alter_id_count {
        let new_uuid = next_id(&prev_id);
        alter_ids.push(Id { uuid: new_uuid, cmd_key: primary.cmd_key.clone() });
        prev_id = new_uuid;
    }
    alter_ids.push(primary.clone());
    alter_ids
}
