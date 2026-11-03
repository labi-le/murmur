use rand::Rng;
use sha2::{Digest, Sha256};

use super::obfs::Obfuscator;

pub(crate) const SALT_LEN: usize = 16;

#[derive(Debug, Clone)]
pub struct XPlusObfuscator {
    pub key: Vec<u8>,
}

#[must_use]
pub const fn new_xplus_obfuscator(key: Vec<u8>) -> XPlusObfuscator {
    XPlusObfuscator { key }
}

impl XPlusObfuscator {
    fn key_for(&self, salt: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.key);
        hasher.update(salt);
        hasher.finalize().into()
    }
}

impl Obfuscator for XPlusObfuscator {
    fn deobfuscate(&self, input: &[u8], output: &mut [u8]) -> usize {
        let Some((salt, payload)) = input.split_at_checked(SALT_LEN) else {
            return 0;
        };
        let p_len = payload.len();
        if p_len == 0 || output.len() < p_len {
            return 0;
        }
        let key = self.key_for(salt);
        for ((out, c), k) in output.iter_mut().zip(payload.iter()).zip(key.iter().cycle()) {
            *out = c ^ k;
        }
        p_len
    }

    fn obfuscate(&self, input: &[u8], output: &mut [u8]) -> usize {
        let Some((salt, payload)) = output.split_at_mut_checked(SALT_LEN) else {
            return 0;
        };
        if payload.len() < input.len() {
            return 0;
        }
        rand::rng().fill(salt);
        let key = self.key_for(salt);
        for ((out, c), k) in payload.iter_mut().zip(input.iter()).zip(key.iter().cycle()) {
            *out = c ^ k;
        }
        input.len() + SALT_LEN
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x_plus_obfuscator() {
        let x = new_xplus_obfuscator(b"Vaundy".to_vec());
        let tests: [(&str, &str); 4] = [
            ("1", "HelloWorld"),
            ("2", "Regret is just a horrible attempt at time travel that ends with you feeling like crap"),
            (
                "3",
                "To be, or not to be, that is the question:\nWhether 'tis nobler in the mind to suffer\n\
                 The slings and arrows of outrageous fortune,\nOr to take arms against a sea of troubles\n\
                 And by opposing end them. To die—to sleep,\nNo more; and by a sleep to say we end",
            ),
            ("empty", ""),
        ];
        for (name, p) in tests {
            let p = p.as_bytes();
            let mut buf = vec![0u8; 10240];
            let n = x.obfuscate(p, &mut buf);
            let (head, tail) = buf.split_at_mut(n);
            let n2 = x.deobfuscate(head, tail);
            assert_eq!(&buf[n..n + n2], p, "inconsistent deobfuscate result for {name}");
        }
    }
}
