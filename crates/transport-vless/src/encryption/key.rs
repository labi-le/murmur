use anyhow::{anyhow, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::rngs::OsRng;
use rand::TryRngCore;

use x25519_dalek::{PublicKey, StaticSecret};

pub const MLKEM768_SEED_LENGTH: usize = mlkem::SEED_SIZE;
pub const MLKEM768_CLIENT_LENGTH: usize = mlkem::ENCAPSULATION_KEY_SIZE_768;
pub const X25519_PASSWORD_SIZE: usize = 32;
pub const X25519_PRIVATE_KEY_SIZE: usize = 32;

pub fn gen_mlkem768(seed_str: &str) -> Result<(String, String, String)> {
    let seed = if seed_str.is_empty() {
        let mut seed = [0u8; MLKEM768_SEED_LENGTH];
        OsRng.try_fill_bytes(&mut seed)?;
        seed
    } else {
        let s = URL_SAFE_NO_PAD.decode(seed_str).unwrap_or_default();
        <[u8; MLKEM768_SEED_LENGTH]>::try_from(s)
            .map_err(|_| anyhow!("invalid length of ML-KEM-768 seed: {seed_str}"))?
    };

    let key = mlkem::new_decapsulation_key_768(&seed)?;
    let client = key.encapsulation_key()?.bytes();
    let hash32 = blake3::hash(&client);
    Ok((URL_SAFE_NO_PAD.encode(seed), URL_SAFE_NO_PAD.encode(&client), URL_SAFE_NO_PAD.encode(hash32.as_bytes())))
}

pub fn gen_x25519(private_key_str: &str) -> Result<(String, String, String)> {
    let mut private_key = if private_key_str.is_empty() {
        let mut private_key = [0u8; X25519_PRIVATE_KEY_SIZE];
        OsRng.try_fill_bytes(&mut private_key)?;
        private_key
    } else {
        let s = URL_SAFE_NO_PAD.decode(private_key_str).unwrap_or_default();
        <[u8; X25519_PRIVATE_KEY_SIZE]>::try_from(s)
            .map_err(|_| anyhow!("invalid length of X25519 private key: {private_key_str}"))?
    };

    // Avoid generating equivalent X25519 private keys by clamping the random bytes, per
    // https://cr.yp.to/ecdh.html.
    private_key[0] &= 0b1111_1000;
    private_key[31] &= 127;
    private_key[31] |= 64;

    let key = StaticSecret::from(private_key);
    let password = PublicKey::from(&key).to_bytes();
    let hash32 = blake3::hash(&password);
    Ok((
        URL_SAFE_NO_PAD.encode(private_key),
        URL_SAFE_NO_PAD.encode(password),
        URL_SAFE_NO_PAD.encode(hash32.as_bytes()),
    ))
}

/// The ML-KEM-768 surface this crate uses, over the `ml-kem` crate (`ml_kem::MlKem768`), which
/// implements FIPS 203.
pub mod mlkem {
    use anyhow::{anyhow, Result};
    use ml_kem::{
        Decapsulate, DecapsulationKey as InnerDecapsulationKey, EncapsulationKey as InnerEncapsulationKey, KeyExport,
        MlKem768, Seed, TryKeyInit, B32,
    };
    use rand::rngs::OsRng;
    use rand::TryRngCore;

    pub const SEED_SIZE: usize = 64;
    pub const ENCAPSULATION_KEY_SIZE_768: usize = 1184;
    pub const CIPHERTEXT_SIZE_768: usize = 1088;

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct EncapsulationKey768 {
        inner: InnerEncapsulationKey<MlKem768>,
    }

    #[derive(Clone)]
    pub struct DecapsulationKey768 {
        seed: [u8; SEED_SIZE],
        inner: InnerDecapsulationKey<MlKem768>,
    }

    impl core::fmt::Debug for DecapsulationKey768 {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("DecapsulationKey768").finish_non_exhaustive()
        }
    }

    pub fn new_encapsulation_key_768(encapsulation_key: &[u8]) -> Result<EncapsulationKey768> {
        if encapsulation_key.len() != ENCAPSULATION_KEY_SIZE_768 {
            return Err(anyhow!("mlkem: invalid encapsulation key length"));
        }
        let inner = InnerEncapsulationKey::<MlKem768>::new_from_slice(encapsulation_key)
            .map_err(|_| anyhow!("mlkem: invalid encapsulation key"))?;
        Ok(EncapsulationKey768 { inner })
    }

    pub fn new_decapsulation_key_768(seed: &[u8]) -> Result<DecapsulationKey768> {
        let seed_bytes: [u8; SEED_SIZE] = seed.try_into().map_err(|_| anyhow!("mlkem: invalid seed length"))?;
        let inner = InnerDecapsulationKey::<MlKem768>::from_seed(Seed::from(seed_bytes));
        Ok(DecapsulationKey768 { seed: seed_bytes, inner })
    }

    pub fn generate_key_768() -> Result<DecapsulationKey768> {
        let mut seed = [0u8; SEED_SIZE];
        OsRng.try_fill_bytes(&mut seed)?;
        new_decapsulation_key_768(&seed)
    }

    impl EncapsulationKey768 {
        #[must_use]
        pub fn bytes(&self) -> Vec<u8> {
            self.inner.to_bytes().as_slice().to_vec()
        }

        ///
        /// Draws the 32-byte encapsulation randomness `m` from the OS RNG and derives the
        /// ciphertext and shared key from it deterministically (FIPS 203 `ML-KEM.Encaps_internal`,
        /// Algorithm 17), the computation performed
        /// internally after drawing `m` from its own DRBG. Returns `(shared_key, ciphertext)`.
        pub fn encapsulate(&self) -> Result<(Vec<u8>, Vec<u8>)> {
            let mut m_bytes = [0u8; 32];
            OsRng.try_fill_bytes(&mut m_bytes)?;
            let m = B32::from(m_bytes);
            let (ciphertext, shared_key) = self.inner.encapsulate_deterministic(&m);
            Ok((shared_key.as_slice().to_vec(), ciphertext.as_slice().to_vec()))
        }
    }

    impl DecapsulationKey768 {
        #[must_use]
        pub fn bytes(&self) -> Vec<u8> {
            self.seed.to_vec()
        }

        pub fn encapsulation_key(&self) -> Result<EncapsulationKey768> {
            Ok(EncapsulationKey768 { inner: self.inner.encapsulation_key().clone() })
        }

        pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
            if ciphertext.len() != CIPHERTEXT_SIZE_768 {
                return Err(anyhow!("mlkem: invalid ciphertext length"));
            }
            let shared_key =
                self.inner.decapsulate_slice(ciphertext).map_err(|_| anyhow!("mlkem: invalid ciphertext length"))?;
            Ok(shared_key.as_slice().to_vec())
        }
    }

    #[cfg(test)]
    mod tests {
        use super::super::gen_mlkem768;
        use super::*;

        fn hex_bytes(hex: &str) -> Vec<u8> {
            (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex")).collect()
        }

        /// Fixed seed, its ML-KEM-768 encapsulation key, a fixed encapsulation randomness `m`, and
        /// the resulting ciphertext and shared key; this vector pins the ML-KEM-768
        /// output.
        const SEED_HEX: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
        const ENCAPSULATION_KEY_HEX: &str = "298aa10d423c8dda069d02bc59e6cdf03a096b8b3da4cab9b80ca4a14907672ccef1ec4faf234a0bc5b7e9d473f2b3133b3b26a1d175cb67a7805919699c02f76531b99c5f89180704bb4ca4535c5b8972679c660a07c5e514b87009c862eb8f5157695efb3fc40a9def6b81c1cc02a249ae4f094ad0d9bd3485c1c1c68080520a7c8c632032cee738154e5c5176c07da56024776a430fe76eacf665a3f7b832102215bc82f10939c8355704336a8fac1d81e4bb0485aa5d7c74d6b59bbe5c5e972a0d8bac411b55b5d5557cd680a1a8f71b4eb86bc48c9a0509731a54bd9d7290b27963e4372dc9b199cfdcac0b01acd28a62395112e4c43648d622c48c8234d01440e8cc376c927f23a5afc9ac0474c662274e424525c8552ece3b3fe26516de901bc7d515bde89558e626c95c80b93342f8010004f39e6c6c94871c5e344cab3966c835f9a96a59afd31c40286b38b1c1a78470bab947518934453ce86736a919f1f5a6d510a86f5454fc3980cb5c765bd2bd5f7b36b1410d6635c8ceb47c4dda0d76a28eac939c71c3024804866c71626658442163c2c22117e50acefce6378a985652302a4ef0c2ce0cc716b7796e2b6b2e3777dfa1ac3da259a31b5a9b530f8cb638a81a62ac301849abaf95a7301bda30068909bfdb7e67dbccbb38a5551a25b1a3a0f685748ad5753d8880f0016c627486166384c5571fe2365900364d038311e2d875db366686932b5ec602430a369e87a6ef5c338786657825bd4c057aceb923eb0935e6905e63b4ced7f80857a773dd64b150d26612ea9ac12052db2017bf1843ccb4b3281b690dc728adfa85c00281b8e3c09287335f856b4fc2892f69a2f57921ada01914c40988662d57769662a786351b9b66493dab79594d986de2100d65ba0ff4ea58b81538d24a4435a258fac25404aa7f41f658b1385065e158dcb60115732720f40459aaac15e406953a90ac52997d1ccd070060efc65db9e653354467fad56ec713c86e7540c423acf2669f52fa6f4ac6888d871ef3e847c029a8aafbb92e17b24aa079b1f419ba6175b442afb11909d4a56b70a0335b28739218aa7c9348e2c3c2f3eb3d15a41e6417c0dd94bfeb21419b311a7bb13a180bbe833218a9a6b17447cc85f225859587a73077049acbcfd44d0f025438e15d1538270d586e1bf83192a9459cf63c0e972f85297679831ecf121509851cb8340f6f107b0fa1a0efd1b36a8189bc085c4f5cb784e553f41b918f80397ce1956f785bee377ca9aa8be6998ada30c26b7c3d8c6b55254cc96203b20c42aee0ac4e1ebb408e49a9e3f879d0ab0785eb7025425d1305a2299c015e120d163b0e19494ce57253d0246d182745cb8197ab7438b3c1bb7972bec5a306eba3567855c014699fef65ae54c770a0d85c18400cf642aedc660777ba4b138502bd5a7812f621f84a48296b98dd4322b6f15828b8a8f0e00a8ba44a53c3a8b143571b0740abd567daf1cde9c79c204b6d5e259d1766a31bbbcb4e6a05cf4502176b301c1c2f41247750157bcec85e809b30a4d60d7747cdd0f5b99aa8c826987517793aaa8080a0b124a8558df72bbe37b75f4edbb6be8216d6c633fb2b2280e25113d8695e43481c3eeb397eb192505229b67a201ea893c3e2cb32da8bc342fa4dea0578";
        const M_HEX: &str = "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0";
        const CIPHERTEXT_HEX: &str = "69855b187905cd3c9bc58b74cc3d43ae7c9f1f730e6f50438e6af0c61ae6f52ef0db085a1b803d5b90d4a60490d9a0faf7ef1e51fddbb7dc590262766ddd14d21c497ff305a7313fbdc12b08890815669027c970662d374255355159753e77a66fb2ecddae29e59e802330f68eb1aef083aac2b35b28cd3c59ab7d1fb83a3782b4453a4885fdf48cbb608d2e20602102a03778515af81922393b4e882fb91967bd6eb277b6620ce00253c34784cab8bd5c0b3ad92a95e147a25461f604e840ba2108cbd303a5b3e1997e6d812480c086c376ecdddee34bbe8f0c4e414d9326d377e4239c9e5a1b455081da9dbfdb51761ce1a03eb8007d8a2270c0c1b0537850821814b44435a74481894dee2ee03731b8c13e9c5fb3f0c4d3d4c6f9d5a55056d4d3a9a2990b31af3745706b8479757f3369cffc253c666e370847650e95677b4965b2aca17bce6f03759e70117de147bef31535a72e8891fcb48e0a2457c2f4844c35fb2254e38e451742f1791c16a1cf0f958cb3756b0985b4fcca6434d3b0e58c71b2c7291ae1f02ff5fda29f90d82992929f475d034931360bf0964459d33408572dbe89142bf10a1b54fd0b95cf25ba5afa3e5c9984552d021a6546751f96f867c98489cdf64c9608af57a2068b4cfce2f95185903fcd3a25962802261a3a880e22d625f80d671872e0423760998dd152d82d70bb0546dddb62fd976ea7662bc4aad511772ba60c7ed3b657d0ab216828d4448bce9af0868823d9cd203ab89adb6cd27ff3e6313bce284f0e4826794b2642cc7975f4151b91c7a0441a89687c9c115447e815917a8938d1163d40bd1d2ce95076c2d2cd9ddb1d655ccab1301079ba2c79fb7db12a2f6fec2426c5b0b0d77ae4d223b42afbb37375c6d3242f135991e217b7ec40108f6fd42ab1f4832e1179a982781ece215611d6aa1edb74bd96cd62a7a1634403d8168dbbb30a2552440eea4206ace06885067321e8b9ad6f98d65ddfdf960f0df47084de476b7c8707d15bf11f10912311052696549e57ab9ffde03d656a1f56d9af1a5eff24ef3adc74f9b8ae35b07f9ccdca7df8215b4693c2c1a5cced9fecfeab97fa63fc50c00636ea892516a7fca4a2b72bb4ad2c6c2d683bcd00bbf0f68316a52a27fa126382228233e5e19c4ad88d1eaea53107dfba3e1c3d2accac50766c20489e5bb4118b5863ea3f42cc10714eb4a0713429647c33ab1b3054b41caa49e45c7184571055b426ee5cdfea74d72be08cf56703eaf81336d588375ab784b958c18888d051e8141e3931cbe997f8b246055d3a5c0e24d27bbeb6683e3bcd0bcb50a4bfea7b86f7bf074f46fb654b2bd5c0ef85a23fc1feb60f1041869e1236333166162878aa0fe2847f48d2ef8d067726caf88fd9aa8b9dc4d29b697b8d230d44a68b82122bbbdf8868b038cf291a5b07cb8cf114c3d2fccdb1d021b9e2b3527d75fee29db8c1199922b6831405b4d050fee5c5ff4b7076d1ef2a044188e3de7971d068906b9651455b7cb4f00f4e78c86b7f";
        const SHARED_KEY_HEX: &str = "f2c2678a3be8ba85e9053a0eaffc557661d15f2742caaf272cd93770062b53ca";

        /// Fixed seed and the base64 outputs `gen_mlkem768` derives from it, pinning the
        /// expected output.
        const GEN_MLKEM768_SEED_B64: &str =
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4vMDEyMzQ1Njc4OTo7PD0-Pw";
        const GEN_MLKEM768_CLIENT_B64: &str = "KYqhDUI8jdoGnQK8WebN8DoJa4s9pMq5uAykoUkHZyzO8exPryNKC8W36dRz8rMTOzsmodF1y2engFkZaZwC92UxuZxfiRgHBLtMpFNcW4lyZ5xmCgfF5RS4cAnIYuuPUVdpXvs_xAqd72uBwcwCokmuTwlK0Nm9NIXBwcaAgFIKfIxjIDLO5zgVTlxRdsB9pWAkd2pDD-durPZlo_e4MhAiFbyC8Qk5yDVXBDNqj6wdgeS7BIWqXXx01rWbvlxelyoNi6xBG1W11VV81oChqPcbTrhrxIyaBQlzGlS9nXKQsnlj5DctybGZz9ysCwGs0opiOVES5MQ2SNYixIyCNNAUQOjMN2ySfyOlr8msBHTGYidOQkUlyFUuzjs_4mUW3pAbx9UVveiVWOYmyVyAuTNC-AEABPOebGyUhxxeNEyrOWbINfmpalmv0xxAKGs4scGnhHC6uUdRiTRFPOhnNqkZ8fWm1RCob1RU_DmAy1x2W9K9X3s2sUENZjXIzrR8TdoNdqKOrJOcccMCSASGbHFiZlhEIWPCwiEX5QrO_OY3iphWUjAqTvDCzgzHFrd5bitrLjd336GsPaJZoxtam1MPjLY4qBpirDAYSauvlacwG9owBokJv9t-Z9vMuzilVRolsaOg9oV0itV1PYiA8AFsYnSGFmOExVcf4jZZADZNA4MR4th12zZmhpMrXsYCQwo2noem71wzh4ZleCW9TAV6zrkj6wk15pBeY7TO1_gIV6dz3WSxUNJmEuqawSBS2yAXvxhDzLSzKBtpDccorfqFwAKBuOPAkoczX4VrT8KJL2mi9XkhraAZFMQJiGYtV3aWYqeGNRubZkk9q3lZTZht4hANZboP9OpYuBU40kpENaJY-sJUBKp_QfZYsThQZeFY3LYBFXMnIPQEWaqsFeQGlTqQrFKZfRzNBwBg78ZdueZTNURn-tVuxxPIbnVAxCOs8mafUvpvSsaIjYce8-hHwCmoqvu5LheySqB5sfQZumF1tEKvsRkJ1KVrcKAzWyhzkhiqfJNI4sPC8-s9FaQeZBfA3ZS_6yFBmzEae7E6GAu-gzIYqaaxdEfMhfIlhZWHpzB3BJrLz9RNDwJUOOFdFTgnDVhuG_gxkqlFnPY8DpcvhSl2eYMezxIVCYUcuDQPbxB7D6Gg79GzaoGJvAhcT1y3hOVT9BuRj4A5fOGVb3hb7jd8qaqL5pmK2jDCa3w9jGtVJUzJYgOyDEKu4KxOHrtAjkmp4_h50KsHhetwJUJdEwWiKZwBXhINFjsOGUlM5XJT0CRtGCdFy4GXq3Q4s8G7eXK-xaMG66NWeFXAFGmf72WuVMdwoNhcGEAM9kKu3GYHd7pLE4UCvVp4EvYh-EpIKWuY3UMitvFYKLio8OAKi6RKU8OosUNXGwdAq9Vn2vHN6cecIEttXiWdF2ajG7vLTmoFz0UCF2swHBwvQSR3UBV7zshegJswpNYNd0fN0PW5mqjIJph1F3k6qoCAoLEkqFWN9yu-N7dfTtu2voIW1sYz-ysigOJRE9hpXkNIHD7rOX6xklBSKbZ6IB6ok8PiyzLai8NC-k3qBXg";
        const GEN_MLKEM768_HASH32_B64: &str = "zEsgfXtp_IkVT8_G8LlvmJk5hzORlpvB_i7qA-bziao";

        #[test]
        fn new_decapsulation_key_768_pins_reference_encapsulation_key() {
            let seed = hex_bytes(SEED_HEX);
            let dk = new_decapsulation_key_768(&seed).expect("seed length is checked");
            let ek = dk.encapsulation_key().expect("real implementation always succeeds");
            assert_eq!(ek.bytes(), hex_bytes(ENCAPSULATION_KEY_HEX));
            assert_eq!(dk.bytes(), seed);
        }

        #[test]
        fn decapsulate_pins_reference_shared_key() {
            let seed = hex_bytes(SEED_HEX);
            let dk = new_decapsulation_key_768(&seed).expect("seed length is checked");
            let shared_key = dk.decapsulate(&hex_bytes(CIPHERTEXT_HEX)).expect("ciphertext length is checked");
            assert_eq!(shared_key, hex_bytes(SHARED_KEY_HEX));
        }

        /// Exercises the `ml-kem` crate's deterministic `encapsulate_deterministic` hazmat entry
        /// point directly (not the OS-randomized public `encapsulate`), proving the implementation's FIPS
        /// 203 encapsulation computation itself is byte-for-byte compatible with the, not just
        /// its decapsulation half.
        #[test]
        fn encapsulate_deterministic_pins_reference_output() {
            let seed = hex_bytes(SEED_HEX);
            let dk = new_decapsulation_key_768(&seed).expect("seed length is checked");
            let ek = dk.encapsulation_key().expect("real implementation always succeeds");
            let m_bytes: [u8; 32] = hex_bytes(M_HEX).try_into().expect("checked m length");
            let (ciphertext, shared_key) = ek.inner.encapsulate_deterministic(&B32::from(m_bytes));
            assert_eq!(ciphertext.as_slice(), hex_bytes(CIPHERTEXT_HEX).as_slice());
            assert_eq!(shared_key.as_slice(), hex_bytes(SHARED_KEY_HEX).as_slice());
        }

        #[test]
        fn encapsulate_then_decapsulate_round_trips() {
            let dk = generate_key_768().expect("real implementation always succeeds");
            let ek = dk.encapsulation_key().expect("real implementation always succeeds");
            let (shared_key, ciphertext) = ek.encapsulate().expect("real implementation always succeeds");
            let decapsulated = dk.decapsulate(&ciphertext).expect("ciphertext length is checked");
            assert_eq!(shared_key, decapsulated);
        }

        #[test]
        fn new_decapsulation_key_768_rejects_wrong_seed_length() {
            assert!(new_decapsulation_key_768(&[0u8; SEED_SIZE - 1]).is_err());
        }

        #[test]
        fn new_encapsulation_key_768_rejects_wrong_length() {
            assert!(new_encapsulation_key_768(&[0u8; ENCAPSULATION_KEY_SIZE_768 - 1]).is_err());
        }

        #[test]
        fn decapsulate_rejects_wrong_ciphertext_length() {
            let dk = generate_key_768().expect("real implementation always succeeds");
            assert!(dk.decapsulate(&[0u8; CIPHERTEXT_SIZE_768 - 1]).is_err());
        }

        #[test]
        fn gen_mlkem768_pins_reference_output() {
            let seed_str = GEN_MLKEM768_SEED_B64;
            let (seed_b64, client_b64, hash32_b64) = gen_mlkem768(seed_str).expect("valid seed");
            assert_eq!(seed_b64, GEN_MLKEM768_SEED_B64);
            assert_eq!(client_b64, GEN_MLKEM768_CLIENT_B64);
            assert_eq!(hash32_b64, GEN_MLKEM768_HASH32_B64);
        }

        #[test]
        fn gen_mlkem768_rejects_invalid_seed() {
            assert!(gen_mlkem768("not-a-valid-seed").is_err());
        }
    }
}
