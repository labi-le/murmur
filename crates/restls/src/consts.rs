//! Wire constants: TLS record, handshake, extension, group and cipher-suite codes, plus the
//! Restls framing sizes and offsets.

pub const RECORD_HEADER_LEN: usize = 5;
pub const MAX_PLAINTEXT: usize = 16384;

pub const RECORD_TYPE_CHANGE_CIPHER_SPEC: u8 = 0x14;
pub const RECORD_TYPE_ALERT: u8 = 0x15;
pub const RECORD_TYPE_HANDSHAKE: u8 = 0x16;
pub const RECORD_TYPE_APPLICATION_DATA: u8 = 0x17;

pub const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 1;
pub const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 2;
pub const HANDSHAKE_TYPE_NEW_SESSION_TICKET: u8 = 4;
pub const HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS: u8 = 8;
pub const HANDSHAKE_TYPE_CERTIFICATE: u8 = 11;
pub const HANDSHAKE_TYPE_CERTIFICATE_VERIFY: u8 = 15;
pub const HANDSHAKE_TYPE_FINISHED: u8 = 20;
pub const HANDSHAKE_TYPE_KEY_UPDATE: u8 = 24;
pub const HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE: u8 = 12;
pub const HANDSHAKE_TYPE_SERVER_HELLO_DONE: u8 = 14;
pub const HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE: u8 = 16;

pub const VERSION_TLS12: u16 = 0x0303;
pub const VERSION_TLS13: u16 = 0x0304;

pub const EXT_SERVER_NAME: u16 = 0;
pub const EXT_SUPPORTED_GROUPS: u16 = 10;
pub const EXT_SIGNATURE_ALGORITHMS: u16 = 13;
pub const EXT_ALPN: u16 = 16;
pub const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 45;
pub const EXT_KEY_SHARE: u16 = 51;
pub const EXT_SUPPORTED_VERSIONS: u16 = 43;
pub const EXT_PRE_SHARED_KEY: u16 = 41;
pub const EXT_SESSION_TICKET: u16 = 35;

pub const GROUP_X25519: u16 = 0x001d;
pub const GROUP_SECP256R1: u16 = 0x0017;
pub const GROUP_SECP384R1: u16 = 0x0018;

pub const TLS12_CURVE_LIST: [u16; 3] = [GROUP_X25519, GROUP_SECP256R1, GROUP_SECP384R1];

#[must_use]
pub fn tls12_curve_index(group: u16) -> Option<usize> {
    TLS12_CURVE_LIST.iter().position(|&g| g == group)
}

pub const CIPHER_SUITE_AES_128_GCM_SHA256: u16 = 0x1301;
pub const CIPHER_SUITE_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

pub const TLS12_GCM_CIPHER_SUITES: [u16; 4] = [0xc02f, 0xc02b, 0xc030, 0xc02c];

pub const SIG_ECDSA_SECP256R1_SHA256: u16 = 0x0403;
pub const SIG_RSA_PSS_RSAE_SHA256: u16 = 0x0804;
pub const SIG_ED25519: u16 = 0x0807;

pub const PSK_KE_MODE_DHE: u8 = 1;

pub const RESTLS_HANDSHAKE_MAC_LEN: usize = 16;
pub const RESTLS_APP_DATA_MAC_LEN: usize = 8;
pub const RESTLS_CMD_LEN: usize = 2;
pub const RESTLS_MASK_LEN: usize = RESTLS_CMD_LEN + 2;
pub const RESTLS_APP_DATA_AUTH_HEADER_LEN: usize = RESTLS_APP_DATA_MAC_LEN + RESTLS_MASK_LEN;
pub const RESTLS_APP_DATA_OFFSET: usize = RESTLS_APP_DATA_AUTH_HEADER_LEN;
pub const RESTLS_APP_DATA_LEN_OFFSET: usize = RESTLS_APP_DATA_MAC_LEN;

/// The HelloRetryRequest sentinel random, RFC 8446 §4.1.3.
pub const HELLO_RETRY_REQUEST_RANDOM: [u8; 32] = [
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91, 0xC2, 0xA2, 0x11,
    0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
];

pub const RESTLS12_CLIENT_AUTH_LAYOUT3: [usize; 4] = [0, 11, 22, 32];
pub const RESTLS12_CLIENT_AUTH_LAYOUT4: [usize; 5] = [0, 8, 16, 24, 32];

/// The expected wire bytes of a Restls ChangeCipherSpec record.
pub const RESTLS_CCS_RECORD: [u8; 6] = [RECORD_TYPE_CHANGE_CIPHER_SPEC, 0x03, 0x03, 0x00, 0x01, 0x01];
