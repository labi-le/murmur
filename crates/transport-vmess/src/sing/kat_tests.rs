//! Known-answer tests against fixed vectors for the exported helpers (the KDF, the
//! ChaCha20-Poly1305 key derivation, the AES-128-GCM/ChaCha20-Poly1305 body and chunk writers, and
//! the stream chunk writer with SHAKE128 masking), run against fixed inputs rather than through
//! the client's dial path, whose internal random sources are not test-injectable. The generator
//! source and full vector JSON are in the wave report, not checked into this repository.

use super::chunk::{
    auth_len_key, new_shake, AeadBodyWriter, AeadChunkReader, AeadChunkWriter, Cipher, StreamChunkWriter,
};
use super::client::{build_codec, Security};
use super::shake128::Shake128Stream;
use crate::header::{kdf, KDF_SALT_CONST_AUTH_ID_ENCRYPTION_KEY};

const NONCE16: &str = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf";
const CMD_KEY: &str = "b50d916ac0cec067981af8e5f38a758f";
const AUTH_ID_FIXED: &str = "000102030405060708090a0b0c0d0e0f";
const CONN_NONCE_FIXED: &str = "a0a1a2a3a4a5a6a7";

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex")).collect()
}

fn seq_bytes(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 256) as u8).collect()
}

#[test]
fn kdf_auth_id_encryption_key_matches_known_answer() {
    let cmd_key = hex(CMD_KEY);
    let got = kdf(&cmd_key, &[KDF_SALT_CONST_AUTH_ID_ENCRYPTION_KEY]);
    assert_eq!(got.to_vec(), hex("1415ba74ca8b3d041a8f583fb4116315c589ae7b6e81765b601aa166c62871f7"));
}

#[test]
fn kdf_with_path_matches_known_answer() {
    let cmd_key = hex(CMD_KEY);
    let auth_id = hex(AUTH_ID_FIXED);
    let conn_nonce = hex(CONN_NONCE_FIXED);

    let len_key = kdf(&cmd_key, &[b"VMess Header AEAD Key_Length", &auth_id, &conn_nonce]);
    assert_eq!(len_key.to_vec(), hex("40f3b252c1ebcfdd9befa4202e5844d5bebf038cc1314c8300b18ac2dca037a1"));

    let len_iv = kdf(&cmd_key, &[b"VMess Header AEAD Nonce_Length", &auth_id, &conn_nonce]);
    assert_eq!(len_iv.to_vec(), hex("5396046f4a91a06d33db93e3d728fa5d93d4a20619806ce904dca13034575000"));

    let hdr_key = kdf(&cmd_key, &[b"VMess Header AEAD Key", &auth_id, &conn_nonce]);
    assert_eq!(hdr_key.to_vec(), hex("8fd522da72e94995d033dfa2d1cc549e0f027f5128df67ed773450192c26939f"));

    let hdr_iv = kdf(&cmd_key, &[b"VMess Header AEAD Nonce", &auth_id, &conn_nonce]);
    assert_eq!(hdr_iv.to_vec(), hex("86e28e522b84e1aaedcfd15bcb2a537b876c6b8ce21a1ae5101fe6806e87a1ee"));
}

#[test]
fn aes_128_gcm_plain_body_matches_known_answer() {
    let key = hex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf");
    let iv = hex(NONCE16);
    let mut w = AeadBodyWriter::new(Cipher::new_aes_128_gcm(&key).expect("valid key"), &iv);

    assert_eq!(w.seal(&seq_bytes(5)).expect("seal"), hex("3f5a245feac623f35797f61f43a4d87c7100d022c0"));
    assert_eq!(w.seal(&seq_bytes(10)).expect("seal"), hex("8fea14c603ef108e9b6729e79d5cfdd92fe08432722a30744886"));
}

#[test]
fn chacha20_poly1305_plain_body_matches_known_answer() {
    let key = hex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf");
    let iv = hex(NONCE16);
    let mut w = AeadBodyWriter::new(Cipher::new_chacha20_poly1305(&key).expect("valid key"), &iv);

    assert_eq!(w.seal(&seq_bytes(5)).expect("seal"), hex("7952311ab3f25e86969581249e2db8daab4b9fed3b"));
}

#[tokio::test]
async fn aes_128_gcm_auth_len_body_matches_known_answer() {
    let body_key = hex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf");
    let iv = hex(NONCE16);
    let mut body = AeadBodyWriter::new(Cipher::new_aes_128_gcm(&body_key).expect("valid key"), &iv);
    let mut framer =
        AeadChunkWriter::new(Cipher::new_aes_128_gcm(&auth_len_key(&body_key)).expect("valid key"), &iv, None);

    let sealed0 = body.seal(&seq_bytes(5)).expect("seal");
    let mut out0 = Vec::new();
    framer.write(&mut out0, &sealed0).await.expect("write chunk0");
    assert_eq!(out0, hex("caf0f181fd6c4676288742cf6817c134734a3f5a245feac623f35797f61f43a4d87c7100d022c0"));

    let sealed1 = body.seal(&seq_bytes(10)).expect("seal");
    let mut out1 = Vec::new();
    framer.write(&mut out1, &sealed1).await.expect("write chunk1");
    assert_eq!(out1, hex("7577e07974c6bc9f1dd75b116cad6ca6d21b8fea14c603ef108e9b6729e79d5cfdd92fe08432722a30744886"));
}

#[tokio::test]
async fn stream_chunk_writer_masking_matches_known_answer() {
    let key = hex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf");
    let iv = hex(NONCE16);
    let mut body = AeadBodyWriter::new(Cipher::new_aes_128_gcm(&key).expect("valid key"), &iv);
    let framer = StreamChunkWriter::new(Some(new_shake(&iv)), None);

    let sealed0 = body.seal(&seq_bytes(5)).expect("seal");
    let mut out0 = Vec::new();
    framer.write(&mut out0, &sealed0).await.expect("write chunk0");
    assert_eq!(out0, hex("3fd13f5a245feac623f35797f61f43a4d87c7100d022c0"));

    let sealed1 = body.seal(&seq_bytes(10)).expect("seal");
    let mut out1 = Vec::new();
    framer.write(&mut out1, &sealed1).await.expect("write chunk1");
    assert_eq!(out1, hex("64528fea14c603ef108e9b6729e79d5cfdd92fe08432722a30744886"));
}

#[tokio::test]
async fn stream_chunk_writer_chacha_matches_known_answer() {
    let key = hex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf");
    let iv = hex(NONCE16);
    let mut body = AeadBodyWriter::new(Cipher::new_chacha20_poly1305(&key).expect("valid key"), &iv);
    let framer = StreamChunkWriter::new(Some(new_shake(&iv)), None);

    let sealed0 = body.seal(&seq_bytes(5)).expect("seal");
    let mut out0 = Vec::new();
    framer.write(&mut out0, &sealed0).await.expect("write chunk0");
    assert_eq!(out0, hex("3fd17952311ab3f25e86969581249e2db8daab4b9fed3b"));
}

#[test]
fn shake128_matches_known_answer_sha3_stream() {
    let iv = hex(NONCE16);
    let mut s = Shake128Stream::new(&iv);
    let got: Vec<u16> = (0..6).map(|_| s.next_u16()).collect();
    assert_eq!(got, vec![16324, 25672, 42329, 17904, 34238, 15079]);
}

/// The `global_padding_option13_seq5` vector: an AES-128-GCM writer with chunk stream, chunk
/// masking and global padding all enabled.
/// `ReviewSingVmess` finding 0: `build_codec`'s non-authenticated-length AES/ChaCha branch must
/// pass `global_padding` to `StreamChunkReader`/`StreamChunkWriter`, not `None`. Fails on
/// 3cfb750b (writes 23 bytes with no padding instead of the 27). The trailing 4 padding bytes are
/// random fill on both sides and are not byte-comparable; only their
/// count is.
#[tokio::test]
async fn global_padding_reaches_stream_chunk_writer_matches_known_answer() {
    let body_key: [u8; 16] = hex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf").try_into().expect("16 bytes");
    let body_nonce: [u8; 16] = hex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf").try_into().expect("16 bytes");
    let dummy_request = [0u8; 16];
    const OPTION_CHUNK_STREAM_MASKING_PADDING: u8 = 1 | 4 | 8;

    let mut codec = build_codec(
        Security::Aes128Gcm,
        OPTION_CHUNK_STREAM_MASKING_PADDING,
        &dummy_request,
        &dummy_request,
        &body_key,
        &body_nonce,
    )
    .expect("valid codec");

    let mut out = Vec::new();
    codec.write_chunk(&mut out, &seq_bytes(5)).await.expect("write chunk");
    assert_eq!(out.len(), 27, "expected the masked-length-prefix + body + 4 bytes of padding");
    assert_eq!(out[..23], hex("64513f5a245feac623f35797f61f43a4d87c7100d022c0")[..]);
}

/// The `auth_len_reader_key_seq5_seq10` vector: an AES-128-GCM writer with chunk stream and
/// authenticated length enabled, and `resp_key/nonce = sha256(request_key/nonce)[..16]`, the real
/// client-reads-response shape.
/// `ReviewSingVmess` finding 4: the authenticated-length reader must key its length cipher (and
/// nonce) from `request_key`/`request_nonce`, like the writer, never `resp_key`/`resp_iv`. Fails
/// on 3cfb750b (`build_codec` keys the reader with `resp_key`, so it cannot open its own
/// service's response). Also exercises `ReviewSingVmess` finding 6: a clean stream end at a
/// chunk boundary is `Ok(None)`, not `UnexpectedEof`.
#[tokio::test]
async fn auth_len_reader_uses_request_key_matches_known_answer() {
    let request_key: [u8; 16] = hex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf").try_into().expect("16 bytes");
    let request_nonce: [u8; 16] = hex("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf").try_into().expect("16 bytes");
    let resp_key = hex("9f52527783ea1185acd5d4dcf1bf91b7");
    let resp_nonce = hex("d4f376ea1200f6ee38e9d24177b882cf");
    const OPTION_CHUNK_STREAM_AUTH_LEN: u8 = 1 | 16;
    let framed = hex("caf0f181fd6c4676288742cf6817c134734a14147b0877e807f47e9a1da2e93bb979eefc96deef\
         7577e07974c6bc9f1dd75b116cad6ca6d21bba3fbc885a62a9462aee2e4c95d3574d3fc935de70f\
         02280efee");

    let mut reader_codec = build_codec(
        Security::Aes128Gcm,
        OPTION_CHUNK_STREAM_AUTH_LEN,
        &request_key,
        &request_nonce,
        &resp_key,
        &resp_nonce,
    )
    .expect("valid codec");

    let mut cursor: &[u8] = &framed;
    let chunk0 = reader_codec.read_chunk(&mut cursor).await.expect("read chunk0").expect("chunk0 present");
    assert_eq!(chunk0, seq_bytes(5));
    let chunk1 = reader_codec.read_chunk(&mut cursor).await.expect("read chunk1").expect("chunk1 present");
    assert_eq!(chunk1, seq_bytes(10));
    let eof = reader_codec.read_chunk(&mut cursor).await.expect("clean eof, not UnexpectedEof");
    assert!(eof.is_none());

    // Pre-fix regression: keying the length cipher with resp_key/resp_nonce, as 3cfb750b did,
    // cannot open the wire bytes the vector encodes.
    let mut broken =
        AeadChunkReader::new(Cipher::new_aes_128_gcm(&auth_len_key(&resp_key)).expect("valid key"), &resp_nonce, None);
    let mut broken_cursor: &[u8] = &framed;
    assert!(broken.read(&mut broken_cursor).await.is_err());
}

/// A VMess chunk stream ends with an explicit termination signal (an empty write), and the reader
/// stops at the first framed size equal to the AEAD overhead plus padding. Under an authenticated
/// body that is a chunk of nothing but the AEAD tag, so the `StreamChunkReader` terminator is 16
/// bytes, not zero.
///
/// The framing below uses the stream chunk writer with `option =
/// ChunkStream|ChunkMasking|GlobalPadding`, where masking and padding draw from one
/// `shake128(nonce)`: the words `shake128_matches_known_answer_sha3_stream` pins give chunk 0 a padding of
/// `16324 % 64 == 4` under mask `25672` (`21 + 4 ^ 25672 == 0x6451`, the prefix
/// `global_padding_reaches_stream_chunk_writer_matches_known_answer` already pins) and chunk 1 a padding of
/// `42329 % 64 == 25` under mask `17904` (`16 + 25 ^ 17904 == 0x45d9`). The terminal tag is
/// AES-128-GCM of an empty body at count 1 under the key and nonce
/// `aes_128_gcm_plain_body_matches_known_answer` pins; no reader ever opens it.
#[tokio::test]
async fn authenticated_terminal_chunk_ends_the_stream() {
    let body_key: [u8; 16] = hex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf").try_into().expect("16 bytes");
    let body_nonce: [u8; 16] = hex(NONCE16).try_into().expect("16 bytes");
    let dummy_request = [0u8; 16];
    const OPTION_CHUNK_STREAM_MASKING_PADDING: u8 = 1 | 4 | 8;

    let mut codec = build_codec(
        Security::Aes128Gcm,
        OPTION_CHUNK_STREAM_MASKING_PADDING,
        &dummy_request,
        &dummy_request,
        &body_key,
        &body_nonce,
    )
    .expect("valid codec");

    // 4 and 25 trailing bytes stand in for the `crypto/rand` fill; only their count is on the
    // wire contract, and the terminal chunk's are never read at all.
    let framed = hex("64513f5a245feac623f35797f61f43a4d87c7100d022c000000000\
                      45d9531c0d34cb9a0410c0e0696e6dbadfe5000000000000000000000000000000\
                      00000000000000000000");
    let mut cursor: &[u8] = &framed;
    assert_eq!(codec.read_chunk(&mut cursor).await.expect("read data chunk"), Some(seq_bytes(5)));
    assert_eq!(codec.read_chunk(&mut cursor).await.expect("tag-only chunk is a clean eof"), None);
}

/// The other side of that boundary: a 16-byte body is only a terminator because of what the body
/// cipher is, so under `security = none` the same size must still come back as plaintext.
#[tokio::test]
async fn plaintext_chunk_of_cipher_overhead_size_is_not_a_terminator() {
    let body_key: [u8; 16] = hex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf").try_into().expect("16 bytes");
    let body_nonce: [u8; 16] = hex(NONCE16).try_into().expect("16 bytes");
    let dummy_request = [0u8; 16];
    const OPTION_CHUNK_STREAM_MASKING_PADDING: u8 = 1 | 4 | 8;

    let mut codec = build_codec(
        Security::None,
        OPTION_CHUNK_STREAM_MASKING_PADDING,
        &dummy_request,
        &dummy_request,
        &body_key,
        &body_nonce,
    )
    .expect("valid codec");

    let framed = hex("645c000102030405060708090a0b0c0d0e0f00000000");
    let mut cursor: &[u8] = &framed;
    assert_eq!(codec.read_chunk(&mut cursor).await.expect("read 16-byte plaintext chunk"), Some(seq_bytes(16)));
    assert_eq!(cursor.len(), 0, "a data chunk must consume its padding too");
}
