//! RFC 8448 §3 (`Simple 1-RTT Handshake`) and §4 (`Resumed 0-RTT Handshake`)
//! known-answer tests for the RFC 8446 §7.1 key schedule in [`crate::keys`],
//! plus RFC 9001 / RFC 9369 Appendix A.1 for the QUIC Initial keys.
//!
//! Each constant is a value RFC 8448 or the QUIC RFCs print for that handshake; the transcript
//! digests they do not print are cross-checked against the ones they do. A salt/IKM inversion, a
//! swapped `derived` value, a wrong label, a wrong transcript point or a swapped client/server
//! secret fails these tests.

use crate::keys::{self, KeySchedule, QuicVersion};
use crate::transcript::Transcript;
use sha2::Digest as _;
use x25519_dalek::{PublicKey, StaticSecret};

const CLIENT_HELLO: &str = "\
010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef\
6283024dece7000006130113031302010000910000000b000900000673657276\
6572ff01000100000a00140012001d0017001800190100010101020103010400\
230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e\
51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603\
020308040805080604010501060102010402050206020202002d00020101001c\
00024001";

const SERVER_HELLO: &str = "\
020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155\
772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdb\
f7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304";

const SERVER_FLIGHT: &str = "\
080000240022000a00140012001d00170018001901000101010201030104001c\
00024001000000000b0001b9000001b50001b0308201ac30820115a003020102\
020102300d06092a864886f70d01010b0500300e310c300a0603550403130372\
7361301e170d3136303733303031323335395a170d3236303733303031323335\
395a300e310c300a0603550403130372736130819f300d06092a864886f70d01\
0101050003818d0030818902818100b4bb498f8279303d980836399b36c6988c\
0c68de55e1bdb826d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19e\
aa6af98c7ced43120998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e2\
2a5fda430846748030530ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a\
8002c47428a6d35a8d88d79f7f1e3f0203010001a31a301830090603551d1304\
023000300b0603551d0f0404030205a0300d06092a864886f70d01010b050003\
81810085aad2a0e5b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594\
365417f2eae8f8a58c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd\
335e5e67f2dbf102702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb\
2bd5203b1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b4\
2b4de100000f000084080400805a747c5d88fa9bd2e55ab085a61015b7211f82\
4cd484145ab3ff52f1fda8477b0b7abc90db78e2d33a5c141a078653fa6bef78\
0c5ea248eeaaa785c4f394cab6d30bbe8d4859ee511f602957b15411ac027671\
459e46445c9ea58c181e818e95b8c3fb0bf3278409d3be152a3da5043e063dda\
65cdf5aea20d53dfacd42f74f3140000209b9b141d906337fbd2cbdce71df4de\
da4ab42c309572cb7fffee5454b78f0718";

const CLIENT_X25519_PRIVATE: &str = "\
49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005";

const SERVER_X25519_PUBLIC: &str = "\
c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f";

const X25519_SHARED_SECRET: &str = "\
8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d";

const HASH_CLIENT_HELLO_SERVER_HELLO: &str = "\
860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8";

const CLIENT_HANDSHAKE_TRAFFIC_SECRET: &str = "\
b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21";

const SERVER_HANDSHAKE_TRAFFIC_SECRET: &str = "\
b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38";

const HASH_CLIENT_HELLO_CERTIFICATE_VERIFY: &str = "\
edb7725fa7a3473b031ec8ef65a2485493900138a2b91291407d7951a06110ed";

const SERVER_HANDSHAKE_TRAFFIC_KEY: &str = "\
3fce516009c21727d0f2e4e86ee403bc";

const SERVER_HANDSHAKE_TRAFFIC_IV: &str = "\
5d313eb2671276ee13000b30";

const SERVER_FINISHED: &str = "\
9b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718";

const HASH_CLIENT_HELLO_SERVER_FINISHED: &str = "\
9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13";

const CLIENT_APPLICATION_TRAFFIC_SECRET: &str = "\
9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5";

const SERVER_APPLICATION_TRAFFIC_SECRET: &str = "\
a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643";

const CLIENT_FINISHED: &str = "\
a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61";

const CLIENT_APPLICATION_TRAFFIC_KEY: &str = "\
17422dda596ed5d9acd890e3c63f5051";

const CLIENT_APPLICATION_TRAFFIC_IV: &str = "\
5b78923dee08579033e523d9";

const SERVER_APPLICATION_TRAFFIC_KEY: &str = "\
9f02283b6c9c07efc26bb9f2ac92e356";

const SERVER_APPLICATION_TRAFFIC_IV: &str = "\
cf782b88dd83549aadf1e984";

const QUIC_DESTINATION_CONNECTION_ID: &str = "8394c8f03e515708";

const QUIC_V1_CLIENT_INITIAL_SECRET: &str = "\
c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea";
const QUIC_V1_CLIENT_KEY: &str = "\
1f369613dd76d5467730efcbe3b1a22d";
const QUIC_V1_CLIENT_IV: &str = "\
fa044b2f42a3fd3b46fb255c";
const QUIC_V1_CLIENT_HP: &str = "\
9f50449e04a0e810283a1e9933adedd2";
const QUIC_V1_SERVER_INITIAL_SECRET: &str = "\
3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b";
const QUIC_V1_SERVER_KEY: &str = "\
cf3a5331653c364c88f0f379b6067e37";
const QUIC_V1_SERVER_IV: &str = "\
0ac1493ca1905853b0bba03e";
const QUIC_V1_SERVER_HP: &str = "\
c206b8d9b9f0f37644430b490eeaa314";
const QUIC_V2_CLIENT_INITIAL_SECRET: &str = "\
14ec9d6eb9fd7af83bf5a668bc17a7e283766aade7ecd0891f70f9ff7f4bf47b";
const QUIC_V2_CLIENT_KEY: &str = "\
8b1a0bc121284290a29e0971b5cd045d";
const QUIC_V2_CLIENT_IV: &str = "\
91f73e2351d8fa91660e909f";
const QUIC_V2_CLIENT_HP: &str = "\
45b95e15235d6f45a6b19cbcb0294ba9";
const QUIC_V2_SERVER_INITIAL_SECRET: &str = "\
0263db1782731bf4588e7e4d93b7463907cb8cd8200b5da55a8bd488eafc37c1";
const QUIC_V2_SERVER_KEY: &str = "\
82db637861d55e1d011f19ea71d5d2a7";
const QUIC_V2_SERVER_IV: &str = "\
dd13c276499c0249d3310652";
const QUIC_V2_SERVER_HP: &str = "\
edf6d05c83121201b436e16877593c3a";

fn unhex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0, "odd-length hex constant");
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex constant")).collect()
}

fn unhex32(s: &str) -> [u8; 32] {
    unhex(s).try_into().expect("32-byte hex constant")
}

#[test]
fn rfc8448_transcript_covers_client_hello_to_server_finished() {
    let mut transcript = Transcript::new();
    transcript.update(&unhex(CLIENT_HELLO));
    transcript.update(&unhex(SERVER_HELLO));
    assert_eq!(
        transcript.hash().to_vec(),
        unhex(HASH_CLIENT_HELLO_SERVER_HELLO),
        "Transcript-Hash(ClientHello..ServerHello)"
    );

    let flight = unhex(SERVER_FLIGHT);
    transcript.update(&flight[..flight.len() - 36]);
    assert_eq!(
        transcript.hash().to_vec(),
        unhex(HASH_CLIENT_HELLO_CERTIFICATE_VERIFY),
        "Transcript-Hash(ClientHello..CertificateVerify)"
    );

    transcript.update(&flight[flight.len() - 36..]);
    assert_eq!(
        transcript.hash().to_vec(),
        unhex(HASH_CLIENT_HELLO_SERVER_FINISHED),
        "Transcript-Hash(ClientHello..server Finished)"
    );
}

#[test]
fn rfc8448_key_schedule_matches_the_rfc_trace() {
    // RFC 8448 publishes both ephemeral private keys, so the ECDHE output the
    // schedule is salted with can be reproduced rather than assumed.
    let shared = StaticSecret::from(unhex32(CLIENT_X25519_PRIVATE))
        .diffie_hellman(&PublicKey::from(unhex32(SERVER_X25519_PUBLIC)));
    assert_eq!(shared.as_bytes().to_vec(), unhex(X25519_SHARED_SECRET), "ECDHE shared secret");

    let mut transcript = Transcript::new();
    transcript.update(&unhex(CLIENT_HELLO));
    transcript.update(&unhex(SERVER_HELLO));
    let mut schedule = KeySchedule::new(None, shared.as_bytes(), &transcript.hash()).expect("handshake schedule");
    assert_eq!(
        schedule.client_handshake_traffic_secret.to_vec(),
        unhex(CLIENT_HANDSHAKE_TRAFFIC_SECRET),
        "client_handshake_traffic_secret"
    );
    assert_eq!(
        schedule.server_handshake_traffic_secret.to_vec(),
        unhex(SERVER_HANDSHAKE_TRAFFIC_SECRET),
        "server_handshake_traffic_secret"
    );
    let (key, iv) = keys::traffic_key_iv(&schedule.server_handshake_traffic_secret).expect("traffic key");
    assert_eq!(key.to_vec(), unhex(SERVER_HANDSHAKE_TRAFFIC_KEY), "server handshake key");
    assert_eq!(iv.to_vec(), unhex(SERVER_HANDSHAKE_TRAFFIC_IV), "server handshake iv");

    let flight = unhex(SERVER_FLIGHT);
    let hash_through_certificate_verify = {
        let mut t = Transcript::new();
        t.update(&unhex(CLIENT_HELLO));
        t.update(&unhex(SERVER_HELLO));
        t.update(&flight[..flight.len() - 36]);
        t.hash()
    };
    assert_eq!(
        keys::compute_finished(&schedule.server_handshake_traffic_secret, &hash_through_certificate_verify)
            .expect("server Finished")
            .to_vec(),
        unhex(SERVER_FINISHED),
        "server Finished verify_data"
    );

    transcript.update(&flight);
    let hash_through_server_finished = transcript.hash();
    assert_eq!(
        hash_through_server_finished.to_vec(),
        unhex(HASH_CLIENT_HELLO_SERVER_FINISHED),
        "Transcript-Hash(ClientHello..server Finished)"
    );
    schedule.derive_application_secrets(&hash_through_server_finished).expect("application secrets");
    assert_eq!(
        schedule.client_application_traffic_secret.to_vec(),
        unhex(CLIENT_APPLICATION_TRAFFIC_SECRET),
        "client_application_traffic_secret"
    );
    assert_eq!(
        schedule.server_application_traffic_secret.to_vec(),
        unhex(SERVER_APPLICATION_TRAFFIC_SECRET),
        "server_application_traffic_secret"
    );
    assert_eq!(
        keys::compute_finished(&schedule.client_handshake_traffic_secret, &hash_through_server_finished)
            .expect("client Finished")
            .to_vec(),
        unhex(CLIENT_FINISHED),
        "client Finished verify_data"
    );
    let (key, iv) = keys::traffic_key_iv(&schedule.client_application_traffic_secret).expect("traffic key");
    assert_eq!(key.to_vec(), unhex(CLIENT_APPLICATION_TRAFFIC_KEY), "client application key");
    assert_eq!(iv.to_vec(), unhex(CLIENT_APPLICATION_TRAFFIC_IV), "client application iv");
    let (key, iv) = keys::traffic_key_iv(&schedule.server_application_traffic_secret).expect("traffic key");
    assert_eq!(key.to_vec(), unhex(SERVER_APPLICATION_TRAFFIC_KEY), "server application key");
    assert_eq!(iv.to_vec(), unhex(SERVER_APPLICATION_TRAFFIC_IV), "server application iv");

    // RFC 8448 §3 `derive secret "tls13 res master"` is taken over the
    // transcript through the client's Finished, which closes the schedule.
    transcript.update(&crate::messages::build_finished(&unhex32(CLIENT_FINISHED)).expect("client Finished message"));
    assert_eq!(
        transcript.hash().to_vec(),
        unhex(HASH_CLIENT_HELLO_CLIENT_FINISHED),
        "Transcript-Hash(ClientHello..client Finished)"
    );
    schedule.derive_resumption_master_secret(&transcript.hash()).expect("resumption master secret");
    assert_eq!(
        schedule.resumption_master_secret.to_vec(),
        unhex(RFC8448_RESUMPTION_MASTER_SECRET),
        "resumption_master_secret"
    );
}

/// RFC 9001 A.1 / RFC 9369 A.1 Initial keys for destination connection ID `8394c8f03e515708`:
/// the `HKDF-Extract(initial_salt, cid)` order, both versions' salts and their
/// `client in`/`server in`/`quic[v2] key`/`iv`/`hp` labels.
#[test]
fn quic_initial_keys_match_rfc9001_and_rfc9369_appendix_a() {
    let dcid = unhex(QUIC_DESTINATION_CONNECTION_ID);

    let (client, server) = keys::quic_initial_secrets(&dcid, QuicVersion::V1).expect("v1 initial secrets");
    assert_eq!(client.to_vec(), unhex(QUIC_V1_CLIENT_INITIAL_SECRET));
    assert_eq!(server.to_vec(), unhex(QUIC_V1_SERVER_INITIAL_SECRET));
    let client_keys = keys::quic_keys(&client, QuicVersion::V1).expect("v1 client keys");
    assert_eq!(client_keys.key.to_vec(), unhex(QUIC_V1_CLIENT_KEY));
    assert_eq!(client_keys.iv.to_vec(), unhex(QUIC_V1_CLIENT_IV));
    assert_eq!(client_keys.hp.to_vec(), unhex(QUIC_V1_CLIENT_HP));
    let server_keys = keys::quic_keys(&server, QuicVersion::V1).expect("v1 server keys");
    assert_eq!(server_keys.key.to_vec(), unhex(QUIC_V1_SERVER_KEY));
    assert_eq!(server_keys.iv.to_vec(), unhex(QUIC_V1_SERVER_IV));
    assert_eq!(server_keys.hp.to_vec(), unhex(QUIC_V1_SERVER_HP));

    let (client, server) = keys::quic_initial_secrets(&dcid, QuicVersion::V2).expect("v2 initial secrets");
    assert_eq!(client.to_vec(), unhex(QUIC_V2_CLIENT_INITIAL_SECRET));
    assert_eq!(server.to_vec(), unhex(QUIC_V2_SERVER_INITIAL_SECRET));
    let client_keys = keys::quic_keys(&client, QuicVersion::V2).expect("v2 client keys");
    assert_eq!(client_keys.key.to_vec(), unhex(QUIC_V2_CLIENT_KEY));
    assert_eq!(client_keys.iv.to_vec(), unhex(QUIC_V2_CLIENT_IV));
    assert_eq!(client_keys.hp.to_vec(), unhex(QUIC_V2_CLIENT_HP));
    let server_keys = keys::quic_keys(&server, QuicVersion::V2).expect("v2 server keys");
    assert_eq!(server_keys.key.to_vec(), unhex(QUIC_V2_SERVER_KEY));
    assert_eq!(server_keys.iv.to_vec(), unhex(QUIC_V2_SERVER_IV));
    assert_eq!(server_keys.hp.to_vec(), unhex(QUIC_V2_SERVER_HP));
}

/// RFC 8448 §3, `derive secret "tls13 res master"`: the resumption master secret.
const RFC8448_RESUMPTION_MASTER_SECRET: &str = "\
    7df235f2031d2a051287d02b0241b0bfdaf86cc856231f2d5aba46c434\
    ec196c";

/// RFC 8448 §3, `generate resumption secret "tls13 resumption"`: the ticket nonce.
const RFC8448_TICKET_NONCE: &str = "\
    0000";

/// RFC 8448 §3, `derive secret "tls13 res master"`: `Transcript-Hash` over
/// `ClientHello..client Finished`.
const HASH_CLIENT_HELLO_CLIENT_FINISHED: &str = "\
    209145a96ee8e2a122ff810047cc952684658d6049e86429426db87c54ad\
    143d";

/// RFC 8448 §4, `extract secret "early"`: the IKM, i.e. the resumption PSK.
const RFC8448_RESUMPTION_PSK: &str = "\
    4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492\
    e1c4f3";

/// RFC 8448 §4, `extract secret "early"`: the client and server early secret.
const RFC8448_EARLY_SECRET: &str = "\
    9b2188e9b2fc6d64d71dc329900e20bb41915000f678aa839cbb797cb7\
    d8332c";

/// RFC 8448 §4, `calculate PSK binder`: the ClientHello truncated after the
/// `pre_shared_key` identities field.
const RFC8448_CLIENT_HELLO_PREFIX: &str = "\
    010001fc03031bc3ceb6bbe39cff938355b5a50adb6db21b7a6af649d7\
    b4bc419d7876487d95000006130113031302010001cd0000000b000900\
    0006736572766572ff01000100000a00140012001d0017001800190100\
    0101010201030104003300260024001d0020e4ffb68ac05f8d96c99da2\
    6698346c6be16482badddafe051a66b4f18d668f0b002a0000002b0003\
    020304000d0020001e0403050306030203080408050806040105010601\
    02010402050206020202002d00020101001c0002400100150057000000\
    0000000000000000000000000000000000000000000000000000000000\
    0000000000000000000000000000000000000000000000000000000000\
    0000000000000000000000000000000000000000000000000000002900\
    dd00b800b22c035d829359ee5ff7af4ec900000000262a6494dc486d2c\
    8a34cb33fa90bf1b0070ad3c498883c9367c09a2be785abc55cd226097\
    a3a982117283f82a03a143efd3ff5dd36d64e861be7fd61d2827db279c\
    ce145077d454a3664d4e6da4d29ee03725a6a4dafcd0fc67d2aea70529\
    513e3da2677fa5906c5b3f7d8f92f228bda40dda721470f9fbf297b5ae\
    a617646fac5c03272e970727c621a79141ef5f7de6505e5bfbc388e933\
    43694093934ae4d357fad6aacb";

/// RFC 8448 §4: `Transcript-Hash` of the truncated ClientHello.
const RFC8448_BINDER_HASH: &str = "\
    63224b2e4573f2d3454ca84b9d009a04f6be9e05711a8396473aefa01e\
    924a14";

/// RFC 8448 §4, `calculate PSK binder`: the binder key (the RFC labels it PRK).
const RFC8448_RESUMPTION_BINDER_KEY: &str = "\
    69fe131a3bbad5d63c64eebcc30e395b9d8107726a13d074e389dbc8a4\
    e47256";

/// RFC 8448 §4, `calculate PSK binder`: the binder itself.
const RFC8448_PSK_BINDER: &str = "\
    3add4fb2d8fdf822a0ca3cf7678ef5e88dae990141c5924d57bb6fa31b\
    9e5f9d";

/// RFC 8448 §4, `send handshake record`: the whole ClientHello, binders included.
const RFC8448_CLIENT_HELLO: &str = "\
    010001fc03031bc3ceb6bbe39cff938355b5a50adb6db21b7a6af649d7\
    b4bc419d7876487d95000006130113031302010001cd0000000b000900\
    0006736572766572ff01000100000a00140012001d0017001800190100\
    0101010201030104003300260024001d0020e4ffb68ac05f8d96c99da2\
    6698346c6be16482badddafe051a66b4f18d668f0b002a0000002b0003\
    020304000d0020001e0403050306030203080408050806040105010601\
    02010402050206020202002d00020101001c0002400100150057000000\
    0000000000000000000000000000000000000000000000000000000000\
    0000000000000000000000000000000000000000000000000000000000\
    0000000000000000000000000000000000000000000000000000002900\
    dd00b800b22c035d829359ee5ff7af4ec900000000262a6494dc486d2c\
    8a34cb33fa90bf1b0070ad3c498883c9367c09a2be785abc55cd226097\
    a3a982117283f82a03a143efd3ff5dd36d64e861be7fd61d2827db279c\
    ce145077d454a3664d4e6da4d29ee03725a6a4dafcd0fc67d2aea70529\
    513e3da2677fa5906c5b3f7d8f92f228bda40dda721470f9fbf297b5ae\
    a617646fac5c03272e970727c621a79141ef5f7de6505e5bfbc388e933\
    43694093934ae4d357fad6aacb0021203add4fb2d8fdf822a0ca3cf767\
    8ef5e88dae990141c5924d57bb6fa31b9e5f9d";

/// RFC 8448 §4, `derive secret "tls13 c e traffic"`: Transcript-Hash(ClientHello).
const RFC8448_HASH_CLIENT_HELLO: &str = "\
    08ad0fa05d7c7233b1775ba2ff9f4c5b8b59276b7f227f13a976245f5d\
    960913";

/// RFC 8448 §4: client_early_traffic_secret.
const RFC8448_CLIENT_EARLY_TRAFFIC_SECRET: &str = "\
    3fbbe6a60deb66c30a32795aba0eff7eaa10105586e7be5c09678d63b6\
    caab62";

/// RFC 8448 §4, `derive write traffic keys for early application data`.
const RFC8448_EARLY_TRAFFIC_KEY: &str = "\
    920205a5b7bf2115e6fc5c2942834f54";

/// RFC 8448 §4: the early application data IV.
const RFC8448_EARLY_TRAFFIC_IV: &str = "\
    6d475f0993c8e564610db2b9";

/// RFC 8448 §4 (`Resumed 0-RTT Handshake`) known-answer test for the
/// resumption half of the key schedule: the PSK a ticket yields, the early
/// secret it is extracted from, the binder over the truncated ClientHello, and
/// the 0-RTT traffic keys.
#[test]
fn rfc8448_resumption_and_binder_match_the_rfc_trace() {
    let psk = keys::resumption_psk(&unhex32(RFC8448_RESUMPTION_MASTER_SECRET), &unhex(RFC8448_TICKET_NONCE))
        .expect("resumption PSK");
    assert_eq!(psk.to_vec(), unhex(RFC8448_RESUMPTION_PSK), "PSK from the resumption master secret");
    assert_eq!(keys::early_secret(Some(&psk)).to_vec(), unhex(RFC8448_EARLY_SECRET), "Early Secret");

    let binder_key = keys::resumption_binder_key(&psk).expect("binder key");
    assert_eq!(binder_key.to_vec(), unhex(RFC8448_RESUMPTION_BINDER_KEY), "binder key");
    let prefix = unhex(RFC8448_CLIENT_HELLO_PREFIX);
    assert_eq!(prefix.len(), 477, "the truncated ClientHello the RFC prints");
    let binder_hash: [u8; 32] = sha2::Sha256::digest(&prefix).into();
    assert_eq!(binder_hash.to_vec(), unhex(RFC8448_BINDER_HASH), "Transcript-Hash of the truncated ClientHello");
    assert_eq!(
        keys::compute_finished(&binder_key, &binder_hash).expect("binder").to_vec(),
        unhex(RFC8448_PSK_BINDER),
        "PskBinderEntry"
    );

    let hello = unhex(RFC8448_CLIENT_HELLO);
    assert_eq!(hello.len(), 512, "the ClientHello the RFC puts on the wire");
    assert_eq!(&hello[..prefix.len()], &prefix[..], "the binder transcript is a prefix of the sent hello");
    let hello_hash: [u8; 32] = sha2::Sha256::digest(&hello).into();
    assert_eq!(hello_hash.to_vec(), unhex(RFC8448_HASH_CLIENT_HELLO), "Transcript-Hash(ClientHello)");
    let early = keys::client_early_traffic_secret(&psk, &hello_hash).expect("client_early_traffic_secret");
    assert_eq!(early.to_vec(), unhex(RFC8448_CLIENT_EARLY_TRAFFIC_SECRET), "client_early_traffic_secret");
    let (key, iv) = keys::traffic_key_iv(&early).expect("early traffic keys");
    assert_eq!(key.to_vec(), unhex(RFC8448_EARLY_TRAFFIC_KEY), "early traffic key");
    assert_eq!(iv.to_vec(), unhex(RFC8448_EARLY_TRAFFIC_IV), "early traffic iv");
}
