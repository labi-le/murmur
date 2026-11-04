//! RFC 8448 §3 (`Simple 1-RTT Handshake`) known-answer test for the RFC 8446 §7.1 key schedule in
//! [`crate::suite`].
//!
//! The SHA-256 constants are values RFC 8448 prints for that handshake; the transcript digests it
//! does not print are cross-checked against the ones it does. RFC 8448 has no SHA-384 trace, so
//! those constants are peer-derived for the same inputs. A salt/IKM inversion, a swapped
//! `derived` value, a wrong label, a wrong transcript point or a swapped client/server secret
//! fails these tests.

use x25519_dalek::{PublicKey, StaticSecret};

use crate::suite::{CipherSuite, KeySchedule};

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

const SHA384_HASH_CLIENT_HELLO_SERVER_HELLO: &str = "\
53585189fd526863cc1afbe3eecb2ba95ac94ba13e94d41603ce79f074ee1c0ae3879807076c5273a1a880d310208c54";
const SHA384_CLIENT_HANDSHAKE_TRAFFIC_SECRET: &str = "\
29577dc122959b0e087c1eedb7a81bf2bf2cafb97c8bccc06536230567a8d85e734a0fb1da5926e4d83a58989fdab7c6";
const SHA384_SERVER_HANDSHAKE_TRAFFIC_SECRET: &str = "\
25351eb01a5c05cb096c6810d72fedf4735d48c878ee62ed44187b3fb6b57feba5c7f3b2fb622c28acb964ac70dba494";
const SHA384_SERVER_HANDSHAKE_TRAFFIC_KEY: &str = "\
116a31a195f8551eebb463ca280d9282ad25156966d01c742c17a822a2950e16";
const SHA384_SERVER_HANDSHAKE_TRAFFIC_IV: &str = "\
040a4d7734ac0a8ccc445e2d";
const SHA384_HASH_CLIENT_HELLO_CERTIFICATE_VERIFY: &str = "\
96cbc7d8d92c5d0ae5b83cbbc6cd6bc42dea196d714b37eb259fd1d82207e9baba6ad0f9f30dd340c230bfacd4cecacd";
const SHA384_SERVER_FINISHED: &str = "\
4cd47099f9afff78486eb4073de97800d5f1f31482c6565df90eed2ea7661a35bd6e4d1640477fc643197aa7ba3bf5c3";
const SHA384_HASH_CLIENT_HELLO_SERVER_FINISHED: &str = "\
314d0b33fd340a44bc9dedb17165e28106d58a8d5a3c3a940d1328f3ca7089ecbbcbf06f718f6a41c9b5d8b7fca3b7a4";
const SHA384_CLIENT_APPLICATION_TRAFFIC_SECRET: &str = "\
bbafec3b0ca7533f456f73d389ef910ec44f2c6fa5dc2e112a4414b6752a1d00ddf6d0ce9b6dd4b111e191562ed967be";
const SHA384_SERVER_APPLICATION_TRAFFIC_SECRET: &str = "\
9aabfb28a3106d6af28555d12ee08fb6b233680580a2a2b7df5cce8742aeba5f8cc14daf944fa21ab06a713deaf829a7";
const SHA384_CLIENT_FINISHED: &str = "\
8bfd3c26a00c3b1e4eb27138c929fc45783dc2c1a182bfe5d9d83fc296894e2c1d51bdb3fc39733d7deff854587f3c4e";
const SHA384_CLIENT_APPLICATION_TRAFFIC_KEY: &str = "\
342ca222906f18b4d4d7935e00c7ce42c667d1869368423dd15ff036240632ca";
const SHA384_CLIENT_APPLICATION_TRAFFIC_IV: &str = "\
3db3c8fdc6a1b76511958bc0";
const SHA384_SERVER_APPLICATION_TRAFFIC_KEY: &str = "\
c662148873b603bd489063ed551439ecdc8723af4addab36f6bd119a221e5a35";
const SHA384_SERVER_APPLICATION_TRAFFIC_IV: &str = "\
290f1d18cef19ec9685d2da8";

fn unhex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0, "odd-length hex constant");
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex constant")).collect()
}

fn unhex32(s: &str) -> [u8; 32] {
    unhex(s).try_into().expect("32-byte hex constant")
}

#[test]
fn rfc8448_transcript_covers_client_hello_to_server_finished() {
    let suite = CipherSuite::Aes128GcmSha256;
    let mut transcript = suite.transcript();
    transcript.update(&unhex(CLIENT_HELLO));
    transcript.update(&unhex(SERVER_HELLO));
    assert_eq!(transcript.digest(), unhex(HASH_CLIENT_HELLO_SERVER_HELLO), "Transcript-Hash(ClientHello..ServerHello)");

    let flight = unhex(SERVER_FLIGHT);
    transcript.update(&flight[..flight.len() - 36]);
    assert_eq!(
        transcript.digest(),
        unhex(HASH_CLIENT_HELLO_CERTIFICATE_VERIFY),
        "Transcript-Hash(ClientHello..CertificateVerify)"
    );

    transcript.update(&flight[flight.len() - 36..]);
    assert_eq!(
        transcript.digest(),
        unhex(HASH_CLIENT_HELLO_SERVER_FINISHED),
        "Transcript-Hash(ClientHello..server Finished)"
    );
}

#[test]
fn rfc8448_key_schedule_matches_the_rfc_trace() {
    let suite = CipherSuite::Aes128GcmSha256;
    let shared = StaticSecret::from(unhex32(CLIENT_X25519_PRIVATE))
        .diffie_hellman(&PublicKey::from(unhex32(SERVER_X25519_PUBLIC)));
    assert_eq!(shared.as_bytes().to_vec(), unhex(X25519_SHARED_SECRET), "ECDHE shared secret");

    let mut transcript = suite.transcript();
    transcript.update(&unhex(CLIENT_HELLO));
    transcript.update(&unhex(SERVER_HELLO));
    let schedule = KeySchedule::new(suite, shared.as_bytes(), &transcript.digest());
    assert_eq!(
        schedule.client_handshake_secret,
        unhex(CLIENT_HANDSHAKE_TRAFFIC_SECRET),
        "client_handshake_traffic_secret"
    );
    assert_eq!(
        schedule.server_handshake_secret,
        unhex(SERVER_HANDSHAKE_TRAFFIC_SECRET),
        "server_handshake_traffic_secret"
    );
    let (key, iv) = schedule.traffic_key_iv(&schedule.server_handshake_secret);
    assert_eq!(key, unhex(SERVER_HANDSHAKE_TRAFFIC_KEY), "server handshake key");
    assert_eq!(iv.to_vec(), unhex(SERVER_HANDSHAKE_TRAFFIC_IV), "server handshake iv");

    let flight = unhex(SERVER_FLIGHT);
    let hash_through_certificate_verify = {
        let mut t = suite.transcript();
        t.update(&unhex(CLIENT_HELLO));
        t.update(&unhex(SERVER_HELLO));
        t.update(&flight[..flight.len() - 36]);
        t.digest()
    };
    assert_eq!(
        schedule.finished_verify_data(&schedule.server_handshake_secret, &hash_through_certificate_verify),
        unhex(SERVER_FINISHED),
        "server Finished verify_data"
    );

    transcript.update(&flight);
    let hash_through_server_finished = transcript.digest();
    assert_eq!(
        hash_through_server_finished,
        unhex(HASH_CLIENT_HELLO_SERVER_FINISHED),
        "Transcript-Hash(ClientHello..server Finished)"
    );
    let (client_application, server_application) = schedule.application_secrets(&hash_through_server_finished);
    assert_eq!(client_application, unhex(CLIENT_APPLICATION_TRAFFIC_SECRET), "client_application_traffic_secret");
    assert_eq!(server_application, unhex(SERVER_APPLICATION_TRAFFIC_SECRET), "server_application_traffic_secret");
    assert_eq!(
        schedule.finished_verify_data(&schedule.client_handshake_secret, &hash_through_server_finished),
        unhex(CLIENT_FINISHED),
        "client Finished verify_data"
    );
    let (key, iv) = schedule.traffic_key_iv(&client_application);
    assert_eq!(key, unhex(CLIENT_APPLICATION_TRAFFIC_KEY), "client application key");
    assert_eq!(iv.to_vec(), unhex(CLIENT_APPLICATION_TRAFFIC_IV), "client application iv");
    let (key, iv) = schedule.traffic_key_iv(&server_application);
    assert_eq!(key, unhex(SERVER_APPLICATION_TRAFFIC_KEY), "server application key");
    assert_eq!(iv.to_vec(), unhex(SERVER_APPLICATION_TRAFFIC_IV), "server application iv");
}

/// Peer-derived: the TLS 1.3 SHA-384 schedule of cipher suite 0x1302 run over the
/// RFC 8448 §3 inputs. Pins the SHA-384 dispatch: 48-byte zero salt/IKM and SHA-384
/// `HKDF-Expand-Label`.
#[test]
fn sha384_schedule_matches_the_peer_vector() {
    let suite = CipherSuite::Aes256GcmSha384;
    let shared = StaticSecret::from(unhex32(CLIENT_X25519_PRIVATE))
        .diffie_hellman(&PublicKey::from(unhex32(SERVER_X25519_PUBLIC)));
    assert_eq!(shared.as_bytes().to_vec(), unhex(X25519_SHARED_SECRET), "ECDHE shared secret");

    let mut transcript = suite.transcript();
    transcript.update(&unhex(CLIENT_HELLO));
    transcript.update(&unhex(SERVER_HELLO));
    assert_eq!(
        transcript.digest(),
        unhex(SHA384_HASH_CLIENT_HELLO_SERVER_HELLO),
        "SHA-384 hash(ClientHello..ServerHello)"
    );

    let schedule = KeySchedule::new(suite, shared.as_bytes(), &transcript.digest());
    assert_eq!(schedule.client_handshake_secret, unhex(SHA384_CLIENT_HANDSHAKE_TRAFFIC_SECRET));
    assert_eq!(schedule.server_handshake_secret, unhex(SHA384_SERVER_HANDSHAKE_TRAFFIC_SECRET));
    let (key, iv) = schedule.traffic_key_iv(&schedule.server_handshake_secret);
    assert_eq!(key, unhex(SHA384_SERVER_HANDSHAKE_TRAFFIC_KEY));
    assert_eq!(iv.to_vec(), unhex(SHA384_SERVER_HANDSHAKE_TRAFFIC_IV));

    let flight = unhex(SERVER_FLIGHT);
    let hash_through_certificate_verify = {
        let mut t = suite.transcript();
        t.update(&unhex(CLIENT_HELLO));
        t.update(&unhex(SERVER_HELLO));
        t.update(&flight[..flight.len() - 36]);
        t.digest()
    };
    assert_eq!(hash_through_certificate_verify, unhex(SHA384_HASH_CLIENT_HELLO_CERTIFICATE_VERIFY));
    assert_eq!(
        schedule.finished_verify_data(&schedule.server_handshake_secret, &hash_through_certificate_verify),
        unhex(SHA384_SERVER_FINISHED)
    );

    transcript.update(&flight);
    let hash_through_server_finished = transcript.digest();
    assert_eq!(hash_through_server_finished, unhex(SHA384_HASH_CLIENT_HELLO_SERVER_FINISHED));
    let (client_application, server_application) = schedule.application_secrets(&hash_through_server_finished);
    assert_eq!(client_application, unhex(SHA384_CLIENT_APPLICATION_TRAFFIC_SECRET));
    assert_eq!(server_application, unhex(SHA384_SERVER_APPLICATION_TRAFFIC_SECRET));
    assert_eq!(
        schedule.finished_verify_data(&schedule.client_handshake_secret, &hash_through_server_finished),
        unhex(SHA384_CLIENT_FINISHED)
    );
    let (key, iv) = schedule.traffic_key_iv(&client_application);
    assert_eq!(key, unhex(SHA384_CLIENT_APPLICATION_TRAFFIC_KEY));
    assert_eq!(iv.to_vec(), unhex(SHA384_CLIENT_APPLICATION_TRAFFIC_IV));
    let (key, iv) = schedule.traffic_key_iv(&server_application);
    assert_eq!(key, unhex(SHA384_SERVER_APPLICATION_TRAFFIC_KEY));
    assert_eq!(iv.to_vec(), unhex(SHA384_SERVER_APPLICATION_TRAFFIC_IV));
}
