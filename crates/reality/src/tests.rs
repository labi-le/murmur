use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use murmur_common_net::io::{close_stream, Stream};

use crate::client::{connect_reality_client, RealityClientConfig};
use crate::handshake::ClientHello;
use crate::record::RecordLayer;
use crate::server::{
    reality_server_accept, within_max_time_diff, FallbackLimit, FallbackThrottle, RealityServerConfig, TokenBucket,
};
use crate::suite::{hkdf_sha256_reality, CipherSuite};
use crate::wire::Writer;
use crate::RealityCloser;

fn keypair() -> ([u8; 32], [u8; 32]) {
    crate::suite::generate_x25519_keypair()
}

fn no_dest_dial() -> crate::server::DialDest {
    Arc::new(|| {
        Box::pin(async {
            let (a, b) = tokio::io::duplex(4096);
            tokio::spawn(async move {
                let mut a = a;
                let mut buf = [0u8; 4096];
                loop {
                    match a.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(_n) => {}
                    }
                }
            });
            let boxed: crate::server::BoxedStream = Box::new(b);
            Ok(boxed)
        })
    })
}

#[tokio::test]
async fn client_and_server_authenticate_and_exchange_application_data() {
    let (server_private, server_public) = keypair();
    let short_id = [0x11u8; 8];

    let mut server_names = HashSet::new();
    server_names.insert("example.test".to_owned());
    let mut short_ids = HashSet::new();
    short_ids.insert(short_id);

    let server_cfg = RealityServerConfig::new(
        server_private,
        server_names,
        short_ids,
        Some(Duration::from_secs(300)),
        no_dest_dial(),
    );
    let client_cfg = RealityClientConfig { public_key: server_public, short_id };

    let (client_io, server_io) = tokio::io::duplex(64 * 1024);

    let server_task = tokio::spawn(async move {
        let mut stream =
            reality_server_accept(server_io, &server_cfg).await.expect("server should authenticate the client");
        let mut buf = [0u8; 5];
        stream.read_exact(&mut buf).await.expect("read ping");
        assert_eq!(&buf, b"ping!");
        stream.write_all(b"pong!").await.expect("write pong");
    });

    let mut client_stream = connect_reality_client(client_io, "example.test", &client_cfg)
        .await
        .expect("client should authenticate against the server");
    client_stream.write_all(b"ping!").await.expect("write ping");
    let mut buf = [0u8; 5];
    client_stream.read_exact(&mut buf).await.expect("read pong");
    assert_eq!(&buf, b"pong!");

    server_task.await.expect("server task should not panic");
}

#[tokio::test]
async fn wrong_short_id_falls_back_instead_of_authenticating() {
    let (server_private, server_public) = keypair();

    let mut server_names = HashSet::new();
    server_names.insert("example.test".to_owned());
    let mut short_ids = HashSet::new();
    short_ids.insert([0xAAu8; 8]); // server only accepts this short id

    let server_cfg = RealityServerConfig::new(server_private, server_names, short_ids, None, no_dest_dial());
    let client_cfg = RealityClientConfig { public_key: server_public, short_id: [0xBBu8; 8] }; // client uses a different one

    let (client_io, server_io) = tokio::io::duplex(64 * 1024);

    let server_task = tokio::spawn(async move {
        let result = reality_server_accept(server_io, &server_cfg).await;
        assert!(result.is_err(), "server must not authenticate a client with an unknown short id");
    });

    let client_result =
        tokio::time::timeout(Duration::from_secs(5), connect_reality_client(client_io, "example.test", &client_cfg))
            .await;
    // An explicit error, or the server's fallback relay simply never producing a ServerHello:
    // both are correct; only a successful handshake is a failure.
    if let Ok(Ok(_)) = client_result {
        panic!("client must not be authenticated when its short id is unknown to the server");
    }

    server_task.await.expect("server task should not panic");
}

/// A `ClientHello` whose `key_share` body is missing its list-length prefix
/// still round-trips through this crate's own parser, so only the wire shape itself catches it --
/// and the wire shape is exactly what a real REALITY server parses.
#[test]
fn client_hello_key_share_is_a_list() {
    use crate::handshake::ClientHello;
    use crate::suite::CipherSuite;

    let public_key = [0x5Au8; 32];
    let hello = ClientHello::build([0x11u8; 32], &[CipherSuite::Aes128GcmSha256], "example.test", public_key);

    let mut body = &hello.raw[4..];
    body = &body[2 + 32..]; // legacy_version + random
    body = &body[1 + 32..]; // session id length + session id
    let suites_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    body = &body[2 + suites_len..];
    let compression_len = body[0] as usize;
    body = &body[1 + compression_len..];
    let exts_len = u16::from_be_bytes([body[0], body[1]]) as usize;
    let mut exts = &body[2..2 + exts_len];

    let mut key_share_body = None;
    while !exts.is_empty() {
        let ext_type = u16::from_be_bytes([exts[0], exts[1]]);
        let ext_len = u16::from_be_bytes([exts[2], exts[3]]) as usize;
        if ext_type == 51 {
            key_share_body = Some(&exts[4..4 + ext_len]);
        }
        exts = &exts[4 + ext_len..];
    }
    let key_share_body = key_share_body.expect("ClientHello must offer a key_share");

    // client_shares: <2..2^16-1> then one KeyShareEntry{group, <1..2^16-1> key_exchange}.
    let list_len = u16::from_be_bytes([key_share_body[0], key_share_body[1]]) as usize;
    assert_eq!(list_len, key_share_body.len() - 2, "key_share must be a length-prefixed entry list");
    assert_eq!(u16::from_be_bytes([key_share_body[2], key_share_body[3]]), 0x001D);
    assert_eq!(u16::from_be_bytes([key_share_body[4], key_share_body[5]]) as usize, 32);
    assert_eq!(&key_share_body[6..], &public_key);
}

/// A `DialDest` that records being reached, so "relayed to dest" is observed directly instead of
/// inferred from how long the relay keeps running.
fn recording_dial_dest() -> (crate::server::DialDest, Arc<AtomicBool>) {
    let dialed = Arc::new(AtomicBool::new(false));
    let dial_dest: crate::server::DialDest = {
        let dialed = Arc::clone(&dialed);
        Arc::new(move || {
            dialed.store(true, Ordering::SeqCst);
            Box::pin(async {
                let (a, b) = tokio::io::duplex(4096);
                tokio::spawn(async move {
                    let mut a = a;
                    let mut buf = [0u8; 4096];
                    while matches!(a.read(&mut buf).await, Ok(n) if n > 0) {}
                });
                let boxed: crate::server::BoxedStream = Box::new(b);
                Ok(boxed)
            })
        })
    };
    (dial_dest, dialed)
}

/// A well-formed `ClientHello` whose only `key_share` entry is (`group`, `key_exchange`), with a
/// REALITY auth seal spliced into its `SessionId` under `auth_key`. Built by hand because
/// `ClientHello::build` always emits a genuine ephemeral X25519 share.
fn forged_client_hello(
    random: [u8; 32],
    key_share_group: u16,
    key_exchange: &[u8],
    auth_key: &[u8; 32],
    short_id: [u8; 8],
) -> ClientHello {
    let mut body = Writer::new();
    body.u16(0x0303);
    body.bytes(&random);
    body.vec_u8(&[0u8; 32]);
    let mut suites = Writer::new();
    suites.u16(CipherSuite::Aes128GcmSha256.id());
    body.vec_u16(&suites.into_bytes());
    body.vec_u8(&[0u8]);
    let mut exts = Writer::new();
    let mut sni_entry = Writer::new();
    sni_entry.u8(0); // name_type: host_name
    sni_entry.vec_u16(b"example.test");
    let mut sni_list = Writer::new();
    sni_list.vec_u16(&sni_entry.into_bytes());
    exts.u16(0);
    exts.vec_u16(&sni_list.into_bytes());
    let mut key_share = Writer::new();
    let mut entry = Writer::new();
    entry.u16(key_share_group);
    entry.vec_u16(key_exchange);
    key_share.vec_u16(&entry.into_bytes());
    exts.u16(51);
    exts.vec_u16(&key_share.into_bytes());
    body.vec_u16(&exts.into_bytes());
    let mut hello =
        ClientHello::parse(&crate::wire::handshake_message(1, &body.into_bytes())).expect("well-formed ClientHello");

    let mut plaintext = Vec::with_capacity(16);
    plaintext.extend_from_slice(&[1, 8, 2, 0]);
    plaintext.extend_from_slice(&0u32.to_be_bytes());
    plaintext.extend_from_slice(&short_id);
    let nonce: [u8; 12] = random[20..32].try_into().expect("12 bytes");
    let aad = hello.raw_with_zero_session_id();
    let sealed =
        CipherSuite::Aes256GcmSha384.seal(auth_key, &nonce, &plaintext, &aad).expect("seal the forged session id");
    hello.splice_session_id(sealed.as_slice().try_into().expect("a 32-byte session id"));
    hello
}

/// An accepted connection answers with a ServerHello before anything else; a rejected one writes
/// nothing back to the client, it only relays the bytes to `dest`. The fallback relay runs for
/// the whole life of the connection, so `dest` being dialed proves nothing on its own -- silence
/// toward the client is the discriminator.
async fn assert_client_hello_is_rejected(dialed: &AtomicBool, server_cfg: RealityServerConfig, hello: ClientHello) {
    let (mut client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server_task = tokio::spawn(async move { reality_server_accept(server_io, &server_cfg).await });

    let mut record = vec![crate::handshake::CONTENT_TYPE_HANDSHAKE, 0x03, 0x01];
    record.extend_from_slice(&(hello.raw.len() as u16).to_be_bytes());
    record.extend_from_slice(&hello.raw);
    client_io.write_all(&record).await.expect("write the forged ClientHello");

    let mut response = Vec::new();
    let mut chunk = [0u8; 64];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(200), client_io.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) => break,
            Ok(Ok(n)) => {
                response.extend_from_slice(&chunk[..n]);
                break;
            }
            Err(_) => {}
        }
    }
    assert!(response.is_empty(), "the ClientHello must not be answered with a ServerHello, got {response:?}");
    assert!(dialed.load(Ordering::SeqCst), "a rejected connection must be relayed to dest");
    server_task.abort();
}

/// A `ClientHello` whose only `key_share` entry is a non-X25519 group must be rejected before
/// authentication, never authenticated from the parser's default `[0u8; 32]` share: authentication
/// is skipped when the client offers no real peer key.
#[tokio::test]
async fn client_hello_without_an_x25519_key_share_is_never_authenticated() {
    let (server_private, _server_public) = keypair();
    let short_id = [0x5Cu8; 8];
    let mut server_names = HashSet::new();
    server_names.insert("example.test".to_owned());
    let mut short_ids = HashSet::new();
    short_ids.insert(short_id);
    let (dial_dest, dialed) = recording_dial_dest();
    let server_cfg = RealityServerConfig::new(server_private, server_names, short_ids, None, dial_dest);

    let random = [0x7Du8; 32];
    let auth_key = hkdf_sha256_reality(&[0u8; 32], &random[..20]);
    let hello = forged_client_hello(random, 0x0017, &[0x04; 65], &auth_key, short_id);
    assert!(hello.x25519_public.is_none(), "a P-256-only key share must leave the X25519 point absent");

    assert_client_hello_is_rejected(&dialed, server_cfg, hello).await;
}

/// A `ClientHello` that offers the all-zero point as its X25519 share is a non-contributory key
/// exchange: the ECDH output is the all-zero secret no matter what the server's private key is, so
/// anyone can derive `HKDF-SHA256(0^32, random[..20], "REALITY")` and seal a valid short id with
/// it. The all-zero peer point is rejected outright as a low-order point, leaving no `AuthKey` and
/// skipping the whole auth block.
#[tokio::test]
async fn client_hello_with_an_all_zero_x25519_key_share_is_never_authenticated() {
    let (server_private, _server_public) = keypair();
    let short_id = [0x3Du8; 8];
    let mut server_names = HashSet::new();
    server_names.insert("example.test".to_owned());
    let mut short_ids = HashSet::new();
    short_ids.insert(short_id);
    let (dial_dest, dialed) = recording_dial_dest();
    let server_cfg = RealityServerConfig::new(server_private, server_names, short_ids, None, dial_dest);

    let random = [0x4Eu8; 32];
    let auth_key = hkdf_sha256_reality(&[0u8; 32], &random[..20]);
    let hello = forged_client_hello(random, 0x001D, &[0u8; 32], &auth_key, short_id);
    assert_eq!(hello.x25519_public, Some([0u8; 32]), "the all-zero share must reach the server verbatim");

    assert_client_hello_is_rejected(&dialed, server_cfg, hello).await;
}
/// `max-time-difference` is a microsecond-granular config value, so a sub-second budget must
/// accept a client whose stamp is a fraction of a second off. Truncating the window to whole
/// seconds reduced every budget under one second to "the client's Unix second must equal the
/// server's".
#[test]
fn max_time_difference_is_compared_at_subsecond_precision() {
    let now = UNIX_EPOCH + Duration::from_millis(1_000_000_400);

    // 400 ms of skew, inside a 500 ms budget: accepted, where `as_secs()` truncation (budget 0)
    // would have rejected it.
    assert!(within_max_time_diff(1_000_000, now, Duration::from_micros(500_000)));
    // The same skew against a 300 ms budget is still refused.
    assert!(!within_max_time_diff(1_000_000, now, Duration::from_micros(300_000)));
    // A stamp 6.4 s behind is refused even against a 5 s budget.
    assert!(!within_max_time_diff(999_994, now, Duration::from_secs(5)));
    // A stamp ahead of the server is treated symmetrically, as the absolute difference requires.
    assert!(within_max_time_diff(1_000_001, now, Duration::from_micros(700_000)));
    assert!(!within_max_time_diff(1_000_001, now, Duration::from_micros(500_000)));
}

/// A REALITY conn splits its transport into record halves during the handshake, so nothing
/// downstream can reach the socket: `close_stream` and a relay half-close both ran the `Stream`
/// trait defaults and did nothing, leaving the peer waiting on a conn that was never closed. This
/// drives the close through a real socket pair.
#[tokio::test]
async fn close_stream_reaches_the_socket_under_a_real_reality_conn() {
    let (mut client, conn) = authenticated_pair_over_tcp().await;

    let mut reply = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut reply))
        .await
        .expect("the reply must arrive")
        .expect("read reply");
    assert_eq!(&reply, b"pong");

    close_stream(&*conn).expect("close the reality conn");
    let mut buf = [0u8; 16];
    let read = tokio::time::timeout(Duration::from_secs(5), client.read(&mut buf)).await;
    assert!(read.is_ok(), "the close must reach the peer instead of leaving its read pending");
}

/// A write half-close closes the whole connection: a real half-close leaked, so the caller closes
/// outright. A read half-close would instead leave the server's read side open, letting
/// the client keep delivering bytes the server can no longer hand anywhere.
#[tokio::test]
async fn shutdown_write_closes_the_read_side_too() {
    let (mut client, mut conn) = authenticated_pair_over_tcp().await;

    conn.shutdown_write().expect("CloseWrite");
    let _ = client.write_all(b"after").await;

    let mut buf = [0u8; 8];
    let read = tokio::time::timeout(Duration::from_secs(5), conn.read(&mut buf))
        .await
        .expect("the closed read side must not hang");
    assert!(matches!(read, Ok(0) | Err(_)), "the read side must be closed as well, got {read:?}");
}

/// Brings up a REALITY client/server pair over a real TCP connection and hands back the client
/// stream plus the server conn wrapped the way the listener wraps it.
async fn authenticated_pair_over_tcp() -> (crate::stream::RealityStream<tokio::net::TcpStream>, Box<dyn Stream>) {
    let (server_private, server_public) = keypair();
    let short_id = [0x23u8; 8];
    let mut server_names = HashSet::new();
    server_names.insert("example.test".to_owned());
    let mut short_ids = HashSet::new();
    short_ids.insert(short_id);
    let server_cfg = RealityServerConfig::new(
        server_private,
        server_names,
        short_ids,
        Some(Duration::from_secs(300)),
        no_dest_dial(),
    );
    let client_cfg = RealityClientConfig { public_key: server_public, short_id };

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (conn_tx, conn_rx) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(async move {
        let (accepted, _) = listener.accept().await.expect("accept");
        let closer = RealityCloser::capture(&accepted);
        let local = accepted.local_addr().expect("local addr");
        let peer = accepted.peer_addr().expect("peer addr");
        let stream = reality_server_accept(accepted, &server_cfg).await.expect("authenticate the client");
        let mut addrs = stream.with_addrs(local, peer);
        if let Some(closer) = closer {
            addrs = addrs.with_closer(closer);
        }
        let mut conn: Box<dyn Stream> = Box::new(addrs);
        let mut buf = [0u8; 4];
        conn.read_exact(&mut buf).await.expect("read ping");
        conn.write_all(b"pong").await.expect("write pong");
        if conn_tx.send(conn).is_err() {
            panic!("hand the conn to the test");
        }
        // The conn now lives in the test; keep the task alive so the client socket is not
        // dropped from under the assertion.
        std::future::pending::<()>().await;
    });

    let client_tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let mut client = connect_reality_client(client_tcp, "example.test", &client_cfg).await.expect("client handshake");
    client.write_all(b"ping").await.expect("write ping");
    let conn = tokio::time::timeout(Duration::from_secs(5), conn_rx)
        .await
        .expect("the server must hand its conn over")
        .expect("the server task must not drop the conn");
    server_task.abort();
    (client, conn)
}

/// A REALITY server pads every handshake record with zeroes so the record's length matches the
/// one its `dest` sent, which leaves the real content type ahead of the padding rather than at the
/// end of the decrypted payload. The message itself ends in a zero byte, so only the padding rule
/// tells the two apart.
#[tokio::test]
async fn a_padded_handshake_record_still_yields_its_message() {
    let suite = CipherSuite::Aes128GcmSha256;
    let key = [0x17u8; 16];
    let iv = [0x29u8; 12];
    let message = crate::handshake::build_finished(b"verify\0dat\0");

    let mut plaintext = message.clone();
    plaintext.push(crate::handshake::CONTENT_TYPE_HANDSHAKE);
    plaintext.extend_from_slice(&[0u8; 48]);
    let mut header = [0u8; 5];
    header[0] = crate::handshake::CONTENT_TYPE_APPLICATION_DATA;
    header[1..3].copy_from_slice(&0x0303u16.to_be_bytes());
    header[3..5].copy_from_slice(&((plaintext.len() + 16) as u16).to_be_bytes());
    let ciphertext =
        suite.seal(&key, &crate::suite::record_nonce(&iv, 0), &plaintext, &header).expect("seal the padded record");

    let (client, mut server) = tokio::io::duplex(1024);
    let mut layer = RecordLayer::new(client);
    layer.set_read_keys(suite, key.to_vec(), iv);
    server.write_all(&header).await.expect("write the record header");
    server.write_all(&ciphertext).await.expect("write the record payload");

    assert_eq!(layer.read_handshake_message().await.expect("read the padded record"), message);
}

/// The throttle starts full, so the burst allowance costs nothing and only the bytes past it are
/// held back.
#[test]
fn the_fallback_bucket_is_full_on_creation() {
    let limit = FallbackLimit { after_bytes: 0, bytes_per_sec: 100, burst_bytes_per_sec: 150 };
    let mut bucket = TokenBucket::new(limit);
    assert!(bucket.charge(150).is_none(), "the burst allowance must not be delayed");
    let delay = bucket.charge(100).expect("bytes past the burst must be metered");
    assert!(delay >= Duration::from_millis(500), "100 bytes at 100 B/s is a second, got {delay:?}");
}

/// `after-bytes` is the free allowance before the bucket starts charging the relay.
#[tokio::test]
async fn the_fallback_free_allowance_is_not_metered() {
    let (source, mut sink) = tokio::io::duplex(64);
    tokio::spawn(async move {
        let _ = sink.write_all(b"0123456789").await;
        let _ = sink.shutdown().await;
    });
    let limit = FallbackLimit { after_bytes: 4, bytes_per_sec: 1, burst_bytes_per_sec: 1 };
    let mut throttled = FallbackThrottle::new(source, limit);
    let mut buf = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), throttled.read_exact(&mut buf))
        .await
        .expect("the free allowance must not be delayed")
        .expect("read the free allowance");
    assert_eq!(&buf, b"0123");
}

/// The record framing a REALITY server puts on the wire: a plaintext `ServerHello`, a dummy
/// plaintext `ChangeCipherSpec`, then the server flight under the handshake keys -- one record when
/// `dest` sent one, one per message when it sent several -- each zero-padded to the length `dest`'s
/// own record had, which the reader unwinds by scanning back for the content type.
async fn reality_shaped_stream(
    mut io: tokio::io::DuplexStream,
    private_key: [u8; 32],
    short_id: [u8; 8],
    split_flight: bool,
) {
    let (header, payload) = read_record(&mut io).await;
    assert_eq!(header[0], crate::handshake::CONTENT_TYPE_HANDSHAKE);
    let client_hello = ClientHello::parse(&payload).expect("the client sends one ClientHello record");
    let client_public = client_hello.x25519_public.expect("the client offers an X25519 key share");

    let shared =
        x25519_dalek::StaticSecret::from(private_key).diffie_hellman(&x25519_dalek::PublicKey::from(client_public));
    let auth_key = hkdf_sha256_reality(shared.as_bytes(), &client_hello.random[..20]);
    let nonce: [u8; 12] = client_hello.random[20..32].try_into().expect("checked length");
    let sealed = CipherSuite::Aes256GcmSha384
        .open(&auth_key, &nonce, &client_hello.session_id, &client_hello.raw_with_zero_session_id())
        .expect("the session id seals under the auth key");
    assert_eq!(sealed[8..16], short_id.to_vec());

    let suite = CipherSuite::Aes128GcmSha256;
    let (server_private, server_public) = keypair();
    let mut server_random = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rng(), &mut server_random);
    let server_hello =
        crate::handshake::ServerHello::build(server_random, &client_hello.session_id, suite, server_public);
    write_plain_record(&mut io, crate::handshake::CONTENT_TYPE_HANDSHAKE, &server_hello.raw).await;
    write_plain_record(&mut io, crate::handshake::CONTENT_TYPE_CHANGE_CIPHER_SPEC, &[1]).await;

    let tls_shared = x25519_dalek::x25519(server_private, client_public);
    let mut transcript = suite.transcript();
    transcript.update(&client_hello.raw);
    transcript.update(&server_hello.raw);
    let schedule = crate::suite::KeySchedule::new(suite, &tls_shared, &transcript.digest());

    let leaf_key = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
    let leaf_public = leaf_key.verifying_key().to_bytes();
    let signature = crate::cert::hmac_signature(&auth_key, &leaf_public);
    let certificate = crate::handshake::build_certificate(&crate::cert::build_fake_leaf(&leaf_public, &signature));

    let encrypted_extensions = crate::handshake::build_encrypted_extensions();
    transcript.update(&encrypted_extensions);
    transcript.update(&certificate);
    let certificate_verify = crate::handshake::build_certificate_verify(&leaf_key, &transcript.digest());
    transcript.update(&certificate_verify);
    let finished_data = schedule.finished_verify_data(&schedule.server_handshake_secret, &transcript.digest());
    let finished = crate::handshake::build_finished(&finished_data);
    transcript.update(&finished);
    let ch_sf_digest = transcript.digest();

    let flight = [encrypted_extensions, certificate, certificate_verify, finished];
    let (handshake_key, handshake_iv) = schedule.traffic_key_iv(&schedule.server_handshake_secret);
    if split_flight {
        for (seq, message) in flight.iter().enumerate() {
            let mut inner = message.clone();
            inner.push(crate::handshake::CONTENT_TYPE_HANDSHAKE);
            inner.resize(inner.len() + 9 + seq * 47, 0);
            write_encrypted_record(&mut io, suite, &handshake_key, &handshake_iv, seq as u64, &inner).await;
        }
    } else {
        let mut inner = flight.concat();
        inner.push(crate::handshake::CONTENT_TYPE_HANDSHAKE);
        inner.resize(1200, 0);
        write_encrypted_record(&mut io, suite, &handshake_key, &handshake_iv, 0, &inner).await;
    }
    io.flush().await.expect("flush the flight");

    let (client_key, client_iv) = schedule.traffic_key_iv(&schedule.client_handshake_secret);
    let (header, ciphertext) = read_record(&mut io).await;
    assert_eq!(header[0], crate::handshake::CONTENT_TYPE_APPLICATION_DATA);
    let plaintext = open_record(header, &ciphertext, suite, &client_key, &client_iv, 0);
    let (content_type, client_finished) = split_inner_plaintext(&plaintext);
    assert_eq!(content_type, crate::handshake::CONTENT_TYPE_HANDSHAKE);
    assert_eq!(
        crate::handshake::parse_finished(&client_finished).expect("a Finished"),
        schedule.finished_verify_data(&schedule.client_handshake_secret, &ch_sf_digest)
    );

    let (client_ap_secret, server_ap_secret) = schedule.application_secrets(&ch_sf_digest);
    let (client_ap_key, client_ap_iv) = schedule.traffic_key_iv(&client_ap_secret);
    let (server_ap_key, server_ap_iv) = schedule.traffic_key_iv(&server_ap_secret);
    let (header, ciphertext) = read_record(&mut io).await;
    let plaintext = open_record(header, &ciphertext, suite, &client_ap_key, &client_ap_iv, 0);
    let (content_type, echoed) = split_inner_plaintext(&plaintext);
    assert_eq!(content_type, crate::handshake::CONTENT_TYPE_APPLICATION_DATA);
    let mut inner = echoed;
    inner.push(crate::handshake::CONTENT_TYPE_APPLICATION_DATA);
    write_encrypted_record(&mut io, suite, &server_ap_key, &server_ap_iv, 0, &inner).await;
    io.flush().await.expect("flush the echo");
}

async fn read_record<R: tokio::io::AsyncRead + Unpin>(io: &mut R) -> ([u8; 5], Vec<u8>) {
    let mut header = [0u8; 5];
    io.read_exact(&mut header).await.expect("read a record header");
    let mut payload = vec![0u8; u16::from_be_bytes([header[3], header[4]]) as usize];
    io.read_exact(&mut payload).await.expect("read a record payload");
    (header, payload)
}

async fn write_plain_record<W: tokio::io::AsyncWrite + Unpin>(io: &mut W, content_type: u8, payload: &[u8]) {
    let mut header = [0u8; 5];
    header[0] = content_type;
    header[1..3].copy_from_slice(&0x0303u16.to_be_bytes());
    header[3..5]
        .copy_from_slice(&u16::try_from(payload.len()).expect("a plaintext record fits a u16 length").to_be_bytes());
    io.write_all(&header).await.expect("write a record header");
    io.write_all(payload).await.expect("write a record payload");
}

/// The five-byte header an encrypted record carries: the AEAD seals over it, so its length field
/// covers the plaintext, the content type byte and the tag.
fn encrypted_record_header(plaintext_len: usize) -> [u8; 5] {
    let mut header = [0u8; 5];
    header[0] = crate::handshake::CONTENT_TYPE_APPLICATION_DATA;
    header[1..3].copy_from_slice(&0x0303u16.to_be_bytes());
    let len = u16::try_from(plaintext_len + 16).expect("a plaintext record fits a u16 length");
    header[3..5].copy_from_slice(&len.to_be_bytes());
    header
}

async fn write_encrypted_record<W: tokio::io::AsyncWrite + Unpin>(
    io: &mut W,
    suite: CipherSuite,
    key: &[u8],
    iv: &[u8; 12],
    seq: u64,
    inner: &[u8],
) {
    let header = encrypted_record_header(inner.len());
    let ciphertext = suite.seal(key, &crate::suite::record_nonce(iv, seq), inner, &header).expect("seal");
    io.write_all(&header).await.expect("write a record header");
    io.write_all(&ciphertext).await.expect("write a record payload");
}

fn open_record(header: [u8; 5], ciphertext: &[u8], suite: CipherSuite, key: &[u8], iv: &[u8; 12], seq: u64) -> Vec<u8> {
    suite.open(key, &crate::suite::record_nonce(iv, seq), ciphertext, &header).expect("open a record")
}

/// RFC 8446 Section 5.2: the content type is the last non-zero octet, because a REALITY server
/// pads the record after it.
fn split_inner_plaintext(plaintext: &[u8]) -> (u8, Vec<u8>) {
    let at = plaintext.iter().rposition(|byte| *byte != 0).expect("a content type byte");
    (plaintext[at], plaintext[..at].to_vec())
}

/// A real REALITY server, not this crate's own, decides the record framing the client has to read:
/// the whole flight may arrive as one padded record or as four, and the client has to reassemble
/// every handshake message out of the padding as well. Reading the content type from the last byte
/// instead of the last non-zero one is what left a server failing with `unexpected record content
/// type 0` after authenticating.
#[tokio::test]
async fn a_reality_shaped_record_stream_is_read_by_the_client() {
    for split_flight in [false, true] {
        let (server_private, server_public) = keypair();
        let short_id = [0x42u8; 8];
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server =
            tokio::spawn(async move { reality_shaped_stream(server_io, server_private, short_id, split_flight).await });
        let client_cfg = RealityClientConfig { public_key: server_public, short_id };

        let mut client = tokio::time::timeout(
            Duration::from_secs(5),
            connect_reality_client(client_io, "example.test", &client_cfg),
        )
        .await
        .expect("the client must not hang on a REALITY-shaped stream")
        .unwrap_or_else(|err| panic!("split_flight={split_flight}: {err:#}"));

        client.write_all(b"hello").await.expect("write through the tunnel");
        let mut echoed = [0u8; 5];
        client.read_exact(&mut echoed).await.expect("read through the tunnel");
        assert_eq!(&echoed, b"hello", "split_flight={split_flight}");
        server.await.expect("the REALITY-shaped server must not panic");
    }
}

/// A record that decrypts to nothing but its content type is legal on the wire, and it is
/// skipped rather than reported as the end of the stream. Returning a zero-byte read here would
/// hand every reader a premature EOF and close a tunnel that is still live.
#[tokio::test]
async fn empty_records_are_skipped_instead_of_ending_the_stream() {
    let suite = CipherSuite::Aes128GcmSha256;
    let key = [0x5au8; 16];
    let iv = [0x27u8; 12];
    let (local, mut peer) = tokio::io::duplex(4096);
    let mut layer = RecordLayer::new(local);
    layer.set_read_keys(suite, key.to_vec(), iv);
    let mut stream = crate::stream::RealityStream::new(layer);

    let empty = [crate::handshake::CONTENT_TYPE_APPLICATION_DATA];
    for seq in 0..3u64 {
        write_encrypted_record(&mut peer, suite, &key, &iv, seq, &empty).await;
    }
    let mut payload = b"tunneled".to_vec();
    payload.push(crate::handshake::CONTENT_TYPE_APPLICATION_DATA);
    write_encrypted_record(&mut peer, suite, &key, &iv, 3, &payload).await;

    let mut buf = [0u8; 8];
    stream.read_exact(&mut buf).await.expect("read past the empty records");
    assert_eq!(&buf, b"tunneled");

    for seq in 4..=36u64 {
        write_encrypted_record(&mut peer, suite, &key, &iv, seq, &empty).await;
    }
    let mut buf = [0u8; 1];
    let err = stream.read(&mut buf).await.expect_err("a run of empty records cannot hold the stream open");
    assert!(err.to_string().contains("too many empty records"), "unexpected error: {err}");
}
