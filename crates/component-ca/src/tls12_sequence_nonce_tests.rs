//! Lives here rather than beside the TLS code it exercises: this crate already depends on
//! `murmur-component-tls`, so the integration test that drives a real handshake through
//! [`murmur_component_tls::utls::build_provider`] sits here instead of the TLS crate taking a
//! dev-only dependency back on this crate for certificate generation.

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::sync::Arc;

    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
    use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection};

    use crate::keypair::{new_random_tls_key_pair, x509_key_pair, KeyPairType};
    use murmur_component_tls::utls;

    const TARGET_SUITE: rustls::CipherSuite = rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;

    #[derive(Debug)]
    struct NoVerify;

    impl ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms.supported_schemes()
        }
    }

    fn test_cert() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let (cert_pem, key_pem, _fingerprint) =
            new_random_tls_key_pair(KeyPairType::P256).expect("generate test key pair");
        let cert = x509_key_pair(cert_pem.as_bytes(), key_pem.as_bytes()).expect("parse test key pair");
        let leaf = CertificateDer::from(cert.certificate[0].clone());
        (leaf, cert.private_key.expect("test key pair has a private key"))
    }

    /// Routes the parity case through `component::tls::utls::build_provider`, the crate's one
    /// production entry point for this substitution, so a regression there (not just in `apply`
    /// itself) fails this module's tests.
    fn provider_for(sequence_nonce: bool) -> rustls::crypto::CryptoProvider {
        let mut provider = if sequence_nonce {
            (*utls::build_provider(&utls::Config::default())).clone()
        } else {
            rustls::crypto::aws_lc_rs::default_provider()
        };
        provider.cipher_suites.retain(|suite| suite.suite() == TARGET_SUITE);
        provider
    }

    fn client_config(sequence_nonce: bool) -> ClientConfig {
        ClientConfig::builder_with_provider(Arc::new(provider_for(sequence_nonce)))
            .with_protocol_versions(&[&rustls::version::TLS12])
            .expect("restrict to TLS 1.2")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth()
    }

    fn server_config(sequence_nonce: bool, cert: CertificateDer<'static>, key: PrivateKeyDer<'static>) -> ServerConfig {
        ServerConfig::builder_with_provider(Arc::new(provider_for(sequence_nonce)))
            .with_protocol_versions(&[&rustls::version::TLS12])
            .expect("restrict to TLS 1.2")
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .expect("build test tls12 server config")
    }

    fn parse_records(mut data: &[u8]) -> Vec<(u8, Vec<u8>)> {
        let mut records = Vec::new();
        while data.len() >= 5 {
            let typ = data[0];
            let len = u16::from_be_bytes([data[3], data[4]]) as usize;
            if data.len() < 5 + len {
                break;
            }
            records.push((typ, data[5..5 + len].to_vec()));
            data = &data[5 + len..];
        }
        records
    }

    const CONTENT_TYPE_CHANGE_CIPHER_SPEC: u8 = 20;
    const CONTENT_TYPE_APPLICATION_DATA: u8 = 23;

    /// Drives the handshake to completion, feeding each side's output to the other, and returns
    /// every raw TLS record the client emitted along the way (handshake bytes only).
    fn drive_handshake(client: &mut ClientConnection, server: &mut ServerConnection) -> Vec<u8> {
        let mut client_wire = Vec::new();
        for _ in 0..8 {
            let mut client_out = Vec::new();
            while client.wants_write() {
                client.write_tls(&mut client_out).expect("client write_tls");
            }
            client_wire.extend_from_slice(&client_out);
            if !client_out.is_empty() {
                let mut cursor = Cursor::new(&client_out);
                while (cursor.position() as usize) < client_out.len() {
                    server.read_tls(&mut cursor).expect("server read_tls");
                }
                server.process_new_packets().expect("server process_new_packets");
            }

            let mut server_out = Vec::new();
            while server.wants_write() {
                server.write_tls(&mut server_out).expect("server write_tls");
            }
            if !server_out.is_empty() {
                let mut cursor = Cursor::new(&server_out);
                while (cursor.position() as usize) < server_out.len() {
                    client.read_tls(&mut cursor).expect("client read_tls");
                }
                client.process_new_packets().expect("client process_new_packets");
            }

            if !client.is_handshaking() && !server.is_handshaking() && client_out.is_empty() && server_out.is_empty() {
                return client_wire;
            }
        }
        panic!("tls 1.2 handshake did not converge");
    }

    fn client_send(client: &mut ClientConnection, server: &mut ServerConnection, payload: &[u8]) -> Vec<u8> {
        use std::io::Write as _;
        client.writer().write_all(payload).expect("buffer plaintext");
        let mut wire = Vec::new();
        while client.wants_write() {
            client.write_tls(&mut wire).expect("client write_tls");
        }
        let mut cursor = Cursor::new(&wire);
        while (cursor.position() as usize) < wire.len() {
            server.read_tls(&mut cursor).expect("server read_tls");
        }
        server.process_new_packets().expect("server process_new_packets");
        wire
    }

    /// The first encrypted record the client sends is its `Finished` message, immediately after
    /// its `ChangeCipherSpec`; the zero-based sequence-number nonce means that record's explicit
    /// nonce is `0x00*8`, and the client's first post-handshake application-data record (sequence
    /// number 1) is `0x00..01`. Both peers use the sequence-nonce provider here.
    #[test]
    fn sequence_nonce_client_finished_and_first_app_record_use_sequence_number_nonces() {
        let (cert, key) = test_cert();
        let mut client =
            ClientConnection::new(Arc::new(client_config(true)), ServerName::try_from("localhost").unwrap())
                .expect("build client connection");
        let mut server = ServerConnection::new(Arc::new(server_config(true, cert, key))).expect("build server");

        let handshake_wire = drive_handshake(&mut client, &mut server);
        let records = parse_records(&handshake_wire);
        let ccs_index =
            records.iter().position(|(typ, _)| *typ == CONTENT_TYPE_CHANGE_CIPHER_SPEC).expect("client sent a CCS");
        let finished = &records.get(ccs_index + 1).expect("a record follows the client's CCS").1;
        assert!(finished.len() >= 8, "encrypted Finished record too short: {} bytes", finished.len());
        assert_eq!(&finished[..8], &[0u8; 8], "client Finished record must carry explicit nonce 0x00*8");

        let app_wire = client_send(&mut client, &mut server, b"ping");
        let app_records = parse_records(&app_wire);
        let (typ, app_payload) = app_records.into_iter().next().expect("client emitted an application-data record");
        assert_eq!(typ, CONTENT_TYPE_APPLICATION_DATA);
        assert_eq!(&app_payload[..8], &[0, 0, 0, 0, 0, 0, 0, 1], "second client record must carry nonce 0x00..01");

        let mut plain = [0u8; 4];
        std::io::Read::read_exact(&mut server.reader(), &mut plain).expect("server decrypts client's ping");
        assert_eq!(&plain, b"ping");
    }

    /// The sequence-nonce provider changes only how *this* side derives its own explicit nonce;
    /// the AEAD decrypter reads whatever explicit nonce bytes are on the wire, so such a peer
    /// still interoperates fully with a stock-rustls peer's randomized nonce baseline.
    #[test]
    fn sequence_nonce_client_interoperates_with_stock_rustls_server() {
        use std::io::{Read as _, Write as _};

        let (cert, key) = test_cert();
        let mut client =
            ClientConnection::new(Arc::new(client_config(true)), ServerName::try_from("localhost").unwrap())
                .expect("build client connection");
        let mut server = ServerConnection::new(Arc::new(server_config(false, cert, key))).expect("build server");

        drive_handshake(&mut client, &mut server);
        assert!(!client.is_handshaking());
        assert!(!server.is_handshaking());

        client.writer().write_all(b"hello from parity client").expect("buffer plaintext");
        let mut wire = Vec::new();
        while client.wants_write() {
            client.write_tls(&mut wire).expect("client write_tls");
        }
        let mut cursor = Cursor::new(&wire);
        while (cursor.position() as usize) < wire.len() {
            server.read_tls(&mut cursor).expect("server read_tls");
        }
        server.process_new_packets().expect("server process_new_packets");
        let mut received = [0u8; 24];
        server.reader().read_exact(&mut received).expect("stock server decrypts parity client's record");
        assert_eq!(&received, b"hello from parity client");

        server.writer().write_all(b"hello back from stock server").expect("buffer plaintext");
        let mut wire = Vec::new();
        while server.wants_write() {
            server.write_tls(&mut wire).expect("server write_tls");
        }
        let mut cursor = Cursor::new(&wire);
        while (cursor.position() as usize) < wire.len() {
            client.read_tls(&mut cursor).expect("client read_tls");
        }
        client.process_new_packets().expect("client process_new_packets");
        let mut received = [0u8; 28];
        client.reader().read_exact(&mut received).expect("parity client decrypts stock server's record");
        assert_eq!(&received, b"hello back from stock server");
    }
}
