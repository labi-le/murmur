#[cfg(feature = "extra-protocols")]
use base64::engine::general_purpose::STANDARD;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

use murmur_component_ech as ech;
#[cfg(feature = "extra-protocols")]
use murmur_transport_sudoku::init::gen_key_pair;
use murmur_transport_vless::encryption::key::{gen_mlkem768, gen_x25519};

use super::x25519::gen_x25519_private_key;

#[expect(clippy::panic, reason = "a CLI entry point has no caller to report a usage or I/O failure to")]
#[expect(clippy::print_stdout, reason = "CLI output on the process stdout, not a log line")]
pub fn main(args: &[String]) {
    let Some(command) = args.first() else {
        let commands = if cfg!(feature = "extra-protocols") {
            "uuid/reality-keypair/wg-keypair/ech-keypair/vless-mlkem768/vless-x25519/sudoku-keypair"
        } else {
            "uuid/reality-keypair/ech-keypair/vless-mlkem768/vless-x25519"
        };
        panic!("Using: generate {commands}");
    };
    match command.as_str() {
        "uuid" => {
            let new_uuid = uuid::Uuid::new_v4();
            println!("{new_uuid}");
        }
        "reality-keypair" => {
            let private_key = gen_x25519_private_key().unwrap_or_else(|err| panic!("{err}"));
            println!("PrivateKey: {}", URL_SAFE_NO_PAD.encode(private_key.bytes()));
            println!("PublicKey: {}", URL_SAFE_NO_PAD.encode(private_key.public_key().bytes()));
        }
        #[cfg(feature = "extra-protocols")]
        "wg-keypair" => {
            let private_key = gen_x25519_private_key().unwrap_or_else(|err| panic!("{err}"));
            println!("PrivateKey: {}", STANDARD.encode(private_key.bytes()));
            println!("PublicKey: {}", STANDARD.encode(private_key.public_key().bytes()));
        }
        "ech-keypair" => {
            let Some(server_name) = args.get(1) else {
                panic!("Using: generate ech-keypair <plain_server_name>");
            };
            let (config_base64, key_pem) = ech::gen_ech_config(server_name).unwrap_or_else(|err| panic!("{err}"));
            println!("Config: {config_base64}");
            println!("Key: {key_pem}");
        }
        "vless-mlkem768" => {
            let seed = args.get(1).cloned().unwrap_or_default();
            let (seed_base64, client_base64, hash32_base64) = gen_mlkem768(&seed).unwrap_or_else(|err| panic!("{err}"));
            println!("Seed: {seed_base64}");
            println!("Client: {client_base64}");
            println!("Hash32: {hash32_base64}");
            println!("-----------------------");
            println!("      Lazy-Config      ");
            println!("-----------------------");
            println!("[Server] decryption: \"mlkem768x25519plus.native.600s.{seed_base64}\"");
            println!("[Client] encryption: \"mlkem768x25519plus.native.0rtt.{client_base64}\"");
        }
        "vless-x25519" => {
            let private_key = args.get(1).cloned().unwrap_or_default();
            let (private_key_base64, password_base64, hash32_base64) =
                gen_x25519(&private_key).unwrap_or_else(|err| panic!("{err}"));
            println!("PrivateKey: {private_key_base64}");
            println!("Password: {password_base64}");
            println!("Hash32: {hash32_base64}");
            println!("-----------------------");
            println!("      Lazy-Config      ");
            println!("-----------------------");
            println!("[Server] decryption: \"mlkem768x25519plus.native.600s.{private_key_base64}\"");
            println!("[Client] encryption: \"mlkem768x25519plus.native.0rtt.{password_base64}\"");
        }
        #[cfg(feature = "extra-protocols")]
        "sudoku-keypair" => {
            let (private_key, public_key) = gen_key_pair().unwrap_or_else(|err| panic!("{err}"));
            println!("PrivateKey: {private_key}");
            println!("PublicKey: {public_key}");
        }
        #[cfg(not(feature = "extra-protocols"))]
        "sudoku-keypair" | "wg-keypair" => panic!("{command} requires feature extra-protocols"),
        _ => panic!("unsupported generator command: {command}"),
    }
}

#[cfg(test)]
mod tests {
    use super::main;

    #[cfg(not(feature = "extra-protocols"))]
    #[test]
    #[should_panic(expected = "sudoku-keypair requires feature extra-protocols")]
    fn removed_sudoku_generator_fails_explicitly() {
        main(&["sudoku-keypair".to_owned()]);
    }

    #[cfg(not(feature = "extra-protocols"))]
    #[test]
    #[should_panic(expected = "wg-keypair requires feature extra-protocols")]
    fn removed_wireguard_generator_fails_explicitly() {
        main(&["wg-keypair".to_owned()]);
    }

    #[test]
    #[should_panic(expected = "unsupported generator command")]
    fn unknown_generator_fails_explicitly() {
        main(&["unknown".to_owned()]);
    }

    #[test]
    fn retained_generators_remain_available() {
        for command in ["uuid", "reality-keypair", "vless-x25519"] {
            main(&[command.to_owned()]);
        }
    }
}
