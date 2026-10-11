use std::collections::HashMap;

use serde::Deserialize;
use serde_json::{json, Map, Value};

use murmur_log::warnln;

use super::base64::{
    decode, decode_base64, decode_url_safe, try_decode_base64, try_decode_base64_bytes, url_safe, ENC, ENC_RAW,
    ENC_RAW_URL,
};
use super::util::{cut, rand_user_agent, verify_method};
use super::v::{handle_v_share_link, parse_query, PathUrl, Url};

pub(crate) fn parse_bool(s: &str) -> Option<bool> {
    match s {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

/// Converts `V2Ray` subscribe proxies data to murmur proxies config.
pub fn converts_v2ray(buf: &[u8]) -> anyhow::Result<Vec<Map<String, Value>>> {
    let data = decode_base64(buf);

    let raw_lines: Vec<&[u8]> = data.split(|b| *b == b'\n').collect();

    let mut proxies: Vec<Map<String, Value>> = Vec::with_capacity(raw_lines.len());
    let mut names: HashMap<String, i32> = HashMap::with_capacity(200);

    for raw in raw_lines {
        let line = String::from_utf8_lossy(raw).trim_end_matches([' ', '\r']).to_owned();
        if line.is_empty() {
            continue;
        }

        let Some((scheme, body)) = line.split_once("://") else {
            continue;
        };

        let scheme = scheme.to_lowercase();
        match scheme.as_str() {
            "hysteria" => convert_hysteria(&mut names, &line, &scheme, &mut proxies),
            "tuic" => convert_tuic(&mut names, &line, &scheme, &mut proxies),
            "trojan" => convert_trojan(&mut names, &line, &scheme, &mut proxies),
            "vless" => convert_vless(&mut names, &line, &scheme, &mut proxies),
            "vmess" => convert_vmess(&mut names, &line, &scheme, body, &mut proxies),
            "ss" => convert_ss(&mut names, &line, &scheme, &mut proxies),
            "ssr" => convert_ssr(&mut names, &scheme, body, &mut proxies),
            "socks" | "socks5" | "socks5h" | "http" | "https" => {
                convert_socks(&mut names, &line, &scheme, &mut proxies);
            }
            "anytls" => convert_anytls(&mut names, &line, &mut proxies),
            _ => {}
        }
    }

    if proxies.is_empty() {
        return Err(anyhow::anyhow!("convert v2ray subscribe error: format invalid"));
    }

    Ok(proxies)
}

fn convert_hysteria(names: &mut HashMap<String, i32>, line: &str, scheme: &str, proxies: &mut Vec<Map<String, Value>>) {
    let Some(url_hysteria) = Url::parse(line) else {
        return;
    };

    let query = url_hysteria.query();
    let name = unique_name(names, &url_hysteria.fragment());
    let mut hysteria = Map::new();

    hysteria.insert("name".to_owned(), json!(name));
    hysteria.insert("type".to_owned(), json!(scheme));
    hysteria.insert("server".to_owned(), json!(url_hysteria.hostname()));
    hysteria.insert("port".to_owned(), json!(url_hysteria.port()));
    hysteria.insert("sni".to_owned(), json!(query.get("peer")));
    hysteria.insert("obfs".to_owned(), json!(query.get("obfs")));
    let alpn = query.get("alpn");
    if !alpn.is_empty() {
        hysteria.insert("alpn".to_owned(), json!(alpn.split(',').collect::<Vec<&str>>()));
    }
    hysteria.insert("auth_str".to_owned(), json!(query.get("auth")));
    hysteria.insert("protocol".to_owned(), json!(query.get("protocol")));
    let mut up = query.get("up");
    let mut down = query.get("down");
    if up.is_empty() {
        up = query.get("upmbps");
    }
    if down.is_empty() {
        down = query.get("downmbps");
    }
    hysteria.insert("down".to_owned(), json!(down));
    hysteria.insert("up".to_owned(), json!(up));
    hysteria.insert("skip-cert-verify".to_owned(), json!(parse_bool(&query.get("insecure")).unwrap_or(false)));

    proxies.push(hysteria);
}

fn convert_tuic(names: &mut HashMap<String, i32>, line: &str, scheme: &str, proxies: &mut Vec<Map<String, Value>>) {
    // A temporary unofficial TUIC share link standard:
    //   1. Support TUICv4, just replace uuid:password with token
    //   2. Remove `allow_insecure` field
    let Some(url_tuic) = Url::parse(line) else {
        return;
    };
    let query = url_tuic.query();

    let mut tuic = Map::new();
    tuic.insert("name".to_owned(), json!(unique_name(names, &url_tuic.fragment())));
    tuic.insert("type".to_owned(), json!(scheme));
    tuic.insert("server".to_owned(), json!(url_tuic.hostname()));
    tuic.insert("port".to_owned(), json!(url_tuic.port()));
    tuic.insert("udp".to_owned(), json!(true));
    match url_tuic.user_password() {
        Some(password) => {
            tuic.insert("uuid".to_owned(), json!(url_tuic.user_username()));
            tuic.insert("password".to_owned(), json!(password));
        }
        None => {
            tuic.insert("token".to_owned(), json!(url_tuic.user_username()));
        }
    }
    let cc = query.get("congestion_control");
    if !cc.is_empty() {
        tuic.insert("congestion-controller".to_owned(), json!(cc));
    }
    let alpn = query.get("alpn");
    if !alpn.is_empty() {
        tuic.insert("alpn".to_owned(), json!(alpn.split(',').collect::<Vec<&str>>()));
    }
    let sni = query.get("sni");
    if !sni.is_empty() {
        tuic.insert("sni".to_owned(), json!(sni));
    }
    if query.get("disable_sni") == "1" {
        tuic.insert("disable-sni".to_owned(), json!(true));
    }
    let udp_relay_mode = query.get("udp_relay_mode");
    if !udp_relay_mode.is_empty() {
        tuic.insert("udp-relay-mode".to_owned(), json!(udp_relay_mode));
    }

    proxies.push(tuic);
}

fn convert_trojan(names: &mut HashMap<String, i32>, line: &str, scheme: &str, proxies: &mut Vec<Map<String, Value>>) {
    let Some(url_trojan) = Url::parse(line) else {
        return;
    };

    let query = url_trojan.query();

    let name = unique_name(names, &url_trojan.fragment());
    let mut trojan = Map::new();

    trojan.insert("name".to_owned(), json!(name));
    trojan.insert("type".to_owned(), json!(scheme));
    trojan.insert("server".to_owned(), json!(url_trojan.hostname()));
    trojan.insert("port".to_owned(), json!(url_trojan.port()));
    trojan.insert("password".to_owned(), json!(url_trojan.user_username()));
    trojan.insert("udp".to_owned(), json!(true));
    trojan.insert("skip-cert-verify".to_owned(), json!(parse_bool(&query.get("allowInsecure")).unwrap_or(false)));

    let sni = query.get("sni");
    if !sni.is_empty() {
        trojan.insert("sni".to_owned(), json!(sni));
    }
    let alpn = query.get("alpn");
    if !alpn.is_empty() {
        trojan.insert("alpn".to_owned(), json!(alpn.split(',').collect::<Vec<&str>>()));
    }

    let network = query.get("type").to_lowercase();
    if !network.is_empty() {
        trojan.insert("network".to_owned(), json!(network.as_str()));
    }

    match network.as_str() {
        "ws" => {
            let mut headers = Map::new();
            let mut ws_opts = Map::new();

            headers.insert("User-Agent".to_owned(), json!(rand_user_agent()));

            ws_opts.insert("path".to_owned(), json!(query.get("path")));
            ws_opts.insert("headers".to_owned(), Value::Object(headers));

            trojan.insert("ws-opts".to_owned(), Value::Object(ws_opts));
        }

        "grpc" => {
            let mut grpc_opts = Map::new();
            grpc_opts.insert("grpc-service-name".to_owned(), json!(query.get("serviceName")));
            trojan.insert("grpc-opts".to_owned(), Value::Object(grpc_opts));
        }
        _ => {}
    }

    let fingerprint = query.get("fp");
    if fingerprint.is_empty() {
        trojan.insert("client-fingerprint".to_owned(), json!("chrome"));
    } else {
        trojan.insert("client-fingerprint".to_owned(), json!(fingerprint));
    }

    let pcs = query.get("pcs");
    if !pcs.is_empty() {
        trojan.insert("fingerprint".to_owned(), json!(pcs));
    }

    proxies.push(trojan);
}

fn convert_vless(names: &mut HashMap<String, i32>, line: &str, scheme: &str, proxies: &mut Vec<Map<String, Value>>) {
    let Some(mut url_vless) = Url::parse(line) else {
        return;
    };
    if let Some(decoded_host) = try_decode_base64_bytes(url_vless.host().as_bytes()) {
        url_vless.set_host(&String::from_utf8_lossy(&decoded_host));
    }
    let query = url_vless.query();
    let mut vless = Map::new();
    if let Err(err) = handle_v_share_link(names, &url_vless, scheme, &mut vless) {
        warnln!("error:{} line:{}", err, line);
        return;
    }
    let flow = query.get("flow");
    if !flow.is_empty() {
        vless.insert("flow".to_owned(), json!(flow.to_lowercase()));
    }
    let encryption = query.get("encryption");
    if !encryption.is_empty() {
        vless.insert("encryption".to_owned(), json!(encryption));
    }
    proxies.push(vless);
}

fn convert_vmess(
    names: &mut HashMap<String, i32>,
    line: &str,
    scheme: &str,
    body: &str,
    proxies: &mut Vec<Map<String, Value>>,
) {
    // V2RayN-styled share link
    let Some(dc_buf) = try_decode_base64_bytes(body.as_bytes()) else {
        convert_vmess_share_link(names, line, scheme, proxies);
        return;
    };

    let mut deserializer = serde_json::Deserializer::from_slice(&dc_buf);
    let Ok(values) = Map::<String, Value>::deserialize(&mut deserializer) else {
        return;
    };
    let temp_name = match values.get("ps").and_then(|v| v.as_str()) {
        Some(temp_name) => temp_name.to_owned(),
        None => return,
    };
    let name = unique_name(names, &temp_name);
    let mut vmess = Map::new();

    vmess.insert("name".to_owned(), json!(name));
    vmess.insert("type".to_owned(), json!(scheme));
    vmess.insert("server".to_owned(), values.get("add").cloned().unwrap_or(Value::Null));
    vmess.insert("port".to_owned(), values.get("port").cloned().unwrap_or(Value::Null));
    vmess.insert("uuid".to_owned(), values.get("id").cloned().unwrap_or(Value::Null));
    if let Some(alter_id) = values.get("aid") {
        vmess.insert("alterId".to_owned(), alter_id.clone());
    } else {
        vmess.insert("alterId".to_owned(), json!(0));
    }
    vmess.insert("udp".to_owned(), json!(true));
    vmess.insert("xudp".to_owned(), json!(true));
    vmess.insert("tls".to_owned(), json!(false));
    vmess.insert("skip-cert-verify".to_owned(), json!(false));

    vmess.insert("cipher".to_owned(), json!("auto"));
    if let Some(cipher) = values.get("scy").and_then(|v| v.as_str()) {
        if !cipher.is_empty() {
            vmess.insert("cipher".to_owned(), json!(cipher));
        }
    }

    if let Some(sni) = values.get("sni").and_then(|v| v.as_str()) {
        if !sni.is_empty() {
            vmess.insert("servername".to_owned(), json!(sni));
        }
    }

    let mut network = String::new();
    if let Some(net) = values.get("net").and_then(|v| v.as_str()) {
        network = net.to_lowercase();
        if matches!(values.get("type"), Some(Value::String(t)) if t == "http") {
            "http".clone_into(&mut network);
        } else if network == "http" {
            "h2".clone_into(&mut network);
        }
        vmess.insert("network".to_owned(), Value::String(network.clone()));
    }

    if let Some(tls) = values.get("tls").and_then(|v| v.as_str()) {
        let tls = tls.to_lowercase();
        if tls.ends_with("tls") {
            vmess.insert("tls".to_owned(), json!(true));
        }
        if let Some(alpn) = values.get("alpn").and_then(|v| v.as_str()) {
            vmess.insert("alpn".to_owned(), json!(alpn.split(',').collect::<Vec<&str>>()));
        }
    }

    insert_vmess_transport(&network, &values, &mut vmess);

    proxies.push(vmess);
}

fn convert_ss(names: &mut HashMap<String, i32>, line: &str, scheme: &str, proxies: &mut Vec<Map<String, Value>>) {
    let Some(mut url_ss) = Url::parse(line) else {
        return;
    };

    let name = unique_name(names, &url_ss.fragment());
    let port = url_ss.port();

    if port.is_empty() {
        let Ok(dc_buf) = decode(&ENC_RAW, url_ss.host().as_bytes()) else {
            return;
        };

        match Url::parse(&format!("ss://{}", String::from_utf8_lossy(&dc_buf))) {
            Some(reparsed) => url_ss = reparsed,
            None => return,
        }
    }

    let cipher_raw = url_ss.user_username();
    let mut cipher = cipher_raw.clone();
    let mut password;

    let password_found = if let Some(found_password) = url_ss.user_password() {
        password = found_password;
        true
    } else {
        password = String::new();
        false
    };
    if !password_found {
        let dc_buf = match decode(&ENC_RAW_URL, cipher_raw.as_bytes()) {
            Ok(dc_buf) => dc_buf,
            Err(_) => decode(&ENC, cipher_raw.as_bytes()).unwrap_or_default(),
        };
        let (cut_cipher, cut_password, found) = cut(&String::from_utf8_lossy(&dc_buf), ":");
        cipher = cut_cipher;
        password = cut_password;
        if !found {
            return;
        }
        if verify_method(&cipher, &password).is_err() {
            let dc_buf = decode(&ENC_RAW, cipher_raw.as_bytes()).unwrap_or_default();
            let (cut_cipher, cut_password, _) = cut(&String::from_utf8_lossy(&dc_buf), ":");
            cipher = cut_cipher;
            password = cut_password;
        }
    }

    let mut ss = Map::new();

    ss.insert("name".to_owned(), json!(name));
    ss.insert("type".to_owned(), json!(scheme));
    ss.insert("server".to_owned(), json!(url_ss.hostname()));
    ss.insert("port".to_owned(), json!(url_ss.port()));
    ss.insert("cipher".to_owned(), json!(cipher));
    ss.insert("password".to_owned(), json!(password));
    let query = url_ss.query();
    ss.insert("udp".to_owned(), json!(true));
    if query.get("udp-over-tcp") == "true" || query.get("uot") == "1" {
        ss.insert("udp-over-tcp".to_owned(), json!(true));
    }
    let plugin = query.get("plugin");
    if plugin.contains(';') {
        let (plugin_info, _) = parse_query(&format!("pluginName={}", plugin.replace(';', "&")));
        let plugin_name = plugin_info.get("pluginName");
        if plugin_name.contains("obfs") {
            let mut plugin_opts = Map::new();
            plugin_opts.insert("mode".to_owned(), json!(plugin_info.get("obfs")));
            plugin_opts.insert("host".to_owned(), json!(plugin_info.get("obfs-host")));
            ss.insert("plugin".to_owned(), json!("obfs"));
            ss.insert("plugin-opts".to_owned(), Value::Object(plugin_opts));
        } else if plugin_name.contains("v2ray-plugin") {
            let mut mode = plugin_info.get("mode");
            if mode.is_empty() {
                mode = plugin_info.get("obfs");
            }
            let mut host = plugin_info.get("host");
            if host.is_empty() {
                host = plugin_info.get("obfs-host");
            }
            let mut plugin_opts = Map::new();
            plugin_opts.insert("mode".to_owned(), json!(mode));
            plugin_opts.insert("host".to_owned(), json!(host));
            plugin_opts.insert("path".to_owned(), json!(plugin_info.get("path")));
            plugin_opts.insert("tls".to_owned(), json!(plugin.contains("tls")));
            ss.insert("plugin".to_owned(), json!("v2ray-plugin"));
            ss.insert("plugin-opts".to_owned(), Value::Object(plugin_opts));
        }
    }

    proxies.push(ss);
}

fn convert_ssr(names: &mut HashMap<String, i32>, scheme: &str, body: &str, proxies: &mut Vec<Map<String, Value>>) {
    let Ok(dc_buf) = try_decode_base64(body) else {
        return;
    };

    // ssr://host:port:protocol:method:obfs:urlsafebase64pass/?obfsparam=urlsafebase64param&protoparam=urlsafebase64param&remarks=urlsafebase64remarks&group=urlsafebase64group&udpport=0&uot=1

    let (before, after, ok) = cut(&String::from_utf8_lossy(&dc_buf), "/?");
    if !ok {
        return;
    }

    let before_arr: Vec<&str> = before.split(':').collect();
    let [host, port, protocol, method, obfs, cut_password] = before_arr.as_slice() else {
        return;
    };
    let password = decode_url_safe(&url_safe(cut_password));

    let (query, err) = parse_query(&url_safe(&after));
    if err.is_some() {
        return;
    }

    let remarks = decode_url_safe(&query.get("remarks"));
    let name = unique_name(names, &remarks);

    let obfs_param = decode_url_safe(&query.get("obfsparam"));
    let protocol_param = decode_url_safe(&query.get("protoparam"));

    let mut ssr = Map::new();

    ssr.insert("name".to_owned(), json!(name));
    ssr.insert("type".to_owned(), json!(scheme));
    ssr.insert("server".to_owned(), json!(host));
    ssr.insert("port".to_owned(), json!(port));
    ssr.insert("cipher".to_owned(), json!(method));
    ssr.insert("password".to_owned(), json!(password));
    ssr.insert("obfs".to_owned(), json!(obfs));
    ssr.insert("protocol".to_owned(), json!(protocol));
    ssr.insert("udp".to_owned(), json!(true));

    if !obfs_param.is_empty() {
        ssr.insert("obfs-param".to_owned(), json!(obfs_param));
    }

    if !protocol_param.is_empty() {
        ssr.insert("protocol-param".to_owned(), json!(protocol_param));
    }

    proxies.push(ssr);
}

fn convert_socks(names: &mut HashMap<String, i32>, line: &str, scheme: &str, proxies: &mut Vec<Map<String, Value>>) {
    let Some(parsed_url) = Url::parse(line) else {
        return;
    };
    let server = parsed_url.hostname();
    if server.is_empty() {
        return;
    }
    let port_str = parsed_url.port();
    if port_str.is_empty() {
        return;
    }
    let mut remarks = parsed_url.fragment();
    if remarks.is_empty() {
        remarks = format!("{server}:{port_str}");
    }
    let name = unique_name(names, &remarks);
    let encode_str = parsed_url.user_string();
    let mut username = String::new();
    let mut password = String::new();
    if !encode_str.is_empty() {
        let decode_str = String::from_utf8_lossy(&decode_base64(encode_str.as_bytes())).into_owned();
        let split_str: Vec<&str> = decode_str.split(':').collect();
        match split_str.as_slice() {
            [user, pass] => {
                username.push_str(user);
                password.push_str(pass);
            }
            [user, ..] => username.push_str(user),
            [] => {}
        }
    }
    let socks_type = match scheme {
        "socks" | "socks5" | "socks5h" => "socks5",
        "http" | "https" => "http",
        _ => scheme,
    };
    let mut socks = Map::new();
    socks.insert("name".to_owned(), json!(name));
    socks.insert("type".to_owned(), json!(socks_type));
    socks.insert("server".to_owned(), json!(server));
    socks.insert("port".to_owned(), json!(port_str));
    socks.insert("username".to_owned(), json!(username));
    socks.insert("password".to_owned(), json!(password));
    socks.insert("skip-cert-verify".to_owned(), json!(true));
    if scheme == "https" {
        socks.insert("tls".to_owned(), json!(true));
    }

    proxies.push(socks);
}

fn convert_anytls(names: &mut HashMap<String, i32>, line: &str, proxies: &mut Vec<Map<String, Value>>) {
    // The anytls share-link scheme.
    let Some(parsed_url) = Url::parse(line) else {
        return;
    };
    let username = parsed_url.user_username();
    let password = match parsed_url.user_password() {
        Some(password) => password,
        None => username.clone(),
    };
    let query = parsed_url.query();
    let server = parsed_url.hostname();
    if server.is_empty() {
        return;
    }
    let port_str = parsed_url.port();
    if port_str.is_empty() {
        return;
    }
    let insecure = query.get("insecure");
    let sni = query.get("sni");
    let insecure_bool = insecure == "1";
    let fingerprint = query.get("hpkp");

    let mut remarks = parsed_url.fragment();
    if remarks.is_empty() {
        remarks = format!("{server}:{port_str}");
    }
    let name = unique_name(names, &remarks);
    let mut anytls = Map::new();
    anytls.insert("name".to_owned(), json!(name));
    anytls.insert("type".to_owned(), json!("anytls"));
    anytls.insert("server".to_owned(), json!(server));
    anytls.insert("port".to_owned(), json!(port_str));
    anytls.insert("username".to_owned(), json!(username));
    anytls.insert("password".to_owned(), json!(password));
    anytls.insert("sni".to_owned(), json!(sni));
    anytls.insert("fingerprint".to_owned(), json!(fingerprint));
    anytls.insert("skip-cert-verify".to_owned(), json!(insecure_bool));
    anytls.insert("udp".to_owned(), json!(true));

    proxies.push(anytls);
}

/// The Xray VMessAEAD share-link form, which the base64-JSON form shadows.
fn convert_vmess_share_link(
    names: &mut HashMap<String, i32>,
    line: &str,
    scheme: &str,
    proxies: &mut Vec<Map<String, Value>>,
) {
    // Xray VMessAEAD share link
    let Some(url_vmess) = Url::parse(line) else {
        return;
    };
    let query = url_vmess.query();
    let mut vmess = Map::new();
    if let Err(err) = handle_v_share_link(names, &url_vmess, scheme, &mut vmess) {
        warnln!("error:{} line:{}", err, line);
        return;
    }
    vmess.insert("alterId".to_owned(), json!(0));
    vmess.insert("cipher".to_owned(), json!("auto"));
    let encryption = query.get("encryption");
    if !encryption.is_empty() {
        vmess.insert("cipher".to_owned(), json!(encryption));
    }
    proxies.push(vmess);
}

fn insert_vmess_transport(network: &str, values: &Map<String, Value>, vmess: &mut Map<String, Value>) {
    match network {
        "http" => {
            let mut headers = Map::new();
            let mut http_opts = Map::new();
            if let Some(host) = values.get("host").and_then(|v| v.as_str()) {
                if !host.is_empty() {
                    headers.insert("Host".to_owned(), json!([host]));
                }
            }
            http_opts.insert("path".to_owned(), json!(["/"]));
            if let Some(path) = values.get("path").and_then(|v| v.as_str()) {
                if !path.is_empty() {
                    http_opts.insert("path".to_owned(), json!([path]));
                }
            }
            http_opts.insert("headers".to_owned(), Value::Object(headers));

            vmess.insert("http-opts".to_owned(), Value::Object(http_opts));
        }

        "h2" => {
            let mut h2_opts = Map::new();
            h2_opts.insert("path".to_owned(), json!("/"));
            if let Some(path) = values.get("path").and_then(|v| v.as_str()) {
                if !path.is_empty() {
                    h2_opts.insert("path".to_owned(), json!(path));
                }
            }
            if let Some(host) = values.get("host").and_then(|v| v.as_str()) {
                if !host.is_empty() {
                    h2_opts.insert("host".to_owned(), json!([host]));
                }
            }
            vmess.insert("h2-opts".to_owned(), Value::Object(h2_opts));
        }

        "ws" | "httpupgrade" => {
            let mut headers = Map::new();
            let mut ws_opts = Map::new();
            ws_opts.insert("path".to_owned(), json!("/"));
            if let Some(host) = values.get("host").and_then(|v| v.as_str()) {
                if !host.is_empty() {
                    headers.insert("Host".to_owned(), json!(host));
                }
            }
            if let Some(path) = values.get("path").and_then(|v| v.as_str()) {
                if !path.is_empty() {
                    if let Some(mut path_url) = PathUrl::parse(path) {
                        let mut query = path_url.query();
                        let early_data = query.get("ed");
                        if !early_data.is_empty() {
                            if let Ok(med) = early_data.parse::<i32>() {
                                match network {
                                    "ws" => {
                                        ws_opts.insert("max-early-data".to_owned(), json!(med));
                                        ws_opts.insert(
                                            "early-data-header-name".to_owned(),
                                            json!("Sec-WebSocket-Protocol"),
                                        );
                                    }
                                    "httpupgrade" => {
                                        ws_opts.insert("v2ray-http-upgrade-fast-open".to_owned(), json!(true));
                                    }
                                    _ => {}
                                }
                                query.del("ed");
                                path_url.set_raw_query(query.encode());
                            }
                        }
                        let early_data_header = query.get("eh");
                        if !early_data_header.is_empty() {
                            ws_opts.insert("early-data-header-name".to_owned(), json!(early_data_header));
                        }
                        ws_opts.insert("path".to_owned(), json!(path_url.string()));
                    } else {
                        ws_opts.insert("path".to_owned(), json!(path));
                    }
                }
            }
            ws_opts.insert("headers".to_owned(), Value::Object(headers));
            vmess.insert("ws-opts".to_owned(), Value::Object(ws_opts));
        }

        "grpc" => {
            let mut grpc_opts = Map::new();
            grpc_opts.insert("grpc-service-name".to_owned(), values.get("path").cloned().unwrap_or(Value::Null));
            vmess.insert("grpc-opts".to_owned(), Value::Object(grpc_opts));
        }
        _ => {}
    }
}

pub(crate) fn unique_name(names: &mut HashMap<String, i32>, name: &str) -> String {
    let index = names.entry(name.to_owned()).or_insert(-1);
    *index += 1;
    if *index == 0 {
        name.to_owned()
    } else {
        format!("{name}-{:02}", *index)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    /// Only the converted maps are asserted; the results are not run through the adapter parser.
    #[test]
    fn test_converts_v2_ray_reality_and_keeps_the_rest() {
        let reality = "vless://a1b2c3d4-eacc-4433-981b-7e5f9a8b@192.0.2.1:34888?encryption=none&security=reality&type=tcp&sni=example.org&fp=chrome&pbk=ppQ9FwLrLIa0AOrp1WvcyiaQ37vg2WSy_CD4bIdiTUw&sid=6ba85179f3a2b4c5&flow=xtls-rprx-vision#My-VLESS-Reality-Vision";
        let plain = "vless://uuid@example.com:443?security=tls&type=tcp#keep-me";

        let proxies = converts_v2ray(format!("{reality}\n{plain}").as_bytes()).unwrap();

        assert_eq!(2, proxies.len());
        assert_eq!(json!("My-VLESS-Reality-Vision"), proxies[0]["name"]);
        assert_eq!(json!(true), proxies[0]["tls"]);
        assert_eq!(json!("chrome"), proxies[0]["client-fingerprint"]);
        assert_eq!(json!("example.org"), proxies[0]["servername"]);
        assert_eq!(
            json!({
                "public-key": "ppQ9FwLrLIa0AOrp1WvcyiaQ37vg2WSy_CD4bIdiTUw",
                "short-id": "6ba85179f3a2b4c5",
            }),
            proxies[0]["reality-opts"]
        );
        assert_eq!(json!("keep-me"), proxies[1]["name"]);
        assert!(!proxies[1].contains_key("reality-opts"));
    }

    #[test]
    fn test_converts_v2_ray_reality_mlkem768() {
        let public_key = "ppQ9FwLrLIa0AOrp1WvcyiaQ37vg2WSy_CD4bIdiTUw";
        let cases = [
            ("", Value::Null),
            ("&support-x25519mlkem768=", Value::Null),
            ("&support-x25519mlkem768=true", json!(true)),
            ("&support-x25519mlkem768=1", json!(true)),
            ("&support-x25519mlkem768=false", json!(false)),
            ("&support-x25519mlkem768=0", json!(false)),
            ("&support-x25519mlkem768=invalid", Value::Null),
        ];
        for scheme in ["vless", "vmess"] {
            for (query, want) in &cases {
                let uri = format!(
                    "{scheme}://b831381d-6324-4d53-ad4f-8cda48b30811@example.com:443\
                     ?security=reality&type=tcp&sid=00112233&pbk={public_key}{query}"
                );
                let encoded = {
                    use base64::Engine as _;
                    ENC.encode(uri.as_bytes())
                };
                for input in [uri.as_str(), encoded.as_str()] {
                    let proxies = converts_v2ray(input.as_bytes()).unwrap();
                    assert_eq!(1, proxies.len(), "{scheme} {query}");
                    let mut expected = json!({ "public-key": public_key, "short-id": "00112233" });
                    if !want.is_null() {
                        expected["support-x25519mlkem768"] = want.clone();
                    }
                    assert_eq!(expected, proxies[0]["reality-opts"], "{scheme} {query}");
                }
            }
        }
    }

    #[test]
    fn test_converts_v2_ray_reality_without_public_key_omits_reality_opts() {
        let vless_test = "vless://uuid@example.com:443?security=reality&type=tcp&sid=00112233";

        let proxies = converts_v2ray(vless_test.as_bytes()).unwrap();

        assert_eq!(1, proxies.len());
        assert!(!proxies[0].contains_key("reality-opts"));
    }

    #[test]
    fn test_converts_v2_ray_vless_tcp_http_header_type() {
        let vless_test = "vless://uuid@example.com:443?security=tls&type=tcp&headerType=http&host=cdn.example.com&path=%2Fedge&method=POST#vless-http";

        let proxies = converts_v2ray(vless_test.as_bytes()).unwrap();

        assert_eq!(1, proxies.len());
        assert_eq!(json!("http"), proxies[0]["network"]);
        assert_eq!(
            json!({
                "method": "POST",
                "path": ["/edge"],
                "headers": {
                    "Host": ["cdn.example.com"],
                },
            }),
            proxies[0]["http-opts"]
        );
        assert!(!proxies[0].contains_key("h2-opts"));
    }

    #[test]
    fn test_converts_v2_ray_vless_http_transport_uses_h2_opts() {
        let vless_test =
            "vless://uuid@example.com:443?security=tls&type=http&host=cdn.example.com&path=%2Fgrpc#vless-h2";

        let proxies = converts_v2ray(vless_test.as_bytes()).unwrap();

        assert_eq!(1, proxies.len());
        assert_eq!(json!("h2"), proxies[0]["network"]);
        assert_eq!(
            json!({
                "host": ["cdn.example.com"],
                "path": "/grpc",
            }),
            proxies[0]["h2-opts"]
        );
        assert!(!proxies[0].contains_key("http-opts"));
    }

    /// Regression test: the legacy v2rayN-style base64-JSON VMess parser must place `host` under
    /// h2-opts.host, not inside a non-existent h2-opts.headers.Host key.
    #[test]
    fn test_converts_v2_ray_vmess_base64_h2_transport() {
        let vmess_test = "vmess://eyJ2IjoiMiIsInBzIjoiZGVtbyIsImFkZCI6InNlcnZlci5leGFtcGxlLmNvbSIsInBvcnQiOiI0NDMiLCJpZCI6ImI4MzEzODFkLTYzMjQtNGQ1My1hZDRmLThjZGE0OGIzMDgxMSIsImFpZCI6IjAiLCJzY3kiOiJhdXRvIiwibmV0IjoiaDIiLCJ0eXBlIjoibm9uZSIsImhvc3QiOiJjZG4uZXhhbXBsZS5jb20iLCJwYXRoIjoiL2dycGMiLCJ0bHMiOiJ0bHMifQ==";

        let proxies = converts_v2ray(vmess_test.as_bytes()).unwrap();

        assert_eq!(1, proxies.len());
        assert_eq!(json!("h2"), proxies[0]["network"]);
        assert_eq!(
            json!({
                "host": ["cdn.example.com"],
                "path": "/grpc",
            }),
            proxies[0]["h2-opts"]
        );
        assert!(!proxies[0].contains_key("http-opts"));
    }

    /// `net: http` with `type != "http"` is remapped to h2 transport at the network-resolution step,
    /// so it must produce the same h2-opts shape as `net: h2`.
    #[test]
    fn test_converts_v2_ray_vmess_base64_http_remapped_to_h2_transport() {
        let vmess_test = "vmess://eyJ2IjoiMiIsInBzIjoiZGVtby1odHRwLXJlbWFwcGVkIiwiYWRkIjoic2VydmVyLmV4YW1wbGUuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoiYjgzMTM4MWQtNjMyNC00ZDUzLWFkNGYtOGNkYTQ4YjMwODExIiwiYWlkIjoiMCIsInNjeSI6ImF1dG8iLCJuZXQiOiJodHRwIiwidHlwZSI6Im5vbmUiLCJob3N0IjoiY2RuLmV4YW1wbGUuY29tIiwicGF0aCI6Ii9ncnBjIiwidGxzIjoidGxzIn0=";

        let proxies = converts_v2ray(vmess_test.as_bytes()).unwrap();

        assert_eq!(1, proxies.len());
        assert_eq!(json!("h2"), proxies[0]["network"]);
        assert_eq!(
            json!({
                "host": ["cdn.example.com"],
                "path": "/grpc",
            }),
            proxies[0]["h2-opts"]
        );
        assert!(!proxies[0].contains_key("http-opts"));
    }
}
