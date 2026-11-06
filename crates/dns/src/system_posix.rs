#[cfg(not(target_os = "windows"))]
use std::io::{BufRead, BufReader};

#[cfg(not(target_os = "windows"))]
const RESOLV_CONF: &str = "/etc/resolv.conf";

#[cfg(not(target_os = "windows"))]
pub(crate) fn dns_read_config() -> anyhow::Result<Vec<String>> {
    let file =
        std::fs::File::open(RESOLV_CONF).map_err(|err| anyhow::anyhow!("failed to read {RESOLV_CONF}: {err}"))?;
    let mut servers = Vec::new();
    for line in BufReader::new(file).lines() {
        let line = line?;
        if line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.first() == Some(&"nameserver") {
            if let Some(addr) = fields.get(1) {
                if let Ok(addr) = addr.parse::<std::net::IpAddr>() {
                    servers.push(addr.to_string());
                }
            }
        }
    }
    Ok(servers)
}
