/// Splits a `scheme://host:port` network string. `scheme` keeps the `shecme` spelling.
pub fn split_network_type(s: &str) -> anyhow::Result<(String, String)> {
    let result: Vec<&str> = s.split("://").collect();
    let (mut shecme, host_port) = match result.as_slice() {
        [scheme, host_port] => ((*scheme).to_owned(), (*host_port).to_owned()),
        [only] => (String::new(), (*only).to_owned()),
        _ => return Err(anyhow::anyhow!("tcp/udp style error")),
    };
    if shecme.is_empty() {
        "udp".clone_into(&mut shecme);
    }
    if shecme != "tcp" && shecme != "udp" {
        return Err(anyhow::anyhow!("scheme should be tcp:// or udp://"));
    }
    Ok((shecme, host_port))
}
pub fn split_host_port(s: &str) -> anyhow::Result<(String, String, bool)> {
    let mut temp = s.to_owned();

    let has_port = if s.contains(':') || s.contains("]:") {
        true
    } else {
        temp += ":0";
        false
    };

    let (host, port) = murmur_common::net_addr::split_host_port(&temp)?;
    Ok((host, port, has_port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_network_type_defaults_to_udp() {
        assert_eq!(
            split_network_type("1.2.3.4:53").expect("host port only"),
            ("udp".to_owned(), "1.2.3.4:53".to_owned())
        );
        assert_eq!(
            split_network_type("tcp://1.2.3.4:443").expect("tcp scheme"),
            ("tcp".to_owned(), "1.2.3.4:443".to_owned())
        );
        assert!(split_network_type("a://b://c").is_err());
        assert!(split_network_type("http://1.2.3.4:80").is_err());
    }

    #[test]
    fn split_host_port_marks_a_missing_port_and_defaults_it_to_zero() {
        assert_eq!(
            split_host_port("example.com").expect("host only"),
            ("example.com".to_owned(), "0".to_owned(), false)
        );
        assert_eq!(
            split_host_port("example.com:443").expect("host and port"),
            ("example.com".to_owned(), "443".to_owned(), true)
        );
        assert_eq!(split_host_port("[::1]:53").expect("bracketed ipv6"), ("::1".to_owned(), "53".to_owned(), true));
        assert!(split_host_port("[::1]").is_err());
        assert!(split_host_port("::1").is_err());
    }
}
