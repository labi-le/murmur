//! Shared core of host:port splitting.
//!
//! Previously duplicated in `common::net::tcpip`, `component::dialer::bind` and
//! `config::config` (P3 item 67). Every caller that needs the exact host:port parsing
//! behaviour, including its exact error text, calls [`split_host_port`]; callers that need a
//! different error shape map [`SplitHostPortError`] to their own type.

/// The error reasons, rendering as `address <addr>: <why>`.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SplitHostPortError {
    #[error("address {0}: missing port in address")]
    MissingPort(String),
    #[error("address {0}: too many colons in address")]
    TooManyColons(String),
    #[error("address {0}: {1}")]
    Other(String, &'static str),
}

/// The core parser: strict, never defaults a missing port.
pub fn split_host_port(hostport: &str) -> Result<(String, String), SplitHostPortError> {
    let bytes = hostport.as_bytes();

    let Some(i) = hostport.rfind(':') else {
        return Err(SplitHostPortError::MissingPort(hostport.to_owned()));
    };

    let (j, k, host);
    if bytes.first() == Some(&b'[') {
        let Some(end) = hostport.find(']') else {
            return Err(SplitHostPortError::Other(hostport.to_owned(), "missing ']' in address"));
        };
        if end + 1 == hostport.len() {
            return Err(SplitHostPortError::MissingPort(hostport.to_owned()));
        }
        if end + 1 != i {
            if bytes.get(end + 1) == Some(&b':') {
                return Err(SplitHostPortError::TooManyColons(hostport.to_owned()));
            }
            return Err(SplitHostPortError::MissingPort(hostport.to_owned()));
        }
        // The address opened with '[' and `end` indexes its matching ']'.
        let Some(inner) = hostport.get(1..end) else {
            return Err(SplitHostPortError::MissingPort(hostport.to_owned()));
        };
        host = inner.to_owned();
        j = 1;
        k = end + 1;
    } else {
        let Some(inner) = hostport.get(..i) else {
            return Err(SplitHostPortError::MissingPort(hostport.to_owned()));
        };
        host = inner.to_owned();
        if host.contains(':') {
            return Err(SplitHostPortError::TooManyColons(hostport.to_owned()));
        }
        j = 0;
        k = 0;
    }
    let Some(rest) = hostport.get(j..) else {
        return Err(SplitHostPortError::MissingPort(hostport.to_owned()));
    };
    if rest.contains('[') {
        return Err(SplitHostPortError::Other(hostport.to_owned(), "unexpected '[' in address"));
    }
    let Some(rest) = hostport.get(k..) else {
        return Err(SplitHostPortError::MissingPort(hostport.to_owned()));
    };
    if rest.contains(']') {
        return Err(SplitHostPortError::Other(hostport.to_owned(), "unexpected ']' in address"));
    }

    let Some(port) = hostport.get(i + 1..) else {
        return Err(SplitHostPortError::MissingPort(hostport.to_owned()));
    };
    Ok((host, port.to_owned()))
}

#[cfg(test)]
mod tests {
    use super::split_host_port;

    #[test]
    fn strips_ipv6_brackets() {
        assert_eq!(split_host_port("192.0.2.1:80").unwrap(), ("192.0.2.1".to_owned(), "80".to_owned()));
        assert_eq!(split_host_port("[::1]:80").unwrap(), ("::1".to_owned(), "80".to_owned()));
        assert_eq!(split_host_port("example.com:http").unwrap(), ("example.com".to_owned(), "http".to_owned()));
    }

    #[test]
    fn rejects_missing_port() {
        assert!(split_host_port("example.com").is_err());
        assert!(split_host_port("[::1]").is_err());
    }

    #[test]
    fn rejects_bare_ipv6() {
        assert!(split_host_port("::1").is_err());
        assert!(split_host_port("fe80::1").is_err());
        assert!(split_host_port("2001:db8::53").is_err());
        assert!(split_host_port("[::1]:80:90").is_err());
    }
}
