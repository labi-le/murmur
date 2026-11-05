use std::fmt;

use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use murmur_common_net::tcpip::split_host_port;

/// The `tunnel` listener's address mapping. One struct suffices: decoding never needs a
/// separate unexported twin.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Tunnel {
    #[serde(rename = "network")]
    pub network: Vec<String>,
    #[serde(rename = "address")]
    pub address: String,
    #[serde(rename = "target")]
    pub target: String,
    #[serde(rename = "proxy")]
    pub proxy: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct TunnelFields {
    #[serde(rename = "network")]
    network: Vec<String>,
    #[serde(rename = "address")]
    address: String,
    #[serde(rename = "target")]
    target: String,
    #[serde(rename = "proxy")]
    proxy: String,
}

impl<'de> Deserialize<'de> for Tunnel {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TunnelVisitor;

        impl<'de> Visitor<'de> for TunnelVisitor {
            type Value = Tunnel;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a tunnel string (\"tcp/udp,address,target[,proxy]\") or mapping")
            }

            fn visit_str<E>(self, v: &str) -> Result<Tunnel, E>
            where
                E: de::Error,
            {
                parse_tunnel(v).map_err(de::Error::custom)
            }

            fn visit_string<E>(self, v: String) -> Result<Tunnel, E>
            where
                E: de::Error,
            {
                self.visit_str(&v)
            }

            fn visit_map<A>(self, map: A) -> Result<Tunnel, A::Error>
            where
                A: MapAccess<'de>,
            {
                let fields = TunnelFields::deserialize(de::value::MapAccessDeserializer::new(map))?;
                Ok(Tunnel {
                    network: fields.network,
                    address: fields.address,
                    target: fields.target,
                    proxy: fields.proxy,
                })
            }
        }

        deserializer.deserialize_any(TunnelVisitor)
    }
}

/// The string branch of the parses `udp/tcp,address,target,proxy`.
fn parse_tunnel(tp: &str) -> Result<Tunnel, String> {
    let parts: Vec<String> = tp.split(',').map(|s| s.trim().to_owned()).collect();
    let (network_field, address, target, proxy) = match parts.as_slice() {
        [network, address, target] => (network, address, target, None),
        [network, address, target, proxy] => (network, address, target, Some(proxy)),
        _ => return Err(format!("invalid tunnel config {tp}")),
    };
    let network: Vec<String> = network_field.split('/').map(str::to_owned).collect();

    for n in &network {
        match n.as_str() {
            "tcp" | "udp" => {}
            _ => return Err(format!("invalid tunnel network {n}")),
        }
    }

    for addr in [address, target] {
        match split_host_port(addr) {
            Ok((_, _, true)) => {}
            _ => return Err(format!("invalid tunnel target or address {addr}")),
        }
    }

    let mut tunnel = Tunnel { network, address: address.clone(), target: target.clone(), proxy: String::new() };
    if let Some(proxy) = proxy {
        tunnel.proxy.clone_from(proxy);
    }
    Ok(tunnel)
}
