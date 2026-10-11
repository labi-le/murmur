use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use serde_yaml::Mapping;

use murmur_adapter_outboundgroup::parser::GroupCommonOption;
use murmur_common::structure::structure::{new_decoder, Option as StructureOption};
use murmur_constant::adapters::Proxy as CProxy;

/// Local to the proxy-group DAG sort.
struct GraphNode {
    indegree: i32,
    data: Option<Mapping>,
    outdegree: i32,
    option: Option<GroupCommonOption>,
    from: Vec<String>,
}

impl GraphNode {
    const fn new(indegree: i32) -> Self {
        Self { indegree, data: None, outdegree: 0, option: None, from: Vec::new() }
    }
}

/// Check if `ProxyGroups` form DAG(Directed Acyclic Graph), and sort all `ProxyGroups` by dependency order.
/// Meanwhile, record the original index in the config file.
/// If loop is detected, return an error with location of loop.
pub(crate) fn proxy_groups_dag_sort(groups_config: &mut [Mapping]) -> Result<()> {
    let (mut graph, graph_order) = new_group_graph(groups_config)?;

    let mut index = 0usize;
    let mut queue: Vec<String> = Vec::new();
    for name in &graph_order {
        if graph.get(name).is_some_and(|node| node.indegree == 0) {
            queue.push(name.clone());
        }
    }

    let mut cursor = 0usize;
    while let Some(name) = queue.get(cursor).cloned() {
        cursor += 1;

        let (node_data, option_proxies, has_option) = match graph.get(&name) {
            Some(node) => (node.data.clone(), node.option.as_ref().map(|o| o.proxies.clone()), node.option.is_some()),
            None => return Err(anyhow!("ProxyGroup {name}: queued node is missing")),
        };

        if has_option {
            index += 1;
            let Some(data) = node_data else {
                return Err(anyhow!("ProxyGroup {name}: queued node has no data"));
            };
            let target = groups_config.len() - index;
            let Some(slot) = groups_config.get_mut(target) else {
                return Err(anyhow!("ProxyGroup {name}: queued node has no config slot"));
            };
            *slot = data;

            let proxies = option_proxies.unwrap_or_default();
            if proxies.is_empty() {
                graph.remove(&name);
                continue;
            }

            for proxy in &proxies {
                if let Some(child) = graph.get_mut(proxy) {
                    child.indegree -= 1;
                    if child.indegree == 0 {
                        queue.push(proxy.clone());
                    }
                }
            }
        }

        graph.remove(&name);
    }

    if graph.is_empty() {
        return Ok(());
    }

    let remaining: Vec<String> = graph.keys().cloned().collect();
    let loop_elements = loop_members(graph, &remaining);
    Err(anyhow!("loop is detected in ProxyGroup, please check following ProxyGroups: {loop_elements:?}"))
}

fn new_group_graph(groups_config: &[Mapping]) -> Result<(HashMap<String, GraphNode>, Vec<String>)> {
    let decoder =
        new_decoder(StructureOption { tag_name: "group".to_owned(), weakly_typed_input: true, key_replacer: None });
    let mut graph: HashMap<String, GraphNode> = HashMap::new();
    let mut graph_order: Vec<String> = Vec::new();

    for mapping in groups_config {
        let name_hint = mapping.get("name").and_then(|v| v.as_str()).unwrap_or_default().to_owned();
        let option: GroupCommonOption =
            decoder.decode(mapping).map_err(|err| anyhow!("ProxyGroup {name_hint}: {err}"))?;

        let group_name = option.name.clone();
        if let Some(node) = graph.get_mut(&group_name) {
            if node.data.is_some() {
                return Err(anyhow!("ProxyGroup {group_name}: duplicate group name"));
            }
            node.data = Some(mapping.clone());
            node.option = Some(option.clone());
        } else {
            let mut node = GraphNode::new(0);
            node.data = Some(mapping.clone());
            node.option = Some(option.clone());
            graph.insert(group_name.clone(), node);
            graph_order.push(group_name.clone());
        }

        for proxy in &option.proxies {
            if let Some(node) = graph.get_mut(proxy) {
                node.indegree += 1;
            } else {
                graph.insert(proxy.clone(), GraphNode::new(1));
                graph_order.push(proxy.clone());
            }
        }
    }

    Ok((graph, graph_order))
}

fn loop_members(mut graph: HashMap<String, GraphNode>, remaining: &[String]) -> Vec<String> {
    for name in remaining {
        let proxies = match graph.get(name).and_then(|node| node.option.as_ref()) {
            Some(option) if !option.proxies.is_empty() => option.proxies.clone(),
            _ => continue,
        };
        for proxy in &proxies {
            if let Some(node) = graph.get_mut(name) {
                node.outdegree += 1;
            }
            if let Some(child) = graph.get_mut(proxy) {
                child.from.push(name.clone());
            }
        }
    }

    let mut queue: Vec<String> = Vec::new();
    for name in remaining {
        if graph.get(name).is_some_and(|node| node.outdegree == 0) {
            queue.push(name.clone());
        }
    }

    let mut cursor = 0usize;
    while let Some(name) = queue.get(cursor).cloned() {
        cursor += 1;

        let from = graph.get(&name).map(|node| node.from.clone()).unwrap_or_default();
        for f in &from {
            if let Some(node) = graph.get_mut(f) {
                node.outdegree -= 1;
                if node.outdegree == 0 {
                    queue.push(f.clone());
                }
            }
        }
        graph.remove(&name);
    }

    graph.keys().cloned().collect()
}

/// validateDialerProxies checks if all dialer-proxy references are valid
pub(crate) fn validate_dialer_proxies(proxies: &HashMap<String, Arc<dyn CProxy>>) -> Result<()> {
    let mut graph: HashMap<String, String> = HashMap::new();

    for (name, proxy) in proxies {
        let dialer_proxy = proxy.proxy_info().dialer_proxy;
        if !dialer_proxy.is_empty() {
            if !proxies.contains_key(&dialer_proxy) {
                return Err(anyhow!("proxy [{name}] dialer-proxy [{dialer_proxy}] not found"));
            }
            graph.insert(name.clone(), dialer_proxy);
        }
    }

    for name in graph.keys() {
        let mut visited: HashMap<String, bool> = HashMap::with_capacity(graph.len());
        let path: Vec<String> = Vec::with_capacity(graph.len());
        if validate_dialer_proxies_has_cycle(name, &graph, &mut visited, path) {
            return Err(anyhow!("proxy [{name}] has circular dialer-proxy dependency"));
        }
    }

    Ok(())
}

/// validateDialerProxiesHasCycle performs DFS to detect if there's a cycle starting from current proxy
fn validate_dialer_proxies_has_cycle(
    current: &str,
    graph: &HashMap<String, String>,
    visited: &mut HashMap<String, bool>,
    mut path: Vec<String>,
) -> bool {
    if path.iter().any(|p| p == current) {
        return true;
    }

    if *visited.get(current).unwrap_or(&false) {
        return false;
    }

    visited.insert(current.to_owned(), true);
    path.push(current.to_owned());

    if let Some(dialer_proxy) = graph.get(current) {
        if validate_dialer_proxies_has_cycle(dialer_proxy, graph, visited, path) {
            return true;
        }
    }

    false
}

pub(crate) fn verify_ip6() -> bool {
    if let Ok(value) = std::env::var("SKIP_SYSTEM_IPV6_CHECK") {
        if value.parse::<bool>() == Ok(true) {
            return true;
        }
    }

    match if_addrs::get_if_addrs() {
        Ok(addrs) => addrs.iter().any(|addr| match addr.ip().to_canonical() {
            IpAddr::V6(v6) => is_global_unicast_v6(v6),
            IpAddr::V4(_) => false,
        }),
        // Interface enumeration fails on Android SDK 30; treat IPv6 as available in that case.
        Err(_) => true,
    }
}

const fn is_global_unicast_v6(ip: std::net::Ipv6Addr) -> bool {
    !ip.is_unspecified() && !ip.is_loopback() && !ip.is_multicast() && !ip.is_unicast_link_local()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{parse_proxies, RawConfig};

    fn mapping(pairs: &[(&str, serde_yaml::Value)]) -> Mapping {
        let mut m = Mapping::new();
        for (k, v) in pairs {
            m.insert(serde_yaml::Value::String((*k).to_owned()), v.clone());
        }
        m
    }

    #[test]
    fn test_validate_dialer_proxies() {
        struct TestCase {
            proxy: Vec<Mapping>,
            err_contains: &'static str,
        }

        let cases: Vec<TestCase> = vec![
            TestCase {
                proxy: vec![
                    mapping(&[
                        ("name", "base-proxy".into()),
                        ("type", "socks5".into()),
                        ("server", "127.0.0.1".into()),
                        ("port", 1080.into()),
                    ]),
                    mapping(&[
                        ("name", "proxy-with-dialer".into()),
                        ("type", "socks5".into()),
                        ("server", "127.0.0.1".into()),
                        ("port", 1081.into()),
                        ("dialer-proxy", "base-proxy".into()),
                    ]),
                ],
                err_contains: "",
            },
            TestCase {
                proxy: vec![mapping(&[
                    ("name", "proxy-with-dialer".into()),
                    ("type", "socks5".into()),
                    ("server", "127.0.0.1".into()),
                    ("port", 1081.into()),
                    ("dialer-proxy", "non-existent-proxy".into()),
                ])],
                err_contains: "not found",
            },
            TestCase {
                proxy: vec![
                    mapping(&[
                        ("name", "proxy-a".into()),
                        ("type", "socks5".into()),
                        ("server", "127.0.0.1".into()),
                        ("port", 1080.into()),
                        ("dialer-proxy", "proxy-c".into()),
                    ]),
                    mapping(&[
                        ("name", "proxy-b".into()),
                        ("type", "socks5".into()),
                        ("server", "127.0.0.1".into()),
                        ("port", 1081.into()),
                        ("dialer-proxy", "proxy-a".into()),
                    ]),
                    mapping(&[
                        ("name", "proxy-c".into()),
                        ("type", "socks5".into()),
                        ("server", "127.0.0.1".into()),
                        ("port", 1082.into()),
                        ("dialer-proxy", "proxy-a".into()),
                    ]),
                ],
                err_contains: "circular",
            },
            TestCase {
                proxy: vec![
                    mapping(&[
                        ("name", "proxy-a".into()),
                        ("type", "socks5".into()),
                        ("server", "127.0.0.1".into()),
                        ("port", 1080.into()),
                    ]),
                    mapping(&[
                        ("name", "proxy-b".into()),
                        ("type", "socks5".into()),
                        ("server", "127.0.0.1".into()),
                        ("port", 1081.into()),
                        ("dialer-proxy", "proxy-a".into()),
                    ]),
                    mapping(&[
                        ("name", "proxy-c".into()),
                        ("type", "socks5".into()),
                        ("server", "127.0.0.1".into()),
                        ("port", 1082.into()),
                        ("dialer-proxy", "proxy-b".into()),
                    ]),
                    mapping(&[
                        ("name", "proxy-d".into()),
                        ("type", "socks5".into()),
                        ("server", "127.0.0.1".into()),
                        ("port", 1083.into()),
                        ("dialer-proxy", "proxy-c".into()),
                    ]),
                ],
                err_contains: "",
            },
            TestCase {
                proxy: vec![mapping(&[
                    ("name", "simple-proxy".into()),
                    ("type", "socks5".into()),
                    ("server", "127.0.0.1".into()),
                    ("port", 1080.into()),
                ])],
                err_contains: "",
            },
            TestCase {
                proxy: vec![mapping(&[
                    ("name", "self-proxy".into()),
                    ("type", "socks5".into()),
                    ("server", "127.0.0.1".into()),
                    ("port", 1080.into()),
                    ("dialer-proxy", "self-proxy".into()),
                ])],
                err_contains: "circular",
            },
        ];

        for case in cases {
            let config = RawConfig { proxy: case.proxy, ..Default::default() };
            let result = parse_proxies(&config);
            if case.err_contains.is_empty() {
                assert!(result.is_ok(), "{}", result.err().map_or_else(String::new, |e| e.to_string()));
            } else {
                let Err(err) = result else { panic!("expected an error") };
                let err = err.to_string();
                assert!(err.contains(case.err_contains), "{err}");
            }
        }
    }

    #[test]
    fn nil_proxy_fields_leave_the_option_at_its_zero_value() {
        let config = RawConfig {
            proxy: vec![mapping(&[
                ("name", "v1".into()),
                ("type", "vless".into()),
                ("server", "s.example.com".into()),
                ("port", 443.into()),
                ("uuid", "00000000-0000-0000-0000-000000000000".into()),
                ("flow", serde_yaml::Value::Null),
                ("udp", serde_yaml::Value::Null),
            ])],
            ..Default::default()
        };

        let (proxies, _) = parse_proxies(&config).expect("a nil field is ignored");
        assert_eq!(proxies["v1"].name(), "v1");
    }

    #[test]
    fn a_nil_value_inside_a_proxy_map_field_is_still_rejected() {
        let config = RawConfig {
            proxy: vec![mapping(&[
                ("name", "v1".into()),
                ("type", "vmess".into()),
                ("server", "s.example.com".into()),
                ("port", 443.into()),
                ("uuid", "00000000-0000-0000-0000-000000000000".into()),
                ("alterId", 0.into()),
                ("cipher", "auto".into()),
                (
                    "ws-opts",
                    serde_yaml::Value::Mapping(mapping(&[(
                        "headers",
                        serde_yaml::Value::Mapping(mapping(&[("X-Token", serde_yaml::Value::Null)])),
                    )])),
                ),
            ])],
            ..Default::default()
        };

        let Err(err) = parse_proxies(&config) else { panic!("a nil map entry has to be rejected") };
        let err = err.to_string();
        assert!(err.contains("X-Token"), "{err}");
    }
}
