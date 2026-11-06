use std::sync::LazyLock;

use anyhow::{anyhow, Result};
use parking_lot::Mutex;

use murmur_common::cmd;
use murmur_component::dialer::options::DEFAULT_ROUTING_MARK;

/// The module-level transparent-proxy state.
struct State {
    dns_port: u16,
    t_proxy_port: u16,
    interface_name: String,
    dns_redirect: bool,
}

static STATE: LazyLock<Mutex<State>> = LazyLock::new(|| {
    Mutex::new(State { dns_port: 0, t_proxy_port: 0, interface_name: String::new(), dns_redirect: false })
});

pub const PROXY_FWMARK: &str = "0x2d0";
pub const PROXY_ROUTE_TABLE: &str = "0x2d0";

pub async fn set_tproxy_iptables(
    ifname: &str,
    bypass: &[String],
    tport: u16,
    dnsredir: bool,
    dport: u16,
) -> Result<()> {
    if cmd::exec_cmd("iptables -V").await.is_err() {
        return Err(anyhow!(
            "current operations system [{}] are not support iptables or command iptables does not exist",
            std::env::consts::OS
        ));
    }

    if ifname.is_empty() {
        return Err(anyhow!("the 'interface-name' can not be empty"));
    }

    let interface_name;
    let t_proxy_port;
    let dns_redirect;
    let dns_port;
    {
        let mut state = STATE.lock();
        ifname.clone_into(&mut state.interface_name);
        state.t_proxy_port = tport;
        state.dns_redirect = dnsredir;
        state.dns_port = dport;
        interface_name = state.interface_name.clone();
        t_proxy_port = state.t_proxy_port;
        dns_redirect = state.dns_redirect;
        dns_port = state.dns_port;
    }

    add_route(&interface_name).await;
    if interface_name != "lo" {
        set_forward(&interface_name).await;
    }
    set_divert_chain().await;
    set_prerouting_chain(bypass, t_proxy_port, dns_redirect).await;
    if dns_redirect {
        set_prerouting_dns_redirect(dns_port).await;
    }
    if interface_name != "lo" {
        set_postrouting(&interface_name).await;
    }
    set_output_chain(bypass, &interface_name, dns_redirect).await;
    if dns_redirect {
        set_dns_output_chain(dns_port).await;
    }

    Ok(())
}

async fn add_route(interface_name: &str) {
    exec_cmd(&format!("ip -f inet rule add fwmark {PROXY_FWMARK} lookup {PROXY_ROUTE_TABLE}")).await;
    exec_cmd(&format!("ip -f inet route add local default dev {interface_name} table {PROXY_ROUTE_TABLE}")).await;
}

async fn set_forward(interface_name: &str) {
    exec_cmd("sysctl -w net.ipv4.ip_forward=1").await;
    exec_cmd(&format!(
        "iptables -t filter -A FORWARD -o {interface_name} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
    ))
    .await;
    exec_cmd(&format!("iptables -t filter -A FORWARD -o {interface_name} -j ACCEPT")).await;
    exec_cmd(&format!("iptables -t filter -A FORWARD -i {interface_name} ! -o {interface_name} -j ACCEPT")).await;
    exec_cmd(&format!("iptables -t filter -A FORWARD -i {interface_name} -o {interface_name} -j ACCEPT")).await;
}

async fn set_divert_chain() {
    exec_cmd("iptables -t mangle -N murmur_divert").await;
    exec_cmd("iptables -t mangle -F murmur_divert").await;
    exec_cmd(&format!("iptables -t mangle -A murmur_divert -j MARK --set-mark {PROXY_FWMARK}")).await;
    exec_cmd("iptables -t mangle -A murmur_divert -j ACCEPT").await;
}

async fn set_prerouting_chain(bypass: &[String], t_proxy_port: u16, dns_redirect: bool) {
    exec_cmd("iptables -t mangle -N murmur_prerouting").await;
    exec_cmd("iptables -t mangle -F murmur_prerouting").await;
    exec_cmd("iptables -t mangle -A murmur_prerouting -s 172.17.0.0/16 -j RETURN").await;
    if dns_redirect {
        exec_cmd("iptables -t mangle -A murmur_prerouting -p udp --dport 53 -j ACCEPT").await;
        exec_cmd("iptables -t mangle -A murmur_prerouting -p tcp --dport 53 -j ACCEPT").await;
    }
    exec_cmd("iptables -t mangle -A murmur_prerouting -m addrtype --dst-type LOCAL -j RETURN").await;
    add_localnetwork_to_chain("murmur_prerouting", bypass).await;
    exec_cmd("iptables -t mangle -A murmur_prerouting -p tcp -m socket -j murmur_divert").await;
    exec_cmd("iptables -t mangle -A murmur_prerouting -p udp -m socket -j murmur_divert").await;
    exec_cmd(&format!("iptables -t mangle -A murmur_prerouting -p tcp -j TPROXY --on-port {t_proxy_port} --tproxy-mark {PROXY_FWMARK}/{PROXY_FWMARK}")).await;
    exec_cmd(&format!("iptables -t mangle -A murmur_prerouting -p udp -j TPROXY --on-port {t_proxy_port} --tproxy-mark {PROXY_FWMARK}/{PROXY_FWMARK}")).await;
    exec_cmd("iptables -t mangle -A PREROUTING -j murmur_prerouting").await;
}

async fn set_prerouting_dns_redirect(dns_port: u16) {
    exec_cmd(&format!("iptables -t nat -I PREROUTING ! -s 172.17.0.0/16 ! -d 127.0.0.0/8 -p tcp --dport 53 -j REDIRECT --to {dns_port}")).await;
    exec_cmd(&format!("iptables -t nat -I PREROUTING ! -s 172.17.0.0/16 ! -d 127.0.0.0/8 -p udp --dport 53 -j REDIRECT --to {dns_port}")).await;
}

async fn set_postrouting(interface_name: &str) {
    exec_cmd(&format!(
        "iptables -t nat -A POSTROUTING -o {interface_name} -m addrtype ! --src-type LOCAL -j MASQUERADE"
    ))
    .await;
}

async fn set_output_chain(bypass: &[String], interface_name: &str, dns_redirect: bool) {
    exec_cmd("iptables -t mangle -N murmur_output").await;
    exec_cmd("iptables -t mangle -F murmur_output").await;
    exec_cmd(&format!(
        "iptables -t mangle -A murmur_output -m mark --mark {:#x} -j RETURN",
        DEFAULT_ROUTING_MARK.load()
    ))
    .await;
    if dns_redirect {
        exec_cmd("iptables -t mangle -A murmur_output -p udp -m multiport --dports 53,123,137 -j ACCEPT").await;
        exec_cmd("iptables -t mangle -A murmur_output -p tcp --dport 53 -j ACCEPT").await;
    }
    exec_cmd("iptables -t mangle -A murmur_output -m addrtype --dst-type LOCAL -j RETURN").await;
    exec_cmd("iptables -t mangle -A murmur_output -m addrtype --dst-type BROADCAST -j RETURN").await;
    add_localnetwork_to_chain("murmur_output", bypass).await;
    exec_cmd(&format!("iptables -t mangle -A murmur_output -p tcp -j MARK --set-mark {PROXY_FWMARK}")).await;
    exec_cmd(&format!("iptables -t mangle -A murmur_output -p udp -j MARK --set-mark {PROXY_FWMARK}")).await;
    exec_cmd(&format!("iptables -t mangle -I OUTPUT -o {interface_name} -j murmur_output")).await;
}

async fn set_dns_output_chain(dns_port: u16) {
    exec_cmd("iptables -t nat -N murmur_dns_output").await;
    exec_cmd("iptables -t nat -F murmur_dns_output").await;
    exec_cmd(&format!(
        "iptables -t nat -A murmur_dns_output -m mark --mark {:#x} -j RETURN",
        DEFAULT_ROUTING_MARK.load()
    ))
    .await;
    exec_cmd("iptables -t nat -A murmur_dns_output -s 172.17.0.0/16 -j RETURN").await;
    exec_cmd(&format!("iptables -t nat -A murmur_dns_output -p udp -j REDIRECT --to-ports {dns_port}")).await;
    exec_cmd(&format!("iptables -t nat -A murmur_dns_output -p tcp -j REDIRECT --to-ports {dns_port}")).await;
    exec_cmd("iptables -t nat -I OUTPUT -p tcp --dport 53 -j murmur_dns_output").await;
    exec_cmd("iptables -t nat -I OUTPUT -p udp --dport 53 -j murmur_dns_output").await;
}

pub async fn cleanup_tproxy_iptables() {
    let (interface_name, t_proxy_port, dns_redirect, dns_port) = {
        let state = STATE.lock();
        (state.interface_name.clone(), state.t_proxy_port, state.dns_redirect, state.dns_port)
    };

    if !cfg!(target_os = "linux") || interface_name.is_empty() || t_proxy_port == 0 {
        return;
    }

    murmur_log::warnln!("Cleanup tproxy linux iptables");

    let _ = DEFAULT_ROUTING_MARK.compare_and_swap(2158, 0);

    if cmd::exec_cmd("iptables -t mangle -L murmur_divert").await.is_err() {
        return;
    }

    clean_route(&interface_name).await;
    if interface_name != "lo" {
        clean_forward(&interface_name).await;
    }
    clean_prerouting(dns_redirect, dns_port).await;
    if interface_name != "lo" {
        clean_postrouting(&interface_name).await;
    }
    clean_output(&interface_name, dns_redirect).await;
    clean_chains(dns_redirect).await;

    let mut state = STATE.lock();
    state.interface_name.clear();
    state.t_proxy_port = 0;
    state.dns_port = 0;
}

async fn clean_route(interface_name: &str) {
    exec_cmd(&format!("ip -f inet rule del fwmark {PROXY_FWMARK} lookup {PROXY_ROUTE_TABLE}")).await;
    exec_cmd(&format!("ip -f inet route del local default dev {interface_name} table {PROXY_ROUTE_TABLE}")).await;
}

async fn clean_forward(interface_name: &str) {
    exec_cmd(&format!("iptables -t filter -D FORWARD -i {interface_name} ! -o {interface_name} -j ACCEPT")).await;
    exec_cmd(&format!("iptables -t filter -D FORWARD -i {interface_name} -o {interface_name} -j ACCEPT")).await;
    exec_cmd(&format!(
        "iptables -t filter -D FORWARD -o {interface_name} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
    ))
    .await;
    exec_cmd(&format!("iptables -t filter -D FORWARD -o {interface_name} -j ACCEPT")).await;
}

async fn clean_prerouting(dns_redirect: bool, dns_port: u16) {
    if dns_redirect {
        exec_cmd(&format!("iptables -t nat -D PREROUTING ! -s 172.17.0.0/16 ! -d 127.0.0.0/8 -p tcp --dport 53 -j REDIRECT --to {dns_port}")).await;
        exec_cmd(&format!("iptables -t nat -D PREROUTING ! -s 172.17.0.0/16 ! -d 127.0.0.0/8 -p udp --dport 53 -j REDIRECT --to {dns_port}")).await;
    }
    exec_cmd("iptables -t mangle -D PREROUTING -j murmur_prerouting").await;
}

async fn clean_postrouting(interface_name: &str) {
    exec_cmd(&format!(
        "iptables -t nat -D POSTROUTING -o {interface_name} -m addrtype ! --src-type LOCAL -j MASQUERADE"
    ))
    .await;
}

async fn clean_output(interface_name: &str, dns_redirect: bool) {
    exec_cmd(&format!("iptables -t mangle -D OUTPUT -o {interface_name} -j murmur_output")).await;
    if dns_redirect {
        exec_cmd("iptables -t nat -D OUTPUT -p tcp --dport 53 -j murmur_dns_output").await;
        exec_cmd("iptables -t nat -D OUTPUT -p udp --dport 53 -j murmur_dns_output").await;
    }
}

async fn clean_chains(dns_redirect: bool) {
    exec_cmd("iptables -t mangle -F murmur_prerouting").await;
    exec_cmd("iptables -t mangle -X murmur_prerouting").await;
    exec_cmd("iptables -t mangle -F murmur_divert").await;
    exec_cmd("iptables -t mangle -X murmur_divert").await;
    exec_cmd("iptables -t mangle -F murmur_output").await;
    exec_cmd("iptables -t mangle -X murmur_output").await;
    if dns_redirect {
        exec_cmd("iptables -t nat -F murmur_dns_output").await;
        exec_cmd("iptables -t nat -X murmur_dns_output").await;
    }
}

async fn add_localnetwork_to_chain(chain: &str, bypass: &[String]) {
    for bp in bypass {
        if bp.parse::<ipnet::IpNet>().is_err() {
            murmur_log::warnln!("[IPTABLES] invalid CIDR: {bp}");
            continue;
        }
        exec_cmd(&format!("iptables -t mangle -A {chain} -d {bp} -j RETURN")).await;
    }
    exec_cmd(&format!("iptables -t mangle -A {chain} -d 0.0.0.0/8 -j RETURN")).await;
    exec_cmd(&format!("iptables -t mangle -A {chain} -d 10.0.0.0/8 -j RETURN")).await;
    exec_cmd(&format!("iptables -t mangle -A {chain} -d 100.64.0.0/10 -j RETURN")).await;
    exec_cmd(&format!("iptables -t mangle -A {chain} -d 127.0.0.0/8 -j RETURN")).await;
    exec_cmd(&format!("iptables -t mangle -A {chain} -d 169.254.0.0/16 -j RETURN")).await;
    exec_cmd(&format!("iptables -t mangle -A {chain} -d 172.16.0.0/12 -j RETURN")).await;
    exec_cmd(&format!("iptables -t mangle -A {chain} -d 192.0.0.0/24 -j RETURN")).await;
    exec_cmd(&format!("iptables -t mangle -A {chain} -d 192.0.2.0/24 -j RETURN")).await;
    exec_cmd(&format!("iptables -t mangle -A {chain} -d 192.88.99.0/24 -j RETURN")).await;
    exec_cmd(&format!("iptables -t mangle -A {chain} -d 192.168.0.0/16 -j RETURN")).await;
    exec_cmd(&format!("iptables -t mangle -A {chain} -d 198.51.100.0/24 -j RETURN")).await;
    exec_cmd(&format!("iptables -t mangle -A {chain} -d 203.0.113.0/24 -j RETURN")).await;
    exec_cmd(&format!("iptables -t mangle -A {chain} -d 224.0.0.0/4 -j RETURN")).await;
    exec_cmd(&format!("iptables -t mangle -A {chain} -d 240.0.0.0/4 -j RETURN")).await;
    exec_cmd(&format!("iptables -t mangle -A {chain} -d 255.255.255.255/32 -j RETURN")).await;
}

async fn exec_cmd(cmd_str: &str) {
    murmur_log::debugln!("[IPTABLES] {cmd_str}");

    if let Err(err) = cmd::exec_cmd(cmd_str).await {
        murmur_log::warnln!("[IPTABLES] exec cmd: {err}");
    }
}
