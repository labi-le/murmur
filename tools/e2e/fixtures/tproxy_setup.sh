#!/usr/bin/env bash
# Two-namespace topology for the wildcard/TPROXY scenario: a LAN client behind
# a router and a target network holding the matched address. Idempotent.
set -uo pipefail

ip link show br-lan >/dev/null 2>&1 || ip link add br-lan type bridge
ip addr add 192.0.2.1/24 dev br-lan 2>/dev/null || true
ip link set br-lan up

ip netns show | grep -qx lan || ip netns add lan
ip link show lan-router >/dev/null 2>&1 || ip link add lan-router type veth peer name lan-client
ip link set lan-router master br-lan
ip link set lan-router up
ip link set lan-client netns lan 2>/dev/null || true
ip netns exec lan ip link set lo up
ip netns exec lan ip link set lan-client name eth0 2>/dev/null || true
ip netns exec lan ip addr add 192.0.2.2/24 dev eth0 2>/dev/null || true
ip netns exec lan ip link set eth0 up
ip netns exec lan ip route replace default via 192.0.2.1

ip netns show | grep -qx target || ip netns add target
ip link show target-wan-r >/dev/null 2>&1 || ip link add target-wan-r type veth peer name target-wan-c
ip addr add 198.19.0.1/24 dev target-wan-r 2>/dev/null || true
ip link set target-wan-r up
ip link set target-wan-c netns target 2>/dev/null || true
ip netns exec target ip link set lo up
ip netns exec target ip link set target-wan-c name eth0 2>/dev/null || true
ip netns exec target ip addr add 198.19.0.2/24 dev eth0 2>/dev/null || true
ip netns exec target ip addr add 149.154.160.10/32 dev lo 2>/dev/null || true
ip netns exec target ip link set eth0 up
ip netns exec target ip route replace default via 198.19.0.1
ip route replace 149.154.160.10/32 via 198.19.0.2 dev target-wan-r

sysctl -qw net.ipv4.ip_forward=1
sysctl -qw net.ipv4.conf.all.rp_filter=0
sysctl -qw net.ipv4.conf.default.rp_filter=0

ip rule show | grep -q 'fwmark 0x1 lookup 100' || ip rule add fwmark 0x1 lookup 100
ip route show table 100 | grep -q 'local 0.0.0.0/0 dev lo' || ip route add local 0.0.0.0/0 dev lo table 100

nft -f "${1:-/mnt/test/e2e/fixtures/tproxy.nft}"
