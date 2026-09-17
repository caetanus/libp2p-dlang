#!/usr/bin/env bash
# Present a second, genuinely-NATed peer on the public server, so the two-NAT
# webrtc punch (2e) can be validated without a phone: run one punch-peer natively
# on your home desktop (behind the home CGNAT) and the other inside this network
# namespace on the server (behind an iptables NAT), with the relay-node on the
# server's public IP. Desktop(CGNAT) <-> server-netns(iptables NAT) is a real
# two-NAT punch across two distinct networks.
#
# Why this is a faithful testbed: Linux MASQUERADE gives ENDPOINT-INDEPENDENT
# mapping (the netns peer's src port maps to one stable external port regardless
# of destination) with endpoint-dependent *filtering* — which is exactly the
# "port-preserving / endpoint-independent" NAT class your natcheck measured on
# the desktop and the 4G side, and the class hole punching is designed for: the
# symmetric ICE in the punch (both sides send checks) opens the filter both ways.
# A phone on 4G stays the final real-world confirmation; this proves the mechanics.
#
# Run as root on the server:  sudo ./2e-netns-setup.sh <public-iface>   (e.g. eth0)
# Tear down:                  sudo ./2e-netns-setup.sh <public-iface> down
set -euo pipefail

NS=punchns
HOST_VETH=veth-h
NS_VETH=veth-n
HOST_IP=10.200.0.1
NS_IP=10.200.0.2
SUBNET=10.200.0.0/24
IFACE="${1:?usage: 2e-netns-setup.sh <public-iface> [down]}"
ACTION="${2:-up}"

if [[ "$ACTION" == "down" ]]; then
    ip netns del "$NS" 2>/dev/null || true
    ip link del "$HOST_VETH" 2>/dev/null || true
    iptables -t nat -D POSTROUTING -s "$SUBNET" -o "$IFACE" -j MASQUERADE 2>/dev/null || true
    iptables -D FORWARD -i "$HOST_VETH" -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -o "$HOST_VETH" -j ACCEPT 2>/dev/null || true
    echo "torn down."
    exit 0
fi

ip netns add "$NS"
ip link add "$HOST_VETH" type veth peer name "$NS_VETH"
ip link set "$NS_VETH" netns "$NS"

ip addr add "$HOST_IP/24" dev "$HOST_VETH"
ip link set "$HOST_VETH" up
ip netns exec "$NS" ip addr add "$NS_IP/24" dev "$NS_VETH"
ip netns exec "$NS" ip link set "$NS_VETH" up
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip route add default via "$HOST_IP"

sysctl -q -w net.ipv4.ip_forward=1
# Endpoint-independent mapping is the default; MASQUERADE it out the public iface.
iptables -t nat -C POSTROUTING -s "$SUBNET" -o "$IFACE" -j MASQUERADE 2>/dev/null \
    || iptables -t nat -A POSTROUTING -s "$SUBNET" -o "$IFACE" -j MASQUERADE
iptables -C FORWARD -i "$HOST_VETH" -j ACCEPT 2>/dev/null || iptables -A FORWARD -i "$HOST_VETH" -j ACCEPT
iptables -C FORWARD -o "$HOST_VETH" -j ACCEPT 2>/dev/null || iptables -A FORWARD -o "$HOST_VETH" -j ACCEPT

# DNS inside the namespace, so the punch-peer can resolve the STUN hostname.
mkdir -p "/etc/netns/$NS"
echo "nameserver 8.8.8.8" > "/etc/netns/$NS/resolv.conf"

echo "netns '$NS' ready (peer NATed behind $IFACE)."
echo "sanity:  ip netns exec $NS getent hosts stun.l.google.com"
echo "run the punched peer inside it, e.g.:"
echo "  ip netns exec $NS ./bin/punch-peer --relay /ip4/<server-public-ip>/tcp/<port>/p2p/<relayId> --role responder"
