#!/bin/bash
set -e
mkdir -p /run/wireguard /root/.wgvpn
python3 /httpd.py &
export VPN_BIN=/opt/vpn/bin VPN_STATE=/root/.wgvpn VPN_NODE=/usr/local/bin/wg-punch VPN_IFACE=wgvpn VPN_RENDEZVOUS=/opt/vpn/bin/vpn-rendezvous
echo "[vpnpeer-dht] discovering peer over the DHT (secret set)..."
exec /opt/vpn/vpn connect-dht --secret "$SECRET" --grace 12
