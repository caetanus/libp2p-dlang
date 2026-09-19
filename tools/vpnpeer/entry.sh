#!/bin/bash
set -e
mkdir -p /run/wireguard
python3 /httpd.py &
mkdir -p /root/.wgvpn
cp /wg/B.key /root/.wgvpn/wg.key; wg pubkey < /root/.wgvpn/wg.key > /root/.wgvpn/wg.pub
export VPN_BIN=/opt/vpn/bin VPN_STATE=/root/.wgvpn VPN_NODE=/usr/local/bin/wg-punch VPN_IFACE=wgvpn
echo "[vpnpeer] listener starting; wg pubkey $(cat /root/.wgvpn/wg.pub)"
exec /opt/vpn/vpn connect --role listener --wg-ip 10.9.0.2 \
   --emit-ticket /rv/b.ticket --peer-ticket-file /rv/b.peerticket
