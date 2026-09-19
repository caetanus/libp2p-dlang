# vpnpeer — the `vpn` CLI as a NAT'd container peer (for testing / a headless node)

Runs the same `tools/vpn` CLI with **userspace WireGuard** inside a Docker
container, so it sits behind Docker's NAT — used to test the serverless
WireGuard-over-libp2p punch against a peer behind a real second NAT (e.g. on a
VPS whose host has a public IP).

Build context needs, alongside this dir:
  - `wg-punch`        the node binary (`dub build -c wg-punch`), built for the image's distro
  - `wireguard-go`    a linux-amd64 userspace WireGuard (`git clone https://git.zx2c4.com/wireguard-go && go build`)
  - `lib/`            the matching `libngtcp2*.so*` (1.25) the node links

Run (privileged for the TUN + module; bridge network = the NAT):
  docker run -d --name vpnb --cap-add NET_ADMIN --device /dev/net/tun \
     -v $PWD/wg:/wg -v $PWD/rv:/rv vpnpeer:latest
It writes its ticket to /rv/b.ticket and waits for the peer's at /rv/b.peerticket.
