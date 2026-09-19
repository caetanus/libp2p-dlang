#!/bin/bash
VPSPUB=62.238.38.245
D=$PWD/bin/interop-peer
GO=$PWD/interop/go-peer/go-peer
RUST=$PWD/interop/rust-peer/target/release/interop-rust-peer
HGO='$HOME/go-peer'; HRUST='$HOME/rust-peer'; HD='$HOME/lab/libp2p-dlang/bin/interop-peer'
hstop(){ ssh -o BatchMode=yes hetzner 'pkill -x go-peer; pkill -x rust-peer; pkill -x interop-peer; true' >/dev/null 2>&1; }
hlisten(){ # $1=remote bin -> echoes pubaddr
  ssh -o BatchMode=yes hetzner "rm -f /tmp/hl.log; LISTEN_HOST=0.0.0.0 LD_LIBRARY_PATH=/usr/local/lib nohup $1 listen >/tmp/hl.log 2>&1 & sleep 0.2; true" >/dev/null 2>&1
  local a=""
  for i in $(seq 1 40); do a=$(ssh -o BatchMode=yes hetzner "grep -m1 '^LISTEN ' /tmp/hl.log 2>/dev/null"); [ -n "$a" ] && break; sleep 0.4; done
  local port id
  port=$(echo "$a" | grep -oE '/tcp/[0-9]+' | head -1 | cut -d/ -f3)
  id=$(echo "$a" | grep -oE '/p2p/[A-Za-z0-9]+' | head -1 | cut -d/ -f3)
  [ -n "$port" ] && [ -n "$id" ] && echo "/ip4/$VPSPUB/tcp/$port/p2p/$id"
}
run(){ hstop; local addr=$(hlisten "$2")
  if [ -z "$addr" ]; then echo "$3: FAIL (no LISTEN on vps)"; return; fi
  if timeout 45 "$1" dial "$addr" >/tmp/wgt/cd.log 2>&1; then echo "$3: PASS  ($addr)"; else echo "$3: FAIL"; tail -1 /tmp/wgt/cd.log; fi
  hstop; }
run "$D"    "$HGO"   "D(local)->go(vps)"
run "$D"    "$HRUST" "D(local)->rust(vps)"
run "$GO"   "$HD"    "go(local)->D(vps)   [inverte]"
run "$RUST" "$HD"    "rust(local)->D(vps) [inverte]"
run "$GO"   "$HRUST" "go->rust(vps)  (control)"
