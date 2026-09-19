#!/bin/bash
D=$PWD/bin/interop-peer
GO=$PWD/interop/go-peer/go-peer
RUST=$PWD/interop/rust-peer/target/release/interop-rust-peer
W=$(mktemp -d)
run(){ # $1=dialerBin $2=listenerBin $3=label
  "$2" listen >"$W/l.log" 2>&1 & lp=$!
  for i in $(seq 1 60); do grep -q '^LISTEN ' "$W/l.log" && break; sleep 0.3; done
  addr=$(grep -m1 '^LISTEN ' "$W/l.log" | cut -d' ' -f2 | sed 's#/ip4/0.0.0.0/#/ip4/127.0.0.1/#')
  if [ -z "$addr" ]; then echo "$3: FAIL (no LISTEN)"; kill $lp 2>/dev/null; return; fi
  if timeout 40 "$1" dial "$addr" >"$W/d.log" 2>&1; then echo "$3: PASS"; else echo "$3: FAIL"; sed -n '$p' "$W/d.log"; fi
  kill $lp 2>/dev/null; wait $lp 2>/dev/null
}
run "$D"    "$GO"   "D    -> go  "
run "$GO"   "$D"    "go   -> D   "
run "$D"    "$RUST" "D    -> rust"
run "$RUST" "$D"    "rust -> D   "
run "$GO"   "$RUST" "go   -> rust (control)"
run "$RUST" "$GO"   "rust -> go   (control)"
rm -rf "$W"
