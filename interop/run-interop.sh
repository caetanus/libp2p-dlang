#!/usr/bin/env bash
#
# Talk to a real rust-libp2p node.
#
# Everything else in this repository checks libp2p-dlang against itself or
# against pinned byte vectors. Neither can catch the failure that matters most
# here: a shared misreading. When the dialer, the listener and the vectors all
# come from the same author, a protocol detail understood wrongly is understood
# wrongly consistently, and the whole suite agrees with itself.
#
# Two runs, because the two dial directions exercise different code, and each
# run is bidirectional once connected — a libp2p connection is symmetric, so the
# peer that dialed is also expected to answer.
#
#   1. D dials rust    D must ping AND read rust's identify;
#                      rust must ping and identify us back.
#   2. rust dials D    rust must ping and identify;  D must serve both.
#
# Both identify directions matter and only one used to be checked: a node that
# answers identify has proved it can encode one, not that it can read the
# reference implementation's.
#
# Stack under test, in both: TCP -> multistream-select -> Noise XX -> yamux ->
# multistream-select -> ping / identify.
#
# Usage: interop/run-interop.sh
# Exit:  0 = both directions verified, 1 = anything else.
set -uo pipefail

cd "$(dirname "$0")/.."

work=$(mktemp -d)
pids=()
cleanup() {
    for p in "${pids[@]:-}"; do kill -9 "$p" 2>/dev/null; done
    rm -rf "$work"
}
trap cleanup EXIT

status=0
fail() { echo "FAIL  $1"; status=1; }
pass() { echo "ok    $1"; }

echo "── building ──"
dub build -q -c interop-peer || { echo "FAIL  could not build interop-peer"; exit 1; }
(cd interop/rust-peer && cargo build --release --quiet) \
    || { echo "FAIL  could not build the rust peer"; exit 1; }
rust=interop/rust-peer/target/release/interop-rust-peer

# Wait for a process to announce its address rather than sleeping a guess: a
# fixed sleep turns "slower than I assumed" into "broken", which is a mistake
# this repository has already paid for once.
await_listen() {
    local log=$1 tries=0
    while [ $tries -lt 200 ]; do
        if grep -q '^LISTEN ' "$log" 2>/dev/null; then return 0; fi
        sleep 0.05
        tries=$((tries + 1))
    done
    return 1
}

echo
echo "── 1. D dials rust ──"
"$rust" listen >"$work/rust1.log" 2>&1 &
pids+=($!)
if await_listen "$work/rust1.log"; then
    addr=$(grep -m1 '^LISTEN ' "$work/rust1.log" | cut -d' ' -f2)
    if timeout 40 ./bin/interop-peer dial "$addr" >"$work/d1.log" 2>&1; then
        grep -q '^PING ' "$work/d1.log" \
            && pass "D pinged rust over Noise+yamux ($(grep -m1 '^PING ' "$work/d1.log"))" \
            || fail "D connected but reported no ping"
        # Answering identify only proves we can encode one. Decoding the
        # reference implementation's is the half that catches a field read
        # wrongly, and D checks the record's peer id against the one Noise
        # authenticated rather than trusting what the record claims.
        grep -q '^IDENTIFY ' "$work/d1.log" \
            && pass "D read rust's identify ($(grep -m1 '^IDENTIFY ' "$work/d1.log" | cut -d' ' -f3-))" \
            || fail "D did not decode rust's identify"
    else
        fail "the D dialer exited non-zero"
    fi
    # Give the rust side a moment to finish reporting, then read its verdict.
    sleep 2
    grep -q '^OK ' "$work/rust1.log" \
        && pass "rust pinged and identified D back over the same connection" \
        || fail "rust did not complete its half: $(tail -3 "$work/rust1.log" | tr '\n' ' ')"
else
    fail "the rust peer never announced a listen address"
fi
cat "$work/rust1.log" | sed 's/^/      rust: /'
cat "$work/d1.log" 2>/dev/null | sed 's/^/      D:    /'

echo
echo "── 2. rust dials D ──"
./bin/interop-peer listen >"$work/d2.log" 2>&1 &
pids+=($!)
if await_listen "$work/d2.log"; then
    addr=$(grep -m1 '^LISTEN ' "$work/d2.log" | cut -d' ' -f2)
    if timeout 40 "$rust" dial "$addr" >"$work/rust2.log" 2>&1; then
        grep -q '^OK ' "$work/rust2.log" \
            && pass "rust pinged and identified a D listener ($(grep -m1 '^PING ' "$work/rust2.log"))" \
            || fail "rust connected but did not complete"
    else
        fail "the rust dialer exited non-zero"
    fi
else
    fail "the D peer never announced a listen address"
fi
cat "$work/rust2.log" 2>/dev/null | sed 's/^/      rust: /'

echo
echo "──────── interop ────────"
if [ $status -eq 0 ]; then
    echo "PASS  both directions verified against the rust-libp2p release pinned in"
    echo "      interop/rust-peer/Cargo.toml"
else
    echo "FAIL"
fi
exit $status
