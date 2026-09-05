# libp2p-dlang

libp2p in D, on vibe-core fibers, crypto on libsodium.

This branch (`v2`) is a restart. The previous codebase, laundered from
rust-libp2p, lives on `new-version` and is kept as a quarry: its tests and wire
vectors are under `contract/` and move into `tests/` as each module is rebuilt
against the new architecture. Nothing else from it is reused.

Read `DESIGN.md` first. It states the laws every module is reviewed against,
the layer interfaces, and the build order for milestone 1: TCP, noise, yamux,
a swarm, ping and identify, interoperating with a real rust-libp2p node in both
directions.

```
dub build                 # the library
tools/run-tests.sh        # the gate: tests, no fibers left, no descriptors left
interop/run-interop.sh    # both dial directions against a real rust-libp2p node
```

Milestone 1 is reached and both checks are green; identify/push, Kademlia,
gossipsub, circuit relay v2 with DCUtR, and AutoNAT followed. What remains under
`contract/` belongs to later milestones (mplex, plaintext, DNS, mdns, WebRTC) and
is untouched until its turn.
