# libp2p-dlang v2 — design for milestone 1

**Status:** proposal, awaiting the author's approval. No module is written until
the seams below are agreed. Where a choice is still open it is marked **OPEN**
with a recommendation.

**What this is.** A libp2p node in D, on vibe-core fibers, with an architecture
that is ours. go-libp2p is consulted when a concurrency or lifecycle question
comes up, because goroutines are fibers; rust-libp2p is consulted for wire
formats, defaults and test vectors, never for shape. The previous codebase
(branch `new-version`) was laundered from rust and is kept as a quarry: its
tests and vectors live under `contract/` and are brought into `tests/` one by
one, as the module each covers is built.

**Milestone 1.** `tcp → noise → yamux`, a swarm that owns its connections, a
host that hands protocol streams to handlers, and `ping` + `identify` on top —
talking to a real rust-libp2p node in both directions
(`interop/rust-peer`), with connection close and cancellation that leave zero
fibers and zero file descriptors behind. Nothing else is started until this
passes the gate in `tools/run-tests.sh` and the interop script.

---

## 1. Laws

These are not preferences. Every review of every module asks these five
questions first.

1. **A blocking operation ends two ways: the result, or a throw.** No null, no
   bool, no zero-count-means-EOF, no `isClosed()` pre-condition. `read(buf)`
   returns 1..buf.length bytes or throws an `Ending`. A caller writes the call
   and nothing else.
2. **Cancellation is an exception, and the stack is the propagation.** Stopping
   a fiber is `Task.interrupt`; the `InterruptException` unwinds through the
   work, every `scope (exit)` and destructor runs, and the owner learns because
   the join returns. Work never catches it. Nothing is ever written with
   `waitUninterruptible`.
3. **Only the owner of a fiber catches.** A `catch` is legitimate only where the
   code can *decide* something with the exception. Logging is not a decision.
   The policy for a class of fibers is stated once, at the owner's `spawn`, not
   at every call site. Translating a foreign error into a typed `Ending` at a
   library boundary is the one other place a `catch` may appear, and it must
   rethrow.
4. **A claim that must be given back is a struct with `~this()`.** A slot in a
   connection limit, a registered stream in a session, a hold that keeps a
   connection from idle-closing, a temporary handler registration. The GC
   owns memory; RAII owns everything else. If releasing something requires
   remembering to call a method, the design is wrong.
5. **`select` lives inside the operation.** When an operation must race against
   its own ending (a read against the session dying, an accept against
   `close()`, a dial against its deadline), the race is inside the operation
   and the caller sees one call that returns or throws. Mechanism never leaks
   upward: no `accept(Duration)`, no exposing queues and events for the caller
   to race.

Two derived rules: **no fiber without an owner** (every `runTask` is reachable
from an object whose `close()` interrupts and joins it), and **`close()` is
idempotent, blocking, and complete** — when it returns the fibers are joined
and the descriptors are gone, which is what the leak gate checks.

## 2. Layers

Bottom-up. Each layer sees only the interface of the one below.

```
 protocols     ping · identify                          (services on a Host)
 host          Host: handlers by protocol id, newStream, connect, notifiees
 swarm         Swarm: pool of Connection, listeners, dial, limits, idle close
 upgrade       raw Stream → SecureConn → Muxer          (a function, not a service)
 muxer         yamux: Session ⇒ many Stream
 security      noise XX: Stream → SecureConn (Stream + remote PeerId)
 multistream   multistream-select 1.0.0 over a Stream
 transport     tcp: dial(Multiaddr) → Stream, listen(Multiaddr) → Listener
 core          Stream · Ending · PeerId · Keypair · Multiaddr · select/cancel
 wire          varint · protobuf (UDA codec) · multihash · base58/multibase
```

### 2.1 core

**`Stream`** — the one byte-oriented surface, presented identically by a TCP
socket, a noise-secured connection and a yamux substream.

```d
interface Stream {
    size_t read(ubyte[] buf);          // ≥1 bytes, or throws an Ending
    void   write(const(ubyte)[] data); // all of it, or throws (sendall)
    void   close();                    // graceful; idempotent; never throws
    void   reset();                    // abortive; idempotent; never throws
}
```

Semantics follow the TCP socket API as Python exposes it: `sendall`,
`recv_into`, `close`. `close()` means "I am done, and I will not read any
more": on TCP it closes the socket, on yamux it sends FIN and discards what
still arrives (this is go-yamux's `Close`, and it is what identify and ping
need). `reset()` is RST. There is no `shutdown(how)`; a protocol that needs a
true half-close will get `closeWrite()` when one exists, not before.

> **OPEN A — `reset()` on the surface.** Recommendation: yes. FIN and RST are
> different bytes on the wire and the peer behaves differently on each; a
> handler that fails mid-protocol must be able to say so. Without it every
> abandonment looks like a clean finish, which is the `isNormalEnd` problem of
> the last codebase in a new hat.

**`Ending`** — the typed reasons a blocking operation stops. Carried from the
July work, whose tests already pin it (`contract/core/ending_test.d`):

```
Exception
└── Ending                 "the operation cannot continue; not a protocol error"
    ├── EndOfStream        peer finished speaking (FIN)
    ├── StreamReset        peer abandoned this stream (RST)
    └── ConnClosed         the connection under the stream is gone
        └── ConnResetByPeer
```

Foreign errors (vibe-core, libsodium) are translated **once**, at the boundary
where they are caught, by `asEnding`, which keeps the original as
`Throwable.next`. An unrecognised failure is left as it is, not promoted. A
`Cancelled`/`InterruptException` is *not* an `Ending`: it belongs to the owner,
and `catch (Ending)` must never swallow it.

**`select` / `waitAll` / cancellation** — the ~15-line wait-any the author
dictated: one fiber per alternative, first to finish takes a one-shot lock and
signals, losers are interrupted and joined before `select` returns. This is
the *only* racing primitive in the codebase; nothing uses vibe's
`asyncAwaitAny`/`Waitable`. Its tests carry (`contract/util/select_test.d`).

**Identity** — `Keypair` (Ed25519 via libsodium), `PublicKey` for all four
libp2p key types *as data* (we must parse and hash a peer's RSA or secp256k1
key to get its PeerId even though we sign only with Ed25519), `PeerId`
(multihash: identity for keys ≤ 42 bytes, sha2-256 otherwise). Vectors carry
from `contract/crypto` and `contract/core/peer_id_test.d`.

**`Multiaddr`** — binary form is canonical, string form is a view. Milestone 1
protocols: `ip4 ip6 tcp p2p dns dns4 dns6 dnsaddr`. Others are added when a
transport needs them, not in advance.

### 2.2 wire

Small, pure, vector-tested. `varint` (unsigned LEB128, 10-byte cap),
`multihash`, `base58btc`, `multibase` (base58btc + base32 for peer ids).

**protobuf.** No generator, no `tools/protogen`. A proto2 struct is a D struct
whose fields carry a UDA, and the codec is derived at compile time:

```d
struct IdentifyMsg {
    @field(5) Optional!string   protocolVersion;
    @field(6) Optional!string   agentVersion;
    @field(1) Optional!(ubyte[]) publicKey;
    @field(2) ubyte[][]          listenAddrs;
    @field(4) Optional!(ubyte[]) observedAddr;
    @field(3) string[]           protocols;
}
ubyte[] bytes = encode(msg);   IdentifyMsg m = decode!IdentifyMsg(bytes);
```

Wire types are inferred from the D type (varint for integers/bools/enums,
length-delimited for bytes/strings/nested structs, repeated for arrays);
unknown fields are skipped, as proto2 requires. The `.proto` files under
`proto/` are the spec we conform to and are what the tests read their field
numbers from. Milestone 1 needs three: `keys`, `noise_payload`, `identify`.

> **OPEN D — UDA codec vs generator.** Recommendation: UDA codec. It is a few
> hundred lines, it is where D is strongest (the author's stated wish for
> compile-time parameterisation), and it removes a build step and a binary
> from the repo.

### 2.3 transport (tcp)

```d
interface Transport {
    Stream   dial(Multiaddr remote);          // connected, or throws
    Listener listen(Multiaddr local);
    bool     canHandle(Multiaddr);
}
interface Listener {
    Stream   accept();                        // or throws ConnClosed after close()
    Multiaddr address();                      // the actual bound address
    void     close();                         // wakes accept() by *cancelling* it
}
```

`accept()` after `close()` throws; `close()` does not close a socket in order
to wake a parked accept, it interrupts the accepting fiber (law 5 and law 2).
DNS multiaddrs are resolved by the swarm before the transport sees them,
through vibe's resolver; c-ares comes back only if that proves insufficient.

### 2.4 multistream-select

Two free functions over a `Stream`:

```d
string negotiate(Stream s, string[] wanted);   // dialer: first the listener accepts, or throws
string listen(Stream s, string[] offered);      // listener: what the dialer chose, or throws
```

Protocol id strings are `/multistream/1.0.0` framed: varint length, id,
`\n`. `na` is a negative. The dialer sends the header and its first proposal
together (one write, as go and rust both do). Eager (V1) negotiation only;
lazy negotiation is an optimisation for later, and only if interop shows the
extra round trip matters.

### 2.5 security (noise)

Noise `XX_25519_ChaChaPoly_SHA256`, entirely on libsodium (no OpenSSL in
milestone 1). Frames are 2-byte big-endian length + payload, 65535 max. The
libp2p payload is the `NoiseHandshakePayload` protobuf carrying our identity
key and a signature over `"noise-libp2p-static-key:" ++ static_public`.

```d
SecureConn secureOutbound(Stream raw, Keypair local, Nullable!PeerId expected);
SecureConn secureInbound (Stream raw, Keypair local);
interface SecureConn : Stream { PeerId remotePeer(); PublicKey remoteKey(); }
```

A dial with an expected peer id that comes back as someone else throws before
the connection reaches the swarm. Handshake vectors carry from
`contract/security/noise_test.d`.

### 2.6 muxer (yamux)

```d
interface Muxer {
    Stream open();              // outbound substream, or throws ConnClosed
    Stream accept();            // inbound substream, or throws ConnClosed
    void   close();             // graceful GoAway; interrupts open/accept; joins the reader
    bool   isClosed();          // for sweeping dead sessions from a list — never a pre-condition
}
Muxer yamuxClient(Stream secured, YamuxConfig);
Muxer yamuxServer(Stream secured, YamuxConfig);
```

One reader fiber per session owns demultiplexing: it reads frames, credits
per-stream receive buffers, wakes waiting readers, answers pings, and on any
error closes the session with that error as the cause of every stream's
`ConnClosed`. Writers write directly to the underlying stream under a
`TaskMutex`; go-yamux's send loop is the alternative if fairness ever shows
up as a problem.

Windows: 256 KiB initial receive window per stream, window updates when half is
consumed; a peer that overruns is a protocol error and resets the session.
Stream ids: odd for the client, even for the server; 32-bit, no reuse. The
substream's `close()` sends FIN and marks the stream as discarding inbound
data; `reset()` sends RST. Each substream holds a struct `Slot` in the
session's table whose destructor removes it: a stream cannot be dropped and
left registered.

> **OPEN C — direct writes under a mutex vs a send loop.** Recommendation:
> mutex. Simpler, one fewer fiber per connection, and TCP backpressure stalls
> writers either way. The tests in `contract/muxer/yamux_test.d` (664 lines)
> are the acceptance bar and do not care which.

mplex is *not* in milestone 1. rust's default is yamux and nothing in the
interop target speaks mplex.

### 2.7 upgrade

A function: `MuxedConn upgrade(Stream raw, Endpoint role, Keypair local,
Nullable!PeerId expected, UpgradeConfig cfg)`. Negotiates security with
multistream-select (`/noise`), secures, negotiates the muxer (`/yamux/1.0.0`),
returns the muxer plus the remote's identity. It takes no host, no swarm, no
callback: the last codebase learned the hard way that "the upgrade is a rung,
not a service the host does you."

### 2.8 swarm

The swarm is the pool and the owner of every network fiber. It has no
`NetworkBehaviour`, no event queue the user polls and no `poll()`.

```d
final class Swarm {
    this(Keypair local, Transport[] transports, SwarmConfig cfg);

    void       listen(Multiaddr);                       // starts an accept loop
    Connection connect(PeerId, Multiaddr[] addrs);      // existing or new; or throws
    Connection connection(PeerId);                      // existing or throws NotConnected
    Stream     newStream(PeerId, string[] protocols);   // negotiated; or throws
    void       setStreamHandler(string proto, StreamHandler);
    void       addNotifiee(Notifiee);                   // connected / disconnected
    void       close();                                 // everything, joined
}
final class Connection {
    PeerId    remotePeer();  Multiaddr remoteAddr();  Endpoint role();
    Stream    newStream(string[] protocols);            // or throws
    Hold      hold();                                   // RAII: no idle-close while alive
    void      close();                                  // cancels its fibers, then the muxer
}
```

**Fibers and who owns them.**

| fiber | owner | on failure |
|---|---|---|
| accept loop (one per listener) | Swarm | listener closes; swarm logs once |
| dial (one per attempt) | Swarm | throws to the `connect()` caller |
| muxer reader | Connection | connection closes with that cause |
| inbound-stream loop (accept → negotiate → handler) | Connection | the stream is reset; the connection lives |
| one handler invocation | Connection | same as above |
| idle timer | Connection | n/a; `Hold` count > 0 suppresses it |

`Connection.close()` interrupts and joins all of those, then closes the muxer
(as a consequence, not as the mechanism), then notifies `disconnected`. The
`Notifiee` is called from the connection's own fiber after it is fully gone,
so a notifiee that dials again never observes the dying connection.

**Limits** as RAII `Lease`s from a `Limiter`: pending inbound, pending
outbound, established total, established per peer. An inbound connection
takes a pending lease *before* it is upgraded (admit before paying), converts
it to an established lease on success, and the destructor returns whichever
it holds. rust's defaults are the initial values; the shape is ours.

**Dial** is `select` over the attempts to each address (α = 1 in milestone 1,
concurrent later) and a deadline; the first `Connection` wins, the rest are
interrupted and their half-open sockets closed by their destructors. A dial
to a peer already connected returns the existing connection.

> **OPEN B — Go-shaped host or a behaviour trait.** Recommendation:
> Go-shaped. Protocols are ordinary objects holding a `Swarm` (or the `Host`
> façade), registering handlers and spawning their own owned fibers. There is
> no central event loop to feed and nothing to poll. This is the single
> largest departure from rust and the one the fiber model makes natural.

### 2.9 host

`Host` is a thin façade over `Swarm` plus a `Peerstore` (addresses and
protocols per peer, in memory) and the local node's advertised protocol list,
which identify reads. It exists so protocols depend on an interface rather
than on the pool.

### 2.10 protocols

**ping** (`/ipfs/ping/1.0.0`): handler echoes 32-byte frames until the peer
closes. Client side is a service: one fiber per connection (owned by the
service, stopped by `disconnected` or `Ping.close()`), open stream, send 32
random bytes, read 32 back, compare, report the RTT, sleep `interval`, repeat;
after `timeout` or a mismatch the stream is reset and the failure is reported.
rust's defaults: 15 s interval, 20 s timeout.

**identify** (`/ipfs/id/1.0.0`): on `connected` the service opens a stream,
reads one protobuf message to EOF, verifies the public key matches the peer
id, records the peer's addresses and protocols in the peerstore, and reports.
The handler side writes our message and `close()`s. `identify/push` is *not*
milestone 1. The 375-byte go-libp2p interop vector that rust's
`protobuf_roundtrip` carries is a required test.

## 3. Tests and the gate

- Unit tests are vectors and behaviour, in `tests/`, run with `dub run -c ut`
  under the July harness rules (fluent-asserts only, explicit module list,
  `scheduler = null`, no `.should` inside a fiber body).
- Integration tests run real loopback TCP inside the `ut` binary, driving the
  event loop explicitly; the in-process fiber pipe from `contract/util` is
  rewritten only if a pure-codec test needs it.
- `tools/run-tests.sh` is the gate from the first commit: exit code, zero
  tasks still running, zero eventcore handles at teardown. Any entry is a
  regression, not noise.
- Interop (`interop/rust-peer`, both directions) is the acceptance test for
  milestone 1 and runs in CI.
- A file in `contract/` is deleted when its assertions live in `tests/` against
  the new API, or when it is judged a shape test with a note in the commit.
  `contract/` empty for the milestone-1 modules is part of "done".

## 4. Build order

Each step: the module, its carried tests, gate green, one commit. No step
begins before the previous one is committed.

1. `core.ending`, `util.select` + cancellation — carried tests.
2. `wire.varint`, `multihash`, `base58`, `multibase`; `core.multiaddr`.
3. `crypto.keys` (Ed25519 + the four key types as data), `core.peer_id`.
4. `wire.protobuf` UDA codec, tested against `keys.proto` and `identify.proto`.
5. `core.stream`, `transport.tcp` — loopback tests, gate proves close leaks nothing.
6. `multistream`.
7. `security.noise` — vectors, then a loopback handshake.
8. `muxer.yamux` — the 664-line contract; loopback session tests; cancellation tests.
9. `upgrade`, `swarm`, `host` — limits, dial, idle close, `Hold`, notifiees.
10. `protocol.ping`, `protocol.identify`.
11. interop script rewritten; both directions green; CI.

## 5. Not in milestone 1

QUIC (ngtcp2), WebRTC, WebSocket, mplex, plaintext, relay, dcutr, autonat,
kad, gossipsub, mdns, identify/push, DNS via c-ares, the browser/WASM target.
Their contract tests stay in `contract/` untouched until their turn.
