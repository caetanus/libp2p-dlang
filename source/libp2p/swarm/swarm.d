/**
 * The swarm: the pool of connections and the owner of every network fiber.
 *
 * There is no behaviour trait, no event queue to poll and no `poll()`.
 * Protocols register a handler per protocol id and are told, through a
 * `Notifiee`, when a connection appears or goes; everything else they do is
 * ordinary blocking code on fibers they own. The swarm owns the accept loops
 * and the fibers that admit inbound connections; each connection owns the
 * fibers that serve it.
 *
 * Admission is "admit before paying": an inbound connection takes a pending
 * slot and passes the gater before the handshake runs, then converts the slot
 * to an established one. Both are leases on the fiber's stack, so a failure
 * anywhere in between returns them by unwinding.
 */
module libp2p.swarm.swarm;

import core.time : msecs, Duration, seconds;
import std.algorithm.mutation : move;
import std.algorithm.searching : canFind, find;
import std.range : empty, front;
import std.exception : enforce;
import std.typecons : Nullable, nullable;

import vibe.core.log : logDebug, logDiagnostic;
import vibe.core.task : InterruptException;

import libp2p.core.ending;
import libp2p.core.peer_id : PeerId;
import libp2p.core.stream : Stream;
import libp2p.core.upgrade;
import libp2p.crypto.keys : Keypair, PublicKey;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.muxer.muxer : Muxer;
import libp2p.muxer.yamux : YamuxFactory;
import libp2p.security.noise : NoiseTransport;
import libp2p.security.security : SecureTransport;
import libp2p.swarm.connection;
import libp2p.swarm.limiter;
import libp2p.transport.transport;
import libp2p.transport.dns : DnsResolver, resolve, needsResolution;
version (LibP2P_Lite) {} else import libp2p.transport.dns_cares : CaresDns;
import libp2p.util.fibers : FiberGroup;
import libp2p.util.timeout : withTimeout;

public import libp2p.swarm.connection : Connection, Hold, Notifiee, StreamHandler;
public import libp2p.swarm.limiter : Limits, LimitExceeded, LimitKind;

struct SwarmConfig
{
	Limits limits;
	/// Close a connection nobody holds and nobody is serving after this long.
	/// Zero disables idle closing.
	Duration idleTimeout = Duration.zero;
	Duration dialTimeout = 10.seconds;
	Duration handshakeTimeout = 10.seconds;
	size_t maxConcurrentDials = 8; /// addresses of one peer dialed at once (happy eyeballs)
	Duration dialStagger = 100.msecs; /// pause between launching two of them
	/// The most inbound substreams one connection will serve at once. A peer that
	/// keeps opening streams would otherwise pile up an unbounded number of handler
	/// fibers; at the ceiling the connection stops accepting, and the muxer resets
	/// the peer's streams past its own backlog. 0 is unlimited.
	uint maxInboundStreams = 256;
	/// Stream muxers offered in negotiation order. Empty ⇒ [yamux] (the default).
	/// Set e.g. [new MplexFactory] to offer mplex — used to validate the mplex muxer
	/// D↔D over a real connection, self-standing (no rust interop).
	MuxerFactory[] muxers;
	/// Security transports offered in negotiation order, built from the host's
	/// identity. null ⇒ [Noise] (the default). Set e.g. (k) => [new
	/// PlaintextTransport(k)] to offer plaintext — used to validate it D↔D.
	SecureTransport[] delegate(Keypair identity) securityFactory;
}

/// A connection that arrives already authenticated and multiplexed: what a
/// transport with its own security and muxing (webrtc-direct) hands over.
struct UpgradedConn
{
	Muxer muxer;
	PeerId remotePeer;
	PublicKey remoteKey;
	Multiaddr localAddr;
	Multiaddr remoteAddr;
}

/// A transport that does the whole upgrade itself. The swarm still owns
/// admission: limits, the gater, the pool.
interface CapableTransport
{
	bool canHandle(const Multiaddr addr);
	UpgradedConn dial(const Multiaddr remote, Nullable!PeerId expected);
	/// Start listening; `onInbound` is called with each connection, on a fiber
	/// of the transport's. Returns the address actually listening on.
	Multiaddr listen(const Multiaddr local, void delegate(UpgradedConn) onInbound);
	/// Our address on this transport a NAT'd peer could reach after a hole punch
	/// (a server-reflexive webrtc-direct address), or Multiaddr.init if none.
	/// Gathered lazily; may block briefly the first time.
	Multiaddr reflexiveAddr();
	/// Begin gathering the reflexive address in the BACKGROUND (idempotent), so a
	/// DCUtR offer reads a warm srflx instead of blocking on STUN — and so it exists
	/// before the first punch. The relay service calls it when a relayed connection
	/// forms (a punch is imminent); a transport with none may no-op. Must never
	/// throw or block — it runs in the connection-admission (notifiee) path.
	void startReflexive() nothrow;
	/// Punch a direct connection to `remote` at its reflexive address `peerSrflx`,
	/// reusing the mapping reflexiveAddr() gathered. Both peers call this at once
	/// (DCUtR), with `asDialer` splitting the one asymmetric role a hole punch
	/// still needs (the securing handshake's client vs. server).
	UpgradedConn punch(const Multiaddr peerSrflx, PeerId remote, bool asDialer, Nullable!PeerId expected);
	void close() nothrow;
}

/// Policy on who may connect. Every method answers true by default.
interface ConnectionGater
{
	/// Before the handshake: may this remote address connect to us at all?
	bool allowInbound(Multiaddr remote);
	/// After the handshake, either direction: may we keep a connection to this peer?
	bool allowPeer(PeerId peer, Endpoint role);
}

final class NotConnected : Exception
{
	this(PeerId peer, string file = __FILE__, size_t line = __LINE__)
	{
		super("not connected to " ~ peer.toString, file, line);
	}
}

final class DialFailure : Exception
{
	this(string msg, Throwable cause = null, string file = __FILE__, size_t line = __LINE__)
	{
		super(msg, file, line, cause);
	}
}

/// The shared state of one happy-eyeballs dial (see Swarm.dialAny): heap-owned,
/// so the dial tasks and the caller never share a stack frame.
private final class DialRace
{
	import vibe.core.sync : LocalManualEvent, createManualEvent;
	import vibe.core.task : Task;

	Connection winner;
	Exception last;
	size_t finished;
	Task[] tasks;
	bool done; /// the caller has left; late results are disposed of, not reported
	LocalManualEvent changed;

	this()
	{
		changed = createManualEvent();
	}
}

final class Swarm
{
	private PeerId localPeer_;
	private Keypair identity;
	private SwarmConfig cfg;
	private Transport[] transports;
	private CapableTransport[] capable;
	private Multiaddr[] capableAddrs;
	private UpgradeConfig upgradeCfg;
	private ConnectionGater gater;
	private Limiter limiter;
	/// How names in addresses are resolved; replaceable for tests.
	DnsResolver resolver;

	private Connection[] pool;
	private Listener[] listeners;
	private StreamHandler[string] handlers;
	private string[] protocolIds; // registration order, offered to the peer
	private Notifiee[] notifiees;

	private FiberGroup fibers; // accept loops and admissions
	private bool closed;

	this(Keypair identity, Transport[] transports, SwarmConfig cfg = SwarmConfig.init, ConnectionGater gater = null)
	{
		this.identity = identity;
		this.localPeer_ = PeerId.fromPublicKey(identity.publicKey);
		this.transports = transports;
		this.cfg = cfg;
		this.gater = gater;
		this.limiter = new Limiter(cfg.limits);
		version (LibP2P_Lite) {} else resolver = new CaresDns;   // lite (the phone): no c-ares, IP addresses only
		upgradeCfg.security = cfg.securityFactory !is null
			? cfg.securityFactory(identity) : [cast(SecureTransport) new NoiseTransport(identity)];
		upgradeCfg.muxers = cfg.muxers.length ? cfg.muxers : [cast(MuxerFactory) new YamuxFactory];
		// An admission that fails is one connection not made; the swarm goes on.
		fibers = new FiberGroup((Exception e) nothrow {
			logDebug("libp2p: inbound connection not admitted: %s", e.msg);
		});
	}

	PeerId localPeer() const
	{
		return PeerId(localPeer_.bytes.dup);
	}

	PublicKey localKey() const
	{
		return identity.publicKey;
	}

	const(SwarmConfig) config() const @safe pure nothrow
	{
		return cfg;
	}

	/// Another way to dial and listen (a relay client, say).
	void addTransport(Transport t)
	{
		transports ~= t;
	}

	/// A transport that secures and multiplexes on its own.
	/// Reflexive addresses our self-securing transports offer for a hole punch
	/// (webrtc-direct srflx), for DCUtR to advertise over the relay.
	Multiaddr[] reflexiveAddrs()
	{
		Multiaddr[] out_;
		foreach (t; capable)
		{
			auto a = t.reflexiveAddr();
			if (a.bytes.length)
				out_ ~= a;
		}
		return out_;
	}

	/// Warm every capable transport's reflexive-address cache ahead of a punch, so
	/// the next DCUtR offer carries a public srflx without blocking on STUN. Best
	/// effort and nothrow: one transport's failure never stops the others or the
	/// caller (this runs in the notifiee path, right before an auto-punch spawns).
	void startReflexive() nothrow
	{
		foreach (t; capable)
			try
				t.startReflexive();
			catch (Exception)
			{
			}
	}

	void addCapableTransport(CapableTransport t)
	{
		capable ~= t;
	}

	/// Punch a direct connection to `peer` at its reflexive address `addr` (a
	/// webrtc-direct srflx a capable transport gathered), and adopt it into the
	/// pool like any dialed one. `asDialer` carries the DCUtR initiator/responder
	/// split down to the one asymmetric role a hole punch keeps; the endpoint role
	/// follows it, so the limiter and gater see the initiator as a dialer.
	Connection punch(const Multiaddr addr, PeerId peer, bool asDialer)
	{
		enforce(!closed, "swarm: closed");
		foreach (t; capable)
			if (t.canHandle(addr))
			{
				auto up = withTimeout(cfg.dialTimeout + cfg.handshakeTimeout, "punch " ~ addr.toString,
					() => t.punch(addr, peer, asDialer, nullable(peer)));
				return admitCapable(up, asDialer ? Endpoint.dialer : Endpoint.listener);
			}
		throw new Exception("swarm: no capable transport for punch address " ~ addr.toString);
	}

	/// Dial `addr` as a hole punch on a raw transport (TCP): egress from our own
	/// listen port with address reuse, so the connect reuses the mapping the peer
	/// was told to expect. Both peers call this at once (DCUtR); with no matching
	/// listen port it falls back to a plain dial. `expected` pins the peer.
	Connection dialPunch(Multiaddr addr, PeerId expected)
	{
		enforce(!closed, "swarm: closed");
		return dialOne(addr, nullable(expected), tcpListenPort(addr));
	}

	// The port of our own listener that matches `addr`'s transport (TCP today), or
	// 0 if none — then dialPunch degrades to an ordinary dial.
	private ushort tcpListenPort(const Multiaddr addr)
	{
		if (!addr.components.canFind!(c => c.name == "tcp"))
			return 0;
		foreach (l; listeners)
			try
			{
				auto lc = l.address().components;
				auto tcp = lc.find!(c => c.name == "tcp");
				if (!tcp.empty)
					return cast(ushort)((tcp.front.value[0] << 8) | tcp.front.value[1]);
			}
			catch (Exception)
			{
			}
		return 0;
	}

	// --- listening ---------------------------------------------------------------------

	void listen(Multiaddr addr)
	{
		enforce(!closed, "swarm: closed");
		foreach (t; capable)
			if (t.canHandle(addr))
			{
				capableAddrs ~= t.listen(addr, (UpgradedConn up) { admitCapable(up, Endpoint.listener); });
				return;
			}
		auto l = transportFor(addr).listen(addr);
		listeners ~= l;
		fibers.spawn({ acceptLoop(l); });
	}

	Multiaddr[] listenAddrs()
	{
		Multiaddr[] out_;
		foreach (l; listeners)
			out_ ~= l.address;
		return out_ ~ capableAddrs;
	}

	/// Admission for a connection a capable transport upgraded itself.
	private Connection admitCapable(UpgradedConn up, Endpoint role)
	{
		scope (failure)
			up.muxer.close();
		if (gater !is null && !gater.allowPeer(up.remotePeer, role))
			throw new Exception("swarm: gater refused " ~ up.remotePeer.toString);
		auto established = limiter.established(role, up.remotePeer);
		Upgraded u;
		u.muxer = up.muxer;
		u.remotePeer = up.remotePeer;
		u.remoteKey = up.remoteKey;
		return admit(u, role, up.localAddr, up.remoteAddr, established);
	}

	// --- dialing -----------------------------------------------------------------------

	/// A connection to `peer`: the one we have, or a new one over `addrs`.
	Connection connect(PeerId peer, const(Multiaddr)[] addrs)
	{
		if (auto c = find(peer))
			return c;
		enforce(!closed, "swarm: closed");
		enforce(addrs.length > 0, "swarm: no addresses for " ~ peer.toString);
		return dialAny(expand(addrs), peer);
	}

	/// Connect to `peer` over a NEW path even though we may already hold a
	/// connection to it: a peer found on the LAN while its WAN connection still
	/// lives gets a second connection, and both stay in the pool (roaming: the
	/// application prefers one for new streams and migrates). Only an existing
	/// connection to one of these exact addresses is reused.
	Connection connectFresh(PeerId peer, const(Multiaddr)[] addrs)
	{
		enforce(!closed, "swarm: closed");
		enforce(addrs.length > 0, "swarm: no addresses for " ~ peer.toString);
		auto targets = expand(addrs);
		foreach (c; pool)
			if (c.remotePeer == peer && !c.isClosed && targets.canFind!(a => sameEndpoint(a, c.remoteAddr)))
				return c;
		return dialAny(targets, peer);
	}

	/// The connection new streams to a peer go on, when it has several: set by the
	/// application (a phone prefers Wi-Fi over a metered link). Given the live
	/// connections to the peer, returns the one to use. Null: direct over relayed,
	/// then the oldest.
	Connection delegate(Connection[]) nothrow preferConnection;

	// The same host+transport+port, ignoring a trailing /p2p/<id>.
	private static bool sameEndpoint(const Multiaddr a, const Multiaddr b)
	{
		auto x = a.components, y = b.components;
		if (x.length && x[$ - 1].name == "p2p")
			x = x[0 .. $ - 1];
		if (y.length && y[$ - 1].name == "p2p")
			y = y[0 .. $ - 1];
		if (x.length != y.length)
			return false;
		foreach (i; 0 .. x.length)
			if (x[i].name != y[i].name || x[i].value != y[i].value)
				return false;
		return true;
	}

	/// Dial `addrs` the happy-eyeballs way: up to `cfg.maxConcurrentDials` at once,
	/// each launched `cfg.dialStagger` after the previous, the first connection to
	/// come up wins and the rest are interrupted. A peer's address list is full of
	/// dead ends for whoever is dialing it (its LAN address from another network,
	/// its public address behind a NAT, a circuit whose relay it left) and each
	/// dead end costs a whole dial timeout; in sequence that was a minute before
	/// the one live address got its turn.
	private Connection dialAny(Multiaddr[] addrs, PeerId peer)
	{
		import vibe.core.task : Task;

		auto race = new DialRace;
		size_t next;
		try
		{
			while (race.winner is null)
			{
				immutable inFlight = race.tasks.length - race.finished;
				if (next < addrs.length && inFlight < cfg.maxConcurrentDials)
				{
					launchDial(race, addrs[next++], peer);
					if (race.winner is null && next < addrs.length && cfg.dialStagger > Duration.zero)
					{
						auto ec = race.changed.emitCount;
						race.changed.wait(cfg.dialStagger, ec); // a fast win or failure cuts the stagger short
					}
					continue;
				}
				if (race.finished == race.tasks.length && next >= addrs.length)
					break; // everything tried, nothing won
				auto ec = race.changed.emitCount;
				race.changed.wait(ec);
			}
		}
		finally
		{
			// The race is decided (or abandoned): the dials still running are told
			// to stop, and whatever they do from here on — a late connection, a late
			// failure — they do against `race`, never against this frame. A late
			// connection is closed by the task itself (see launchDial).
			race.done = true;
			auto me = Task.getThis();
			foreach (t; race.tasks)
				if (t != me && t.running)
					t.interrupt();
		}
		if (race.winner is null)
			throw new DialFailure("dial " ~ peer.toString ~ " failed: "
				~ (race.last is null ? "no address worked" : race.last.msg), race.last);
		return race.winner;
	}

	// One dial of the race, on its own task. Everything it touches lives in `race`
	// (a GC object shared with the other dials and with dialAny), so a task that
	// outlives dialAny — the stagger, the interrupt, a connection that came up
	// just as the race was decided — still has valid state to report into, and
	// once the race is done it reports nothing: it only disposes of what it made.
	private void launchDial(DialRace race, Multiaddr addr, PeerId peer)
	{
		import vibe.core.core : runTask;

		race.tasks ~= runTask((DialRace r, Multiaddr a, PeerId p) nothrow {
			Connection c;
			Exception failure;
			try
				c = dialOne(a, nullable(p));
			catch (InterruptException)
			{
			}
			catch (Exception e)
				failure = e;
			if (c !is null && (r.done || r.winner !is null))
			{
				c.close(); // the race is over (or another dial won): one connection is enough
				c = null;
			}
			if (r.done)
				return; // nobody is waiting on this race any more
			if (c !is null)
				r.winner = c;
			else if (failure !is null)
				r.last = failure;
			r.finished++;
			try
				r.changed.emit();
			catch (Exception)
			{
			}
		}, race, addr, peer);
	}

	/// Dial an address whose peer we do not know yet.
	Connection dial(Multiaddr addr)
	{
		enforce(!closed, "swarm: closed");
		Exception last;
		foreach (a; expand([addr]))
		{
			try
				return dialOne(a, Nullable!PeerId.init);
			catch (InterruptException e)
				throw e; // the dialer is being cancelled, not this address failing
			catch (Exception e)
				last = e;
		}
		throw new DialFailure("dial " ~ addr.toString ~ " failed: " ~ (last is null ? "no address to dial" : last.msg), last);
	}

	/// Names become addresses before a transport sees them.
	private Multiaddr[] expand(const(Multiaddr)[] addrs)
	{
		Multiaddr[] out_;
		foreach (a; addrs)
		{
			auto m = Multiaddr(a.bytes.dup);
			// A transport that already handles the unresolved address resolves the
			// name itself (WebSocket keeps the hostname for TLS SNI + the Host
			// header); only names no transport claims are resolved here.
			if (needsResolution(m) && !handledRaw(m))
			{
				if (resolver is null)
					throw new Exception("no DNS resolver in this build: " ~ m.toString);
				out_ ~= resolve(m, resolver);
			}
			else
				out_ ~= m;
		}
		return out_;
	}

	private bool handledRaw(const Multiaddr m)
	{
		foreach (t; transports)
		{
			try
				if (t.canHandle(m))
					return true;
			catch (Exception)
			{
			}
		}
		return false;
	}

	private Connection dialOne(const Multiaddr target, Nullable!PeerId expected, ushort reusePort = 0)
	{
		// An address may name its peer (`.../p2p/<id>`); transports dial the
		// part before it, and the name becomes the peer we expect.
		auto addr = Multiaddr(target.bytes.dup);
		auto comps = addr.components;
		if (comps.length > 0 && comps[$ - 1].name == "p2p")
		{
			auto named = PeerId.fromBytes(comps[$ - 1].value);
			enforce(expected.isNull || expected.get == named,
				"swarm: address names " ~ named.toString ~ " but " ~ expected.get.toString ~ " was expected");
			expected = named;
			// A relayed address (`.../p2p-circuit/p2p/<dst>`) keeps its destination:
			// the relay transport needs it. A plain one is dialed without.
			if (!comps.canFind!(c => c.name == "p2p-circuit"))
			{
				Multiaddr bare;
				foreach (c; comps[0 .. $ - 1])
					bare = bare ~ Multiaddr.parse("/" ~ c.name ~ (c.protocol.size != 0 ? "/" ~ c.text : ""));
				addr = bare;
			}
		}
		auto pending = limiter.pending(Endpoint.dialer);
		scope (exit)
			pending.release(); // and by unwinding, whichever comes first

		foreach (t; capable)
			if (t.canHandle(addr))
			{
				auto up = withTimeout(cfg.dialTimeout + cfg.handshakeTimeout, "dial " ~ addr.toString,
					() => t.dial(addr, expected));
				return admitCapable(up, Endpoint.dialer);
			}

		// A punch (reusePort != 0) egresses from our listen port with address reuse
		// when the transport supports it (TCP); otherwise a plain dial.
		RawConn raw = withTimeout(cfg.dialTimeout, "dial " ~ addr.toString, () {
			auto t = transportFor(addr);
			if (reusePort != 0)
				if (auto pt = cast(PunchableTransport) t)
					return pt.dialReusing(addr, reusePort);
			return t.dial(addr);
		});
		scope (failure)
			raw.close();

		Upgraded up = withTimeout(cfg.handshakeTimeout, "handshake with " ~ addr.toString,
			() => upgrade(raw, Endpoint.dialer, upgradeCfg, expected, reusePort != 0));
		scope (failure)
			up.muxer.close();

		if (gater !is null && !gater.allowPeer(up.remotePeer, Endpoint.dialer))
			throw new Exception("swarm: gater refused " ~ up.remotePeer.toString);

		auto established = limiter.established(Endpoint.dialer, up.remotePeer);
		return admit(up, Endpoint.dialer, raw.localAddr, raw.remoteAddr, established);
	}

	// --- the pool ----------------------------------------------------------------------

	Connection[] connectionsTo(PeerId peer)
	{
		Connection[] out_;
		foreach (c; pool)
			if (c.remotePeer == peer)
				out_ ~= c;
		return out_;
	}

	Connection connection(PeerId peer)
	{
		if (auto c = find(peer))
			return c;
		throw new NotConnected(peer);
	}

	bool isConnected(PeerId peer)
	{
		return find(peer) !is null;
	}

	PeerId[] connectedPeers()
	{
		PeerId[] out_;
		foreach (c; pool)
			if (!out_.canFind(c.remotePeer))
				out_ ~= c.remotePeer;
		return out_;
	}

	Connection[] connections()
	{
		return pool.dup;
	}

	/// Fibers serving connections right now, across the swarm.
	size_t liveTasks()
	{
		size_t n;
		foreach (c; pool)
			n += c.liveTasks;
		return n;
	}

	/// A negotiated stream to `peer`, on an existing connection.
	Stream newStream(PeerId peer, const(string)[] protocols, out string chosen)
	{
		return connection(peer).newStream(protocols, chosen);
	}

	// --- protocols and notifiees -----------------------------------------------------------

	void setStreamHandler(string protocol, StreamHandler handler)
	{
		if (protocol !in handlers)
			protocolIds ~= protocol;
		handlers[protocol] = handler;
	}

	void removeStreamHandler(string protocol)
	{
		import std.algorithm.mutation : remove;

		handlers.remove(protocol);
		protocolIds = protocolIds.remove!(p => p == protocol);
	}

	/// The protocol ids we answer to, in registration order.
	string[] protocols()
	{
		return protocolIds.dup;
	}

	package StreamHandler handlerFor(string protocol)
	{
		return handlers.get(protocol, null);
	}

	void addNotifiee(Notifiee n)
	{
		notifiees ~= n;
	}

	void removeNotifiee(Notifiee n)
	{
		import std.algorithm.mutation : remove;

		notifiees = notifiees.remove!(x => x is n);
	}

	// --- closing -----------------------------------------------------------------------

	/// Stop listening, close every connection, and wait for every fiber. When
	/// this returns nothing of the swarm is running.
	void close() nothrow
	{
		if (closed)
			return;
		closed = true;
		foreach (l; listeners)
			l.close(); // wakes the accept loops, which then leave
		foreach (t; capable)
			t.close();
		fibers.stopAll();
		foreach (c; pool.dup)
			c.close();
		listeners = null;
	}

	// --- internals ---------------------------------------------------------------------

	private void acceptLoop(Listener l)
	{
		try
		{
			for (;;)
			{
				auto raw = l.accept();
				fibers.spawn({ admitInbound(raw); });
			}
		}
		catch (ConnClosed)
		{
			// The listener was closed; that is how this loop ends.
		}
	}

	private Connection admitInbound(RawConn raw)
	{
		// Read the addresses up front: after the handshake the peer may already be
		// gone, and a closed socket has no addresses to report.
		auto local = raw.localAddr;
		auto remote = raw.remoteAddr;
		scope (failure)
			raw.close();

		auto pending = limiter.pending(Endpoint.listener);
		scope (exit)
			pending.release();
		if (gater !is null && !gater.allowInbound(raw.remoteAddr))
			throw new Exception("swarm: gater refused " ~ raw.remoteAddr.toString);

		Upgraded up = withTimeout(cfg.handshakeTimeout, "handshake with " ~ remote.toString,
			() => upgrade(raw, Endpoint.listener, upgradeCfg));
		scope (failure)
			up.muxer.close();

		if (gater !is null && !gater.allowPeer(up.remotePeer, Endpoint.listener))
			throw new Exception("swarm: gater refused " ~ up.remotePeer.toString);

		auto established = limiter.established(Endpoint.listener, up.remotePeer);
		return admit(up, Endpoint.listener, local, remote, established);
	}

	/// A raw connection established some other way (a relayed stream, say),
	/// taken through the upgrade as the dialer and into the pool.
	Connection admitOutbound(RawConn raw, Nullable!PeerId expected)
	{
		auto pending = limiter.pending(Endpoint.dialer);
		scope (exit)
			pending.release();
		scope (failure)
			raw.close();
		Upgraded up = withTimeout(cfg.handshakeTimeout, "handshake with " ~ raw.remoteAddr.toString,
			() => upgrade(raw, Endpoint.dialer, upgradeCfg, expected));
		scope (failure)
			up.muxer.close();
		if (gater !is null && !gater.allowPeer(up.remotePeer, Endpoint.dialer))
			throw new Exception("swarm: gater refused " ~ up.remotePeer.toString);
		auto established = limiter.established(Endpoint.dialer, up.remotePeer);
		return admit(up, Endpoint.dialer, raw.localAddr, raw.remoteAddr, established);
	}

	/// The same for one that arrived: the listener's side of the upgrade.
	Connection admitInboundRaw(RawConn raw)
	{
		enforce(!closed, "swarm: closed");
		return admitInbound(raw);
	}

	private Connection admit(ref Upgraded up, Endpoint role, Multiaddr local, Multiaddr remote, ref Lease established)
	{
		// A dial or handshake that was in flight when close() ran resumes here
		// after the swarm is already closed. Do not adopt it into a pool that
		// close() already drained (it would never be torn down); the caller's
		// scope(failure) disposes the muxer.
		enforce(!closed, "swarm: closed while a connection was upgrading");
		auto c = new Connection(this, up.muxer, role, up.remotePeer, up.remoteKey, local, remote, established);
		pool ~= c;
		c.start();
		// A throwing notifiee must not abort admission nor keep the others from
		// running (matches forget()'s disconnected() dispatch).
		foreach (n; notifiees.dup)
			try
				n.connected(c);
			catch (Exception e)
				logDiagnostic("libp2p: notifiee failed on connect: %s", e.msg);
		return c;
	}

	package void forget(Connection c) nothrow
	{
		import std.algorithm.mutation : remove;

		pool = pool.remove!(x => x is c);
		foreach (n; notifiees.dup)
		{
			try
				n.disconnected(c);
			catch (Exception e)
				logDiagnostic("libp2p: notifiee failed on disconnect: %s", e.msg);
		}
	}

	// The connection new streams to `peer` go on. A direct one wins over a relayed
	// one (a /p2p-circuit remote address): after a hole punch both are in the pool,
	// the relayed one first, and a relay circuit carries only a small byte budget
	// meant for the punch itself — data on it dies mid-transfer.
	private Connection find(PeerId peer)
	{
		Connection[] live;
		foreach (c; pool)
			if (c.remotePeer == peer && !c.isClosed)
				live ~= c;
		if (live.length == 0)
			return null;
		if (live.length > 1 && preferConnection !is null)
			if (auto chosen = preferConnection(live))
				return chosen;
		foreach (c; live)
			if (!c.remoteAddr.components.canFind!(x => x.name == "p2p-circuit"))
				return c;
		return live[0];
	}

	private Transport transportFor(Multiaddr addr)
	{
		foreach (t; transports)
			if (t.canHandle(addr))
				return t;
		throw new Exception("swarm: no transport for " ~ addr.toString);
	}
}
