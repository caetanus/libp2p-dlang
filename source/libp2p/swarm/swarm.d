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

import core.time : Duration, seconds;
import std.algorithm.mutation : move;
import std.algorithm.searching : canFind;
import std.exception : enforce;
import std.typecons : Nullable, nullable;

import vibe.core.log : logDebug, logDiagnostic;

import libp2p.core.ending;
import libp2p.core.peer_id : PeerId;
import libp2p.core.stream : Stream;
import libp2p.core.upgrade;
import libp2p.crypto.keys : Keypair, PublicKey;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.muxer.yamux : YamuxFactory;
import libp2p.security.noise : NoiseTransport;
import libp2p.swarm.connection;
import libp2p.swarm.limiter;
import libp2p.transport.transport;
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

final class Swarm
{
	private PeerId localPeer_;
	private Keypair identity;
	private SwarmConfig cfg;
	private Transport[] transports;
	private UpgradeConfig upgradeCfg;
	private ConnectionGater gater;
	private Limiter limiter;

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
		upgradeCfg.security = [new NoiseTransport(identity)];
		upgradeCfg.muxers = [new YamuxFactory];
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

	// --- listening ---------------------------------------------------------------------

	void listen(Multiaddr addr)
	{
		enforce(!closed, "swarm: closed");
		auto l = transportFor(addr).listen(addr);
		listeners ~= l;
		fibers.spawn({ acceptLoop(l); });
	}

	Multiaddr[] listenAddrs()
	{
		Multiaddr[] out_;
		foreach (l; listeners)
			out_ ~= l.address;
		return out_;
	}

	// --- dialing -----------------------------------------------------------------------

	/// A connection to `peer`: the one we have, or a new one over `addrs`.
	Connection connect(PeerId peer, const(Multiaddr)[] addrs)
	{
		if (auto c = find(peer))
			return c;
		enforce(!closed, "swarm: closed");
		enforce(addrs.length > 0, "swarm: no addresses for " ~ peer.toString);
		Exception last;
		foreach (addr; addrs)
		{
			try
				return dialOne(addr, nullable(peer));
			catch (Exception e)
				last = e;
		}
		throw new DialFailure("dial " ~ peer.toString ~ " failed: " ~ (last is null ? "no address worked" : last.msg), last);
	}

	/// Dial an address whose peer we do not know yet.
	Connection dial(Multiaddr addr)
	{
		enforce(!closed, "swarm: closed");
		try
			return dialOne(addr, Nullable!PeerId.init);
		catch (Exception e)
			throw new DialFailure("dial " ~ addr.toString ~ " failed: " ~ e.msg, e);
	}

	private Connection dialOne(const Multiaddr target, Nullable!PeerId expected)
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
			Multiaddr bare;
			foreach (c; comps[0 .. $ - 1])
				bare = bare ~ Multiaddr.parse("/" ~ c.name ~ (c.protocol.size != 0 ? "/" ~ c.text : ""));
			addr = bare;
		}
		auto pending = limiter.pending(Endpoint.dialer);
		scope (exit)
			pending.release(); // and by unwinding, whichever comes first

		RawConn raw = withTimeout(cfg.dialTimeout, "dial " ~ addr.toString, () => transportFor(addr).dial(addr));
		scope (failure)
			raw.close();

		Upgraded up = withTimeout(cfg.handshakeTimeout, "handshake with " ~ addr.toString,
			() => upgrade(raw, Endpoint.dialer, upgradeCfg, expected));
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

	private void admitInbound(RawConn raw)
	{
		scope (failure)
			raw.close();

		auto pending = limiter.pending(Endpoint.listener);
		scope (exit)
			pending.release();
		if (gater !is null && !gater.allowInbound(raw.remoteAddr))
			throw new Exception("swarm: gater refused " ~ raw.remoteAddr.toString);

		Upgraded up = withTimeout(cfg.handshakeTimeout, "handshake with " ~ raw.remoteAddr.toString,
			() => upgrade(raw, Endpoint.listener, upgradeCfg));
		scope (failure)
			up.muxer.close();

		if (gater !is null && !gater.allowPeer(up.remotePeer, Endpoint.listener))
			throw new Exception("swarm: gater refused " ~ up.remotePeer.toString);

		auto established = limiter.established(Endpoint.listener, up.remotePeer);
		admit(up, Endpoint.listener, raw.localAddr, raw.remoteAddr, established);
	}

	private Connection admit(ref Upgraded up, Endpoint role, Multiaddr local, Multiaddr remote, ref Lease established)
	{
		auto c = new Connection(this, up.muxer, role, up.remotePeer, up.remoteKey, local, remote, established);
		pool ~= c;
		c.start();
		foreach (n; notifiees.dup)
			n.connected(c);
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

	private Connection find(PeerId peer)
	{
		foreach (c; pool)
			if (c.remotePeer == peer && !c.isClosed)
				return c;
		return null;
	}

	private Transport transportFor(Multiaddr addr)
	{
		foreach (t; transports)
			if (t.canHandle(addr))
				return t;
		throw new Exception("swarm: no transport for " ~ addr.toString);
	}
}
