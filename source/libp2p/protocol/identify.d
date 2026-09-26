/**
 * identify (`/ipfs/id/1.0.0`): who are you, and what did you see me as.
 *
 * The side that wants to know opens the stream and reads one varint
 * length-prefixed protobuf message; the other side writes its description and
 * closes. (rust and go both frame it this way; a reader that waited for EOF
 * would work between two copies of itself and with nobody else.) The
 * service does this for every new connection on a fiber it owns, verifies that
 * the key in the message is the key the handshake proved, and records what it
 * learned in the peerstore. The observed address the peer reports is how a
 * node behind NAT learns what it looks like from outside.
 */
module libp2p.protocol.identify;

import core.time : Duration, MonoTime, seconds, minutes;
import std.algorithm.searching : canFind;
import std.exception : enforce;
import std.typecons : Nullable;

import vibe.core.task : InterruptException;

import libp2p.core.peer_id : PeerId;
import libp2p.core.stream;
import libp2p.crypto.keys : PublicKey;
import libp2p.host.host;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.util.fibers : FiberGroup;
import libp2p.util.timeout : withTimeout;
import libp2p.wire.protobuf;

enum identifyProtocol = "/ipfs/id/1.0.0";
/// The same message, in the other direction: a peer telling us it changed.
enum identifyPushProtocol = "/ipfs/id/push/1.0.0";

/// The largest identify message we accept. rust allows 4 KiB by default and go
/// 8 KiB; 64 KiB leaves room for a peer with many addresses and protocols.
enum maxIdentifyMessage = 64 * 1024;

/// The wire message (`identify.proto`).
struct Identify
{
	@field(1) @optional ubyte[] publicKey;
	@field(2) ubyte[][] listenAddrs;
	@field(3) string[] protocols;
	@field(4) @optional ubyte[] observedAddr;
	@field(5) @optional string protocolVersion;
	@field(6) @optional string agentVersion;
	@field(8) @optional ubyte[] signedPeerRecord;

	ubyte[] encode() const
	{
		return libp2p.wire.protobuf.encode(this);
	}

	static Identify decode(const(ubyte)[] bytes)
	{
		return libp2p.wire.protobuf.decode!Identify(bytes);
	}
}

/// Read one identify message: a varint length, then the protobuf.
Identify readIdentify(Stream s)
{
	return Identify.decode(s.readLengthPrefixed(maxIdentifyMessage));
}

void sendIdentify(Stream s, const Identify msg)
{
	s.writeLengthPrefixed(msg.encode);
}

/// What identify learned about a peer, decoded.
struct IdentifyInfo
{
	PeerId peer;
	PublicKey key;
	Multiaddr[] listenAddrs;
	string[] protocols;
	Nullable!Multiaddr observedAddr;
	string protocolVersion;
	string agentVersion;
}

struct IdentifyConfig
{
	Duration timeout = 30.seconds;
}

final class IdentifyService : Notifiee
{
	private Host host;
	private IdentifyConfig cfg;
	private FiberGroup fibers;
	// What peers observed us at, kept PER CONNECTION: at most a few addresses per
	// connection, a bounded number of connections, each observation aging out and
	// all of a connection's gone when it closes. A peer pushing a new address in
	// every identify-push can therefore neither grow this without bound nor
	// leave anything behind once it is disconnected.
	private static struct Observation
	{
		Multiaddr[] addrs;
		MonoTime at;
	}
	private Observation[string] observedBy; // by connection
	enum size_t maxObservedPerConn = 4;
	enum size_t maxObservedConns = 64;
	enum observationTtl = 30.minutes;

	/// Called after a peer's identity was received, verified and stored.
	void delegate(IdentifyInfo info) onIdentified;
	/// Called after we told a peer who we are.
	void delegate(PeerId peer) onSent;

	this(Host host, IdentifyConfig cfg = IdentifyConfig.init)
	{
		this.host = host;
		this.cfg = cfg;
		fibers = new FiberGroup; // a peer that will not identify is not our problem
		host.setStreamHandler(identifyProtocol, &serve);
		host.setStreamHandler(identifyPushProtocol, &servePush);
		host.addNotifiee(this);
		host.addObservedAddrSource(&observedAddrs);
		// a new network: every observation is of the old one (QUIC connections on the
		// wildcard socket are not closed by networkChanged, so theirs would linger);
		// new connections observe us afresh
		host.swarm.addNetworkChangedHandler(() nothrow { observedBy = null; });
	}

	/// Tell `peer` that our description changed (new listen address, new
	/// protocol). Blocks until the message is sent; throws if it cannot be.
	void push(PeerId peer)
	{
		auto c = host.swarm.connection(peer);
		auto s = c.newStream(identifyPushProtocol);
		scope (exit)
			s.close();
		sendIdentify(s, describe(c));
	}

	/// Push to every connected peer, on fibers of ours; a peer that cannot be
	/// reached is skipped.
	void pushAll()
	{
		foreach (c; host.swarm.connections)
			fibers.spawn({
				try
					push(c.remotePeer);
				catch (InterruptException e)
					throw e; // the group is stopping us, not a peer that will not listen
				catch (Exception)
				{
				} // it is gone, or will not listen; nothing to decide here
			});
	}

	/// Addresses peers have reported seeing us at: candidates for our own
	/// external address.
	private static bool isRelayed(Connection c)
	{
		return c.remoteAddr.components.canFind!(x => x.name == "p2p-circuit");
	}

	Multiaddr[] observedAddrs()
	{
		Multiaddr[] out_;
		immutable now = MonoTime.currTime;
		foreach (ob; observedBy)
		{
			if (now - ob.at > observationTtl)
				continue;
			foreach (a; ob.addrs)
				if (!out_.canFind(a))
					out_ ~= a;
		}
		return out_;
	}

	private static string connKey(Connection c)
	{
		import std.format : format;
		return format("%x", cast(size_t) cast(void*) c);
	}

	private void observe(Connection c, Multiaddr a)
	{
		immutable key = connKey(c);
		auto ob = key in observedBy;
		if (ob is null)
		{
			if (observedBy.length >= maxObservedConns)
			{
				// Room for this connection: the connection observed longest ago goes.
				string oldest;
				MonoTime oldestAt;
				foreach (k, o; observedBy)
					if (oldest is null || o.at < oldestAt)
					{
						oldest = k;
						oldestAt = o.at;
					}
				observedBy.remove(oldest);
			}
			observedBy[key] = Observation();
			ob = key in observedBy;
		}
		ob.at = MonoTime.currTime;
		if (ob.addrs.canFind(a))
			return;
		if (ob.addrs.length >= maxObservedPerConn)
			ob.addrs = ob.addrs[1 .. $]; // the newest observation replaces the oldest
		ob.addrs ~= a;
	}

	void connected(Connection c)
	{
		fibers.spawn({ identify(c); });
	}

	void disconnected(Connection c)
	{
		observedBy.remove(connKey(c)); // its observations go with it
	}

	void close() nothrow
	{
		try
		{
			host.removeNotifiee(this);
			host.removeStreamHandler(identifyProtocol);
			host.removeStreamHandler(identifyPushProtocol);
		}
		catch (Exception)
		{
		}
		fibers.stopAll();
	}

	/// Our description, as seen from `c`.
	Identify describe(Connection c)
	{
		Identify msg;
		msg.publicKey = host.key.toProtobuf;
		foreach (a; host.addrs)
			msg.listenAddrs ~= a.encode;
		msg.protocols = host.protocols;
		// Over a relay circuit the address we see is the relay's, not the peer's:
		// reporting it as "observed" would tell the peer it is reachable there.
		if (!isRelayed(c))
			msg.observedAddr = c.remoteAddr.encode;
		msg.protocolVersion = host.config.protocolVersion;
		msg.agentVersion = host.config.agentVersion;
		return msg;
	}

	private void serve(Stream s, Connection c, string)
	{
		scope (exit)
			s.close();
		sendIdentify(s, describe(c));
		if (onSent !is null)
			onSent(c.remotePeer);
	}

	/// The peer changed and says so: the same bookkeeping as a fresh identify.
	private void servePush(Stream s, Connection c, string)
	{
		scope (exit)
			s.close();
		auto msg = withTimeout(cfg.timeout, "identify push", () => readIdentify(s));
		record(c, msg);
	}

	private void identify(Connection c)
	{
		auto hold = c.hold(); // asking who they are is use
		auto s = c.newStream(identifyProtocol);
		scope (exit)
			s.close();
		auto msg = withTimeout(cfg.timeout, "identify", () => readIdentify(s));
		record(c, msg);
	}

	/// Verify a peer's message against the connection it came over, store it,
	/// and report it.
	private void record(Connection c, Identify msg)
	{
		IdentifyInfo info;
		info.peer = c.remotePeer;
		if (msg.publicKey.length > 0)
		{
			info.key = PublicKey.fromProtobuf(msg.publicKey);
			enforce(c.remotePeer.matches(info.key), "identify: the key sent is not the key the handshake proved");
		}
		else
			info.key = c.remoteKey;
		foreach (a; msg.listenAddrs)
			info.listenAddrs ~= Multiaddr.decode(a);
		info.protocols = msg.protocols;
		if (msg.observedAddr.length > 0)
			info.observedAddr = Multiaddr.decode(msg.observedAddr);
		info.protocolVersion = msg.protocolVersion;
		info.agentVersion = msg.agentVersion;

		host.peerstore.setKey(info.peer, info.key);
		host.peerstore.addAddrs(info.peer, info.listenAddrs);
		host.peerstore.setProtocols(info.peer, info.protocols);
		host.peerstore.setAgent(info.peer, info.agentVersion);
		// Likewise inbound: an address a peer observed for us over a circuit is
		// the relay's public address, never ours to advertise.
		if (!info.observedAddr.isNull && !isRelayed(c))
			observe(c, info.observedAddr.get);

		if (onIdentified !is null)
			onIdentified(info);
	}
}
