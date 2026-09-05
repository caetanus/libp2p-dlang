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

import core.time : Duration, seconds;
import std.algorithm.searching : canFind;
import std.exception : enforce;
import std.typecons : Nullable;

import libp2p.core.peer_id : PeerId;
import libp2p.core.stream;
import libp2p.crypto.keys : PublicKey;
import libp2p.host.host;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.util.fibers : FiberGroup;
import libp2p.util.timeout : withTimeout;
import libp2p.wire.protobuf;

enum identifyProtocol = "/ipfs/id/1.0.0";

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
	private Multiaddr[] observed;

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
		host.addNotifiee(this);
	}

	/// Addresses peers have reported seeing us at: candidates for our own
	/// external address.
	Multiaddr[] observedAddrs()
	{
		return observed.dup;
	}

	void connected(Connection c)
	{
		fibers.spawn({ identify(c); });
	}

	void disconnected(Connection)
	{
	}

	void close() nothrow
	{
		try
		{
			host.removeNotifiee(this);
			host.removeStreamHandler(identifyProtocol);
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

	private void identify(Connection c)
	{
		auto hold = c.hold(); // asking who they are is use
		auto s = c.newStream(identifyProtocol);
		scope (exit)
			s.close();
		auto msg = withTimeout(cfg.timeout, "identify", () => readIdentify(s));

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
		if (!info.observedAddr.isNull && !observed.canFind(info.observedAddr.get))
			observed ~= info.observedAddr.get;

		if (onIdentified !is null)
			onIdentified(info);
	}
}
