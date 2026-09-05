/**
 * The Kademlia wire message (`kademlia.proto`, proto3). One message per
 * request and one per response, each varint length-prefixed on the stream.
 *
 * A peer's advertised addresses are normalised on decode: a bare address gets
 * `/p2p/<id>` appended, an address naming a different peer is dropped, and one
 * that does not parse is dropped.
 */
module libp2p.protocol.kad.message;

import libp2p.core.peer_id : PeerId;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.wire.protobuf;

enum kadProtocolId = "/ipfs/kad/1.0.0";

enum MessageType : uint
{
	putValue = 0,
	getValue = 1,
	addProvider = 2,
	getProviders = 3,
	findNode = 4,
	ping = 5,
}

enum ConnectionType : uint
{
	notConnected = 0,
	connected = 1,
	canConnect = 2,
	cannotConnect = 3,
}

/// A record as it travels. Fields 666 and 777 are rust-libp2p's publisher and
/// remaining TTL in seconds; go ignores them and we read them when present.
struct Record
{
	@field(1) @optional ubyte[] key;
	@field(2) @optional ubyte[] value;
	@field(666) @optional ubyte[] publisher;
	@field(777) @optional uint ttl;
	@field(5) @optional string timeReceived;
}

private struct PeerMsg
{
	@field(1) @optional ubyte[] id;
	@field(2) ubyte[][] addrs;
	@field(3) @optional uint connection;
}

struct KadPeer
{
	PeerId nodeId;
	Multiaddr[] multiaddrs;
	ConnectionType connectionTy;

	ubyte[] encode() const
	{
		return libp2p.wire.protobuf.encode(toMsg);
	}

	static KadPeer decode(const(ubyte)[] bytes)
	{
		return fromMsg(libp2p.wire.protobuf.decode!PeerMsg(bytes));
	}

	private PeerMsg toMsg() const
	{
		PeerMsg m;
		m.id = nodeId.bytes.dup;
		foreach (a; multiaddrs)
			m.addrs ~= a.encode;
		m.connection = connectionTy;
		return m;
	}

	private static KadPeer fromMsg(PeerMsg m)
	{
		KadPeer p;
		p.nodeId = PeerId.fromBytes(m.id);
		p.connectionTy = cast(ConnectionType) m.connection;
		foreach (raw; m.addrs)
		{
			Multiaddr a;
			try
				a = Multiaddr.decode(raw);
			catch (Exception)
				continue; // not an address we can read; the peer may still be reachable otherwise
			auto normalised = withPeer(a, p.nodeId);
			if (!normalised.isNull)
				p.multiaddrs ~= normalised.get;
		}
		return p;
	}
}

private struct WireMessage
{
	@field(1) @optional uint type;
	@field(10) @optional int clusterLevelRaw;
	@field(2) @optional ubyte[] key;
	@field(3) Nullable!Record record;
	@field(8) PeerMsg[] closerPeers;
	@field(9) PeerMsg[] providerPeers;
}

import std.typecons : Nullable;

struct KadMessage
{
	MessageType type;
	ubyte[] key;
	bool hasRecord;
	Record record;
	KadPeer[] closerPeers;
	KadPeer[] providerPeers;
	int clusterLevelRaw;

	ubyte[] encode() const
	{
		WireMessage w;
		w.type = type;
		w.clusterLevelRaw = clusterLevelRaw;
		w.key = key.dup;
		if (hasRecord)
			w.record = Record(record.key.dup, record.value.dup, record.publisher.dup, record.ttl, record.timeReceived);
		foreach (p; closerPeers)
			w.closerPeers ~= p.toMsg;
		foreach (p; providerPeers)
			w.providerPeers ~= p.toMsg;
		return libp2p.wire.protobuf.encode(w);
	}

	static KadMessage decode(const(ubyte)[] bytes)
	{
		auto w = libp2p.wire.protobuf.decode!WireMessage(bytes);
		KadMessage m;
		m.type = cast(MessageType) w.type;
		m.clusterLevelRaw = w.clusterLevelRaw;
		m.key = w.key;
		if (!w.record.isNull)
		{
			m.hasRecord = true;
			m.record = w.record.get;
		}
		foreach (p; w.closerPeers)
			m.closerPeers ~= KadPeer.fromMsg(p);
		foreach (p; w.providerPeers)
			m.providerPeers ~= KadPeer.fromMsg(p);
		return m;
	}
}

/// `addr` with `/p2p/<peer>` at the end: appended if absent, kept if it names
/// `peer`, refused (null) if it names someone else.
Nullable!Multiaddr withPeer(Multiaddr addr, PeerId peer)
{
	auto comps = addr.components;
	if (comps.length > 0 && comps[$ - 1].name == "p2p")
	{
		PeerId named;
		try
			named = PeerId.fromBytes(comps[$ - 1].value);
		catch (Exception)
			return Nullable!Multiaddr.init;
		return named == peer ? Nullable!Multiaddr(addr) : Nullable!Multiaddr.init;
	}
	return Nullable!Multiaddr(addr ~ Multiaddr.parse("/p2p/" ~ peer.toBase58));
}

/// `addr` without a trailing `/p2p/...`, for a transport that dials addresses.
Multiaddr withoutPeer(Multiaddr addr)
{
	auto comps = addr.components;
	if (comps.length == 0 || comps[$ - 1].name != "p2p")
		return addr;
	Multiaddr out_;
	foreach (c; comps[0 .. $ - 1])
		out_ = out_ ~ Multiaddr.parse("/" ~ c.name ~ (c.protocol.size != 0 ? "/" ~ c.text : ""));
	return out_;
}
