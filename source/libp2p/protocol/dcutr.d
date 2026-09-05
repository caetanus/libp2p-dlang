/**
 * DCUtR (`/libp2p/dcutr`): direct connection upgrade through a relay.
 *
 * Over a relayed connection the two sides swap the addresses they are
 * reachable at and measure the round trip, then dial each other at the same
 * moment so that each side's SYN opens the hole the other's comes through.
 *
 *   B (behind NAT, initiator)  → CONNECT{addrs}   → A
 *   B                          ← CONNECT{addrs}   ← A          (B measures RTT)
 *   B                          → SYNC             → A          (A dials now; B dials after RTT/2)
 *
 * This module is the exchange; the service in `relay/service.d` does the dialing.
 */
module libp2p.protocol.dcutr;

import core.time : Duration, MonoTime;
import std.exception : enforce;

import libp2p.core.stream;
import libp2p.wire.protobuf;

enum dcutrProtocol = "/libp2p/dcutr";
enum maxHolePunchMessage = 4 * 1024;

struct HolePunch
{
	enum Type : uint
	{
		CONNECT = 100,
		SYNC = 300,
	}

	@field(1) Type type;
	@field(2) ubyte[][] ObsAddrs;

	ubyte[] encode() const
	{
		return libp2p.wire.protobuf.encode(this);
	}

	static HolePunch decode(const(ubyte)[] bytes)
	{
		return libp2p.wire.protobuf.decode!HolePunch(bytes);
	}
}

struct DcutrResult
{
	ubyte[][] peerAddrs; /// the peer's addresses, as encoded multiaddrs
	Duration rtt;
}

/// The initiator's half: offer `ourAddrs`, learn theirs, time it, say SYNC.
DcutrResult initiateHolePunch(Stream s, ubyte[][] ourAddrs)
{
	HolePunch connect;
	connect.type = HolePunch.Type.CONNECT;
	connect.ObsAddrs = ourAddrs;
	immutable started = MonoTime.currTime;
	s.writeLengthPrefixed(connect.encode);

	auto reply = HolePunch.decode(s.readLengthPrefixed(maxHolePunchMessage));
	enforce(reply.type == HolePunch.Type.CONNECT, "dcutr: expected CONNECT");
	immutable rtt = MonoTime.currTime - started;

	HolePunch sync;
	sync.type = HolePunch.Type.SYNC;
	s.writeLengthPrefixed(sync.encode);
	return DcutrResult(reply.ObsAddrs, rtt);
}

/// The responder's half: learn theirs, offer `ourAddrs`, wait for SYNC.
ubyte[][] respondHolePunch(Stream s, ubyte[][] ourAddrs)
{
	auto connect = HolePunch.decode(s.readLengthPrefixed(maxHolePunchMessage));
	enforce(connect.type == HolePunch.Type.CONNECT, "dcutr: expected CONNECT");

	HolePunch reply;
	reply.type = HolePunch.Type.CONNECT;
	reply.ObsAddrs = ourAddrs;
	s.writeLengthPrefixed(reply.encode);

	auto sync = HolePunch.decode(s.readLengthPrefixed(maxHolePunchMessage));
	enforce(sync.type == HolePunch.Type.SYNC, "dcutr: expected SYNC");
	return connect.ObsAddrs;
}
