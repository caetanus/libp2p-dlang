/**
 * Circuit relay v2 messages (`circuit_relay.proto`). HOP is what a client says
 * to the relay (RESERVE, CONNECT); STOP is what the relay says to the
 * destination (CONNECT). Both answer with STATUS. Each message is varint
 * length-prefixed on its stream.
 */
module libp2p.protocol.relay.wire;

import std.typecons : Nullable;

import libp2p.wire.protobuf;

enum hopProtocol = "/libp2p/circuit/relay/0.2.0/hop";
enum stopProtocol = "/libp2p/circuit/relay/0.2.0/stop";

enum Status : uint
{
	OK = 100,
	RESERVATION_REFUSED = 200,
	RESOURCE_LIMIT_EXCEEDED = 201,
	PERMISSION_DENIED = 202,
	CONNECTION_FAILED = 203,
	NO_RESERVATION = 204,
	MALFORMED_MESSAGE = 400,
	UNEXPECTED_MESSAGE = 401,
}

struct Peer
{
	@field(1) ubyte[] id;
	@field(2) ubyte[][] addrs;

	ubyte[] encode() const
	{
		return libp2p.wire.protobuf.encode(this);
	}

	static Peer decode(const(ubyte)[] bytes)
	{
		return libp2p.wire.protobuf.decode!Peer(bytes);
	}
}

struct Reservation
{
	@field(1) ulong expire; /// unix seconds
	@field(2) ubyte[][] addrs; /// the relay's addresses, for the reserving peer to advertise
	@field(3) @optional ubyte[] voucher;
}

struct Limit
{
	@field(1) @optional uint duration; /// seconds
	@field(2) @optional ulong data; /// bytes
}

private struct HopWire
{
	@field(1) uint type;
	@field(2) Nullable!Peer peer;
	@field(3) Nullable!Reservation reservation;
	@field(4) Nullable!Limit limit;
	@field(5) Nullable!uint status;
}

struct HopMessage
{
	enum Type : uint
	{
		RESERVE = 0,
		CONNECT = 1,
		STATUS = 2,
	}

	Type type;
	Peer peer;
	bool hasPeer;
	Reservation reservation;
	bool hasReservation;
	Limit limit;
	bool hasLimit;
	Status status;
	bool hasStatus;

	ubyte[] encode() const
	{
		HopWire w;
		w.type = type;
		if (hasPeer)
			w.peer = Peer(peer.id.dup, deepDup(peer.addrs));
		if (hasReservation)
			w.reservation = Reservation(reservation.expire, deepDup(reservation.addrs), reservation.voucher.dup);
		if (hasLimit)
			w.limit = limit;
		if (hasStatus)
			w.status = cast(uint) status;
		return libp2p.wire.protobuf.encode(w);
	}

	static HopMessage decode(const(ubyte)[] bytes)
	{
		auto w = libp2p.wire.protobuf.decode!HopWire(bytes);
		HopMessage m;
		m.type = cast(Type) w.type;
		if (!w.peer.isNull)
		{
			m.peer = w.peer.get;
			m.hasPeer = true;
		}
		if (!w.reservation.isNull)
		{
			m.reservation = w.reservation.get;
			m.hasReservation = true;
		}
		if (!w.limit.isNull)
		{
			m.limit = w.limit.get;
			m.hasLimit = true;
		}
		if (!w.status.isNull)
		{
			m.status = cast(Status) w.status.get;
			m.hasStatus = true;
		}
		return m;
	}

	static HopMessage statusReply(Status s)
	{
		HopMessage m;
		m.type = Type.STATUS;
		m.status = s;
		m.hasStatus = true;
		return m;
	}
}

private struct StopWire
{
	@field(1) uint type;
	@field(2) Nullable!Peer peer;
	@field(3) Nullable!Limit limit;
	@field(4) Nullable!uint status;
}

struct StopMessage
{
	enum Type : uint
	{
		CONNECT = 0,
		STATUS = 1,
	}

	Type type;
	Peer peer;
	bool hasPeer;
	Limit limit;
	bool hasLimit;
	Status status;
	bool hasStatus;

	ubyte[] encode() const
	{
		StopWire w;
		w.type = type;
		if (hasPeer)
			w.peer = Peer(peer.id.dup, deepDup(peer.addrs));
		if (hasLimit)
			w.limit = limit;
		if (hasStatus)
			w.status = cast(uint) status;
		return libp2p.wire.protobuf.encode(w);
	}

	static StopMessage decode(const(ubyte)[] bytes)
	{
		auto w = libp2p.wire.protobuf.decode!StopWire(bytes);
		StopMessage m;
		m.type = cast(Type) w.type;
		if (!w.peer.isNull)
		{
			m.peer = w.peer.get;
			m.hasPeer = true;
		}
		if (!w.limit.isNull)
		{
			m.limit = w.limit.get;
			m.hasLimit = true;
		}
		if (!w.status.isNull)
		{
			m.status = cast(Status) w.status.get;
			m.hasStatus = true;
		}
		return m;
	}

	static StopMessage statusReply(Status s)
	{
		StopMessage m;
		m.type = Type.STATUS;
		m.status = s;
		m.hasStatus = true;
		return m;
	}
}

private ubyte[][] deepDup(const(ubyte[])[] a)
{
	ubyte[][] out_;
	foreach (x; a)
		out_ ~= x.dup;
	return out_;
}
