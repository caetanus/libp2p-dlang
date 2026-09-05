/// AutoNAT v1 wire message (`autonat_v1.proto`), one varint length-prefixed
/// message per request and per response.
module libp2p.protocol.autonat.wire;

import std.typecons : Nullable;

import libp2p.wire.protobuf;

enum autonatProtocol = "/libp2p/autonat/1.0.0";

struct PeerInfo
{
	@field(1) @optional ubyte[] id;
	@field(2) ubyte[][] addrs;
}

struct Dial
{
	@field(1) Nullable!PeerInfo peer;
}

enum MessageType : uint
{
	DIAL = 0,
	DIAL_RESPONSE = 1,
}

enum ResponseStatus : uint
{
	OK = 0,
	E_DIAL_ERROR = 100,
	E_DIAL_REFUSED = 101,
	E_BAD_REQUEST = 200,
	E_INTERNAL_ERROR = 300,
}

struct DialResponseWire
{
	@field(1) Nullable!uint status;
	@field(2) @optional string statusText;
	@field(3) @optional ubyte[] addr;
}

struct Message
{
	@field(1) Nullable!uint type;
	@field(2) Nullable!Dial dial;
	@field(3) Nullable!DialResponseWire dialResponse;

	ubyte[] encode() const
	{
		return libp2p.wire.protobuf.encode(this);
	}

	static Message decode(const(ubyte)[] bytes)
	{
		return libp2p.wire.protobuf.decode!Message(bytes);
	}
}
