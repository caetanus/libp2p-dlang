/// Multihash: `varint(code) varint(len) digest`. Identity and sha2-256 are the
/// two libp2p needs for peer ids; anything else decodes but is not produced.
module libp2p.multiformats.multihash;

import std.exception : enforce;
import libp2p.multiformats.varint;

enum HashCode : ulong
{
	identity = 0x00,
	sha2_256 = 0x12,
}

struct Multihash
{
	ulong code;
	ubyte[] digest;

	ubyte[] encode() const @safe pure nothrow
	{
		return encodeVarint(code) ~ encodeVarint(digest.length) ~ digest;
	}

	/// Decode from the front of `bytes`; trailing bytes are ignored.
	static Multihash decode(const(ubyte)[] bytes) @safe pure
	{
		auto c = decodeVarint(bytes);
		bytes = bytes[c.consumed .. $];
		auto l = decodeVarint(bytes);
		bytes = bytes[l.consumed .. $];
		enforce(l.value <= bytes.length, "multihash: truncated digest");
		return Multihash(c.value, bytes[0 .. cast(size_t) l.value].dup);
	}

	bool opEquals(const Multihash o) const @safe pure nothrow
	{
		return code == o.code && digest == o.digest;
	}

	size_t toHash() const @safe pure nothrow
	{
		return hashOf(digest, hashOf(code));
	}
}

Multihash multihashIdentity(const(ubyte)[] data) @safe pure nothrow
{
	return Multihash(HashCode.identity, data.dup);
}

Multihash multihashSha256(const(ubyte)[] data) @safe pure nothrow
{
	import std.digest.sha : sha256Of;

	return Multihash(HashCode.sha2_256, sha256Of(data).dup);
}
