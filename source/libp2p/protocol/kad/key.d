/**
 * Kademlia keys: the SHA-256 of a peer id or of a record key, and the XOR
 * distance between two of them. A key made from a peer remembers the peer, so
 * a routing-table entry can be dialed.
 */
module libp2p.protocol.kad.key;

import std.digest.sha : sha256Of;

import libp2p.core.peer_id : PeerId;

/// A 256-bit XOR distance. Ordered as an unsigned big-endian integer.
struct Distance
{
	ubyte[32] bytes;

	/// The 0-based index of the most significant set bit, or -1 for zero: the
	/// bucket a key at this distance belongs to.
	long ilog2() const @safe pure nothrow @nogc
	{
		foreach (i, b; bytes)
			if (b != 0)
			{
				int bit = 7;
				while ((b & (1 << bit)) == 0)
					bit--;
				return cast(long)((31 - i) * 8 + bit);
			}
		return -1;
	}

	int opCmp(const Distance o) const @safe pure nothrow @nogc
	{
		foreach (i; 0 .. 32)
			if (bytes[i] != o.bytes[i])
				return bytes[i] < o.bytes[i] ? -1 : 1;
		return 0;
	}

	bool opEquals(const Distance o) const @safe pure nothrow @nogc
	{
		return bytes == o.bytes;
	}

	size_t toHash() const @safe pure nothrow @nogc
	{
		return hashOf(bytes[]);
	}
}

/// `a + b` as 256-bit integers; `overflow` says whether the sum wrapped.
Distance addChecked(const Distance a, const Distance b, out bool overflow) @safe pure nothrow @nogc
{
	Distance out_;
	uint carry;
	for (int i = 31; i >= 0; i--)
	{
		immutable s = cast(uint) a.bytes[i] + b.bytes[i] + carry;
		out_.bytes[i] = cast(ubyte)(s & 0xff);
		carry = s >> 8;
	}
	overflow = carry != 0;
	return out_;
}

struct Key
{
	ubyte[32] hash;
	/// The peer this key was made from, if any.
	PeerId peer;

	static Key fromPeer(PeerId peer) @safe pure nothrow
	{
		Key k;
		k.hash = sha256Of(peer.bytes);
		k.peer = PeerId(peer.bytes.dup);
		return k;
	}

	/// A key for arbitrary bytes (a record key).
	static Key fromBytes(const(ubyte)[] bytes) @safe pure nothrow
	{
		Key k;
		k.hash = sha256Of(bytes);
		return k;
	}

	/// A key with this exact hash (for tests and for keys read off the wire).
	static Key fromHash(const(ubyte)[] hash) @safe pure nothrow
	{
		Key k;
		k.hash[] = hash[0 .. 32];
		return k;
	}

	Distance distance(const Key o) const @safe pure nothrow @nogc
	{
		Distance d;
		foreach (i; 0 .. 32)
			d.bytes[i] = hash[i] ^ o.hash[i];
		return d;
	}

	bool opEquals(const Key o) const @safe pure nothrow @nogc
	{
		return hash == o.hash;
	}

	size_t toHash() const @safe pure nothrow @nogc
	{
		return hashOf(hash[]);
	}
}
