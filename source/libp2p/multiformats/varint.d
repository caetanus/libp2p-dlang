/**
 * Unsigned varints (LEB128), as multiformats specifies them: little-endian
 * groups of seven bits, continuation bit set on all but the last, at most ten
 * bytes for a 64-bit value.
 */
module libp2p.multiformats.varint;

import std.exception : enforce;

/// The longest encoding of a `ulong`.
enum size_t maxVarintLen64 = 10;

struct Decoded
{
	ulong value;
	size_t consumed;
}

/// Encode into a fresh array.
ubyte[] encodeVarint(ulong v) @safe pure nothrow
{
	ubyte[maxVarintLen64] scratch;
	return encodeVarintInto(v, scratch[]).dup;
}

/// Encode into `buf` (at least `maxVarintLen64` bytes) and return the slice used.
ubyte[] encodeVarintInto(ulong v, ubyte[] buf) @safe pure nothrow @nogc
{
	assert(buf.length >= maxVarintLen64);
	size_t i;
	while (v >= 0x80)
	{
		buf[i++] = cast(ubyte)(v | 0x80);
		v >>= 7;
	}
	buf[i++] = cast(ubyte) v;
	return buf[0 .. i];
}

/**
 * Decode a varint from the front of `buf`. Throws if the buffer ends before the
 * varint does, if it runs past ten bytes, or if the tenth byte carries bits
 * that do not fit a `ulong`.
 */
Decoded decodeVarint(const(ubyte)[] buf) @safe pure
{
	ulong value;
	foreach (i, b; buf)
	{
		enforce(i < maxVarintLen64, "varint: longer than 10 bytes");
		if (i == maxVarintLen64 - 1)
			enforce((b & 0x7e) == 0, "varint: overflows 64 bits");
		value |= (cast(ulong)(b & 0x7f)) << (7 * i);
		if ((b & 0x80) == 0)
			return Decoded(value, i + 1);
	}
	throw new Exception("varint: truncated");
}
