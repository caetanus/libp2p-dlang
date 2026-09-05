/// Multibase: one prefix character naming the base, then the digits. Encodes as
/// base64url (`u`), the form libp2p's certhashes use; decodes the bases libp2p
/// text forms actually carry.
module libp2p.multiformats.multibase;

import std.exception : enforce;
import libp2p.multiformats.base58 : base58Encode, base58Decode;

string multibaseEncode(const(ubyte)[] data) @safe pure
{
	import std.base64 : Base64URLNoPadding;

	return "u" ~ Base64URLNoPadding.encode(data);
}

ubyte[] multibaseDecode(const(char)[] text) @safe pure
{
	import std.base64 : Base64URLNoPadding;

	enforce(text.length > 0, "multibase: empty");
	auto body_ = text[1 .. $];
	switch (text[0])
	{
	case 'u':
		return Base64URLNoPadding.decode(body_);
	case 'z':
		return base58Decode(body_);
	case 'f':
		return hexDecode(body_);
	case 'b':
		return base32Decode(body_);
	default:
		throw new Exception("multibase: unsupported base '" ~ text[0] ~ "'");
	}
}

private ubyte[] hexDecode(const(char)[] h) @safe pure
{
	import std.conv : to;

	enforce(h.length % 2 == 0, "multibase: odd hex length");
	auto out_ = new ubyte[h.length / 2];
	foreach (i; 0 .. out_.length)
		out_[i] = to!ubyte(h[2 * i .. 2 * i + 2], 16);
	return out_;
}

// RFC 4648 lowercase alphabet, no padding — multibase's `b`.
private ubyte[] base32Decode(const(char)[] s) @safe pure
{
	ubyte[] out_;
	uint buffer;
	int bits;
	foreach (c; s)
	{
		int v;
		if (c >= 'a' && c <= 'z')
			v = c - 'a';
		else if (c >= '2' && c <= '7')
			v = c - '2' + 26;
		else
			throw new Exception("multibase: base32 character outside the alphabet");
		buffer = (buffer << 5) | v;
		bits += 5;
		if (bits >= 8)
		{
			bits -= 8;
			out_ ~= cast(ubyte)(buffer >> bits);
			buffer &= (1u << bits) - 1;
		}
	}
	return out_;
}
