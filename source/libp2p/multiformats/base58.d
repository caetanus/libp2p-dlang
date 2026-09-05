/// base58btc, the Bitcoin alphabet: leading zero bytes become leading '1's.
module libp2p.multiformats.base58;

import std.exception : enforce;

private immutable string alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

private immutable byte[128] lookup = () {
	byte[128] t = -1;
	foreach (i, c; alphabet)
		t[c] = cast(byte) i;
	return t;
}();

string base58Encode(const(ubyte)[] data) @safe pure nothrow
{
	size_t zeros;
	while (zeros < data.length && data[zeros] == 0)
		zeros++;

	// Base-256 → base-58 long division, most significant digit first.
	auto digits = new ubyte[(data.length - zeros) * 138 / 100 + 1];
	size_t length;
	foreach (b; data[zeros .. $])
	{
		uint carry = b;
		size_t i;
		for (; i < length || carry != 0; i++)
		{
			carry += 256u * digits[i];
			digits[i] = cast(ubyte)(carry % 58);
			carry /= 58;
		}
		length = i;
	}

	auto out_ = new char[zeros + length];
	out_[0 .. zeros] = '1';
	foreach (i; 0 .. length)
		out_[zeros + i] = alphabet[digits[length - 1 - i]];
	return out_.idup;
}

ubyte[] base58Decode(const(char)[] text) @safe pure
{
	size_t ones;
	while (ones < text.length && text[ones] == '1')
		ones++;

	auto bytes = new ubyte[(text.length - ones) * 733 / 1000 + 1];
	size_t length;
	foreach (c; text[ones .. $])
	{
		enforce(c < 128 && lookup[c] >= 0, "base58: character outside the alphabet");
		uint carry = lookup[c];
		size_t i;
		for (; i < length || carry != 0; i++)
		{
			carry += 58u * bytes[i];
			bytes[i] = cast(ubyte)(carry & 0xff);
			carry >>= 8;
		}
		length = i;
	}

	auto out_ = new ubyte[ones + length];
	foreach (i; 0 .. length)
		out_[ones + i] = bytes[length - 1 - i];
	return out_;
}
