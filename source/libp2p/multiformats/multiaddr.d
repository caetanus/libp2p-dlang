/**
 * Multiaddr. The binary form is canonical — `varint(code) value` per protocol —
 * and the text form (`/ip4/127.0.0.1/tcp/4001`) is a view of it. Values are
 * fixed-size (ip4, tcp), length-prefixed (dns names, unix paths, peer ids) or
 * absent (ws, quic-v1).
 */
module libp2p.multiformats.multiaddr;

import std.exception : enforce;
import std.format : format;
import std.string : split, join;

import libp2p.multiformats.varint;
import libp2p.multiformats.base58 : base58Encode, base58Decode;
import libp2p.multiformats.multihash : Multihash;

/// The size of a protocol's value, in bits; `lengthPrefixed` for varint-prefixed
/// bytes, `none` for a marker protocol that carries no value.
private enum lengthPrefixed = -1;
private enum none = 0;

struct Protocol
{
	ulong code;
	string name;
	int size; /// bits; `lengthPrefixed`; or `none`
	bool path; /// the text value runs to the end of the string (unix)
}

// The protocols this node speaks or expects to see in the addresses it is
// handed. Adding one is one line; the codec below is driven by `size`.
immutable Protocol[] protocols = [
	Protocol(4, "ip4", 32),
	Protocol(6, "tcp", 16),
	Protocol(41, "ip6", 128),
	Protocol(53, "dns", lengthPrefixed),
	Protocol(54, "dns4", lengthPrefixed),
	Protocol(55, "dns6", lengthPrefixed),
	Protocol(56, "dnsaddr", lengthPrefixed),
	Protocol(273, "udp", 16),
	Protocol(280, "webrtc-direct", none),
	Protocol(281, "webrtc", none),
	Protocol(290, "p2p-circuit", none),
	Protocol(400, "unix", lengthPrefixed, true),
	Protocol(421, "p2p", lengthPrefixed),
	Protocol(448, "tls", none),
	Protocol(449, "sni", lengthPrefixed),
	Protocol(454, "noise", none),
	Protocol(460, "quic", none),
	Protocol(461, "quic-v1", none),
	Protocol(465, "webtransport", none),
	Protocol(466, "certhash", lengthPrefixed),
	Protocol(477, "ws", none),
	Protocol(478, "wss", none),
	Protocol(777, "memory", 64),
];

const(Protocol)* protocolByName(const(char)[] name) @safe pure nothrow
{
	foreach (ref p; protocols)
		if (p.name == name)
			return &p;
	return null;
}

const(Protocol)* protocolByCode(ulong code) @safe pure nothrow
{
	foreach (ref p; protocols)
		if (p.code == code)
			return &p;
	return null;
}

/// One decoded protocol with its raw value bytes.
struct Component
{
	const(Protocol)* protocol;
	ubyte[] value;

	string name() const @safe pure nothrow
	{
		return protocol.name;
	}

	/// The value in text form (what follows `/name/` in the string).
	string text() const @safe pure
	{
		return valueToText(*protocol, value);
	}
}

struct Multiaddr
{
	ubyte[] bytes;

	static Multiaddr parse(const(char)[] text) @safe pure
	{
		enforce(text.length > 0 && text[0] == '/', "multiaddr: must start with '/'");
		auto parts = text[1 .. $].split('/');
		ubyte[] out_;
		size_t i;
		while (i < parts.length)
		{
			auto name = parts[i++];
			enforce(name.length > 0, "multiaddr: empty protocol name");
			auto p = protocolByName(name);
			enforce(p !is null, "multiaddr: unknown protocol '" ~ name.idup ~ "'");
			out_ ~= encodeVarint(p.code);
			if (p.size == none)
				continue;
			enforce(i < parts.length, "multiaddr: missing value for " ~ p.name);
			const(char)[] value;
			if (p.path)
			{
				value = parts[i .. $].join("/");
				i = parts.length;
			}
			else
				value = parts[i++];
			out_ ~= valueFromText(*p, value);
		}
		return Multiaddr(out_);
	}

	static Multiaddr decode(const(ubyte)[] bytes) @safe pure
	{
		// Walking it is the validation.
		auto ma = Multiaddr(bytes.dup);
		cast(void) ma.components;
		return ma;
	}

	ubyte[] encode() const @safe pure nothrow
	{
		return bytes.dup;
	}

	Component[] components() const @safe pure
	{
		Component[] out_;
		const(ubyte)[] rest = bytes;
		while (rest.length > 0)
		{
			auto c = decodeVarint(rest);
			rest = rest[c.consumed .. $];
			auto p = protocolByCode(c.value);
			enforce(p !is null, format("multiaddr: unknown protocol code %d", c.value));
			size_t len;
			if (p.size == lengthPrefixed)
			{
				auto l = decodeVarint(rest);
				rest = rest[l.consumed .. $];
				len = cast(size_t) l.value;
			}
			else
				len = p.size / 8;
			enforce(len <= rest.length, "multiaddr: truncated value for " ~ p.name);
			out_ ~= Component(p, rest[0 .. len].dup);
			rest = rest[len .. $];
		}
		return out_;
	}

	string toString() const @safe pure
	{
		string s;
		foreach (c; components)
		{
			s ~= "/" ~ c.protocol.name;
			if (c.protocol.size != none)
				s ~= "/" ~ c.text;
		}
		return s;
	}

	Multiaddr opBinary(string op : "~")(const Multiaddr o) const @safe pure nothrow
	{
		return Multiaddr(bytes ~ o.bytes);
	}

	bool opEquals(const Multiaddr o) const @safe pure nothrow
	{
		return bytes == o.bytes;
	}

	size_t toHash() const @safe pure nothrow
	{
		return hashOf(bytes);
	}
}

// --- value codecs -----------------------------------------------------------

private ubyte[] valueFromText(const ref Protocol p, const(char)[] text) @safe pure
{
	import std.conv : to;

	switch (p.name)
	{
	case "ip4":
		return parseIp4(text);
	case "ip6":
		return parseIp6(text);
	case "tcp", "udp":
		{
			immutable port = to!ushort(text);
			return [cast(ubyte)(port >> 8), cast(ubyte)(port & 0xff)];
		}
	case "memory":
		{
			immutable v = to!ulong(text);
			ubyte[] out_ = new ubyte[8];
			foreach (i; 0 .. 8)
				out_[i] = cast(ubyte)(v >> (8 * (7 - i)));
			return out_;
		}
	case "p2p":
		{
			auto mh = base58Decode(text);
			cast(void) Multihash.decode(mh); // must be a multihash
			return encodeVarint(mh.length) ~ mh;
		}
	case "certhash":
		{
			import libp2p.multiformats.multibase : multibaseDecode;

			auto mh = multibaseDecode(text);
			return encodeVarint(mh.length) ~ mh;
		}
	default:
		enforce(p.size == lengthPrefixed, "multiaddr: no codec for " ~ p.name);
		return encodeVarint(text.length) ~ cast(ubyte[]) text.dup;
	}
}

private string valueToText(const ref Protocol p, const(ubyte)[] v) @safe pure
{
	switch (p.name)
	{
	case "ip4":
		return format("%d.%d.%d.%d", v[0], v[1], v[2], v[3]);
	case "ip6":
		return formatIp6(v);
	case "tcp", "udp":
		return format("%d", (v[0] << 8) | v[1]);
	case "memory":
		{
			ulong x;
			foreach (b; v)
				x = (x << 8) | b;
			return format("%d", x);
		}
	case "p2p":
		return base58Encode(v);
	case "certhash":
		{
			import libp2p.multiformats.multibase : multibaseEncode;

			return multibaseEncode(v);
		}
	default:
		return (cast(const(char)[]) v).idup;
	}
}

private ubyte[] parseIp4(const(char)[] text) @safe pure
{
	import std.conv : to;

	auto parts = text.split('.');
	enforce(parts.length == 4, "multiaddr: bad ip4 address");
	ubyte[] out_ = new ubyte[4];
	foreach (i, part; parts)
		out_[i] = to!ubyte(part);
	return out_;
}

private ubyte[] parseIp6(const(char)[] text) @safe pure
{
	import std.conv : to;

	ushort[8] groups;
	auto halves = text.split("::");
	enforce(halves.length <= 2, "multiaddr: bad ip6 address");

	ushort[] head, tail;
	if (halves[0].length > 0)
		foreach (g; halves[0].split(':'))
			head ~= to!ushort(g, 16);
	if (halves.length == 2 && halves[1].length > 0)
		foreach (g; halves[1].split(':'))
			tail ~= to!ushort(g, 16);
	if (halves.length == 1)
		enforce(head.length == 8, "multiaddr: bad ip6 address");
	else
		enforce(head.length + tail.length < 8, "multiaddr: bad ip6 address");

	groups[0 .. head.length] = head;
	groups[8 - tail.length .. 8] = tail;

	ubyte[] out_ = new ubyte[16];
	foreach (i, g; groups)
	{
		out_[2 * i] = cast(ubyte)(g >> 8);
		out_[2 * i + 1] = cast(ubyte)(g & 0xff);
	}
	return out_;
}

// RFC 5952: lowercase, compress the longest run of zero groups (two or more),
// the leftmost on a tie.
private string formatIp6(const(ubyte)[] v) @safe pure
{
	ushort[8] g;
	foreach (i; 0 .. 8)
		g[i] = cast(ushort)((v[2 * i] << 8) | v[2 * i + 1]);

	int bestStart = -1, bestLen = 0;
	for (int i = 0; i < 8;)
	{
		if (g[i] != 0)
		{
			i++;
			continue;
		}
		int j = i;
		while (j < 8 && g[j] == 0)
			j++;
		if (j - i > bestLen)
		{
			bestStart = i;
			bestLen = j - i;
		}
		i = j;
	}
	if (bestLen < 2)
		bestStart = -1;

	string s;
	for (int i = 0; i < 8;)
	{
		if (i == bestStart)
		{
			s ~= "::";
			i += bestLen;
			continue;
		}
		if (s.length > 0 && s[$ - 1] != ':')
			s ~= ":";
		s ~= format("%x", g[i]);
		i++;
	}
	return s;
}
