/**
 * Protocol Buffers (proto2 wire format) derived from a D struct at compile time.
 *
 * A message is a struct whose fields carry `@field(n)`. The wire type follows
 * from the D type: integers, `bool` and enums are varints; `ubyte[]`, `string`
 * and nested structs are length-delimited; any other array is a repeated
 * field, one tag per element; `Nullable!T` is an optional field that is only
 * written when set. Plain fields are always written. Fields are written in
 * ascending field-number order, which is what the other implementations do
 * and what makes byte-for-byte vectors comparable. Unknown fields are skipped
 * on decode, as proto2 requires.
 *
 * ```
 * struct PublicKeyMsg { @field(1) uint type; @field(2) ubyte[] data; }
 * ubyte[] bytes = encode(msg);
 * auto back = decode!PublicKeyMsg(bytes);
 * ```
 */
module libp2p.wire.protobuf;

import std.exception : enforce;
import std.traits : isIntegral, isBoolean, hasUDA, getUDAs, isArray, isSomeString;
import std.typecons : Nullable;
import std.meta : Filter, staticSort, NoDuplicates;

import libp2p.multiformats.varint : encodeVarint, encodeVarintInto, decodeVarint, maxVarintLen64;

/// Marks a struct member as protobuf field `number`.
struct field
{
	uint number;
}

/// A plain field that is written only when it holds something: a non-empty
/// string or array, a non-default scalar. proto2 `optional` without the
/// `Nullable` on the D side, for messages where "absent" and "empty" mean the
/// same thing to every reader.
enum optional;

enum WireType : ubyte
{
	varint = 0,
	fixed64 = 1,
	lengthDelimited = 2,
	startGroup = 3,
	endGroup = 4,
	fixed32 = 5,
}

private template isNullable(T)
{
	enum isNullable = is(T : Nullable!U, U);
}

private template isBytes(T)
{
	enum isBytes = is(T : const(ubyte)[]);
}

private template isMessage(T)
{
	enum isMessage = is(T == struct) && !isNullable!T && fieldMembers!T.length > 0;
}

private template fieldMembers(T)
{
	template hasField(string m)
	{
		static if (__traits(compiles, __traits(getMember, T, m)) && !is(typeof(__traits(getMember, T, m)) == function))
			enum hasField = hasUDA!(__traits(getMember, T, m), field);
		else
			enum hasField = false;
	}

	alias fieldMembers = Filter!(hasField, __traits(allMembers, T));
}

private template fieldNumber(T, string m)
{
	enum fieldNumber = getUDAs!(__traits(getMember, T, m), field)[0].number;
}

private template byNumber(T)
{
	template less(string a, string b)
	{
		enum less = fieldNumber!(T, a) < fieldNumber!(T, b);
	}

	alias byNumber = staticSort!(less, fieldMembers!T);
}

// --- encode ---------------------------------------------------------------

ubyte[] encode(T)(auto ref const T msg) if (isMessage!T)
{
	ubyte[] out_;
	encodeInto(msg, out_);
	return out_;
}

private void encodeInto(T)(auto ref const T msg, ref ubyte[] out_) if (isMessage!T)
{
	static foreach (m; byNumber!T)
		encodeField!(fieldNumber!(T, m), hasUDA!(__traits(getMember, T, m), optional))(__traits(getMember, msg, m), out_);
}

private void encodeField(uint number, bool skipEmpty = false, T)(auto ref const T value, ref ubyte[] out_)
{
	static if (skipEmpty)
	{
		static if (isArray!T || isSomeString!T)
		{
			if (value.length == 0)
				return;
		}
		else static if (!isNullable!T)
		{
			if (value == T.init)
				return;
		}
	}
	static if (isNullable!T)
	{
		if (!value.isNull)
			encodeField!number(value.get, out_);
	}
	else static if (isBytes!T || isSomeString!T)
	{
		putTag(out_, number, WireType.lengthDelimited);
		out_ ~= encodeVarint(value.length);
		out_ ~= cast(const(ubyte)[]) value;
	}
	else static if (isArray!T)
	{
		foreach (ref e; value)
			encodeField!number(e, out_);
	}
	else static if (isIntegral!T || isBoolean!T || is(T == enum))
	{
		putTag(out_, number, WireType.varint);
		out_ ~= encodeVarint(cast(ulong) cast(long) value);
	}
	else static if (isMessage!T)
	{
		ubyte[] inner;
		encodeInto(value, inner);
		putTag(out_, number, WireType.lengthDelimited);
		out_ ~= encodeVarint(inner.length);
		out_ ~= inner;
	}
	else
		static assert(0, "protobuf: no wire type for " ~ T.stringof);
}

private void putTag(ref ubyte[] out_, uint number, WireType wt)
{
	out_ ~= encodeVarint((cast(ulong) number << 3) | wt);
}

// --- decode ---------------------------------------------------------------

T decode(T)(const(ubyte)[] bytes) if (isMessage!T)
{
	T msg;
	decodeInto(msg, bytes);
	return msg;
}

private void decodeInto(T)(ref T msg, const(ubyte)[] bytes) if (isMessage!T)
{
	while (bytes.length > 0)
	{
		auto tag = decodeVarint(bytes);
		bytes = bytes[tag.consumed .. $];
		immutable number = cast(uint)(tag.value >> 3);
		immutable wt = cast(WireType)(tag.value & 7);

		bool known;
		static foreach (m; fieldMembers!T)
		{
			if (number == fieldNumber!(T, m))
			{
				known = true;
				bytes = decodeField(__traits(getMember, msg, m), wt, bytes);
			}
		}
		if (!known)
			bytes = skipField(wt, bytes);
	}
}

private const(ubyte)[] decodeField(T)(ref T target, WireType wt, const(ubyte)[] bytes)
{
	static if (isNullable!T)
	{
		alias U = typeof(target.get);
		U v;
		bytes = decodeField(v, wt, bytes);
		target = v;
		return bytes;
	}
	else static if (isBytes!T || isSomeString!T)
	{
		auto payload = takeLengthDelimited(wt, bytes);
		static if (isSomeString!T)
			target = cast(T) payload.idup;
		else
			target = payload.dup;
		return bytes;
	}
	else static if (isArray!T)
	{
		import std.range.primitives : ElementType;

		ElementType!T e;
		bytes = decodeField(e, wt, bytes);
		target ~= e;
		return bytes;
	}
	else static if (isIntegral!T || isBoolean!T || is(T == enum))
	{
		enforce(wt == WireType.varint, "protobuf: expected a varint");
		auto v = decodeVarint(bytes);
		target = cast(T) v.value;
		return bytes[v.consumed .. $];
	}
	else static if (isMessage!T)
	{
		auto payload = takeLengthDelimited(wt, bytes);
		T inner;
		decodeInto(inner, payload);
		target = inner;
		return bytes;
	}
	else
		static assert(0, "protobuf: no wire type for " ~ T.stringof);
}

private const(ubyte)[] takeLengthDelimited(WireType wt, ref const(ubyte)[] bytes)
{
	enforce(wt == WireType.lengthDelimited, "protobuf: expected a length-delimited field");
	auto len = decodeVarint(bytes);
	bytes = bytes[len.consumed .. $];
	enforce(len.value <= bytes.length, "protobuf: truncated field");
	auto payload = bytes[0 .. cast(size_t) len.value];
	bytes = bytes[cast(size_t) len.value .. $];
	return payload;
}

private const(ubyte)[] skipField(WireType wt, const(ubyte)[] bytes)
{
	final switch (wt)
	{
	case WireType.varint:
		return bytes[decodeVarint(bytes).consumed .. $];
	case WireType.fixed64:
		enforce(bytes.length >= 8, "protobuf: truncated field");
		return bytes[8 .. $];
	case WireType.lengthDelimited:
		cast(void) takeLengthDelimited(wt, bytes);
		return bytes;
	case WireType.fixed32:
		enforce(bytes.length >= 4, "protobuf: truncated field");
		return bytes[4 .. $];
	case WireType.startGroup:
	case WireType.endGroup:
		throw new Exception("protobuf: groups are not supported");
	}
}
