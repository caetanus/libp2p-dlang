/// Proves the compact-encoding port against byte-exact vectors generated from
/// the real JS (tests/cenc_vectors.d, produced by tests/vectors/gen.js). Each
/// case encodes the same input the generator fed the reference and asserts the
/// bytes are identical; a representative subset also round-trips through decode.
///
/// The whole hyperswarm wire rides on this codec, so "identical to the
/// reference" is the only acceptable bar — a field understood a byte wrong here
/// is understood wrong everywhere above it.
module tests.wire.cenc_test;

import fluent.asserts;
import libp2p.wire.cenc;
import tests.wire.cenc_vectors;
import std.format : format;

private string toHex(const(ubyte)[] b)
{
    string r;
    foreach (x; b)
        r ~= format("%02x", x);
    return r;
}

private string expect(string name)
{
    foreach (ref v; cencVectors)
        if (v.name == name)
            return v.hex;
    assert(0, "missing vector: " ~ name);
}

/// Build a ubyte[] from int literals without the int[]→ubyte[] cast trap.
private ubyte[] B(int[] xs...)
{
    auto r = new ubyte[](xs.length);
    foreach (i, x; xs)
        r[i] = cast(ubyte)x;
    return r;
}

@("cenc: uint (varint) matches the reference across the width boundaries")
unittest
{
    toHex(encode!Uint(0UL)).should.equal(expect("uint:0"));
    toHex(encode!Uint(1UL)).should.equal(expect("uint:1"));
    toHex(encode!Uint(0xfcUL)).should.equal(expect("uint:0xfc"));
    toHex(encode!Uint(0xfdUL)).should.equal(expect("uint:0xfd"));
    toHex(encode!Uint(0xffUL)).should.equal(expect("uint:0xff"));
    toHex(encode!Uint(0x100UL)).should.equal(expect("uint:0x100"));
    toHex(encode!Uint(0xffffUL)).should.equal(expect("uint:0xffff"));
    toHex(encode!Uint(0x10000UL)).should.equal(expect("uint:0x10000"));
    toHex(encode!Uint(0xffffffffUL)).should.equal(expect("uint:0xffffffff"));
    toHex(encode!Uint(0x100000000UL)).should.equal(expect("uint:0x100000000"));
    toHex(encode!Uint(MAX_SAFE_INTEGER)).should.equal(expect("uint:maxsafe"));
}

@("cenc: fixed-width uints, little- and big-endian")
unittest
{
    toHex(encode!Uint8(255UL)).should.equal(expect("uint8:255"));
    toHex(encode!Uint16(65535UL)).should.equal(expect("uint16:65535"));
    toHex(encode!Uint24(0x123456UL)).should.equal(expect("uint24:0x123456"));
    toHex(encode!Uint32(0xdeadbeefUL)).should.equal(expect("uint32:0xdeadbeef"));
    toHex(encode!Uint32be(0xdeadbeefUL)).should.equal(expect("uint32be:0xdeadbeef"));
    toHex(encode!Uint40(0x123456789aUL)).should.equal(expect("uint40:0x123456789a"));
    toHex(encode!Uint48(0x123456789abcUL)).should.equal(expect("uint48:0x123456789abc"));
    toHex(encode!Uint56(0x123456789abcdeUL)).should.equal(expect("uint56:0x123456789abcde"));
    toHex(encode!Uint64(0x1fffffffffffffUL)).should.equal(expect("uint64:0x1fffffffffffff"));
    toHex(encode!Uint64be(0x1fffffffffffffUL)).should.equal(expect("uint64be:0x1fffffffffffff"));
}

@("cenc: signed ints use zig-zag exactly")
unittest
{
    toHex(encode!Int(0L)).should.equal(expect("int:0"));
    toHex(encode!Int(-1L)).should.equal(expect("int:-1"));
    toHex(encode!Int(1L)).should.equal(expect("int:1"));
    toHex(encode!Int(-2L)).should.equal(expect("int:-2"));
    toHex(encode!Int(2L)).should.equal(expect("int:2"));
    toHex(encode!Int(100L)).should.equal(expect("int:100"));
    toHex(encode!Int(-100L)).should.equal(expect("int:-100"));
    toHex(encode!Int(MAX_SAFE_INT)).should.equal(expect("int:maxsafe"));
    toHex(encode!Int(MIN_SAFE_INT)).should.equal(expect("int:minsafe"));
    toHex(encode!Int32(-70000L)).should.equal(expect("int32:-70000"));
}

@("cenc: floats are IEEE-754 little-endian")
unittest
{
    toHex(encode!Float32(1.5f)).should.equal(expect("float32:1.5"));
    toHex(encode!Float64(-3.14159)).should.equal(expect("float64:-3.14159"));
}

@("cenc: bool")
unittest
{
    toHex(encode!Bool(true)).should.equal(expect("bool:true"));
    toHex(encode!Bool(false)).should.equal(expect("bool:false"));
}

@("cenc: length-prefixed buffers, incl. the 3-byte length boundary")
unittest
{
    toHex(encode!Buffer(B())).should.equal(expect("buffer:empty"));
    toHex(encode!Buffer(B(1, 2, 3))).should.equal(expect("buffer:123"));

    auto big = new ubyte[](300);
    foreach (i; 0 .. 300)
        big[i] = cast(ubyte)(i & 0xff);
    toHex(encode!Buffer(big)).should.equal(expect("buffer:300"));
}

@("cenc: fixed-width byte fields carry no length prefix")
unittest
{
    toHex(encode!(Fixed!4)(B(1, 2, 3, 4))).should.equal(expect("fixed4:1234"));

    auto f = new ubyte[](32);
    foreach (i; 0 .. 32)
        f[i] = cast(ubyte)i;
    toHex(encode!Fixed32(f)).should.equal(expect("fixed32"));
}

@("cenc: utf8 strings, multibyte and past the 1-byte length boundary")
unittest
{
    toHex(encode!Utf8("")).should.equal(expect("utf8:empty"));
    toHex(encode!Utf8("hi")).should.equal(expect("utf8:hi"));
    toHex(encode!Utf8("héllo")).should.equal(expect("utf8:multibyte"));

    auto s = new char[](300);
    s[] = 'x';
    toHex(encode!Utf8(cast(string)s)).should.equal(expect("utf8:long"));
}

@("cenc: array combinator (count + items)")
unittest
{
    toHex(encode!(ArrayOf!Uint)(cast(ulong[])[])).should.equal(expect("array-uint:empty"));
    toHex(encode!(ArrayOf!Uint)([1UL, 2UL, 3UL])).should.equal(expect("array-uint:123"));
    toHex(encode!(ArrayOf!Uint)([300UL, 70000UL])).should.equal(expect("array-uint:big"));
    toHex(encode!(ArrayOf!Utf8)(["a", "bb"])).should.equal(expect("array-utf8"));
}

@("cenc: frame prefixes the inner message with its byte length")
unittest
{
    toHex(encode!(Frame!Utf8)("hello")).should.equal(expect("frame-utf8:hello"));
}

@("cenc: ipv4/ipv6/ip and address forms")
unittest
{
    toHex(encode!Ipv4("127.0.0.1")).should.equal(expect("ipv4:127.0.0.1"));
    toHex(encode!Ipv4("255.255.255.255")).should.equal(expect("ipv4:255.255.255.255"));
    toHex(encode!Ipv6("::1")).should.equal(expect("ipv6:::1"));
    toHex(encode!Ipv6("2001:db8::1")).should.equal(expect("ipv6:2001:db8::1"));
    toHex(encode!Ipv6("fe80::1")).should.equal(expect("ipv6:fe80::1"));
    toHex(encode!Ip("127.0.0.1")).should.equal(expect("ip:v4"));
    toHex(encode!Ip("::1")).should.equal(expect("ip:v6"));
    toHex(encode!IpAddress(Address("127.0.0.1", 4, 49737))).should.equal(expect("ipAddress:v4"));
    toHex(encode!IpAddress(Address("::1", 6, 1))).should.equal(expect("ipAddress:v6"));
    toHex(encode!Ipv4Address(Address("10.0.0.7", 4, 8080))).should.equal(expect("ipv4Address"));
    toHex(encode!Ipv6Address(Address("2001:db8::1", 6, 4001))).should.equal(expect("ipv6Address"));
}

// ── round-trips: decode must recover exactly what encode wrote ───────────────

@("cenc: uint round-trips across widths")
unittest
{
    foreach (n; [0UL, 1, 0xfc, 0xfd, 0xffff, 0x10000, 0xffffffff, 0x100000000, MAX_SAFE_INTEGER])
        decode!Uint(encode!Uint(n)).should.equal(n);
}

@("cenc: int round-trips (zig-zag)")
unittest
{
    foreach (n; [0L, -1, 1, -2, 2, 100, -100, MAX_SAFE_INT, MIN_SAFE_INT])
        decode!Int(encode!Int(n)).should.equal(n);
}

@("cenc: buffer/utf8/bool round-trip")
unittest
{
    decode!Buffer(encode!Buffer(B(9, 8, 7))).should.equal(B(9, 8, 7));
    decode!Utf8(encode!Utf8("héllo world")).should.equal("héllo world");
    decode!Bool(encode!Bool(true)).should.equal(true);
    decode!Bool(encode!Bool(false)).should.equal(false);
}

@("cenc: array/frame/ipAddress round-trip")
unittest
{
    decode!(ArrayOf!Uint)(encode!(ArrayOf!Uint)([300UL, 70000UL])).should.equal([300UL, 70000UL]);
    decode!(Frame!Utf8)(encode!(Frame!Utf8)("hello")).should.equal("hello");

    auto a = decode!IpAddress(encode!IpAddress(Address("127.0.0.1", 4, 49737)));
    a.host.should.equal("127.0.0.1");
    a.family.should.equal(4);
    a.port.should.equal(49737);
}

@("cenc: decode past the buffer end throws")
unittest
{
    ubyte[] short_ = [0xfd, 0x01]; // says u16 follows but only one byte is left
    ({ cast(void)decode!Uint(short_); }).should.throwAnyException;
}
