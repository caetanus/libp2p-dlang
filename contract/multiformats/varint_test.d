module tests.multiformats.varint_test;

import libp2p.multiformats.varint;
import fluent.asserts;

@("encode single-byte values")
unittest
{
	ubyte[] zero = [0x00];
	ubyte[] one = [0x01];
	ubyte[] max7 = [0x7f];
	encodeVarint(0).should.equal(zero);
	encodeVarint(1).should.equal(one);
	encodeVarint(127).should.equal(max7);
}

@("encode multi-byte values (rust unsigned-varint vectors)")
unittest
{
	ubyte[] v128 = [0x80, 0x01];
	ubyte[] v255 = [0xff, 0x01];
	ubyte[] v300 = [0xac, 0x02];
	ubyte[] v16384 = [0x80, 0x80, 0x01];
	encodeVarint(128).should.equal(v128);
	encodeVarint(255).should.equal(v255);
	encodeVarint(300).should.equal(v300);
	encodeVarint(16384).should.equal(v16384);
	// max u64 is the canonical 10-byte LEB128 form (nine 0xff then 0x01).
	encodeVarint(ulong.max).should.equal(
		cast(ubyte[])[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]);
}

@("decode roundtrip across representative values")
unittest
{
	foreach (ulong v; [0UL, 1, 127, 128, 255, 300, 16384, 0x7fff_ffff, ulong.max])
	{
		auto enc = encodeVarint(v);
		auto dec = decodeVarint(enc);
		dec.value.should.equal(v);
		dec.consumed.should.equal(enc.length);
	}
}

@("decode stops at end of varint and reports consumed")
unittest
{
	ubyte[] buf = [0xac, 0x02, 0xff, 0xff]; // 300, then trailing garbage
	auto dec = decodeVarint(buf);
	dec.value.should.equal(300UL);
	dec.consumed.should.equal(2);
}

@("decode of truncated varint throws")
unittest
{
	ubyte[] buf = [0x80]; // continuation bit set, no following byte
	buf.decodeVarint.should.throwAnyException;
}

@("encodeVarintInto matches encodeVarint")
unittest
{
	ubyte[maxVarintLen64] scratch;
	foreach (ulong v; [0UL, 1, 300, 16384, ulong.max])
		encodeVarintInto(v, scratch[]).should.equal(encodeVarint(v));
}

// rust `unsigned-varint` distinguishes Overflow from Insufficient. The truncation
// (Insufficient) path is tested elsewhere; this covers Overflow: more than 10
// bytes, and a 10th byte carrying more than one payload bit (u64 overflow).
@("varint decode rejects overflow")
unittest
{
	bool threwTooLong, threwU64;
	ubyte[] tooLong = new ubyte[11];
	foreach (ref b; tooLong)
		b = 0x80; // all continuation, never terminates within 10 bytes
	try
		decodeVarint(tooLong);
	catch (Exception)
		threwTooLong = true;

	ubyte[] u64over = [0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02];
	try
		decodeVarint(u64over);
	catch (Exception)
		threwU64 = true;

	threwTooLong.should.equal(true);
	threwU64.should.equal(true);
}
