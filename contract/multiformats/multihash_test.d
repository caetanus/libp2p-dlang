module tests.multiformats.multihash_test;

import std.digest : toHexString;
import libp2p.multiformats.multihash;
import fluent.asserts;

@("identity multihash wraps data verbatim")
unittest
{
	ubyte[] data = ['h', 'e', 'l', 'l', 'o'];
	auto mh = multihashIdentity(data);
	mh.code.should.equal(cast(ulong) HashCode.identity);
	mh.digest.should.equal(data);

	ubyte[] expected = [0x00, 0x05, 'h', 'e', 'l', 'l', 'o'];
	mh.encode.should.equal(expected);
}

@("sha2-256 multihash matches canonical NIST/RFC digests")
unittest
{
	// Full 32-byte digests (uppercase hex), not just the prefix — a partial
	// check would pass even with a broken hash.
	auto empty = multihashSha256([]);
	empty.code.should.equal(cast(ulong) HashCode.sha2_256);
	empty.digest.length.should.equal(32);
	empty.digest.toHexString.should.equal(
		"E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855");
	// multihash prefix 0x12 (code) 0x20 (len=32) then the digest.
	empty.encode[0 .. 2].should.equal(cast(ubyte[])[0x12, 0x20]);

	// SHA-256("abc") — the canonical RFC 6234 vector.
	auto abc = multihashSha256(cast(ubyte[]) "abc");
	abc.digest.toHexString.should.equal(
		"BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD");
}

@("multihash encode/decode roundtrip")
unittest
{
	ubyte[] payload = [1, 2, 3, 4, 5, 6, 7, 8];
	foreach (mh; [multihashIdentity(payload), multihashSha256(payload)])
	{
		auto back = Multihash.decode(mh.encode);
		back.code.should.equal(mh.code);
		back.digest.should.equal(mh.digest);
	}
}

@("multihash decode ignores trailing bytes")
unittest
{
	auto mh = multihashIdentity([0xaa, 0xbb]);
	auto bytes = mh.encode ~ cast(ubyte[])[0xff, 0xff];
	auto back = Multihash.decode(bytes);
	back.digest.should.equal(cast(ubyte[])[0xaa, 0xbb]);
}
