module tests.multiformats.base58_test;

import libp2p.multiformats.base58;
import fluent.asserts;

/// Test vectors lifted from rust `bs58`'s `TEST_CASES`.
private struct Vec
{
	string encoded;
	ubyte[] decoded;
}

private static immutable Vec[] cases = [
	Vec("", []),
	Vec("Z", [32]),
	Vec("n", [45]),
	Vec("q", [48]),
	Vec("r", [49]),
	Vec("z", [57]),
	Vec("4SU", [45, 49]),
	Vec("4k8", [49, 49]),
	Vec("ZiCa", [97, 98, 99]),
	Vec("2NEpo7TZRRrLZSi2U", [
		'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'
	]),
];

@("base58 encode matches rust bs58 vectors")
unittest
{
	foreach (v; cases)
		base58Encode(v.decoded).should.equal(v.encoded);
}

@("base58 decode matches rust bs58 vectors")
unittest
{
	foreach (v; cases)
		base58Decode(v.encoded).should.equal(v.decoded);
}

@("base58 leading zero bytes become leading ones")
unittest
{
	ubyte[] data = [0x00, 0x00, 0x28, 0x7f, 0xb4, 0xcd];
	base58Encode(data).should.equal("11233QC4");
	base58Decode("11233QC4").should.equal(data);
}

@("base58 roundtrips arbitrary bytes")
unittest
{
	ubyte[] data = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x7f, 0x80, 0xff];
	base58Decode(base58Encode(data)).should.equal(data);
}

@("base58 rejects characters outside the alphabet")
unittest
{
	base58Decode("0OIl").should.throwAnyException; // 0, O, I, l are excluded
}
