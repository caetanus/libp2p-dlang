module tests.multiformats.multibase_test;

import libp2p.multiformats.multibase;
import fluent.asserts;

@("multibase base64url encodes with a 'u' prefix and round-trips")
unittest
{
	ubyte[] data = [0x12, 0x20, 0xe2, 0x92, 0x9e, 0x4a];
	auto enc = multibaseEncode(data);
	enc[0].should.equal('u');
	multibaseDecode(enc).should.equal(data);
}

@("multibase decodes the libp2p certhash vector to its multihash bytes")
unittest
{
	// The certhash from the webrtc-direct parse vectors: base64url of the
	// SHA-256 multihash (0x12 0x20 || 32-byte digest).
	auto mh = multibaseDecode("uEiDikp5KVUgkLta1EjUN-IKbHk-dUBg8VzKgf5nXxLK46w");
	mh.length.should.equal(34);
	mh[0 .. 2].should.equal(cast(ubyte[])[0x12, 0x20]);
	mh[2 .. 6].should.equal(cast(ubyte[])[0xe2, 0x92, 0x9e, 0x4a]);
}

@("multibase rejects unsupported bases and empty input")
unittest
{
	multibaseDecode("bMFRGG").should.throwException!Exception;
	multibaseDecode("").should.throwException!Exception;
}
