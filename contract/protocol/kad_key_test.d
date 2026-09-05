module tests.protocol.kad_key_test;

import libp2p.crypto.keys : Keypair;
import libp2p.core.peer_id : PeerId;
import libp2p.protocol.kad.key;
import fluent.asserts;

private Key randomKey()
{
	return Key.fromPeer(PeerId.fromPublicKey(Keypair.generateEd25519.publicKey));
}

// Laundered from rust `kbucket/key.rs::tests::identity`: a key is at distance 0
// from itself.
@("kad key: distance to self is zero")
unittest
{
	foreach (_; 0 .. 50)
	{
		auto a = randomKey();
		a.distance(a).should.equal(Distance.init);
		a.distance(a).ilog2.should.equal(-1);
	}
}

// Laundered from `symmetry`: distance is symmetric.
@("kad key: distance is symmetric")
unittest
{
	foreach (_; 0 .. 50)
	{
		auto a = randomKey(), b = randomKey();
		(a.distance(b) == b.distance(a)).should.equal(true);
	}
}

// Laundered from `triangle_inequality`: d(a,c) <= d(a,b) + d(b,c) (discarding
// runs where the sum overflows the 256-bit space, as rust does).
@("kad key: the XOR metric obeys the triangle inequality")
unittest
{
	foreach (_; 0 .. 100)
	{
		auto a = randomKey(), b = randomKey(), c = randomKey();
		auto ab = a.distance(b);
		auto bc = b.distance(c);
		bool overflow;
		auto sum = addChecked(ab, bc, overflow);
		if (overflow)
			continue; // discard, like rust's TestResult::discard
		(a.distance(c) <= sum).should.equal(true);
	}
}

// Laundered from `unidirectionality`: for a fixed distance d = dist(a,b), no
// other key c has dist(a,c) == d (XOR distance is a bijection).
@("kad key: distance is unidirectional")
unittest
{
	foreach (_; 0 .. 20)
	{
		auto a = randomKey(), b = randomKey();
		auto d = a.distance(b);
		foreach (_2; 0 .. 100)
		{
			auto c = randomKey();
			(a.distance(c) != d || b == c).should.equal(true);
		}
	}
}

// ilog2 gives the 0-based index of the most-significant differing bit.
@("kad key: ilog2 indexes the most-significant set bit")
unittest
{
	Distance d;
	d.bytes[31] = 0x01; // least significant bit set
	d.ilog2.should.equal(0);

	Distance e;
	e.bytes[0] = 0x80; // most significant bit set
	e.ilog2.should.equal(255);

	Distance f;
	f.bytes[30] = 0x01; // bit 8
	f.ilog2.should.equal(8);

	Distance z;
	z.ilog2.should.equal(-1);
}
