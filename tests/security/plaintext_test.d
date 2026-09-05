module tests.security.plaintext_test;

import std.exception : collectExceptionMsg;

import libp2p.core.stream;
import libp2p.crypto.keys : Keypair;
import libp2p.core.peer_id : PeerId;
import libp2p.security.plaintext : plaintextUpgrade, plaintextProtocol, PlaintextStream, Exchange;
import tests.util.pipe : runPair;
import fluent.asserts;

// The whole protocol: each side learns who the other is, and nothing is hidden
// from anyone watching. The identity half is the part worth testing.
@("plaintext: both sides learn the other's authenticated identity")
unittest
{
	auto a = Keypair.generateEd25519;
	auto b = Keypair.generateEd25519;
	PeerId aSaw, bSaw;
	ubyte[] carried;

	runPair(
		(Stream c) {
		auto s = plaintextUpgrade(c, a);
		aSaw = s.remotePeer;
		s.write(cast(ubyte[]) "hello".dup);
	},
		(Stream c) {
		auto s = plaintextUpgrade(c, b);
		bSaw = s.remotePeer;
		auto buf = new ubyte[5];
		s.readExact(buf);
		carried = buf;
	});

	(aSaw == PeerId.fromPublicKey(b.publicKey)).should.equal(true);
	(bSaw == PeerId.fromPublicKey(a.publicKey)).should.equal(true);
	carried.should.equal(cast(ubyte[]) "hello");
}

// The one check the protocol makes. Without it the claimed id is decoration: a
// peer could name any identity while presenting a key it actually holds.
@("plaintext: a peer id that does not derive from the key is refused")
unittest
{
	auto honest = Keypair.generateEd25519;
	auto liar = Keypair.generateEd25519;
	auto victim = Keypair.generateEd25519;

	string err;
	runPair(
		(Stream c) {
		// Claims the victim's identity while holding its own key.
		Exchange forged;
		forged.id = PeerId.fromPublicKey(victim.publicKey).bytes.dup;
		forged.pubkey = liar.publicKey.toProtobuf;
		c.writeLengthPrefixed(forged.encode);
		try
			c.readExact(new ubyte[1]);
		catch (Exception)
		{
		}
	},
		(Stream c) { err = collectExceptionMsg(plaintextUpgrade(c, honest)); });

	err.should.equal("plaintext: the peer id does not match the public key");
}

@("plaintext: an empty exchange is refused")
unittest
{
	auto honest = Keypair.generateEd25519;
	string err;
	runPair(
		(Stream c) {
		Exchange empty;
		c.writeLengthPrefixed(empty.encode);
		try
			c.readExact(new ubyte[1]);
		catch (Exception)
		{
		}
	},
		(Stream c) { err = collectExceptionMsg(plaintextUpgrade(c, honest)); });

	err.should.equal("plaintext: peer sent no public key");
}
