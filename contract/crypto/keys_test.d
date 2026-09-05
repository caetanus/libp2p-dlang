module tests.crypto.keys_test;

import libp2p.crypto.keys;
import fluent.asserts;

@("ed25519 sign then verify succeeds")
unittest
{
	auto kp = Keypair.generateEd25519;
	ubyte[] msg = cast(ubyte[]) "hello libp2p".dup;
	auto sig = kp.sign(msg);
	sig.length.should.equal(64);
	kp.publicKey.verify(msg, sig).should.equal(true);
}

@("verify rejects a tampered message")
unittest
{
	auto kp = Keypair.generateEd25519;
	ubyte[] msg = cast(ubyte[]) "authentic".dup;
	auto sig = kp.sign(msg);
	ubyte[] forged = cast(ubyte[]) "authentiC".dup;
	kp.publicKey.verify(forged, sig).should.equal(false);
}

@("verify rejects a tampered signature")
unittest
{
	auto kp = Keypair.generateEd25519;
	ubyte[] msg = cast(ubyte[]) "data".dup;
	auto sig = kp.sign(msg);
	sig[0] ^= 0x01;
	kp.publicKey.verify(msg, sig).should.equal(false);
}

@("fromSeed is deterministic")
unittest
{
	ubyte[32] seed = 7;
	auto a = Keypair.fromSeed(seed[]);
	auto b = Keypair.fromSeed(seed[]);
	a.pub.should.equal(b.pub);
	// A signature from one verifies under the other's identical public key.
	ubyte[] msg = cast(ubyte[]) "same".dup;
	b.publicKey.verify(msg, a.sign(msg)).should.equal(true);
}

@("PublicKey protobuf roundtrips")
unittest
{
	auto kp = Keypair.generateEd25519;
	auto pk = kp.publicKey;
	auto back = PublicKey.fromProtobuf(pk.toProtobuf);
	back.type.should.equal(KeyType.ed25519);
	back.data.should.equal(pk.data);
}

@("Ed25519 PublicKey protobuf has the expected 36-byte layout")
unittest
{
	auto kp = Keypair.generateEd25519;
	auto pb = kp.publicKey.toProtobuf;
	pb.length.should.equal(36);
	pb[0].should.equal(cast(ubyte) 0x08); // field 1, varint
	pb[1].should.equal(cast(ubyte) 0x01); // KeyType.ed25519
	pb[2].should.equal(cast(ubyte) 0x12); // field 2, bytes
	pb[3].should.equal(cast(ubyte) 0x20); // length 32
}
