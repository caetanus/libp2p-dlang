module tests.core.peer_id_test;

import std.digest : toHexString;
import libp2p.core.peer_id;
import libp2p.crypto.keys;
import libp2p.multiformats.multihash : Multihash, HashCode;
import fluent.asserts;

// Cross-impl vector from rust-libp2p `identity/src/keypair.rs`
// (keypair_protobuf_roundtrip_ed25519): the 32-byte Ed25519 seed and the
// pubkey-protobuf it must derive to. Pins our libsodium key derivation +
// PeerId formatting to rust/dalek byte-for-byte.
private enum edSeedHex = "7E0830617C4A7DE83925DFB2694556B12936C477A0E1FEB2E148EC9DA60FEE7D";
private enum edPubProtobufHex = "080112201ED1E8FAE2C4A144B8BE8FD4B47BF3D3B34B871C3CACF6010F0E42D474FCE27E";
private enum edPeerId = "12D3KooWBtg3aaRMjxwedh83aGiUkwSxDwUZkzuJcfaqUmo7R3pq";

private ubyte[] fromHex(string s)
{
	ubyte[] r;
	foreach (i; 0 .. s.length / 2)
	{
		import std.conv : to;

		r ~= s[2 * i .. 2 * i + 2].to!ubyte(16);
	}
	return r;
}

@("Ed25519 peer id uses an identity multihash")
unittest
{
	auto kp = Keypair.generateEd25519;
	auto pid = PeerId.fromPublicKey(kp.publicKey);
	auto mh = Multihash.decode(pid.bytes);
	// Ed25519 protobuf is 36 bytes (<= 42) so it is inlined, not hashed.
	mh.code.should.equal(cast(ulong) HashCode.identity);
	mh.digest.should.equal(kp.publicKey.toProtobuf);
}

@("Ed25519 peer id renders as a 12D3Koo… string")
unittest
{
	auto kp = Keypair.generateEd25519;
	auto pid = PeerId.fromPublicKey(kp.publicKey);
	// The fixed multihash+protobuf prefix always base58-encodes to this.
	pid.toBase58[0 .. 7].should.equal("12D3Koo");
}

@("peer id base58 roundtrips")
unittest
{
	auto kp = Keypair.generateEd25519;
	auto pid = PeerId.fromPublicKey(kp.publicKey);
	PeerId.fromBase58(pid.toBase58).should.equal(pid);
}

@("peer id embeds the public key so it can be recovered")
unittest
{
	auto kp = Keypair.generateEd25519;
	auto pid = PeerId.fromPublicKey(kp.publicKey);
	auto mh = Multihash.decode(pid.bytes);
	auto recovered = PublicKey.fromProtobuf(mh.digest);
	recovered.data.should.equal(kp.pub);
}

// Cross-impl fixed vector (rust-libp2p): a known Ed25519 seed must produce the
// exact pubkey protobuf and the exact 12D3Koo… PeerId that rust/go compute.
@("Ed25519 seed produces the rust-libp2p pubkey and peer id vector")
unittest
{
	auto kp = Keypair.fromSeed(fromHex(edSeedHex));
	// Our libsodium derivation matches rust/dalek's public key exactly.
	kp.publicKey.toProtobuf.toHexString.should.equal(edPubProtobufHex);
	// And the canonical PeerId string matches.
	PeerId.fromPublicKey(kp.publicKey).toBase58.should.equal(edPeerId);
	// Round-trips through the textual form.
	PeerId.fromBase58(edPeerId).toBase58.should.equal(edPeerId);
}

// The SHA2-256 PeerId path (for keys whose protobuf exceeds 42 bytes, e.g. RSA)
// — exercised with a synthetic oversized key so the branch is covered.
@("large public keys hash to a sha2-256 peer id")
unittest
{
	auto big = PublicKey(KeyType.rsa, new ubyte[64]); // protobuf > 42 bytes
	auto pid = PeerId.fromPublicKey(big);
	auto mh = Multihash.decode(pid.bytes);
	mh.code.should.equal(cast(ulong) HashCode.sha2_256);
	mh.digest.length.should.equal(32);
}

@("distinct keys yield distinct peer ids")
unittest
{
	auto a = PeerId.fromPublicKey(Keypair.generateEd25519.publicKey);
	auto b = PeerId.fromPublicKey(Keypair.generateEd25519.publicKey);
	(a == b).should.equal(false);
}
