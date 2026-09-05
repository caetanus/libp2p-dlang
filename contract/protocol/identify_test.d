module tests.protocol.identify_test;

import libp2p.protocol.identify;
import libp2p.core.stream : ByteStream;
import libp2p.crypto.keys : Keypair;
import libp2p.core.peer_id : PeerId;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.muxer.mplex : Mplex;
import libp2p.multistream.select : negotiateDialer, negotiateListener;
import tests.util.fiberpipe : runPair;
import fluent.asserts;

private Identify sample()
{
	auto kp = Keypair.generateEd25519;
	Identify id;
	id.publicKey = kp.publicKey.toProtobuf;
	id.listenAddrs ~= Multiaddr.parse("/ip4/127.0.0.1/tcp/4001").encode;
	id.listenAddrs ~= Multiaddr.parse("/ip6/::1/tcp/4001").encode;
	id.protocols = ["/ipfs/ping/1.0.0", "/ipfs/id/1.0.0"];
	id.observedAddr = Multiaddr.parse("/ip4/1.2.3.4/tcp/55555").encode;
	id.protocolVersion = "ipfs/0.1.0";
	id.agentVersion = "libp2p-dlang/0.1.0";
	return id;
}

@("Identify protobuf roundtrips all fields")
unittest
{
	auto id = sample();
	auto back = Identify.decode(id.encode);
	back.publicKey.should.equal(id.publicKey);
	back.listenAddrs.should.equal(id.listenAddrs);
	back.protocols.should.equal(id.protocols);
	back.observedAddr.should.equal(id.observedAddr);
	back.protocolVersion.should.equal(id.protocolVersion);
	back.agentVersion.should.equal(id.agentVersion);
}

@("Identify decode ignores unknown fields")
unittest
{
	// A minimal message with only agentVersion (field 6) plus an unknown
	// varint field 9 that must be skipped.
	Identify id;
	id.agentVersion = "x";
	auto bytes = id.encode ~ cast(ubyte[])[(9 << 3) | 0, 0x2a]; // field 9 varint = 42
	auto back = Identify.decode(bytes);
	back.agentVersion.should.equal("x");
}

@("identify exchange delivers the observed address")
unittest
{
	auto id = sample();
	Identify got;
	runPair(
		(ByteStream s) { got = readIdentify(s); },
		(ByteStream s) { sendIdentify(s, id); });
	got.observedAddr.should.equal(id.observedAddr);
	got.protocols.should.equal(id.protocols);
}

@("full stack: mplex + multistream + identify recovers the peer id")
unittest
{
	auto kp = Keypair.generateEd25519;
	Identify self;
	self.publicKey = kp.publicKey.toProtobuf;
	self.observedAddr = Multiaddr.parse("/ip4/9.9.9.9/tcp/1").encode;

	Identify got;
	string served;
	runPair(
		(ByteStream c) {
		auto m = new Mplex(c, true);
		auto s = m.openStream();
		negotiateDialer(s, [identifyProtocol]);
		got = readIdentify(s);
	},
		(ByteStream c) {
		auto m = new Mplex(c, false);
		auto s = m.acceptStream();
		served = negotiateListener(s, [identifyProtocol]);
		sendIdentify(s, self);
	});
	served.should.equal(identifyProtocol);
	// The peer id derived from the identify'd public key matches the sender's.
	import libp2p.crypto.keys : PublicKey;

	auto recovered = PeerId.fromPublicKey(PublicKey.fromProtobuf(got.publicKey));
	recovered.should.equal(PeerId.fromPublicKey(kp.publicKey));
}
