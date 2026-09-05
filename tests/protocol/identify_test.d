module tests.protocol.identify_test;

import libp2p.protocol.identify;
import libp2p.core.stream;
import libp2p.crypto.keys : Keypair, PublicKey;
import libp2p.core.peer_id : PeerId;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.muxer.yamux : YamuxConn;
import libp2p.multistream.select : negotiateDialer, negotiateListener;
import tests.util.pipe : runPair;
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

// The 375-byte vector rust-libp2p's `protobuf_roundtrip` carries from go-libp2p.
// It is go's raw file descriptor read as an Identify message, so it exercises
// what a real foreign message does: fields we know in unexpected shapes, fields
// we do not know at all, and one we must preserve (field 8, the signed peer
// record) whose bytes rust asserts on. Decoding must succeed, and what we decode
// must survive our own encode/decode unchanged.
@("Identify decodes the go-libp2p interop vector and round-trips what it read")
unittest
{
	import std.conv : to;

	static ubyte[] unhex(string h)
	{
		ubyte[] r;
		for (size_t i = 0; i + 1 < h.length; i += 2)
			r ~= to!ubyte(h[i .. i + 2], 16);
		return r;
	}

	auto goProtobuf = unhex(""
			~ "0a277032702f70726f746f636f6c2f6964656e746966792f70622f6964656e74"
			~ "6966792e70726f746f120b6964656e746966792e70622286020a084964656e74"
			~ "69667912280a0f70726f746f636f6c56657273696f6e180520012809520f7072"
			~ "6f746f636f6c56657273696f6e12220a0c6167656e7456657273696f6e180620"
			~ "012809520c6167656e7456657273696f6e121c0a097075626c69634b65791801"
			~ "2001280c52097075626c69634b657912200a0b6c697374656e41646472731802"
			~ "2003280c520b6c697374656e416464727312220a0c6f62736572766564416464"
			~ "7218042001280c520c6f6273657276656441646472121c0a0970726f746f636f"
			~ "6c73180320032809520970726f746f636f6c73122a0a107369676e6564506565"
			~ "725265636f726418082001280c52107369676e6564506565725265636f726442"
			~ "365a346769746875622e636f6d2f6c69627032702f676f2d6c69627032702f70"
			~ "32702f70726f746f636f6c2f6964656e746966792f7062");
	goProtobuf.length.should.equal(375);

	auto msg = Identify.decode(goProtobuf);
	(cast(string) msg.signedPeerRecord).should.equal("Z4github.com/libp2p/go-libp2p/p2p/protocol/identify/pb");

	auto again = Identify.decode(msg.encode);
	again.publicKey.should.equal(msg.publicKey);
	again.listenAddrs.should.equal(msg.listenAddrs);
	again.protocols.should.equal(msg.protocols);
	again.observedAddr.should.equal(msg.observedAddr);
	again.protocolVersion.should.equal(msg.protocolVersion);
	again.agentVersion.should.equal(msg.agentVersion);
	again.signedPeerRecord.should.equal(msg.signedPeerRecord);
}

@("identify exchange delivers the observed address")
unittest
{
	auto id = sample();
	Identify got;
	runPair(
		(Stream s) { got = readIdentify(s); },
		(Stream s) { sendIdentify(s, id); });
	got.observedAddr.should.equal(id.observedAddr);
	got.protocols.should.equal(id.protocols);
}

@("full stack: yamux + multistream + identify recovers the peer id")
unittest
{
	auto kp = Keypair.generateEd25519;
	Identify self;
	self.publicKey = kp.publicKey.toProtobuf;
	self.observedAddr = Multiaddr.parse("/ip4/9.9.9.9/tcp/1").encode;

	Identify got;
	string served;
	runPair(
		(Stream c) {
		auto m = new YamuxConn(c, true);
		scope (exit)
			m.close();
		auto s = m.open();
		scope (exit)
			s.close();
		negotiateDialer(s, [identifyProtocol]);
		got = readIdentify(s);
	},
		(Stream c) {
		auto m = new YamuxConn(c, false);
		scope (exit)
			m.close();
		auto s = m.accept();
		served = negotiateListener(s, [identifyProtocol]);
		sendIdentify(s, self);
		s.close();
	});
	served.should.equal(identifyProtocol);
	auto recovered = PeerId.fromPublicKey(PublicKey.fromProtobuf(got.publicKey));
	recovered.should.equal(PeerId.fromPublicKey(kp.publicKey));
}
