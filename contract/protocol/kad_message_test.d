module tests.protocol.kad_message_test;

import libp2p.crypto.keys : Keypair;
import libp2p.core.peer_id : PeerId;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.util.protobuf : pbBytes, pbVarint;
import libp2p.protocol.kad.message;
import fluent.asserts;

private PeerId randomPeer()
{
	return PeerId.fromPublicKey(Keypair.generateEd25519.publicKey);
}

// Laundered from rust `protocol.rs::tests::append_p2p`: a bare advertised
// multiaddr gets `/p2p/<id>` appended on decode.
@("kad message: KadPeer decode appends /p2p to a bare address")
unittest
{
	auto peer = randomPeer();
	auto p = KadPeer(peer, [Multiaddr.parse("/ip6/2001:db8::/tcp/1234")], ConnectionType.canConnect);
	auto back = KadPeer.decode(p.encode);

	back.multiaddrs.length.should.equal(1);
	back.multiaddrs[0].toString.should.equal("/ip6/2001:db8::/tcp/1234/p2p/" ~ peer.toBase58);
	back.connectionTy.should.equal(ConnectionType.canConnect);
	(back.nodeId == peer).should.equal(true);
}

// Laundered from `skip_invalid_multiaddr`: an address carrying a different
// /p2p, and an unparseable one, are dropped; only the matching one survives.
@("kad message: KadPeer decode skips mismatched and invalid addresses")
unittest
{
	auto peer = randomPeer();
	auto other = randomPeer();
	auto valid = Multiaddr.parse("/ip6/2001:db8::/tcp/1234/p2p/" ~ peer.toBase58);
	auto wrong = Multiaddr.parse("/ip6/2001:db8::/tcp/1234/p2p/" ~ other.toBase58);

	// Build the raw Peer protobuf by hand to inject the bad addresses.
	ubyte[] buf;
	pbBytes(buf, 1, peer.bytes);
	pbBytes(buf, 2, valid.encode);
	pbBytes(buf, 2, wrong.encode);
	pbBytes(buf, 2, cast(ubyte[])[255, 255, 255, 255, 255, 255, 255, 255]);
	pbVarint(buf, 3, cast(ulong) ConnectionType.canConnect);

	auto p = KadPeer.decode(buf);
	p.multiaddrs.length.should.equal(1);
	p.multiaddrs[0].toString.should.equal(valid.toString);
}

// FIND_NODE request round-trips its type + key + cluster level.
@("kad message: FIND_NODE request round-trips")
unittest
{
	KadMessage m;
	m.type = MessageType.findNode;
	m.key = cast(ubyte[])[1, 2, 3, 4];
	m.clusterLevelRaw = 10;

	auto back = KadMessage.decode(m.encode);
	back.type.should.equal(MessageType.findNode);
	back.key.should.equal(m.key);
	back.clusterLevelRaw.should.equal(10);
}

// PUT_VALUE (type 0, omitted on the wire per proto3) round-trips with its record.
@("kad message: PUT_VALUE round-trips its record (default type omitted)")
unittest
{
	auto pub = randomPeer();
	KadMessage m;
	m.type = MessageType.putValue;
	m.key = cast(ubyte[]) "k";
	m.hasRecord = true;
	m.record = Record(cast(ubyte[]) "k", cast(ubyte[]) "v", pub.bytes.dup, 3600);

	auto wire = m.encode;
	auto back = KadMessage.decode(wire);
	back.type.should.equal(MessageType.putValue); // absent → default putValue
	back.hasRecord.should.equal(true);
	back.record.key.should.equal(cast(ubyte[]) "k");
	back.record.value.should.equal(cast(ubyte[]) "v");
	back.record.publisher.should.equal(pub.bytes);
	back.record.ttl.should.equal(3600u);
}

// GET_PROVIDERS response round-trips closer + provider peers.
@("kad message: GET_PROVIDERS response round-trips peers")
unittest
{
	auto a = randomPeer(), b = randomPeer();
	auto pa = KadPeer(a, [Multiaddr.parse("/ip4/1.2.3.4/tcp/1/p2p/" ~ a.toBase58)],
		ConnectionType.connected);
	auto pb = KadPeer(b, [Multiaddr.parse("/ip4/5.6.7.8/tcp/2/p2p/" ~ b.toBase58)],
		ConnectionType.notConnected);

	KadMessage m;
	m.type = MessageType.getProviders;
	m.closerPeers = [pa];
	m.providerPeers = [pb];
	m.clusterLevelRaw = 9;

	auto back = KadMessage.decode(m.encode);
	back.type.should.equal(MessageType.getProviders);
	back.closerPeers.length.should.equal(1);
	(back.closerPeers[0].nodeId == a).should.equal(true);
	back.closerPeers[0].multiaddrs[0].toString.should.equal(pa.multiaddrs[0].toString);
	back.providerPeers.length.should.equal(1);
	(back.providerPeers[0].nodeId == b).should.equal(true);
	back.providerPeers[0].connectionTy.should.equal(ConnectionType.notConnected);
}
