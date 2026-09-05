module tests.discovery.mdns_test;

import libp2p.crypto.keys : Keypair;
import libp2p.core.peer_id : PeerId;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.discovery.mdns;
import fluent.asserts;

@("mDNS query round-trips through the DNS codec")
unittest
{
	DnsMessage m;
	m.questions ~= DnsQuestion(serviceName, typePtr, classIn);

	auto back = decodeMessage(encodeMessage(m));

	back.questions.length.should.equal(1);
	back.questions[0].name.should.equal(serviceName);
	back.questions[0].qtype.should.equal(typePtr);
	back.questions[0].qclass.should.equal(classIn);
	back.answers.length.should.equal(0);
}

@("mDNS response advertises and recovers a peer's addresses")
unittest
{
	auto other = PeerId.fromPublicKey(Keypair.generateEd25519().publicKey);
	auto self = PeerId.fromPublicKey(Keypair.generateEd25519().publicKey);
	auto addr = Multiaddr.parse("/ip4/192.168.1.5/udp/4001/quic-v1");

	// Build the response `other` would multicast.
	DnsMessage m;
	m.flags = 0x8400;
	immutable instance = "abcd._p2p._udp.local";
	m.answers ~= DnsRecord(serviceName, typePtr, classIn, 120, instance);
	DnsRecord txt;
	txt.name = instance;
	txt.rtype = typeTxt;
	txt.rclass = classIn;
	txt.ttl = 120;
	txt.txts = dnsaddrStrings(other, [addr]);
	m.answers ~= txt;

	auto decoded = decodeMessage(encodeMessage(m));
	auto peers = peersFromMessage(decoded, self);

	peers.length.should.equal(1);
	peers[0].id.should.equal(other);
	peers[0].addrs.length.should.equal(1);
	peers[0].addrs[0].toString().should.equal(
		(addr ~ Multiaddr.parse("/p2p/" ~ other.toBase58)).toString());
}

@("mDNS peersFromMessage skips our own advertisement")
unittest
{
	auto self = PeerId.fromPublicKey(Keypair.generateEd25519().publicKey);
	auto addr = Multiaddr.parse("/ip4/10.0.0.1/udp/4001/quic-v1");

	DnsMessage m;
	m.flags = 0x8400;
	DnsRecord txt;
	txt.name = "x._p2p._udp.local";
	txt.rtype = typeTxt;
	txt.rclass = classIn;
	txt.txts = dnsaddrStrings(self, [addr]);
	m.answers ~= txt;

	peersFromMessage(decodeMessage(encodeMessage(m)), self).length.should.equal(0);
}

@("mDNS readName follows a compression pointer")
unittest
{
	// offset 0: label "a" then terminator; offset 3: a pointer back to offset 0.
	ubyte[] msg = [0x01, 'a', 0x00, 0xc0, 0x00];
	size_t pos = 3;
	readName(msg, pos).should.equal("a");
	pos.should.equal(5); // advanced past the 2-byte pointer, not the jump target
}
