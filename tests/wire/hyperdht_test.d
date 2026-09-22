/// The GENERATED hyperdht codec (libp2p.wire.hyperdht, from proto/hyperdht.cenc via
/// tools/cencgen) is byte-exact against the reference vectors: the peer record and
/// the signed announce (hyperdht messages.js, tests.wire.hdht_vectors) and the
/// dht-rpc request datagram (dht-rpc io.js, tests.wire.dht_vectors). Codec only —
/// the signature bytes come from the vector, no crypto here. Plus decode round-trips.
module tests.wire.hyperdht_test;

import fluent.asserts;
import libp2p.wire.hyperdht;
import libp2p.wire.cenc : Address, State, Uint, Fixed, ArrayOf, Ipv4Address;
import tests.wire.hdht_vectors;
import tests.wire.dht_vectors;
import std.format : format;

private string toHex(scope const(ubyte)[] b)
{
	string r;
	foreach (x; b)
		r ~= format("%02x", x);
	return r;
}

private ubyte[] fromHex(string h)
{
	import std.conv : to;

	auto r = new ubyte[](h.length / 2);
	foreach (i; 0 .. r.length)
		r[i] = h[2 * i .. 2 * i + 2].to!ubyte(16);
	return r;
}

private string hd(string name)
{
	foreach (ref v; hdhtVectors)
		if (v.name == name)
			return v.hex;
	assert(0, "missing hdht vector: " ~ name);
}

private string dv(string name)
{
	foreach (ref v; dhtVectors)
		if (v.name == name)
			return v.hex;
	assert(0, "missing dht vector: " ~ name);
}

@("hyperdht wire (generated): peer record + signed announce are byte-exact")
unittest
{
	PeerRecord peer;
	peer.publicKey[] = fromHex(hd("pubkey_seed3"))[0 .. 32];
	peer.relayAddresses = [Address("1.2.3.4", 4, 5)];
	toHex(peer.encode()).should.equal(hd("peer_enc"));

	Announce ann;
	ann.hasPeer = true;
	ann.peer = peer;
	ann.hasSignature = true;
	ann.signature[] = fromHex(hd("sign_announce"))[0 .. 64];
	toHex(ann.encode()).should.equal(hd("announce_signed")); // flags 0x05, no refresh, bump omitted

	auto back = Announce.decode(ann.encode());
	back.hasPeer.should.equal(true);
	back.hasSignature.should.equal(true);
	back.hasRefresh.should.equal(false);
	back.bump.should.equal(0);
	back.peer.relayAddresses[0].port.should.equal(5);
	toHex(back.signature[]).should.equal(hd("sign_announce"));
}

@("hyperdht wire (generated): dht-rpc request datagram is byte-exact vs dht-rpc")
unittest
{
	Request fn;
	fn.tid = 0xABCD;
	fn.to = Address("1.2.3.4", 4, 49737);
	fn.internal = true;
	fn.command = RpcCommand.FIND_NODE;
	fn.hasTarget = true;
	fn.target[] = 7;
	toHex(fn.encode()).should.equal(dv("req:findnode"));

	Request pg;
	pg.tid = 0x0102;
	pg.to = Address("1.2.3.4", 4, 49737);
	pg.internal = true;
	pg.command = RpcCommand.PING;
	toHex(pg.encode()).should.equal(dv("req:ping"));
}

@("hyperdht wire (generated): a request round-trips through decode")
unittest
{
	Request r;
	r.tid = 0xBEEF;
	r.to = Address("5.6.7.8", 4, 1234);
	r.internal = true;
	r.command = RpcCommand.FIND_NODE;
	r.hasTarget = true;
	r.target[] = 9;
	auto req = Request.decode(r.encode());
	req.tid.should.equal(0xBEEF);
	req.command.should.equal(RpcCommand.FIND_NODE);
	req.internal.should.equal(true);
	req.to.host.should.equal("5.6.7.8");
	req.to.port.should.equal(1234);
	req.hasTarget.should.equal(true);
	req.target.should.equal(r.target);
	req.hasId.should.equal(false);
	req.hasValue.should.equal(false);

	Request ping;
	ping.tid = 1;
	ping.to = Address("9.9.9.9", 4, 53);
	ping.internal = true;
	auto p = Request.decode(ping.encode());
	p.command.should.equal(RpcCommand.PING);
	p.hasTarget.should.equal(false);
}

@("hyperdht wire (generated): lookup reply decodes the peer records")
unittest
{
	// one-peer lookup reply value: uint count(1) + peer, no trailing bump
	ubyte[32] pk = 0x42;
	State s;
	Uint.preencode(s, 1);
	Fixed!32.preencode(s, pk[]);
	ArrayOf!Ipv4Address.preencode(s, [Address("9.8.7.6", 4, 4242)]);
	s.buffer = new ubyte[](s.end);
	Uint.encode(s, 1);
	Fixed!32.encode(s, pk[]);
	ArrayOf!Ipv4Address.encode(s, [Address("9.8.7.6", 4, 4242)]);

	auto reply = LookupReply.decode(s.buffer);
	reply.peers.length.should.equal(1);
	reply.peers[0].publicKey.should.equal(pk);
	reply.peers[0].relayAddresses[0].host.should.equal("9.8.7.6");
	reply.peers[0].relayAddresses[0].port.should.equal(4242);
	reply.bump.should.equal(0);

	// and the generated encoder agrees with the hand-built bytes (+ a trailing bump)
	toHex(reply.encode()).should.equal(toHex(s.buffer));
	reply.bump = 3;
	auto again = LookupReply.decode(reply.encode());
	again.bump.should.equal(3);
	again.peers.length.should.equal(1);
}

@("hyperdht wire (generated): a reply datagram round-trips (nonzero error, closer nodes, value)")
unittest
{
	Reply r;
	r.tid = 0x1234;
	r.to = Address("8.8.4.4", 4, 49737);
	r.hasId = true;
	r.id[] = 0xaa;
	r.hasCloserNodes = true;
	r.closerNodes = [Address("1.1.1.1", 4, 1), Address("2.2.2.2", 4, 2)];
	r.error = 5; // nonzero → bit 8 set, no has-flag
	r.hasValue = true;
	r.value = [1, 2, 3];
	auto buf = r.encode();
	buf[0].should.equal(0x13);
	buf[1].should.equal(cast(ubyte)(1 | 4 | 8 | 16)); // id | closerNodes | error | value
	auto back = Reply.decode(buf);
	back.tid.should.equal(0x1234);
	back.to.host.should.equal("8.8.4.4");
	back.hasId.should.equal(true);
	back.id.should.equal(r.id);
	back.hasToken.should.equal(false);
	back.hasCloserNodes.should.equal(true);
	back.closerNodes.length.should.equal(2);
	back.closerNodes[1].port.should.equal(2);
	back.error.should.equal(5);
	back.hasValue.should.equal(true);
	back.value.should.equal([1, 2, 3]);

	Reply ok; // the minimal reply: no optionals, error 0 → flags 0
	ok.tid = 1;
	ok.to = Address("9.9.9.9", 4, 9);
	ok.encode()[1].should.equal(0);
	Reply.decode(ok.encode()).error.should.equal(0);
}
