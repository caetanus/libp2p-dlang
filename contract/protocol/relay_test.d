module tests.protocol.relay_test;

import libp2p.protocol.relay;
import libp2p.core.stream : ByteStream;
import libp2p.util.protobuf : writeDelimited, readDelimited;
import tests.util.fiberpipe : runPair;
import fluent.asserts;

@("Peer protobuf roundtrips")
unittest
{
	Peer p;
	p.id = cast(ubyte[])[0x12, 0x20, 1, 2, 3];
	p.addrs ~= cast(ubyte[])[4, 4, 4];
	p.addrs ~= cast(ubyte[])[5, 5];
	auto back = Peer.decode(p.encode);
	back.id.should.equal(p.id);
	back.addrs.should.equal(p.addrs);
}

@("HopMessage roundtrips type, peer and status")
unittest
{
	HopMessage m;
	m.type = HopMessage.Type.CONNECT;
	m.peer.id = cast(ubyte[])[9, 9, 9];
	m.hasPeer = true;
	m.status = Status.OK;
	m.hasStatus = true;
	auto back = HopMessage.decode(m.encode);
	back.type.should.equal(HopMessage.Type.CONNECT);
	back.peer.id.should.equal(cast(ubyte[])[9, 9, 9]);
	back.status.should.equal(Status.OK);
	back.hasStatus.should.equal(true);
}

@("StopMessage roundtrips")
unittest
{
	StopMessage m;
	m.type = StopMessage.Type.STATUS;
	m.status = Status.CONNECTION_FAILED;
	m.hasStatus = true;
	auto back = StopMessage.decode(m.encode);
	back.type.should.equal(StopMessage.Type.STATUS);
	back.status.should.equal(Status.CONNECTION_FAILED);
}

@("a RESERVE/STATUS exchange round-trips over a stream")
unittest
{
	Status seenByRelay;
	Status seenByClient;
	runPair(
		(ByteStream s) {
		// client: send RESERVE, read the status reply
		HopMessage m;
		m.type = HopMessage.Type.RESERVE;
		m.peer.id = cast(ubyte[])[1, 2, 3];
		m.hasPeer = true;
		writeDelimited(s, m.encode);
		auto reply = HopMessage.decode(readDelimited(s));
		seenByClient = reply.status;
	},
		(ByteStream s) {
		// relay: read RESERVE, reply STATUS ok
		auto req = HopMessage.decode(readDelimited(s));
		seenByRelay = req.type == HopMessage.Type.RESERVE ? Status.OK : Status.MALFORMED_MESSAGE;
		HopMessage reply;
		reply.type = HopMessage.Type.STATUS;
		reply.status = Status.OK;
		reply.hasStatus = true;
		writeDelimited(s, reply.encode);
	});
	seenByRelay.should.equal(Status.OK);
	seenByClient.should.equal(Status.OK);
}
