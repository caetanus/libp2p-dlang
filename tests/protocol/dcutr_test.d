module tests.protocol.dcutr_test;

import core.time : Duration;
import libp2p.protocol.dcutr;
import libp2p.core.stream;
import tests.util.pipe : runPair;
import fluent.asserts;

@("HolePunch protobuf roundtrips type and addresses")
unittest
{
	HolePunch m;
	m.type = HolePunch.Type.CONNECT;
	m.ObsAddrs ~= cast(ubyte[])[1, 2, 3];
	m.ObsAddrs ~= cast(ubyte[])[4, 5];
	auto back = HolePunch.decode(m.encode);
	back.type.should.equal(HolePunch.Type.CONNECT);
	back.ObsAddrs.should.equal(m.ObsAddrs);
}

@("DCUtR CONNECT/SYNC exchange swaps addresses and measures RTT")
unittest
{
	ubyte[][] aAddrs = [cast(ubyte[])[0xaa, 0x01]];
	ubyte[][] bAddrs = [cast(ubyte[])[0xbb, 0x02]];
	DcutrResult res;
	ubyte[][] gotA;
	runPair(
		(Stream s) { res = initiateHolePunch(s, aAddrs); },
		(Stream s) { gotA = respondHolePunch(s, bAddrs); });
	res.peerAddrs.should.equal(bAddrs); // A learned B's addresses
	gotA.should.equal(aAddrs); // B learned A's addresses
	(res.rtt >= Duration.zero).should.equal(true);
}
