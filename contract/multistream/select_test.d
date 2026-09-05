module tests.multistream.select_test;

import libp2p.multistream.select;
import libp2p.core.stream : ByteStream;
import tests.util.fiberpipe : runPair;
import fluent.asserts;

@("dialer and listener agree on a shared protocol")
unittest
{
	string dialed, served;
	runPair(
		(ByteStream s) { dialed = negotiateDialer(s, ["/ipfs/ping/1.0.0"]); },
		(ByteStream s) { served = negotiateListener(s, ["/ipfs/ping/1.0.0"]); });
	dialed.should.equal("/ipfs/ping/1.0.0");
	served.should.equal("/ipfs/ping/1.0.0");
}

@("listener declines unsupported proposals then accepts a later one")
unittest
{
	string dialed, served;
	runPair(
		(ByteStream s) {
		dialed = negotiateDialer(s, ["/made/up/1.0.0", "/also/fake/2.0.0", "/mplex/6.7.0"]);
	},
		(ByteStream s) { served = negotiateListener(s, ["/mplex/6.7.0", "/yamux/1.0.0"]); });
	dialed.should.equal("/mplex/6.7.0");
	served.should.equal("/mplex/6.7.0");
}

@("negotiation fails when there is no common protocol")
unittest
{
	({
		runPair(
			(ByteStream s) { negotiateDialer(s, ["/only/dialer/1.0.0"]); },
			(ByteStream s) { negotiateListener(s, ["/only/listener/1.0.0"]); });
	}).should.throwAnyException;
}

@("message codec roundtrips every message form via the wire framing")
unittest
{
	// The framing is the same for every message form (header, a protocol name,
	// and the "na" rejection token): varint(len) + bytes + '\n'. Round-trip each.
	foreach (msg; [multistreamHeader, "/ipfs/ping/1.0.0", naToken, ""])
	{
		string got;
		runPair(
			(ByteStream s) { writeMessage(s, msg); s.close(); },
			(ByteStream s) { got = readMessage(s); });
		got.should.equal(msg);
	}
}
