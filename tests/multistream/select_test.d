module tests.multistream.select_test;

import libp2p.multistream.select;
import libp2p.core.stream : Stream;
import tests.util.pipe : runPair;
import fluent.asserts;

@("dialer and listener agree on a shared protocol")
unittest
{
	string dialed, served;
	runPair(
		(Stream s) { dialed = negotiateDialer(s, ["/ipfs/ping/1.0.0"]); },
		(Stream s) { served = negotiateListener(s, ["/ipfs/ping/1.0.0"]); });
	dialed.should.equal("/ipfs/ping/1.0.0");
	served.should.equal("/ipfs/ping/1.0.0");
}

@("listener declines unsupported proposals then accepts a later one")
unittest
{
	string dialed, served;
	runPair(
		(Stream s) {
		dialed = negotiateDialer(s, ["/made/up/1.0.0", "/also/fake/2.0.0", "/mplex/6.7.0"]);
	},
		(Stream s) { served = negotiateListener(s, ["/mplex/6.7.0", "/yamux/1.0.0"]); });
	dialed.should.equal("/mplex/6.7.0");
	served.should.equal("/mplex/6.7.0");
}

@("negotiation fails when there is no common protocol")
unittest
{
	({
		runPair(
			(Stream s) { negotiateDialer(s, ["/only/dialer/1.0.0"]); },
			(Stream s) { negotiateListener(s, ["/only/listener/1.0.0"]); });
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
			(Stream s) { writeMessage(s, msg); },
			(Stream s) { got = readMessage(s); });
		got.should.equal(msg);
	}
}

// A TCP hole punch leaves two dialers on one connection. Both propose the
// simultaneous-open extension; exactly one ends up the initiator, and the
// protocol they agree on is the same on both sides.
@("simultaneous open: two dialers split the initiator role and agree")
unittest
{
	SimOpenResult a, b;
	runPair(
		(Stream s) { a = negotiateSimOpen(s, ["/noise"]); },
		(Stream s) { b = negotiateSimOpen(s, ["/noise"]); });
	a.protocol.should.equal("/noise");
	b.protocol.should.equal("/noise");
	(a.initiator != b.initiator).should.equal(true);
}

// Against a plain listener the extension is declined with `na` and the dialer
// simply goes on as the initiator — a punch that was accepted by a listener.
@("simultaneous open: a plain listener declines it and the dialer initiates")
unittest
{
	SimOpenResult a;
	string served;
	runPair(
		(Stream s) { a = negotiateSimOpen(s, ["/noise"]); },
		(Stream s) { served = negotiateListener(s, ["/noise"]); });
	a.initiator.should.equal(true);
	a.protocol.should.equal("/noise");
	served.should.equal("/noise");
}
