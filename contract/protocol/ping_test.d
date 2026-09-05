module tests.protocol.ping_test;

import core.time : Duration;
import libp2p.protocol.ping : ping, handlePing;
import libp2p.muxer.mplex : Mplex;
import libp2p.core.stream : ByteStream;
import libp2p.multistream.select : negotiateDialer, negotiateListener;
import libp2p.protocol.ping : pingProtocol;
import tests.util.fiberpipe : runPair;
import fluent.asserts;

@("ping round-trips a payload directly over a stream")
unittest
{
	Duration rtt;
	bool handled;
	runPair(
		(ByteStream s) { rtt = ping(s); },
		(ByteStream s) { handlePing(s); handled = true; });
	handled.should.equal(true);
	(rtt >= Duration.zero).should.equal(true);
}

@("full stack: mplex + multistream + ping")
unittest
{
	Duration rtt;
	string served;
	runPair(
		(ByteStream c) {
		auto m = new Mplex(c, true);
		auto s = m.openStream();
		negotiateDialer(s, [pingProtocol]);
		rtt = ping(s);
	},
		(ByteStream c) {
		auto m = new Mplex(c, false);
		auto s = m.acceptStream();
		served = negotiateListener(s, [pingProtocol]);
		handlePing(s);
	});
	served.should.equal(pingProtocol);
	(rtt >= Duration.zero).should.equal(true);
}

// The dialer rejects a mismatched echo: rust ping treats a payload that comes
// back altered as a protocol failure (InvalidData). Here a handler echoes a
// flipped payload and `ping` must throw.
@("ping rejects a mismatched echo")
unittest
{
	import libp2p.protocol.ping : pingSize;

	bool threw;
	runPair(
		(ByteStream s) {
		try
			ping(s);
		catch (Exception)
			threw = true;
	},
		(ByteStream s) {
		ubyte[pingSize] buf;
		s.readExact(buf[]);
		buf[0] ^= 0xFF; // corrupt one byte of the echo
		s.writeBytes(buf[]);
	});
	threw.should.equal(true);
}
