module tests.protocol.ping_test;

import core.time : Duration;
import libp2p.protocol.ping : ping, handlePing, pingProtocol, pingSize;
import libp2p.muxer.yamux : YamuxConn;
import libp2p.core.stream;
import libp2p.multistream.select : negotiateDialer, negotiateListener;
import tests.util.pipe : runPair;
import fluent.asserts;

@("ping round-trips a payload directly over a stream")
unittest
{
	Duration rtt;
	bool handled;
	runPair(
		(Stream s) { rtt = ping(s); },
		(Stream s) { handlePing(s); handled = true; });
	handled.should.equal(true);
	(rtt >= Duration.zero).should.equal(true);
}

@("full stack: yamux + multistream + ping")
unittest
{
	Duration rtt;
	string served;
	runPair(
		(Stream c) {
		auto m = new YamuxConn(c, true);
		scope (exit)
			m.close();
		auto s = m.open();
		scope (exit)
			s.close();
		negotiateDialer(s, [pingProtocol]);
		rtt = ping(s);
	},
		(Stream c) {
		auto m = new YamuxConn(c, false);
		scope (exit)
			m.close();
		auto s = m.accept();
		scope (exit)
			s.close();
		served = negotiateListener(s, [pingProtocol]);
		handlePing(s);
	});
	served.should.equal(pingProtocol);
	(rtt >= Duration.zero).should.equal(true);
}

// The dialer rejects a mismatched echo: a payload that comes back altered is a
// protocol failure. Here a handler echoes a flipped payload and `ping` must throw.
@("ping rejects a mismatched echo")
unittest
{
	bool threw;
	runPair(
		(Stream s) {
		try
			ping(s);
		catch (Exception)
			threw = true;
	},
		(Stream s) {
		ubyte[pingSize] buf;
		s.readExact(buf[]);
		buf[0] ^= 0xFF; // corrupt one byte of the echo
		s.write(buf[]);
	});
	threw.should.equal(true);
}
