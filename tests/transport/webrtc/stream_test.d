module tests.transport.webrtc.stream_test;

import libp2p.transport.webrtc.stream;
import libp2p.transport.webrtc.state : StreamStateException, IoErrorKind;
import libp2p.core.ending : EndOfStream;
import libp2p.core.stream;
import fluent.asserts;
import tests.util.pipe : runPair;

@("stream round-trips a multi-chunk payload and signals EOF after graceful close")
unittest
{
	// Larger than two full frames, so the writer chunks and the reader reassembles.
	auto payload = new ubyte[2 * MAX_DATA_LEN + 123];
	foreach (i, ref b; payload)
		b = cast(ubyte)(i * 7 + 3);

	ubyte[] got;
	bool sawEof;

	runPair((Stream a) {
		auto s = new WebRtcStream(a);
		s.write(payload);
		s.close(); // graceful FIN
	}, (Stream b) {
		auto s = new WebRtcStream(b);
		auto buf = new ubyte[4096];
		try
			for (;;)
				got ~= buf[0 .. s.read(buf)];
		catch (EndOfStream)
			sawEof = true; // the peer's FIN, once everything before it was handed over
	});

	sawEof.should.equal(true);
	got.length.should.equal(payload.length);
	(got == payload).should.equal(true);
}

@("stream reset makes the peer's subsequent read fail with ConnectionReset")
unittest
{
	IoErrorKind caught = IoErrorKind.other;
	bool threw;

	runPair((Stream a) {
		auto s = new WebRtcStream(a);
		s.reset(); // abrupt RESET, no data
	}, (Stream b) {
		auto s = new WebRtcStream(b);
		auto buf = new ubyte[64];
		// The RESET frame carries no data, so the read hits the reset barrier.
		try
			s.read(buf);
		catch (StreamStateException e)
		{
			threw = true;
			caught = e.kind;
		}
	});

	threw.should.equal(true);
	caught.should.equal(IoErrorKind.connectionReset);
}

@("writing after a graceful close throws BrokenPipe")
unittest
{
	IoErrorKind caught = IoErrorKind.other;
	bool threw;

	runPair((Stream a) {
		auto s = new WebRtcStream(a);
		s.close();
		try
			s.write(cast(ubyte[])[1, 2, 3]);
		catch (StreamStateException e)
		{
			threw = true;
			caught = e.kind;
		}
	}, (Stream b) {
		auto s = new WebRtcStream(b);
		auto buf = new ubyte[16];
		try
			s.read(buf); // drain the FIN so the writer side can terminate
		catch (EndOfStream)
		{
		}
	});

	threw.should.equal(true);
	caught.should.equal(IoErrorKind.brokenPipe);
}
