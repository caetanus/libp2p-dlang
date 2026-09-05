module tests.transport.webrtc.stream_test;

import libp2p.transport.webrtc.stream;
import libp2p.transport.webrtc.stream.state : StreamStateException, IoErrorKind;
import libp2p.core.stream : ByteStream;
import fluent.asserts;
import tests.util.fiberpipe : runPair;

@("stream round-trips a multi-chunk payload and signals EOF after graceful close")
unittest
{
	// Larger than two full frames, so the writer chunks and the reader reassembles.
	auto payload = new ubyte[2 * MAX_DATA_LEN + 123];
	foreach (i, ref b; payload)
		b = cast(ubyte)(i * 7 + 3);

	ubyte[] got;
	bool sawEof;

	runPair((ByteStream a) {
		auto s = new Stream(a);
		s.writeBytes(payload);
		s.close(); // graceful FIN
	}, (ByteStream b) {
		auto s = new Stream(b);
		auto buf = new ubyte[4096];
		for (;;)
		{
			immutable n = s.readAvailable(buf);
			if (n == 0)
				break; // EOF from the peer's FIN
			got ~= buf[0 .. n];
		}
		sawEof = true;
	});

	sawEof.should.equal(true);
	got.length.should.equal(payload.length);
	(got == payload).should.equal(true);
}

@("stream reset makes the peer's subsequent read fail with ConnectionReset")
unittest
{
	size_t firstRead = size_t.max;
	IoErrorKind caught = IoErrorKind.other;
	bool threw;

	runPair((ByteStream a) {
		auto s = new Stream(a);
		s.reset(); // abrupt RESET, no data
	}, (ByteStream b) {
		auto s = new Stream(b);
		auto buf = new ubyte[64];
		// The RESET frame carries no data, so the first read reports EOF (0)...
		firstRead = s.readAvailable(buf);
		try
			s.readAvailable(buf); // ...and the next read hits the reset barrier.
		catch (StreamStateException e)
		{
			threw = true;
			caught = e.kind;
		}
	});

	firstRead.should.equal(0);
	threw.should.equal(true);
	caught.should.equal(IoErrorKind.connectionReset);
}

@("writing after a graceful close throws BrokenPipe")
unittest
{
	IoErrorKind caught = IoErrorKind.other;
	bool threw;

	runPair((ByteStream a) {
		auto s = new Stream(a);
		s.close();
		try
			s.writeBytes(cast(ubyte[])[1, 2, 3]);
		catch (StreamStateException e)
		{
			threw = true;
			caught = e.kind;
		}
	}, (ByteStream b) {
		auto s = new Stream(b);
		auto buf = new ubyte[16];
		s.readAvailable(buf); // drain the FIN so the writer side can terminate
	});

	threw.should.equal(true);
	caught.should.equal(IoErrorKind.brokenPipe);
}
