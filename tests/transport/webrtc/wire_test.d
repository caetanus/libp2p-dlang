module tests.transport.webrtc.wire_test;

import std.typecons : Nullable;
import libp2p.transport.webrtc.wire : Message, FramedDc, encodeFrame, MAX_DATA_LEN, MAX_MSG_LEN;
import libp2p.core.stream;
import fluent.asserts;
import tests.util.pipe : runPair;

@("max data len: the largest message frames to exactly MAX_MSG_LEN (rust parity)")
unittest
{
	// The largest possible message: FIN flag + MAX_DATA_LEN payload bytes.
	Message m;
	m.flag = Message.Flag.FIN;
	m.hasFlag = true;
	m.message = new ubyte[MAX_DATA_LEN];

	// varint-prefixed + protobuf-encoded, it must be no longer than the spec's
	// 16 KB maximum message size.
	encodeFrame(m).length.should.equal(MAX_MSG_LEN);
}

@("framed round-trips messages and reports EOF at the frame boundary")
unittest
{
	// Assertions run OUTSIDE the fiber: fluent-asserts materializes large
	// temporaries, and its frame would overflow the small fiber stack. The
	// reader only collects results into these captured variables (this also
	// forces the lambdas to be genuine delegates — the house `runPair` pattern).
	Message[] got;
	bool sawEof;
	auto hello = cast(ubyte[]) "hello".dup;

	runPair((Stream a) {
		auto f = new FramedDc(a);
		Message m1;
		m1.message = hello;
		Message m2;
		m2.flag = Message.Flag.STOP_SENDING;
		m2.hasFlag = true;
		f.send(m1);
		f.send(m2);
		a.close();
	}, (Stream b) {
		auto f = new FramedDc(b);
		for (auto r = f.next(); !r.isNull; r = f.next())
			got ~= r.get;
		sawEof = true; // reached only via a clean EOF at a frame boundary
	});

	got.length.should.equal(2);
	got[0].message.should.equal(cast(ubyte[]) "hello");
	got[0].hasFlag.should.equal(false);
	got[1].hasFlag.should.equal(true);
	got[1].flag.should.equal(Message.Flag.STOP_SENDING);
	sawEof.should.equal(true);
}
