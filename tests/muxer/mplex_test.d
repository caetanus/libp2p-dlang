module tests.muxer.mplex_test;

import libp2p.muxer.mplex;
import libp2p.core.stream;
import libp2p.multiformats.varint : encodeVarint;
import libp2p.multistream.select : negotiateDialer, negotiateListener;
import tests.util.pipe : runPair;
import fluent.asserts;

@("open, accept, and deliver a message")
unittest
{
	ubyte[] received;
	runPair(
		(Stream c) {
		auto m = new Mplex(c, true);
		scope (exit)
			m.close();
		auto s = m.open("x");
		s.write(cast(ubyte[]) "hello".dup);
		s.close();
	},
		(Stream c) {
		auto m = new Mplex(c, false);
		scope (exit)
			m.close();
		auto s = m.accept();
		auto buf = new ubyte[5];
		s.readExact(buf);
		received = buf;
	});
	received.should.equal(cast(ubyte[]) "hello");
}

@("substreams carry data in both directions")
unittest
{
	ubyte[] reply;
	runPair(
		(Stream c) {
		auto m = new Mplex(c, true);
		scope (exit)
			m.close();
		auto s = m.open();
		s.write(cast(ubyte[]) "ping".dup);
		auto buf = new ubyte[4];
		s.readExact(buf);
		reply = buf;
	},
		(Stream c) {
		auto m = new Mplex(c, false);
		scope (exit)
			m.close();
		auto s = m.accept();
		auto buf = new ubyte[4];
		s.readExact(buf);
		s.write(cast(ubyte[]) "pong".dup);
	});
	reply.should.equal(cast(ubyte[]) "pong");
}

@("multiple substreams are independently multiplexed")
unittest
{
	ubyte[] a, b;
	runPair(
		(Stream c) {
		auto m = new Mplex(c, true);
		scope (exit)
			m.close();
		auto sa = m.open("a");
		sa.write(cast(ubyte[]) "AAA".dup);
		auto sb = m.open("b");
		sb.write(cast(ubyte[]) "BBBB".dup);
		sa.close();
		sb.close();
	},
		(Stream c) {
		auto m = new Mplex(c, false);
		scope (exit)
			m.close();
		auto s1 = m.accept();
		auto b1 = new ubyte[3];
		s1.readExact(b1);
		a = b1;
		auto s2 = m.accept();
		auto b2 = new ubyte[4];
		s2.readExact(b2);
		b = b2;
	});
	a.should.equal(cast(ubyte[]) "AAA");
	b.should.equal(cast(ubyte[]) "BBBB");
}

@("multistream negotiation runs over an mplex substream")
unittest
{
	string dialed, served;
	runPair(
		(Stream c) {
		auto m = new Mplex(c, true);
		scope (exit)
			m.close();
		auto s = m.open();
		dialed = negotiateDialer(s, ["/ipfs/ping/1.0.0"]);
	},
		(Stream c) {
		auto m = new Mplex(c, false);
		scope (exit)
			m.close();
		auto s = m.accept();
		served = negotiateListener(s, ["/ipfs/ping/1.0.0"]);
	});
	dialed.should.equal("/ipfs/ping/1.0.0");
	served.should.equal("/ipfs/ping/1.0.0");
}

@("reading past a peer close reports EOF")
unittest
{
	({
		runPair(
			(Stream c) {
			auto m = new Mplex(c, true);
		scope (exit)
			m.close();
			auto s = m.open();
			s.write(cast(ubyte[]) "hi".dup);
			s.close();
		},
			(Stream c) {
			auto m = new Mplex(c, false);
		scope (exit)
			m.close();
			auto s = m.accept();
			auto buf = new ubyte[10]; // more than was sent
			s.readExact(buf);
		});
	}).should.throwAnyException;
}

// Laundered from rust `muxers/mplex/src/codec.rs` MAX_FRAME_SIZE enforcement: a
// frame that declares a length over the 1 MiB cap is rejected on decode BEFORE
// any payload is allocated (anti-DoS).
@("mplex rejects a frame declaring an oversized length")
unittest
{
	({
		runPair(
			(Stream s) {
			// header = (stream 1 << 3) | messageInitiator(2); then an oversized len.
			s.write(encodeVarint((1UL << 3) | cast(ulong) Flag.messageInitiator));
			s.write(encodeVarint(maxFrameSize + 1));
			s.close();
		},
			(Stream s) { readMplexFrame(s); });
	}).should.throwAnyException;
}

// Laundered from rust `codec.rs` encode_large_messages_fails: the ENCODE side
// also rejects a payload over MAX_FRAME_SIZE, while exactly MAX_FRAME_SIZE is
// accepted and round-trips.
@("mplex rejects encoding an oversized frame, accepts exactly the maximum")
unittest
{
	// Over the cap: writeMplexFrame throws before writing anything.
	({
		runPair(
			(Stream s) { writeMplexFrame(s, 1, Flag.messageInitiator, new ubyte[maxFrameSize + 1]); },
			(Stream s) {});
	}).should.throwAnyException;

	// Exactly the cap: accepted and read back intact.
	MplexFrame got;
	runPair(
		(Stream s) {
		writeMplexFrame(s, 1, Flag.messageInitiator, new ubyte[maxFrameSize]);
		s.close();
	},
		(Stream s) { got = readMplexFrame(s); });
	got.payload.length.should.equal(maxFrameSize);
}

// Laundered from rust `codec.rs` test_60bit_stream_id: a stream id larger than
// 32 bits survives the `(id << 3) | flag` header packing round-trip, proving the
// 3-bit flag shift is correct (a wrong shift would corrupt large ids).
@("mplex round-trips a 60-bit stream id through the header packing")
unittest
{
	enum ulong bigId = (1UL << 59) | 0x1234_5678; // well beyond 32 bits
	MplexFrame got;
	runPair(
		(Stream s) {
		writeMplexFrame(s, bigId, Flag.closeReceiver, [0xAB, 0xCD]);
		s.close();
	},
		(Stream s) { got = readMplexFrame(s); });
	got.id.should.equal(bigId);
	got.flag.should.equal(Flag.closeReceiver);
	got.payload.should.equal([cast(ubyte) 0xAB, 0xCD]);
}

// --- adversarial: a hostile peer past the Noise handshake reaches the muxer with
// arbitrary bytes. mplex must reject malformed frames cleanly (tell the app, don't
// crash/hang), matching the coverage yamux_test already has. -------------------

private ulong mplexHeader(ulong id, ulong flag)
{
	return (id << 3) | flag;
}

@("mplex: a frame with an unknown flag ends the session, and the app is told")
unittest
{
	string victimErr;
	runPair(
		(Stream s) {
		// flag 7 is one past resetInitiator(6): readMplexFrame must refuse it.
		s.write(encodeVarint(mplexHeader(1, 7)));
		s.write(encodeVarint(0));
		s.close();
	},
		(Stream s) {
		auto m = new Mplex(s, false);
		scope (exit)
			m.close();
		try
			m.accept();
		catch (Exception e)
			victimErr = e.msg;
	});
	victimErr.length.should.be.greaterThan(0); // the app learned why, not a silent hang
}

@("mplex: a second newStream for an open id ends the session, and the app is told")
unittest
{
	string victimErr;
	runPair(
		(Stream s) {
		s.write(encodeVarint(mplexHeader(5, cast(ulong) Flag.newStream)));
		s.write(encodeVarint(0));
		s.write(encodeVarint(mplexHeader(5, cast(ulong) Flag.newStream))); // duplicate id
		s.write(encodeVarint(0));
		s.close();
	},
		(Stream s) {
		auto m = new Mplex(s, false);
		scope (exit)
			m.close();
		try
		{
			m.accept(); // the first newStream is fine
			m.accept(); // the duplicate has ended the session by now
		}
		catch (Exception e)
			victimErr = e.msg;
	});
	victimErr.length.should.be.greaterThan(0);
}

@("mplex: a message for an unknown stream is ignored, not fatal")
unittest
{
	bool delivered;
	runPair(
		(Stream s) {
		// A message frame for a stream nobody opened, then a real stream+message.
		s.write(encodeVarint(mplexHeader(99, cast(ulong) Flag.messageInitiator)));
		s.write(encodeVarint(3));
		s.write(cast(ubyte[]) "abc".dup);
		s.write(encodeVarint(mplexHeader(1, cast(ulong) Flag.newStream)));
		s.write(encodeVarint(0));
		s.write(encodeVarint(mplexHeader(1, cast(ulong) Flag.messageInitiator)));
		s.write(encodeVarint(2));
		s.write(cast(ubyte[]) "hi".dup);
		s.close();
	},
		(Stream s) {
		auto m = new Mplex(s, false);
		scope (exit)
			m.close();
		auto st = m.accept(); // the phantom stream did not end the session
		auto buf = new ubyte[2];
		st.readExact(buf);
		delivered = buf == cast(ubyte[]) "hi";
	});
	delivered.should.equal(true);
}


// S1 regression: a reset stream must leave the accept backlog, not just `streams`.
// A peer that opens-then-resets inbound streams a consumer never accepts (at its
// inbound ceiling) otherwise grew the backlog without bound while never holding an
// open stream — the substream cap counts `streams`, which the reset empties.
@("mplex: reset streams do not accumulate in the backlog (S1: unbounded backlog)")
unittest
{
	import core.time : msecs;
	import vibe.core.core : sleep;

	size_t backlogAfter = size_t.max;
	runPair(
		(Stream s) {
		foreach (ulong id; 0 .. 200) // 200 open+reset pairs, distinct ids
		{
			s.write(encodeVarint(mplexHeader(id, cast(ulong) Flag.newStream)));
			s.write(encodeVarint(0));
			s.write(encodeVarint(mplexHeader(id, cast(ulong) Flag.resetInitiator)));
			s.write(encodeVarint(0));
		}
		s.close();
	},
		(Stream s) {
		MplexConfig cfg;
		cfg.maxSubstreams = 8;
		auto m = new Mplex(s, false, cfg);
		scope (exit)
			m.close();
		// Model a consumer at its ceiling: never accept; let the reader process the
		// whole flood (isClosed flips when the peer's close reaches the reader).
		for (int i = 0; i < 3000 && !m.isClosed(); i++)
			sleep(1.msecs);
		backlogAfter = m.backlogLength();
	});
	backlogAfter.should.be.lessThan(cast(size_t) 9); // bounded by the cap, not the 200 sent
}
