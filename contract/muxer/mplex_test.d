module tests.muxer.mplex_test;

import libp2p.muxer.mplex : Mplex;
import libp2p.muxer.frame : readMplexFrame, writeMplexFrame, MplexFrame, Flag, maxFrameSize;
import libp2p.core.stream : ByteStream;
import libp2p.multiformats.varint : encodeVarint;
import libp2p.multistream.select : negotiateDialer, negotiateListener;
import tests.util.fiberpipe : runPair;
import fluent.asserts;

@("open, accept, and deliver a message")
unittest
{
	ubyte[] received;
	runPair(
		(ByteStream c) {
		auto m = new Mplex(c, true);
		auto s = m.openStream("x");
		s.writeBytes(cast(ubyte[]) "hello".dup);
		s.close();
	},
		(ByteStream c) {
		auto m = new Mplex(c, false);
		auto s = m.acceptStream();
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
		(ByteStream c) {
		auto m = new Mplex(c, true);
		auto s = m.openStream();
		s.writeBytes(cast(ubyte[]) "ping".dup);
		auto buf = new ubyte[4];
		s.readExact(buf);
		reply = buf;
	},
		(ByteStream c) {
		auto m = new Mplex(c, false);
		auto s = m.acceptStream();
		auto buf = new ubyte[4];
		s.readExact(buf);
		s.writeBytes(cast(ubyte[]) "pong".dup);
	});
	reply.should.equal(cast(ubyte[]) "pong");
}

@("multiple substreams are independently multiplexed")
unittest
{
	ubyte[] a, b;
	runPair(
		(ByteStream c) {
		auto m = new Mplex(c, true);
		auto sa = m.openStream("a");
		sa.writeBytes(cast(ubyte[]) "AAA".dup);
		auto sb = m.openStream("b");
		sb.writeBytes(cast(ubyte[]) "BBBB".dup);
		sa.close();
		sb.close();
	},
		(ByteStream c) {
		auto m = new Mplex(c, false);
		auto s1 = m.acceptStream();
		auto b1 = new ubyte[3];
		s1.readExact(b1);
		a = b1;
		auto s2 = m.acceptStream();
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
		(ByteStream c) {
		auto m = new Mplex(c, true);
		auto s = m.openStream();
		dialed = negotiateDialer(s, ["/ipfs/ping/1.0.0"]);
	},
		(ByteStream c) {
		auto m = new Mplex(c, false);
		auto s = m.acceptStream();
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
			(ByteStream c) {
			auto m = new Mplex(c, true);
			auto s = m.openStream();
			s.writeBytes(cast(ubyte[]) "hi".dup);
			s.close();
		},
			(ByteStream c) {
			auto m = new Mplex(c, false);
			auto s = m.acceptStream();
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
			(ByteStream s) {
			// header = (stream 1 << 3) | messageInitiator(2); then an oversized len.
			s.writeBytes(encodeVarint((1UL << 3) | cast(ulong) Flag.messageInitiator));
			s.writeBytes(encodeVarint(maxFrameSize + 1));
			s.close();
		},
			(ByteStream s) { readMplexFrame(s); });
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
			(ByteStream s) { writeMplexFrame(s, 1, Flag.messageInitiator, new ubyte[maxFrameSize + 1]); },
			(ByteStream s) {});
	}).should.throwAnyException;

	// Exactly the cap: accepted and read back intact.
	MplexFrame got;
	runPair(
		(ByteStream s) {
		writeMplexFrame(s, 1, Flag.messageInitiator, new ubyte[maxFrameSize]);
		s.close();
	},
		(ByteStream s) { got = readMplexFrame(s); });
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
		(ByteStream s) {
		writeMplexFrame(s, bigId, Flag.closeReceiver, [0xAB, 0xCD]);
		s.close();
	},
		(ByteStream s) { got = readMplexFrame(s); });
	got.id.should.equal(bigId);
	got.flag.should.equal(Flag.closeReceiver);
	got.payload.should.equal([cast(ubyte) 0xAB, 0xCD]);
}
