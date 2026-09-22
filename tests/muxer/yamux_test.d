/**
 * yamux, including the parts a well-behaved peer never exercises.
 *
 * yamux is the default muxer of the TCP stack, so it is the first code a hostile
 * peer reaches after the Noise handshake. The frame header carries a 32-bit
 * length, which means the difference between "validated before allocating" and
 * "allocated then validated" is the difference between a refused frame and a
 * 4 GiB allocation bought with twelve bytes. Most of this file writes frames by
 * hand for exactly that reason: a conforming `YamuxConn` on the other end can
 * never produce them.
 *
 * Each hostile case asserts two things, and both matter: the *peer* is told the
 * session is over (a GoAway on the wire), and the *application* is told why (the
 * exception that reaches whoever was reading). A muxer that closes quietly is
 * indistinguishable from a network failure, and the operator then has no way to
 * tell a broken link from a peer probing for an allocator.
 *
 * These run on a real event loop rather than on the raw-fiber pipe the other
 * protocol tests use: yamux's read loop is a task and its waits are vibe
 * primitives, so an endpoint that blocks has to block without stalling the other.
 */
module tests.muxer.yamux_test;

import core.time : msecs, seconds, MonoTime;
import std.algorithm : any, min;
import std.exception : collectExceptionMsg;

import vibe.core.core : sleep;

import libp2p.core.ending : ConnClosed, EndOfStream, StreamReset;
import libp2p.core.stream;
import libp2p.muxer.yamux : YamuxConn;
import tests.util.pipe : MemStream, memPair;
import tests.util.loop : onLoop, spawn, Side;
import fluent.asserts;

private enum ubyte typeData = 0, typeWindowUpdate = 1, typePing = 2, typeGoAway = 3;
private enum ushort flagSyn = 0x1, flagAck = 0x2, flagFin = 0x4, flagRst = 0x8;
private enum uint window = 256 * 1024; // yamux's initial receive window

// --- hand-written frames ----------------------------------------------------

private ubyte[] frame(ubyte type, ushort flags, uint id, uint length, ubyte ver = 0)
{
	return [
		ver, type,
		cast(ubyte)(flags >> 8), cast(ubyte)(flags & 0xff),
		cast(ubyte)(id >> 24), cast(ubyte)(id >> 16), cast(ubyte)(id >> 8), cast(ubyte) id,
		cast(ubyte)(length >> 24), cast(ubyte)(length >> 16),
		cast(ubyte)(length >> 8), cast(ubyte) length,
	];
}

private uint lengthOf(const(ubyte)[] h)
{
	return (cast(uint) h[8] << 24) | (cast(uint) h[9] << 16) | (cast(uint) h[10] << 8) | h[11];
}

/**
 * Read frames back until the session hangs up on us, or until it answers a ping.
 *
 * The EOF here is genuinely the loop's terminating condition, which is why this
 * is the one place that catches: `MemStream` reports the end of a channel by
 * throwing, so "read what is there" has to stop on it.
 */
private ubyte[][] drainFrames(Stream c, bool stopAtPong = false)
{
	ubyte[][] frames;
	for (;;)
	{
		ubyte[12] h;
		try
			c.readExact(h[]);
		catch (Exception)
			break; // the session is gone; we have everything it sent
		frames ~= h.dup;
		if (h[1] == typeData && lengthOf(h[]) > 0)
		{
			auto payload = new ubyte[lengthOf(h[])];
			try
				c.readExact(payload);
			catch (Exception)
				break;
		}
		if (stopAtPong && h[1] == typePing)
			break;
	}
	return frames;
}

private bool sentGoAway(const ubyte[][] frames)
{
	return frames.any!(f => f[1] == typeGoAway);
}

private bool sentRst(const ubyte[][] frames)
{
	return frames.any!(f => (f[3] & flagRst) != 0);
}

/// What a hostile exchange produced: what the session put on the wire, and what
/// it told the application that was using it.
private struct Outcome
{
	ubyte[][] frames;
	string failure;
}

/**
 * Drive a hand-written peer against a real session. The session is the server,
 * so the peer's stream ids must be odd.
 */
private Outcome againstSession(void delegate(Stream) peer)
{
	Outcome o;
	onLoop({
		MemStream sa, sb;
		memPair(sa, sb);
		// Park on accept, never on a read. A read is not a neutral way to wait:
		// consuming even one byte hands the peer back that much credit and puts
		// a window update on the wire, which is precisely what the flow-control
		// cases are measuring. Accepting touches no stream at all, and the loop
		// ends when the session dies — carrying the reason with it.
		auto session = spawn({
			auto m = new YamuxConn(sa, false);
			for (;;)
				m.accept();
		});
		peer(sb);
		o.frames = drainFrames(sb);
		sb.close();
		o.failure = collectExceptionMsg(session.join());
	});
	return o;
}

// --- the finding this file exists for --------------------------------------

// Twelve bytes claiming a 4 GiB payload. The old read loop did `new
// ubyte[length]` straight off the header; the length is now charged against the
// window we advertised, so this is a protocol violation and not an allocation.
@("yamux: a data frame larger than the receive window is refused, not allocated")
unittest
{
	auto o = againstSession((Stream c) {
		c.write(frame(typeWindowUpdate, flagSyn, 1, 0));
		c.write(frame(typeData, 0, 1, uint.max));
	});
	o.failure.should.equal("yamux: data frame exceeds the receive window");
	sentGoAway(o.frames).should.equal(true);
}

// The same trick without opening a stream first: an unknown id still has to have
// its payload drained to stay framed, so it needs its own ceiling.
@("yamux: a data frame for an unknown stream cannot claim an unbounded payload")
unittest
{
	auto o = againstSession((Stream c) {
		c.write(frame(typeData, 0, 777, uint.max));
	});
	o.failure.should.equal("yamux: data frame for an unknown stream exceeds the window");
	sentGoAway(o.frames).should.equal(true);
}

// The window is only a bound if it is actually debited. Exactly one window of
// legitimate data, none of it read by the application, and then one byte too
// many — which is the point where the receive buffer would otherwise keep going.
@("yamux: a peer may not send past the window it was advertised")
unittest
{
	auto o = againstSession((Stream c) {
		c.write(frame(typeWindowUpdate, flagSyn, 1, 0));
		enum chunk = 16 * 1024;
		foreach (_; 0 .. window / chunk)
		{
			c.write(frame(typeData, 0, 1, chunk));
			c.write(new ubyte[chunk]);
		}
		c.write(frame(typeData, 0, 1, 1)); // one past the window
		c.write([cast(ubyte) 0]);
	});
	o.failure.should.equal("yamux: data frame exceeds the receive window");
	sentGoAway(o.frames).should.equal(true);
}

// --- stream id invariants ---------------------------------------------------

// Ids are split by parity — client odd, server even — so an even id from a peer
// we are serving is an attempt to collide with the ids we hand out ourselves.
@("yamux: an inbound stream id with our own parity is refused")
unittest
{
	auto o = againstSession((Stream c) {
		c.write(frame(typeWindowUpdate, flagSyn, 2, 0));
	});
	o.failure.should.equal("yamux: inbound stream id has the wrong parity");
	sentGoAway(o.frames).should.equal(true);
}

// Id 0 addresses the session (pings, GoAway), never a stream.
@("yamux: stream id 0 cannot be opened as a stream")
unittest
{
	auto o = againstSession((Stream c) {
		c.write(frame(typeWindowUpdate, flagSyn, 0, 0));
	});
	o.failure.should.equal("yamux: stream id 0 is the session, not a stream");
	sentGoAway(o.frames).should.equal(true);
}

// Ids are handed out in increasing order, so a repeat is either a reuse or an
// attempt to resurrect a stream we already retired.
@("yamux: a reused stream id is refused")
unittest
{
	auto o = againstSession((Stream c) {
		c.write(frame(typeWindowUpdate, flagSyn, 3, 0));
		c.write(frame(typeWindowUpdate, flagSyn, 3, 0));
	});
	o.failure.should.equal("yamux: inbound stream id is not increasing");
	sentGoAway(o.frames).should.equal(true);
}

@("yamux: a stream id that goes backwards is refused")
unittest
{
	auto o = againstSession((Stream c) {
		c.write(frame(typeWindowUpdate, flagSyn, 5, 0));
		c.write(frame(typeWindowUpdate, flagSyn, 1, 0));
	});
	o.failure.should.equal("yamux: inbound stream id is not increasing");
	sentGoAway(o.frames).should.equal(true);
}

// --- header invariants ------------------------------------------------------

@("yamux: an unknown frame type is refused")
unittest
{
	auto o = againstSession((Stream c) { c.write(frame(9, 0, 1, 0)); });
	o.failure.should.equal("yamux: unknown frame type");
	sentGoAway(o.frames).should.equal(true);
}

@("yamux: an unknown protocol version is refused")
unittest
{
	auto o = againstSession((Stream c) {
		c.write(frame(typeWindowUpdate, flagSyn, 1, 0, 1));
	});
	o.failure.should.equal("yamux: unknown protocol version");
	sentGoAway(o.frames).should.equal(true);
}

// A window update wide enough to wrap the counter would desynchronise both
// sides' idea of how much may be in flight.
@("yamux: a window update that would overflow the send window is refused")
unittest
{
	auto o = againstSession((Stream c) {
		c.write(frame(typeWindowUpdate, flagSyn, 1, 0));
		c.write(frame(typeWindowUpdate, 0, 1, uint.max));
	});
	o.failure.should.equal("yamux: window update overflows the send window");
	sentGoAway(o.frames).should.equal(true);
}

// --- resource ceilings ------------------------------------------------------

// Past the inbound backlog the session resets new streams instead of queueing
// them. Refusing costs nothing; queueing is what the peer would be paying us to
// do. The trailing ping is an "everything before me is handled" marker, so the
// test waits for a reply instead of for a duration.
@("yamux: inbound streams past the backlog are reset, not buffered")
unittest
{
	enum backlog = 256;
	ubyte[][] frames;
	onLoop({
		MemStream sa, sb;
		memPair(sa, sb);
		// This one must NOT accept: the backlog is the queue of streams nobody
		// has taken yet, so an accepting session would drain it as fast as the
		// peer filled it. The read loop is its own task and runs regardless.
		auto session = spawn({ cast(void) new YamuxConn(sa, false); });

		foreach (i; 0 .. backlog + 8)
			sb.write(frame(typeWindowUpdate, flagSyn, cast(uint)(2 * i + 1), 0));
		sb.write(frame(typePing, flagSyn, 0, 1));
		frames = drainFrames(sb, true);
		sb.close();
		session.join();
	});

	sentRst(frames).should.equal(true);
	sentGoAway(frames).should.equal(false); // a full backlog is not a protocol error
}

// --- flow control, in both directions --------------------------------------

// Several windows of data, which only arrive if the receiver replenishes credit
// as it reads and the sender waits when it runs out.
@("yamux: a payload larger than the window crosses intact")
unittest
{
	enum total = 3 * window;
	auto sent = new ubyte[total];
	foreach (i, ref b; sent)
		b = cast(ubyte)(i * 31 + (i >> 8));

	ubyte[] got;
	onLoop({
		MemStream sa, sb;
		memPair(sa, sb);
		auto reader = spawn({
			auto m = new YamuxConn(sa, false);
			auto s = m.accept();
			auto buf = new ubyte[total];
			s.readExact(buf);
			got = buf;
		});

		auto m = new YamuxConn(sb, true);
		auto s = m.open();
		s.write(sent);
		s.close();
		reader.join();
		m.close();
		sa.close();
	});

	// Never hand three quarters of a megabyte to fluent-asserts: it renders both
	// operands into the message before it compares them, and a mismatch here
	// would spend longer formatting than the whole suite takes to run.
	got.length.should.equal(total);
	size_t firstDiff = size_t.max;
	foreach (i; 0 .. min(got.length, sent.length))
		if (got[i] != sent[i])
		{
			firstDiff = i;
			break;
		}
	firstDiff.should.equal(size_t.max);
}

// The receive window is what bounds the receiver's buffer, and it does so by
// stopping the *sender*. A peer whose data nobody reads runs out of credit after
// exactly one window instead of being allowed to keep going.
@("yamux: a sender stops at one window when nothing reads")
unittest
{
	size_t written;
	string writerEnded;
	onLoop({
		MemStream sa, sb;
		memPair(sa, sb);
		auto other = spawn({
			auto m = new YamuxConn(sa, false);
			m.accept(); // accepted, deliberately never read
		});

		auto m = new YamuxConn(sb, true);
		auto s = m.open();
		auto writer = spawn({
			foreach (_; 0 .. 2)
			{
				s.write(new ubyte[window]);
				written += window;
			}
		});

		// Wait for the first window to land, then give the second every chance
		// to follow it. Waiting longer can only strengthen the assertion.
		immutable deadline = MonoTime.currTime + 5.seconds;
		while (written < window && MonoTime.currTime < deadline)
			sleep(5.msecs);
		sleep(100.msecs);

		m.close(); // ends the session, so the parked writer is told and leaves
		writerEnded = collectExceptionMsg(writer.join());
		other.join();
		sa.close();
	});

	written.should.equal(window); // the second write never got credit
	// The reason the writer reports is the reason it actually stopped. This used
	// to read "yamux: stream reset", which no peer had done: closing marked every
	// stream reset *in order to* wake it, so the wakeup invented its own cause.
	writerEnded.should.equal("yamux: session closed");
}

// --- lifecycle --------------------------------------------------------------

// The routing table used to only grow: one entry per substream for the life of
// the session, which on a long-lived connection is the leak that matters.
@("yamux: a stream closed by both sides leaves the routing table")
unittest
{
	size_t afterOpen, afterClose;
	onLoop({
		MemStream sa, sb;
		memPair(sa, sb);
		auto peer = spawn({
			auto m = new YamuxConn(sa, false);
			auto s = m.accept();
			auto buf = new ubyte[2];
			s.readExact(buf);
			s.close();
		});

		auto m = new YamuxConn(sb, true);
		auto s = m.open();
		s.write(cast(ubyte[]) "hi".dup);
		afterOpen = m.openStreams;
		s.close(); // our FIN; the peer's arrives while we wait below
		immutable deadline = MonoTime.currTime + 5.seconds;
		while (m.openStreams > 0 && MonoTime.currTime < deadline)
			sleep(5.msecs);
		afterClose = m.openStreams;
		peer.join();
		m.close();
		sa.close();
	});

	afterOpen.should.equal(1);
	afterClose.should.equal(0);
}

// A reset stream cannot carry another frame in either direction, so it goes
// immediately rather than waiting for a FIN that will never come.
@("yamux: a reset stream leaves the routing table")
unittest
{
	size_t remaining = size_t.max;
	string ended;
	onLoop({
		MemStream sa, sb;
		memPair(sa, sb);
		YamuxConn m;
		auto session = spawn({
			m = new YamuxConn(sa, false);
			auto s = m.accept();
			auto buf = new ubyte[1];
			s.readExact(buf); // wakes on the RST
		});

		sb.write(frame(typeWindowUpdate, flagSyn, 1, 0));
		sb.write(frame(typeData, flagRst, 1, 0));
		ended = collectExceptionMsg(session.join());
		remaining = m.openStreams;
		sb.close();
	});

	ended.should.equal("yamux: stream reset");
	remaining.should.equal(0);
}

// Closing twice, or closing after the session is gone, is what `scope (exit)`
// does on every error path. It used to throw from inside the unwind — which is
// also where the "yamux: session closed" noise in the test logs came from.
@("yamux: closing a stream is idempotent and survives a dead session")
unittest
{
	string first, second;
	onLoop({
		MemStream sa, sb;
		memPair(sa, sb);
		auto m = new YamuxConn(sb, true);
		auto s = m.open();
		m.close();
		first = collectExceptionMsg(s.close());
		second = collectExceptionMsg(s.close());
		sa.close();
	});

	(first is null).should.equal(true);
	(second is null).should.equal(true);
}

// Closing a session used to work by side effect: `Task.interrupt()` was a no-op
// on every wait in here, so a parked fiber only woke because the socket beneath
// it was closed too and its read blew up. That is cleanup by coincidence, and it
// is why cancellation could not be composed with anything.
//
// Now the waits are interruptible, so an interrupt alone is enough — no socket
// is touched in this test.
@("yamux: a parked reader can be cancelled without closing the transport")
unittest
{
	import vibe.core.task : InterruptException;

	bool woke, wasInterrupt;
	onLoop({
		MemStream sa, sb;
		memPair(sa, sb);
		auto m = new YamuxConn(sa, false);

		// Park a fiber in acceptStream. Nothing will ever arrive.
		auto parked = spawn({
			try
				m.accept();
			catch (InterruptException)
			{
				woke = true;
				wasInterrupt = true;
			}
			catch (Exception)
				woke = true;
		});

		sleep(50.msecs); // let it get there
		parked.interrupt(); // the only thing done: no close, no socket
		parked.join();

		m.close();
		sb.close();
		sleep(20.msecs); // let the session's own read loop unwind before we leave
	});

	woke.should.equal(true);
	wasInterrupt.should.equal(true); // and it woke *because* of the interrupt
}

// --- how a blocked read ends -------------------------------------------------
//
// A read that blocks has to end for a reason, and the reason has to survive the
// trip to whoever called it. These three cover the ways a stream stops mid-read,
// and each asserts the *type* — not a substring of a message, which is what the
// deleted `isNormalEnd` used to do four layers away from the fact it was
// guessing at.

// The session dies while a reader is parked inside `readExact`. It must not hang,
// and it must not report a reset nobody performed: the session is what ended.
@("yamux: a read parked mid-stream ends with the session, and says so")
unittest
{
	bool ended, wasConnClosed;
	string msg;
	onLoop({
		MemStream sa, sb;
		memPair(sa, sb);
		auto peer = spawn({
			auto m = new YamuxConn(sa, false);
			try
				m.accept(); // accepted, and deliberately never written to
			catch (Exception)
			{
			}
		});

		auto m = new YamuxConn(sb, true);
		auto s = m.open();
		auto reader = spawn({
			ubyte[4] b;
			try
				s.readExact(b[]); // nothing will ever arrive
			catch (ConnClosed e)
			{
				ended = true;
				wasConnClosed = true;
				msg = e.msg;
			}
			catch (Exception e)
			{
				ended = true;
				msg = e.msg;
			}
		});

		sleep(50.msecs); // let the reader get all the way into the wait
		m.close();
		reader.join();
		peer.join();
		sa.close();
		sleep(20.msecs);
	});

	ended.should.equal(true); // it woke at all
	wasConnClosed.should.equal(true); // and with the right kind of ending
	msg.should.equal("yamux: session closed");
}

// The peer abandons the substream under a parked reader. That is a reset, and it
// is a different fact from the session closing — a caller may retry one and not
// the other, which it can only do if the two arrive as different types.
@("yamux: a read parked mid-stream reports the peer's reset as a reset")
unittest
{
	bool wasReset;
	string msg;
	onLoop({
		MemStream sa, sb;
		memPair(sa, sb);
		auto app = spawn({
			auto m = new YamuxConn(sa, false);
			auto s = m.accept();
			ubyte[4] b;
			try
				s.readExact(b[]);
			catch (StreamReset e)
			{
				wasReset = true;
				msg = e.msg;
			}
			catch (Exception e)
				msg = e.msg;
			m.close();
		});

		sb.write(frame(typeWindowUpdate, flagSyn, 1, 0)); // open stream 1
		sleep(50.msecs); // let the read park
		sb.write(frame(typeData, flagRst, 1, 0)); // and abandon it
		app.join();
		sb.close();
		sleep(20.msecs);
	});

	wasReset.should.equal(true);
	msg.should.equal("yamux: stream reset");
}

// The bytes that arrived before a FIN are as valid as any others. Ending the read
// the moment the FIN is seen would drop data that was received successfully — so
// the ending is thrown only once there is genuinely nothing left to hand over.
@("yamux: a peer's FIN hands over what already arrived, and only then ends the read")
unittest
{
	string got, msg;
	bool wasEof;
	onLoop({
		MemStream sa, sb;
		memPair(sa, sb);
		auto app = spawn({
			auto m = new YamuxConn(sa, false);
			auto s = m.accept();
			ubyte[5] b;
			s.readExact(b[]); // the bytes that landed before the FIN did
			got = cast(string) b.idup;
			ubyte[1] more;
			try
				s.readExact(more[]); // now there is nothing left
			catch (EndOfStream e)
			{
				wasEof = true;
				msg = e.msg;
			}
			catch (Exception e)
				msg = e.msg;
			m.close();
		});

		// All three land before the application reads any of them, so the FIN is
		// already recorded by the time the first `readExact` runs.
		sb.write(frame(typeWindowUpdate, flagSyn, 1, 0));
		sb.write(frame(typeData, 0, 1, 5) ~ cast(const(ubyte)[]) "hello");
		sb.write(frame(typeData, flagFin, 1, 0));
		app.join();
		sb.close();
		sleep(20.msecs);
	});

	got.should.equal("hello"); // handed over despite the FIN
	wasEof.should.equal(true); // and only then did the read end
	msg.should.equal("yamux: stream closed by peer");
}


// A 1.3 MB length-prefixed message through noise + yamux while every read of the
// transport returns 1..7 bytes: each noise length, yamux header and varint
// straddles a read boundary somewhere along the way. Reported from an Android
// client: an OutOfMemoryError (a ~size_t.max allocation) 20 ms into such a
// message, which a size_t underflow on a partial read would produce.
@("yamux: a 1.3 MB message survives reads that return a few bytes at a time")
unittest
{
	import std.typecons : Nullable;
	import libp2p.core.peer_id : PeerId;
	import libp2p.crypto.keys : Keypair;
	import libp2p.security.noise : NoiseTransport;
	import tests.util.pipe : TrickleStream;

	enum size = 1_334_630;
	size_t gotA, gotB;
	bool contentOk;
	onLoop({
		MemStream sa, sb;
		memPair(sa, sb);
		scope (exit)
		{
			sa.close();
			sb.close();
		}
		auto ka = Keypair.generateEd25519, kb = Keypair.generateEd25519;
		auto big = new ubyte[size];
		foreach (i, ref x; big)
			x = cast(ubyte)(i * 7 + (i >> 8));

		auto ta = spawn({
			auto sec = new NoiseTransport(ka).secureOutbound(new TrickleStream(sa), Nullable!PeerId.init);
			auto m = new YamuxConn(sec, true);
			scope (exit)
				m.close();
			auto st = m.open();
			st.writeLengthPrefixed(big);
			auto back = st.readLengthPrefixed(2 * size);
			gotA = back.length;
			contentOk = back == big;
			st.close();
		});
		auto tb = spawn({
			auto sec = new NoiseTransport(kb).secureInbound(new TrickleStream(sb));
			auto m = new YamuxConn(sec, false);
			scope (exit)
				m.close();
			auto st = m.accept();
			auto msg = st.readLengthPrefixed(2 * size);
			gotB = msg.length;
			st.writeLengthPrefixed(msg); // echo it back the same way
			st.close();
		});
		ta.join();
		tb.join();
	});
	gotB.should.equal(size);
	gotA.should.equal(size);
	contentOk.should.equal(true);
}
