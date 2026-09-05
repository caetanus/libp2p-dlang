/**
 * `Mplex` — the concurrent mplex, and what stops a peer from using it as an
 * allocator.
 *
 * mplex has no flow control; the protocol has none to have. What it has are the
 * two ceilings rust's `libp2p-mplex` puts around that absence, and this file
 * asserts both with rust's defaults: 128 concurrent substreams, and 32 frames
 * buffered for one substream before the whole connection stops being read
 * (`MaxBufferBehaviour::Block`).
 *
 * The blocking case is the one worth reading carefully, because "the read loop
 * stopped" and "the data was dropped" look identical from a distance and are
 * opposites. The test therefore checks both halves: bytes stay unread on the
 * wire while the buffer is full, and every one of them still arrives once the
 * application drains.
 */
module tests.muxer.mplex_conn_test;

import core.time : msecs, seconds, Duration, MonoTime;
import std.exception : collectExceptionMsg;

import vibe.core.core : sleep;

import libp2p.core.stream;
import libp2p.muxer.mplex;
import tests.util.pipe : MemStream, memPair;
import tests.util.loop : onLoop, spawn;
import fluent.asserts;

private enum size_t maxSubstreams = 128; // rust Config::max_substreams
private enum size_t maxBufferLen = 32; // rust Config::max_buffer_len

/// Wait for a condition rather than for a duration.
private bool waitUntil(bool delegate() cond, Duration limit = 5.seconds)
{
	immutable deadline = MonoTime.currTime + limit;
	while (MonoTime.currTime < deadline)
	{
		if (cond())
			return true;
		sleep(2.msecs);
	}
	return false;
}

/// Read back only the frames that are already there. Blocking would be wrong
/// here: the interesting assertion is often that nothing more is coming.
private MplexFrame[] drainAvailable(MemStream c)
{
	MplexFrame[] frames;
	while (c.available > 0)
		frames ~= readMplexFrame(c);
	return frames;
}

private bool sawReset(const MplexFrame[] frames)
{
	foreach (f; frames)
		if (f.flag == Flag.resetReceiver || f.flag == Flag.resetInitiator)
			return true;
	return false;
}

// --- ceilings ---------------------------------------------------------------

// Past the ceiling a substream is refused, not queued. Nothing is allocated for
// the refused id, so a peer that ignores the reset only wastes its own bandwidth.
@("mplex: inbound substreams past the ceiling are reset, not created")
unittest
{
	size_t open;
	MplexFrame[] back;
	onLoop({
		MemStream sa, sb;
		memPair(sa, sb);
		// Deliberately does not accept: the ceiling counts substreams the
		// connection is routing, and accepting does not free a slot.
		Mplex m;
		auto session = spawn({ m = new Mplex(sa, false); });

		foreach (i; 0 .. maxSubstreams + 1)
			writeMplexFrame(sb, i, Flag.newStream, null);
		waitUntil(() => m !is null && m.openStreams >= maxSubstreams);
		sleep(50.msecs); // let the one-too-many be processed too
		open = m.openStreams;
		back = drainAvailable(sb);

		sb.close();
		session.join();
		m.close();
	});

	open.should.equal(maxSubstreams);
	sawReset(back).should.equal(true);
}

// The two sides would disagree about which stream an id names, so upstream
// treats a repeated Open as a protocol error and ends the connection.
@("mplex: a newStream for an already-open substream ends the connection")
unittest
{
	string failure;
	onLoop({
		MemStream sa, sb;
		memPair(sa, sb);
		auto session = spawn({
			auto m = new Mplex(sa, false);
			for (;;)
				m.accept(); // parks, and reports why it stopped
		});

		writeMplexFrame(sb, 7, Flag.newStream, null);
		writeMplexFrame(sb, 7, Flag.newStream, null);
		failure = collectExceptionMsg(session.join());
		sb.close();
	});

	failure.should.equal("mplex: newStream for an already-open substream");
}

// --- backpressure -----------------------------------------------------------

// MaxBufferBehaviour::Block. Once a substream's buffer is full the connection
// stops being read — the bytes stay on the wire rather than in our heap — and
// they are all still there when the application catches up.
@("mplex: a full substream buffer stops the connection, and loses nothing")
unittest
{
	enum frames = maxBufferLen + 16;
	enum payload = 64;

	size_t stalled, drained, got;
	onLoop({
		MemStream sa, sb;
		memPair(sa, sb);
		auto reader = spawn({
			auto m = new Mplex(sa, false);
			auto s = m.accept();
			// Nothing is read until the peer has stopped making progress, which
			// is what makes the stall below meaningful.
			waitUntil(() => sb.unread == 0, 1.seconds);
			sleep(100.msecs);
			stalled = sb.unread;

			auto buf = new ubyte[payload];
			foreach (_; 0 .. frames)
			{
				s.readExact(buf);
				got += buf.length;
			}
			waitUntil(() => sb.unread == 0);
			drained = sb.unread;
			m.close();
		});

		writeMplexFrame(sb, 0, Flag.newStream, null);
		foreach (_; 0 .. frames)
			writeMplexFrame(sb, 0, Flag.messageInitiator, new ubyte[payload]);
		reader.join();
		sb.close();
	});

	stalled.should.be.greaterThan(0); // the read loop stopped, mid-connection
	got.should.equal(frames * payload); // and nothing was dropped to do it
	drained.should.equal(0);
}

// --- lifecycle --------------------------------------------------------------

// The table only ever grew before: one entry per substream for the life of the
// connection, which on a long-lived link is the leak that matters.
@("mplex: a substream closed by both sides leaves the routing table")
unittest
{
	size_t afterOpen, afterClose;
	onLoop({
		MemStream sa, sb;
		memPair(sa, sb);
		auto peer = spawn({
			auto m = new Mplex(sa, false);
			auto s = m.accept();
			auto buf = new ubyte[2];
			s.readExact(buf);
			s.close();
		});

		auto m = new Mplex(sb, true);
		auto s = m.open();
		s.write(cast(ubyte[]) "hi".dup);
		afterOpen = m.openStreams;
		s.close(); // ours; the peer's close arrives while we wait
		waitUntil(() => m.openStreams == 0);
		afterClose = m.openStreams;
		peer.join();
		m.close();
		sa.close();
	});

	afterOpen.should.equal(1);
	afterClose.should.equal(0);
}

// A reset substream cannot carry another frame in either direction, so it goes
// at once rather than waiting for a close that will never come.
@("mplex: a reset substream leaves the routing table")
unittest
{
	size_t remaining = size_t.max;
	string ended;
	onLoop({
		MemStream sa, sb;
		memPair(sa, sb);
		Mplex m;
		auto session = spawn({
			m = new Mplex(sa, false);
			auto s = m.accept();
			auto buf = new ubyte[1];
			s.readExact(buf); // wakes on the reset
		});

		writeMplexFrame(sb, 3, Flag.newStream, null);
		writeMplexFrame(sb, 3, Flag.resetInitiator, null);
		ended = collectExceptionMsg(session.join());
		remaining = m.openStreams;
		sb.close();
	});

	ended.should.equal("mplex: stream reset");
	remaining.should.equal(0);
}

// Closing twice, or closing after the connection is gone, is what
// `scope (exit) s.close()` does on every error path.
@("mplex: closing a substream is idempotent and survives a dead connection")
unittest
{
	string first, second;
	onLoop({
		MemStream sa, sb;
		memPair(sa, sb);
		auto m = new Mplex(sb, true);
		auto s = m.open();
		m.close();
		first = collectExceptionMsg(s.close());
		second = collectExceptionMsg(s.close());
		sa.close();
	});

	(first is null).should.equal(true);
	(second is null).should.equal(true);
}
