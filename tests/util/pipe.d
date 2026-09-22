/**
 * An in-memory duplex on the vibe event loop, for driving two protocol
 * endpoints against each other without a socket. Each end is a `Stream` with
 * the same contract as TCP: a read blocks until bytes arrive or the peer closes
 * (`EndOfStream`), a write after the far side closed is `ConnClosed`.
 */
module tests.util.pipe;

import std.algorithm.comparison : min;

import vibe.core.sync : LocalManualEvent, createManualEvent;

import libp2p.core.ending;
import libp2p.core.stream : Stream;
import tests.util.loop;

private final class Chan
{
	ubyte[] data;
	bool closed;
	LocalManualEvent ev;

	this()
	{
		ev = createManualEvent();
	}
}

final class MemStream : Stream
{
	private Chan rx, tx;
	private bool closed;

	private this(Chan rx, Chan tx)
	{
		this.rx = rx;
		this.tx = tx;
	}

	size_t read(ubyte[] buf)
	{
		if (buf.length == 0)
			return 0;
		auto seen = rx.ev.emitCount;
		while (rx.data.length == 0)
		{
			if (closed)
				throw new ConnClosed("pipe: closed locally");
			if (rx.closed)
				throw new EndOfStream("pipe: closed by peer");
			seen = rx.ev.wait(seen);
		}
		immutable n = min(buf.length, rx.data.length);
		buf[0 .. n] = rx.data[0 .. n];
		rx.data = rx.data[n .. $];
		return n;
	}

	void write(const(ubyte)[] d)
	{
		if (closed)
			throw new ConnClosed("pipe: closed locally");
		if (tx.closed)
			throw new ConnResetByPeer("pipe: peer is gone");
		tx.data ~= d;
		tx.ev.emit();
	}

	void close() nothrow
	{
		if (closed)
			return;
		closed = true;
		tx.closed = true;
		tx.ev.emit();
		rx.ev.emit(); // wake our own parked reader, if any
	}

	void reset() nothrow
	{
		close();
	}

	/// Bytes written by this end that the other has not read yet.
	size_t unread() const @safe pure nothrow @nogc
	{
		return tx.data.length;
	}

	/// Bytes waiting for this end to read.
	size_t available() const @safe pure nothrow @nogc
	{
		return rx.data.length;
	}
}

void memPair(out MemStream a, out MemStream b)
{
	auto p = new Chan;
	auto q = new Chan;
	a = new MemStream(p, q); // a reads p, writes q
	b = new MemStream(q, p);
}

/**
 * Run `a` and `b` against each other on the loop and rethrow the first failure
 * after both have finished. Both ends are closed afterwards, so a body that
 * left a reader parked is woken rather than leaked.
 */
void runPair(void delegate(Stream) a, void delegate(Stream) b)
{
	onLoop({
		MemStream sa, sb;
		memPair(sa, sb);
		scope (exit)
		{
			sa.close();
			sb.close();
		}
		// An end that finishes closes its stream, the way a peer does: the other
		// side's read comes back as an ending instead of parking forever.
		auto ta = spawn({ scope (exit) sa.close(); a(sa); });
		auto tb = spawn({ scope (exit) sb.close(); b(sb); });
		Exception first;
		try
			ta.join();
		catch (Exception e)
			first = e;
		try
			tb.join();
		catch (Exception e)
			if (first is null)
				first = e;
		if (first !is null)
			throw first;
	});
}

/// A stream that hands out reads a few bytes at a time — 1, 2, 3, … up to `maxChunk`,
/// then 1 again — whatever the underlying stream has. Every header and length
/// field of the protocols above it therefore straddles a read boundary at some
/// point, which is what a real TCP segmentation does and a memory pipe never does.
final class TrickleStream : Stream
{
	private Stream inner;
	private size_t maxChunk, next = 1;

	this(Stream inner, size_t maxChunk = 7)
	{
		this.inner = inner;
		this.maxChunk = maxChunk;
	}

	size_t read(ubyte[] buf)
	{
		immutable want = min(buf.length, next);
		next = next >= maxChunk ? 1 : next + 1;
		return inner.read(buf[0 .. want]);
	}

	void write(const(ubyte)[] d)
	{
		inner.write(d);
	}

	void close() nothrow
	{
		inner.close();
	}

	void reset() nothrow
	{
		inner.reset();
	}
}
