/**
 * An in-memory duplex driven by the vibe event loop, plus the two helpers that
 * make a blocked endpoint testable.
 *
 * `tests.util.fiberpipe` drives both endpoints from raw `Fiber.yield()`, which
 * works for pure protocol code but not for anything whose waits are vibe
 * primitives: a muxer's read loop is a task, and a fiber parked in
 * `LocalManualEvent.wait` never hands control back to a raw fiber. Anything with
 * a background read loop — mplex, yamux — needs a real loop under it, so it can
 * have one endpoint block indefinitely without stalling the other.
 */
module tests.util.looppipe;

import std.algorithm : min;
import std.exception : enforce;

import vibe.core.core : runTask, runEventLoop, exitEventLoop;
import vibe.core.task : Task;
import vibe.core.sync : LocalManualEvent, createManualEvent;

import libp2p.core.ending : EndOfStream;
import libp2p.core.stream : ByteStream;

/**
 * A task whose failure survives it.
 *
 * vibe wants a `nothrow` body, so the exception is carried across as a value and
 * thrown again from `join` — the same bargain a muxer makes with its read loop,
 * and the only reason an error here ever stops being an exception.
 */
final class Side
{
	/// The fiber itself. Public because cancelling a parked task — rather than
	/// waiting for it — is a thing a test needs to do now that the waits below
	/// it are interruptible.
	Task task;
	private Exception err;

	void join()
	{
		task.joinUninterruptible();
		if (err !is null)
			throw err;
	}
}

Side spawn(void delegate() body_)
{
	auto s = new Side;
	s.task = runTask(() nothrow{
		try
			body_();
		catch (Exception e)
			s.err = e;
	});
	return s;
}

/// Run `body_` on the event loop and re-throw what it raised, so assertions stay
/// outside the fiber.
void onLoop(void delegate() body_)
{
	Exception err;
	runTask(() nothrow{
		try
			body_();
		catch (Exception e)
			err = e;
		try
			exitEventLoop();
		catch (Exception)
		{
		}
	});
	runEventLoop();
	if (err !is null)
		throw err;
}

private final class Chan
{
	ubyte[] data;
	bool closed;
	LocalManualEvent ev;
}

final class MemStream : ByteStream
{
	private Chan rx, tx;

	private this(Chan rx, Chan tx)
	{
		this.rx = rx;
		this.tx = tx;
	}

	void writeBytes(scope const(ubyte)[] d)
	{
		enforce(!tx.closed, "memstream: closed");
		tx.data ~= d;
		tx.ev.emit();
	}

	void readExact(scope ubyte[] buf)
	{
		size_t got;
		while (got < buf.length)
		{
			if (rx.data.length == 0)
			{
				enforce(!rx.closed, "memstream: EOF");
				immutable ec = rx.ev.emitCount;
				if (rx.data.length == 0 && !rx.closed)
					rx.ev.waitUninterruptible(ec);
				continue;
			}
			immutable n = min(buf.length - got, rx.data.length);
			buf[got .. got + n] = rx.data[0 .. n];
			rx.data = rx.data[n .. $];
			got += n;
		}
	}

	size_t readAvailable(scope ubyte[] buf)
	{
		while (rx.data.length == 0)
		{
			if (rx.closed)
				throw new EndOfStream("pipe: closed by peer");
			immutable ec = rx.ev.emitCount;
			if (rx.data.length == 0 && !rx.closed)
				rx.ev.waitUninterruptible(ec);
		}
		immutable n = min(buf.length, rx.data.length);
		buf[0 .. n] = rx.data[0 .. n];
		rx.data = rx.data[n .. $];
		return n;
	}

	/// How many bytes this endpoint has written that nobody has read. A test
	/// that needs to know whether the far side is still making progress asks
	/// this rather than timing it — it is how backpressure becomes observable.
	size_t unread() const @safe pure nothrow @nogc
	{
		return tx.data.length;
	}

	/// Bytes waiting for this endpoint to read. Lets a test drain only what is
	/// there instead of blocking on a frame that may never come.
	size_t available() const @safe pure nothrow @nogc
	{
		return rx.data.length;
	}

	/// Closes both directions, as owning one end of a socket does: whoever is
	/// parked reading this endpoint has to come back, or the task outlives the
	/// test and the gate reports it.
	void close()
	{
		tx.closed = true;
		rx.closed = true;
		tx.ev.emit();
		rx.ev.emit();
	}
}

void memPair(out MemStream a, out MemStream b)
{
	auto p = new Chan;
	p.ev = createManualEvent();
	auto q = new Chan;
	q.ev = createManualEvent();
	a = new MemStream(p, q); // reads p, writes q
	b = new MemStream(q, p);
}
