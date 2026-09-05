/**
 * A cooperative in-memory duplex for driving two protocol endpoints against
 * each other without a real event loop. Each endpoint runs in its own fiber;
 * a blocked read yields to the other fiber. This lets us test multistream,
 * mplex and the protocols end-to-end, deterministically, in one thread.
 */
module tests.util.fiberpipe;

import core.thread.fiber : Fiber;
import std.algorithm : min;
import std.exception : enforce;
import libp2p.core.ending : EndOfStream;
import libp2p.core.stream : ByteStream;

private final class Pipe
{
	ubyte[] data;
	bool closed;
}

/// A `ByteStream` over a pair of in-memory pipes, cooperatively scheduled.
final class FiberStream : ByteStream
{
	private Pipe rx, tx;

	private this(Pipe rx, Pipe tx)
	{
		this.rx = rx;
		this.tx = tx;
	}

	void writeBytes(scope const(ubyte)[] d)
	{
		tx.data ~= d;
	}

	void readExact(scope ubyte[] buf)
	{
		size_t got;
		while (got < buf.length)
		{
			if (rx.data.length == 0)
			{
				if (rx.closed)
					throw new Exception("fiberpipe: EOF");
				Fiber.yield();
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
			Fiber.yield();
		}
		immutable n = buf.length < rx.data.length ? buf.length : rx.data.length;
		buf[0 .. n] = rx.data[0 .. n];
		rx.data = rx.data[n .. $];
		return n;
	}

	void close()
	{
		tx.closed = true;
	}
}

/**
 * Run `a` and `b` over a shared in-memory duplex until both return, then
 * re-throw the first exception either raised. Fails fast on deadlock.
 */
void runPair(void delegate(ByteStream) a, void delegate(ByteStream) b)
{
	auto p = new Pipe;
	auto q = new Pipe;
	auto sa = new FiberStream(p, q); // a reads p, writes q
	auto sb = new FiberStream(q, p); // b reads q, writes p

	Throwable ea, eb;
	auto fa = new Fiber(() { try
		a(sa);
	catch (Throwable t)
		ea = t; });
	auto fb = new Fiber(() { try
		b(sb);
	catch (Throwable t)
		eb = t; });

	size_t stuck;
	while (fa.state != Fiber.State.TERM || fb.state != Fiber.State.TERM)
	{
		immutable beforeData = p.data.length + q.data.length;
		immutable beforeA = fa.state, beforeB = fb.state;
		if (fa.state != Fiber.State.TERM)
			fa.call();
		if (fb.state != Fiber.State.TERM)
			fb.call();
		immutable progressed = (p.data.length + q.data.length) != beforeData
			|| fa.state != beforeA || fb.state != beforeB;
		if (progressed)
			stuck = 0;
		else if (++stuck > 1000)
			break; // no data moved and no state changed: quiescent or deadlocked
	}

	if (ea)
		throw ea;
	if (eb)
		throw eb;
	enforce(fa.state == Fiber.State.TERM && fb.state == Fiber.State.TERM,
		"fiberpipe: deadlock (an endpoint is still blocked)");
}
