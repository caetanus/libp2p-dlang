/**
 * Endings: the typed reasons a blocking operation stops.
 *
 * A blocking call ends two ways — with its result, or by throwing. When the
 * reason is not a protocol error but the far side going away, the caller often
 * has to tell *how* it went away: a peer that finished speaking (FIN) leaves a
 * stream whose write half may still be useful; a peer that vanished (RST) does
 * not. These types are that distinction. They are exceptions so that the
 * ending unwinds the stack like any other failure and the owner of the fiber
 * learns without anyone threading a status through.
 *
 * Foreign libraries (vibe-core, in practice) report every ending as a plain
 * `Exception` with a message. That message is read in exactly one place —
 * `asEnding`, at the boundary where the foreign call is made — and the result
 * keeps the original as its cause (`Throwable.next`), so nothing is destroyed
 * by being translated. An unrecognised failure is left exactly as it is:
 * dressing an unknown error as an ordinary shutdown is how a broken socket
 * comes to look like a peer saying goodbye.
 *
 * Cancellation (`vibe.core.task.InterruptException`) is deliberately *not* an
 * `Ending`. It belongs to whoever owns the fiber, and a `catch (Ending)` written
 * to absorb ordinary shutdown must never absorb it.
 */
module libp2p.core.ending;

/// Base of every ending. "The operation cannot continue, and it is not a bug
/// or a protocol violation."
class Ending : Exception
{
	this(string msg, Throwable cause = null, string file = __FILE__, size_t line = __LINE__) @safe nothrow
	{
		super(msg, file, line, cause);
	}
}

/// The peer finished speaking on this stream (FIN). Nothing more will arrive.
class EndOfStream : Ending
{
	this(string msg, Throwable cause = null, string file = __FILE__, size_t line = __LINE__) @safe nothrow
	{
		super(msg, cause, file, line);
	}
}

/// The peer abandoned this stream (RST). Whatever was in flight is lost.
class StreamReset : Ending
{
	this(string msg, Throwable cause = null, string file = __FILE__, size_t line = __LINE__) @safe nothrow
	{
		super(msg, cause, file, line);
	}
}

/// The connection under the stream is gone: every stream on it ended at once.
class ConnClosed : Ending
{
	this(string msg, Throwable cause = null, string file = __FILE__, size_t line = __LINE__) @safe nothrow
	{
		super(msg, cause, file, line);
	}
}

/// The connection was torn down by the peer rather than closed in order.
class ConnResetByPeer : ConnClosed
{
	this(string msg, Throwable cause = null, string file = __FILE__, size_t line = __LINE__) @safe nothrow
	{
		super(msg, cause, file, line);
	}
}

/**
 * Translate a foreign failure into a typed ending, once, at the boundary.
 *
 * `where` names the boundary ("tcp", "yamux") so the message says which layer
 * saw the ending. Recognised endings come back typed with `e` as their cause;
 * anything else — and anything already typed — comes back untouched.
 */
Exception asEnding(Exception e, string where) @safe nothrow
{
	if (cast(Ending) e !is null)
		return e;

	immutable kind = classify(e.msg);
	final switch (kind)
	{
	case Kind.none:
		return e;
	case Kind.eof:
		return new EndOfStream(where ~ ": " ~ e.msg, e);
	case Kind.reset:
		return new ConnResetByPeer(where ~ ": " ~ e.msg, e);
	}
}

/**
 * Translate a failure seen *under a session* (a muxer reading its transport).
 *
 * There a transport EOF is not one stream finishing, it is the connection
 * ending, so it is re-typed as `ConnClosed` — keeping the `EndOfStream` it came
 * from, and the original beneath that. A `ConnClosed` (including a reset) is
 * already the most specific answer and is not re-wrapped. Anything unrecognised
 * stays a failure.
 */
Exception asConnEnding(Exception e, string where) @safe nothrow
{
	auto typed = asEnding(e, where);
	if (cast(ConnClosed) typed !is null)
		return typed;
	if (cast(Ending) typed !is null)
		return new ConnClosed(where ~ ": connection closed", typed);
	return typed;
}

private enum Kind
{
	none,
	eof,
	reset
}

// The strings vibe-core emits for the endings it can see. Kept in one place so
// that when vibe changes a message there is one line to change.
private Kind classify(string msg) @safe pure nothrow
{
	import std.algorithm.searching : canFind;

	if (msg.canFind("Reached end of stream") || msg.canFind("end of stream"))
		return Kind.eof;
	if (msg.canFind("reset by peer") || msg.canFind("Broken pipe")
		|| msg.canFind("Connection closed while writing")
		|| msg.canFind("Error writing data to socket"))
		return Kind.reset;
	return Kind.none;
}
