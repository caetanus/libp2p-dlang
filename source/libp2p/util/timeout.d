/**
 * A deadline on a blocking operation, done the way everything else here is
 * done: the operation and a timer race inside `select`, and the loser is
 * interrupted. The caller sees the result, or `Timeout`.
 */
module libp2p.util.timeout;

import core.time : Duration;

import vibe.core.core : sleep;

import libp2p.util.select : select;

final class Timeout : Exception
{
	this(string msg, string file = __FILE__, size_t line = __LINE__) @safe pure nothrow
	{
		super(msg, file, line);
	}
}

/// Run `op`; if it has not finished after `limit`, interrupt it and throw
/// `Timeout`. A zero or negative `limit` means no deadline.
void withTimeout(Duration limit, string what, void delegate() op)
{
	if (limit <= Duration.zero)
	{
		op();
		return;
	}
	immutable winner = select(op, { sleep(limit); });
	if (winner == 1)
		throw new Timeout(what ~ " timed out after " ~ limit.toString);
}

/// The same, for an operation with a result.
T withTimeout(T)(Duration limit, string what, T delegate() op)
{
	T result;
	withTimeout(limit, what, { result = op(); });
	return result;
}
