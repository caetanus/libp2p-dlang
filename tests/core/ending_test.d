/**
 * Endings as types, and the chain of causes underneath them.
 *
 * A blocking read has to be able to fail for the reason it actually failed. The
 * transport under it is a foreign library that reports every ending as a plain
 * `Exception` with nothing but a message, so *somewhere* that message has to be
 * read — and the whole point of `asEnding` is that it is read exactly once, at
 * the boundary where the foreign library hands over.
 *
 * These tests pin the two halves of that bargain: the translation names what it
 * recognises, and it never destroys what it translated.
 */
module tests.core.ending_test;

import libp2p.core.ending;
import fluent.asserts;

// The case that names itself. A peer that vanishes mid-read is not a peer that
// finished speaking, and a caller that retries one and gives up on the other can
// only tell them apart if they arrive as different types.
@("ending: a reset by peer is typed as one, not as a generic close")
unittest
{
	auto original = new Exception("Connection reset by peer");
	auto typed = asEnding(original, "tcp");

	(cast(ConnResetByPeer) typed !is null).should.equal(true);
	// ...and still answers to the broader questions, the way go-libp2p's
	// `errors.Is(err, ErrReset)` does, but without a hand-written matcher.
	(cast(ConnClosed) typed !is null).should.equal(true);
	(cast(Ending) typed !is null).should.equal(true);
}

// Translating an error must never be the same act as discarding it. The layer
// that only wants "is this an ordinary shutdown" matches the type; the one
// debugging at three in the morning walks the chain down to the original.
@("ending: translation keeps the original as the cause")
unittest
{
	auto original = new Exception("Connection reset by peer");
	auto typed = asEnding(original, "tcp");

	(typed.next is original).should.equal(true);
	typed.msg.should.contain("tcp");
	typed.msg.should.contain("Connection reset by peer");
}

// A clean end of stream is an ending too, and a different one: the write half of
// a substream may well still be usable after it.
@("ending: an end of stream is typed as an ending but not as a reset")
unittest
{
	auto typed = asEnding(new Exception("Reached end of stream while reading data"), "tcp");

	(cast(EndOfStream) typed !is null).should.equal(true);
	(cast(Ending) typed !is null).should.equal(true);
	(cast(ConnResetByPeer) typed !is null).should.equal(false);
}

// The half that matters more than the recognising. A read that failed for a
// reason we cannot name is not an ordinary ending, and dressing it as one is
// exactly how a broken socket comes to look like a peer saying goodbye — which
// is what the deleted `isNormalEnd` did, six substrings at a time.
@("ending: an unrecognised failure is left alone, not promoted to an ending")
unittest
{
	auto original = new Exception("SSL_read: decryption failed or bad record mac");
	auto typed = asEnding(original, "tcp");

	(typed is original).should.equal(true); // untouched, not even rewrapped
	(cast(Ending) typed !is null).should.equal(false);
}

// Under a muxer session the transport ending is not one substream finishing, it
// is every substream finishing at once — so it is re-typed. Re-typed, not
// overwritten: the more specific ending it came from stays reachable.
@("ending: a transport EOF under a session becomes a closed connection, keeping the EOF")
unittest
{
	auto original = new Exception("Reached end of stream while reading data");
	auto typed = asConnEnding(original, "yamux");

	(cast(ConnClosed) typed !is null).should.equal(true);
	(cast(EndOfStream) typed.next !is null).should.equal(true); // the step it came from
	(typed.next.next is original).should.equal(true); // and the original beneath it
}

// A reset already says the connection is what ended, so there is nothing to
// re-type: wrapping it again would bury the more specific answer under a vaguer
// one, which is the opposite of what a chain of causes is for.
@("ending: a reset under a session is not re-wrapped into something vaguer")
unittest
{
	auto typed = asConnEnding(new Exception("Connection reset by peer"), "yamux");

	(cast(ConnResetByPeer) typed !is null).should.equal(true);
}

// A failure under a session is still a failure. `catch (Ending)`, written to
// absorb ordinary shutdown, must not absorb a peer breaking the protocol.
@("ending: a genuine failure under a session stays a failure")
unittest
{
	auto original = new Exception("yamux: data frame exceeds the receive window");
	auto typed = asConnEnding(original, "yamux");

	(typed is original).should.equal(true);
	(cast(Ending) typed !is null).should.equal(false);
}
