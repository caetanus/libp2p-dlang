/**
 * A muxer turns one connection into many streams.
 *
 * `open` and `accept` block and end two ways: a stream, or `ConnClosed` (or
 * the failure that ended the session) once it is gone. `isClosed` exists so a
 * pool can sweep dead sessions from a list; it is never a pre-condition for
 * calling anything else here.
 */
module libp2p.muxer.muxer;

import libp2p.core.stream : Stream;

interface Muxer
{
	/// A new outbound stream.
	Stream open();

	/// The next inbound stream.
	Stream accept();

	/// End the session: tell the peer, end every stream with `ConnClosed`, wake
	/// everyone parked in here, stop the reader, and close the transport. Blocks
	/// until that is done. Idempotent; never throws.
	void close() nothrow;

	bool isClosed() nothrow;
}
