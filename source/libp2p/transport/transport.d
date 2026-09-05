/**
 * What the swarm dials and listens through.
 *
 * A transport turns a multiaddr into a raw, unsecured `Stream` in either
 * direction. It knows nothing about peers, security or multiplexing; the
 * upgrade adds those. A listener's `accept` blocks until a connection arrives
 * or the listener is closed, in which case it throws `ConnClosed` — closing
 * does not close a socket in order to wake a parked accept, it wakes it.
 */
module libp2p.transport.transport;

import libp2p.core.stream : Stream;
import libp2p.multiformats.multiaddr : Multiaddr;

/// A raw connection: a `Stream` that knows its two ends.
interface RawConn : Stream
{
	Multiaddr localAddr();
	Multiaddr remoteAddr();
}

interface Listener
{
	/// The next inbound connection, or throws `ConnClosed` once `close()` has
	/// been called.
	RawConn accept();

	/// The address actually bound (a port of 0 in the request becomes real here).
	Multiaddr address();

	/// Stop accepting, wake anyone parked in `accept`, and close connections
	/// accepted but not yet taken. Idempotent.
	void close() nothrow;
}

interface Transport
{
	/// True if this transport can dial or listen on `addr`.
	bool canHandle(const Multiaddr addr);

	/// A connected raw connection, or throws.
	RawConn dial(const Multiaddr remote);

	Listener listen(const Multiaddr local);
}
