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

/// A raw transport that can also dial from a chosen local port with address reuse —
/// what a TCP-style hole punch needs (egress from the listen port so the peer's NAT
/// mapping matches). Implemented alongside `Transport`; the swarm uses it only for a
/// punch.
interface PunchableTransport
{
	/// Dial `remote` egressing from local port `localPort` with SO_REUSEADDR |
	/// SO_REUSEPORT.
	RawConn dialReusing(const Multiaddr remote, ushort localPort);
}

/// A `Stream` dressed as a raw connection: what a relay hands over, so the
/// upgrade can treat it like a socket.
final class StreamRawConn : RawConn
{
	private Stream inner;
	private Multiaddr local, remote;

	this(Stream inner, Multiaddr local, Multiaddr remote)
	{
		this.inner = inner;
		this.local = local;
		this.remote = remote;
	}

	size_t read(ubyte[] buf)
	{
		return inner.read(buf);
	}

	void write(const(ubyte)[] data)
	{
		inner.write(data);
	}

	void close() nothrow
	{
		inner.close();
	}

	void reset() nothrow
	{
		inner.reset();
	}

	Multiaddr localAddr()
	{
		return local;
	}

	Multiaddr remoteAddr()
	{
		return remote;
	}
}
