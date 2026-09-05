/**
 * TCP over vibe-core.
 *
 * vibe hands every accepted connection to a callback on a fiber of its own;
 * with `disableAutoClose` that fiber only has to drop the connection into our
 * queue and leave, so the connection's lifetime is ours from the first moment.
 * vibe reports the far side going away as a plain `Exception` or as
 * `leastSize == 0`; both become typed endings here, at the boundary.
 */
module libp2p.transport.tcp;

import std.algorithm.comparison : min;
import std.exception : enforce;
import std.format : format;

import vibe.core.net;
import vibe.core.stream : IOMode;
import std.socket : AddressFamily;
import vibe.core.sync : LocalManualEvent, createManualEvent;
import vibe.core.task : InterruptException;

import libp2p.core.ending;
import libp2p.core.stream : Stream;
import libp2p.multiformats.multiaddr : Multiaddr, Component;
import libp2p.transport.transport;

final class TcpTransport : Transport
{
	bool canHandle(const Multiaddr addr)
	{
		try
		{
			auto c = addr.components;
			return c.length == 2 && (c[0].name == "ip4" || c[0].name == "ip6") && c[1].name == "tcp";
		}
		catch (Exception)
			return false;
	}

	RawConn dial(const Multiaddr remote)
	{
		enforce(canHandle(remote), "tcp: cannot dial " ~ remote.toString);
		TCPConnection conn;
		try
			conn = connectTCP(toNetworkAddress(remote));
		catch (Exception e)
			throw new Exception("tcp: dial " ~ remote.toString ~ " failed", e);
		conn.tcpNoDelay = true;
		return new TcpConn(conn);
	}

	Listener listen(const Multiaddr local)
	{
		enforce(canHandle(local), "tcp: cannot listen on " ~ local.toString);
		return new TcpListener(toNetworkAddress(local));
	}
}

final class TcpConn : RawConn
{
	private TCPConnection conn;
	private bool closed;

	private this(TCPConnection conn) @safe nothrow
	{
		this.conn = conn;
	}

	size_t read(ubyte[] buf)
	{
		if (buf.length == 0)
			return 0;
		if (closed)
			throw new ConnClosed("tcp: closed locally");
		try
		{
			immutable avail = conn.leastSize; // blocks; 0 means the peer is done
			if (avail == 0)
				throw new EndOfStream("tcp: peer closed the connection");
			return conn.read(buf[0 .. min(buf.length, avail)], IOMode.once);
		}
		catch (Ending e)
			throw e;
		catch (InterruptException e)
			throw e;
		catch (Exception e)
			throw asEnding(e, "tcp");
	}

	void write(const(ubyte)[] data)
	{
		if (closed)
			throw new ConnClosed("tcp: closed locally");
		try
			conn.write(data);
		catch (InterruptException e)
			throw e;
		catch (Exception e)
			throw asEnding(e, "tcp");
	}

	void close() nothrow
	{
		if (closed)
			return;
		closed = true;
		conn.close();
	}

	/// TCP has no application-level reset; the socket is simply closed.
	void reset() nothrow
	{
		close();
	}

	Multiaddr localAddr()
	{
		return toMultiaddr(conn.localAddress);
	}

	Multiaddr remoteAddr()
	{
		return toMultiaddr(conn.remoteAddress);
	}
}

final class TcpListener : Listener
{
	private TCPListener listener;
	private RawConn[] queue;
	private LocalManualEvent arrived;
	private bool closed;

	private this(NetworkAddress bind)
	{
		arrived = createManualEvent();
		listener = listenTCP(&onConnection, bind, TCPListenOptions.disableAutoClose | TCPListenOptions.reuseAddress);
	}

	private void onConnection(TCPConnection c) @safe nothrow
	{
		if (closed)
		{
			c.close();
			return;
		}
		c.tcpNoDelay = true;
		queue ~= new TcpConn(c);
		arrived.emit();
	}

	RawConn accept()
	{
		auto seen = arrived.emitCount;
		while (queue.length == 0)
		{
			if (closed)
				throw new ConnClosed("tcp: listener closed");
			seen = arrived.wait(seen);
		}
		auto c = queue[0];
		queue = queue[1 .. $];
		return c;
	}

	Multiaddr address()
	{
		return toMultiaddr(listener.bindAddress);
	}

	void close() nothrow
	{
		if (closed)
			return;
		closed = true;
		try
			listener.stopListening();
		catch (Exception)
		{
		}
		foreach (c; queue)
			c.close();
		queue = null;
		arrived.emit();
	}
}

// --- addresses --------------------------------------------------------------

NetworkAddress toNetworkAddress(const Multiaddr addr)
{
	auto c = addr.components;
	enforce(c.length == 2 && c[1].name == "tcp", "tcp: not an ip/tcp address");
	auto na = resolveHost(c[0].text, c[0].name == "ip4" ? AddressFamily.INET : AddressFamily.INET6, false);
	na.port = cast(ushort)((c[1].value[0] << 8) | c[1].value[1]);
	return na;
}

Multiaddr toMultiaddr(NetworkAddress na)
{
	immutable ip = na.toAddressString;
	immutable proto = na.family == AddressFamily.INET6 ? "ip6" : "ip4";
	return Multiaddr.parse(format("/%s/%s/tcp/%d", proto, ip, na.port));
}
