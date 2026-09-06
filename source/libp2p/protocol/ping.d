/**
 * ping (`/ipfs/ping/1.0.0`): 32 random bytes out, the same 32 back.
 *
 * The handler echoes until the peer closes. The service pings every connected
 * peer on a fiber of its own, one per connection, owned by the service: it is
 * started on `connected`, stopped on `disconnected` or `close()`, and ends on
 * its own when the connection is gone. It takes no hold on the connection —
 * pinging is not use, and a connection nobody else needs is allowed to go idle.
 */
module libp2p.protocol.ping;

import core.time : Duration, seconds, MonoTime;
import std.exception : enforce;

import vibe.core.core : sleep;
import vibe.core.task : Task, InterruptException;

import libsodium.randombytes : randombytes_buf;

import libp2p.core.ending : Ending;
import libp2p.core.peer_id : PeerId;
import libp2p.core.stream;
import libp2p.host.host;
import libp2p.util.fibers : FiberGroup;
import libp2p.util.timeout : withTimeout;

enum pingProtocol = "/ipfs/ping/1.0.0";
enum pingSize = 32;

/// One round trip on an already-negotiated stream. Throws on a mismatched echo.
Duration ping(Stream s)
{
	ubyte[pingSize] payload, echo;
	randombytes_buf(payload.ptr, payload.length);
	immutable started = MonoTime.currTime;
	s.write(payload[]);
	s.readExact(echo[]);
	enforce(echo == payload, "ping: the echo does not match what was sent");
	return MonoTime.currTime - started;
}

/// Echo until the peer is done. Returns when the stream ends; the caller closes it.
void handlePing(Stream s)
{
	ubyte[pingSize] buf;
	try
	{
		for (;;)
		{
			s.readExact(buf[]);
			s.write(buf[]);
		}
	}
	catch (Ending)
	{
		// The peer finished, or went away: either way there is nothing more to echo.
	}
}

struct PingConfig
{
	Duration interval = 15.seconds;
	Duration timeout = 20.seconds;
}

final class Ping : Notifiee
{
	private Host host;
	private PingConfig cfg;
	private FiberGroup fibers;
	private Task[Connection] loops;

	/// Called with each round-trip time measured.
	void delegate(PeerId peer, Duration rtt) onResult;
	/// Called when a ping fails; the loop goes on unless the connection is gone.
	void delegate(PeerId peer, Exception why) onFailure;

	this(Host host, PingConfig cfg = PingConfig.init)
	{
		this.host = host;
		this.cfg = cfg;
		fibers = new FiberGroup; // a loop's failure is the connection ending; nothing to do
		host.setStreamHandler(pingProtocol, (Stream s, Connection, string) {
			scope (exit)
				s.close();
			handlePing(s);
		});
		host.addNotifiee(this);
	}

	void connected(Connection c)
	{
		loops[c] = fibers.spawn({ loop(c); });
	}

	void disconnected(Connection c)
	{
		if (auto t = c in loops)
		{
			if (t.running && *t != Task.getThis())
				t.interrupt();
			loops.remove(c);
		}
	}

	void close() nothrow
	{
		try
		{
			host.removeNotifiee(this);
			host.removeStreamHandler(pingProtocol);
		}
		catch (Exception)
		{
		}
		fibers.stopAll();
		loops = null;
	}

	private void loop(Connection c)
	{
		scope (exit)
			loops.remove(c);
		while (!c.isClosed)
		{
			try
			{
				auto s = c.newStream(pingProtocol);
				scope (exit)
					s.close();
				immutable rtt = withTimeout(cfg.timeout, "ping", () => ping(s));
				if (onResult !is null)
					onResult(c.remotePeer, rtt);
			}
			catch (Ending)
			{
				return; // the connection is gone; so is the reason to ping it
			}
			catch (InterruptException e)
				throw e; // close() is stopping this loop, not a ping failure
			catch (Exception e)
			{
				if (onFailure !is null)
					onFailure(c.remotePeer, e);
			}
			sleep(cfg.interval);
		}
	}
}
