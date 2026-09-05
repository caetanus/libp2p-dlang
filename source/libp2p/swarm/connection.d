/**
 * A connection to one peer: the muxer, the fibers that serve it, and the
 * policy for what happens when they fail.
 *
 * The connection owns three kinds of fiber. The inbound loop accepts
 * substreams; each one gets a handler fiber that negotiates a protocol and runs
 * the registered handler; the idle timer closes the connection when nobody has
 * used it for a while. `close()` interrupts and joins all of them, then closes
 * the muxer (as a consequence, not as the mechanism), returns the connection's
 * slot in the limiter, removes it from the pool, and notifies. When it returns,
 * nothing of the connection is left running.
 *
 * A handler that fails resets its stream; the connection lives. The muxer
 * failing is the connection ending, whatever the reason: the inbound loop sees
 * it and closes.
 *
 * A `Hold` is a claim that the connection is in use. While one is alive the
 * idle timer is disarmed; when the last is released a fresh timer is armed.
 */
module libp2p.swarm.connection;

import core.time : Duration;

import vibe.core.core : sleep;
import vibe.core.log : logDebug;
import vibe.core.task : Task;

import libp2p.core.ending : Ending;
import libp2p.core.peer_id : PeerId;
import libp2p.core.stream : Stream;
import libp2p.core.upgrade : Endpoint;
import libp2p.crypto.keys : PublicKey;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.multistream.select : negotiateDialer, negotiateListener;
import libp2p.muxer.muxer : Muxer;
import libp2p.swarm.limiter : Lease;
import libp2p.swarm.swarm : Swarm;
import libp2p.util.fibers : FiberGroup;

/// Runs on its own fiber, owned by the connection. Owns `stream` from here on:
/// close it when done, or hand it to someone who will. A throw resets it.
alias StreamHandler = void delegate(Stream stream, Connection conn, string protocol);

interface Notifiee
{
	void connected(Connection c);
	void disconnected(Connection c);
}

/// A claim that the connection is in use. Released on scope exit.
struct Hold
{
	private Connection conn;

	@disable this(this);

	~this() nothrow
	{
		release();
	}

	void release() nothrow
	{
		if (conn is null)
			return;
		conn.releaseHold();
		conn = null;
	}
}

final class Connection
{
	immutable Endpoint role;
	private PeerId remotePeer_;
	private PublicKey remoteKey_;
	private Multiaddr localAddr_, remoteAddr_;

	private Swarm swarm;
	private Muxer muxer;
	private Lease lease;

	private FiberGroup own; // the inbound loop and the idle timer
	private FiberGroup work; // handler fibers
	private Task idleTimer;
	private uint holds;
	private bool closing;
	private bool closed_;

	package this(Swarm swarm, Muxer muxer, Endpoint role, PeerId remotePeer, PublicKey remoteKey,
		Multiaddr localAddr, Multiaddr remoteAddr, ref Lease lease)
	{
		import std.algorithm.mutation : move;

		this.swarm = swarm;
		this.muxer = muxer;
		this.role = role;
		this.remotePeer_ = remotePeer;
		this.remoteKey_ = remoteKey;
		this.localAddr_ = localAddr;
		this.remoteAddr_ = remoteAddr;
		this.lease = move(lease);
		own = new FiberGroup;
		// A handler's failure is that handler's stream ending, and nothing else.
		work = new FiberGroup((Exception e) nothrow {
			logDebug("libp2p: handler on %s failed: %s", remotePeer_.toString, e.msg);
		}, &maybeArmIdle);
	}

	/// Start serving. Called once by the swarm after the connection is in the pool.
	package void start()
	{
		own.spawn(&inboundLoop);
		maybeArmIdle();
	}

	// --- public surface --------------------------------------------------------------

	PeerId remotePeer() const
	{
		return PeerId(remotePeer_.bytes.dup);
	}

	PublicKey remoteKey() const
	{
		return PublicKey(remoteKey_.type, remoteKey_.data.dup);
	}

	Multiaddr localAddr() const
	{
		return Multiaddr(localAddr_.bytes.dup);
	}

	Multiaddr remoteAddr() const
	{
		return Multiaddr(remoteAddr_.bytes.dup);
	}

	/// Open a stream and negotiate one of `protocols`; `chosen` says which.
	Stream newStream(const(string)[] protocols, out string chosen)
	{
		auto s = muxer.open();
		scope (failure)
			s.reset();
		chosen = negotiateDialer(s, protocols);
		return s;
	}

	Stream newStream(string protocol)
	{
		string chosen;
		return newStream([protocol], chosen);
	}

	Hold hold() nothrow
	{
		holds++;
		if (idleTimer != Task.init && idleTimer.running)
			idleTimer.interrupt();
		return Hold(this);
	}

	bool isClosed() const @safe pure nothrow
	{
		return closed_;
	}

	/// Fibers this connection is running right now.
	size_t liveTasks() const @safe pure nothrow
	{
		return work.length;
	}

	void close() nothrow
	{
		if (closing)
			return;
		closing = true;

		// Ours leave first, whatever they were doing.
		work.stopAll();
		own.stopAll();

		// Then the session, and with it the transport.
		muxer.close();
		lease.release();
		closed_ = true;

		// Only now does anyone hear about it: a notifiee that redials never sees
		// the dying connection.
		swarm.forget(this);
	}

	// --- fibers ------------------------------------------------------------------------

	private void inboundLoop()
	{
		try
		{
			for (;;)
			{
				auto s = muxer.accept();
				work.spawn({ serve(s); });
			}
		}
		catch (Ending)
		{
			// The session ended — peer closed, reset, or a protocol error the
			// muxer already reported. Either way this connection is over.
		}
		catch (Exception e)
		{
			logDebug("libp2p: connection to %s ended: %s", remotePeer_.toString, e.msg);
		}
		close();
	}

	private void serve(Stream s)
	{
		scope (failure)
			s.reset();
		immutable proto = negotiateListener(s, swarm.protocols);
		auto handler = swarm.handlerFor(proto);
		assert(handler !is null, "negotiated a protocol we have no handler for");
		handler(s, this, proto);
	}

	private void maybeArmIdle() nothrow
	{
		immutable timeout = swarm.config.idleTimeout;
		if (closing || timeout <= Duration.zero || holds > 0 || work.length > 0)
			return;
		if (idleTimer != Task.init && idleTimer.running)
			return;
		try
			idleTimer = own.spawn({
				sleep(timeout);
				if (holds == 0 && work.length == 0)
					close();
			});
		catch (Exception)
		{
		}
	}

	private void releaseHold() nothrow
	{
		holds--;
		maybeArmIdle();
	}
}
