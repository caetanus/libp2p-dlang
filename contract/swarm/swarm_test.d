module tests.swarm.swarm_test;

import fluent.asserts;

import core.time : Duration, msecs, seconds, MonoTime;
import std.conv : to;
import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;
import vibe.core.log : logError;

import libp2p.core.peer_id : PeerId;
import libp2p.core.stream : ByteStream;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.swarm.swarm : Swarm;
import libp2p.swarm.behaviour : BaseBehaviour, ConnectionDenied;
import libp2p.swarm.handler : ConnectionHandler, ConnectionCtx;
import libp2p.swarm.dial_opts : DialOpts;
import libp2p.swarm.id : ConnectionId;
import libp2p.swarm.endpoint : Endpoint;
import ev = libp2p.swarm.events;

// Give tasks woken by close() a turn to unwind (see tests/vibe_probe_test.d).
private void drain()
{
	runTask(() nothrow{
		try
			exitEventLoop();
		catch (Exception)
		{
		}
	});
	runEventLoop();
}

// --- a minimal protocol built on the swarm ---------------------------------
//
// "echo": the dialer opens a substream, writes a word, reads it back and reports
// it to its behaviour, which surfaces it to the application. This exercises the
// whole path a real protocol uses — handler requests a substream, connection
// negotiates it, handler reports up, behaviour emits — without any protocol
// logic getting in the way.

enum echoProtocol = "/test/echo/1.0.0";

/// What the handler reports to its behaviour.
final class EchoDone
{
	string got;
	this(string got) @safe pure nothrow
	{
		this.got = got;
	}
}

final class EchoHandler : ConnectionHandler
{
	private bool _initiate;

	this(bool initiate) @safe pure nothrow
	{
		_initiate = initiate;
	}

	override string[] listenProtocols()
	{
		return [echoProtocol];
	}

	/// Responder: read one line, echo it, done.
	override void handleInbound(ConnectionCtx, ByteStream stream, string)
	{
		scope (exit)
			stream.close();
		ubyte[16] buf;
		auto n = stream.readAvailable(buf[]);
		if (n > 0)
			stream.writeBytes(buf[0 .. n]);
	}

	/// Initiator: one exchange, then report it. The whole handler — no state
	/// machine, because the stack IS the state machine.
	override void run(ConnectionCtx ctx)
	{
		if (!_initiate)
			return;
		auto s = ctx.openStream(echoProtocol);
		scope (exit)
			s.close();
		s.writeBytes(cast(const(ubyte)[]) "ping");
		ubyte[16] buf;
		auto n = s.readAvailable(buf[]);
		ctx.notify(new EchoDone(cast(string)(buf[0 .. n]).idup));
	}

	override void onBehaviourEvent(Object)
	{
	}
}

final class EchoBehaviour : BaseBehaviour
{
	/// Set when a peer connected, so the test can assert the swarm told us.
	bool sawConnected;
	bool sawClosed;
	string echoed;

	override ConnectionHandler handleEstablishedInboundConnection(ConnectionId, PeerId,
		Multiaddr, Multiaddr)
	{
		return new EchoHandler(false); // responder
	}

	override ConnectionHandler handleEstablishedOutboundConnection(ConnectionId, PeerId,
		Multiaddr, Endpoint)
	{
		return new EchoHandler(true); // initiator
	}

	override void onSwarmEvent(ev.FromSwarm event)
	{
		if (cast(ev.ConnectionEstablished) event)
			sawConnected = true;
		else if (cast(ev.ConnectionClosed) event)
			sawClosed = true;
	}

	override void onConnectionHandlerEvent(PeerId, ConnectionId, Object event)
	{
		if (auto d = cast(EchoDone) event)
		{
			echoed = d.got;
			swarm.emit(d); // surfacing is a call, not a returned command
		}
	}
}

// A behaviour that refuses every inbound connection, to prove ConnectionDenied
// is honoured (this is the mechanism connection limits are built on).
final class DenyAllBehaviour : BaseBehaviour
{
	override void handlePendingInboundConnection(ConnectionId, Multiaddr, Multiaddr)
	{
		throw new ConnectionDenied("no inbound connections wanted");
	}
}

// ---------------------------------------------------------------------------

@("swarm: two swarms connect and a behaviour protocol completes end to end")
unittest
{
	scope (exit)
		drain();

	auto listener = Swarm.generate(new EchoBehaviour);
	listener.idleConnectionTimeout = 5.seconds;
	scope (exit)
		listener.close();
	listener.listenOn("127.0.0.1", 0);
	immutable port = portOf(listener);

	auto dialerBehaviour = new EchoBehaviour;
	auto dialer = new Swarm(libp2pKeypair(), dialerBehaviour);
	dialer.idleConnectionTimeout = 5.seconds;
	scope (exit)
		dialer.close();

	string echoed;
	bool established;
	runTask(() nothrow{
		try
		{
			dialer.dial("127.0.0.1", port);
			// Drive the swarm the way an application does.
			foreach (_; 0 .. 20)
			{
				auto e = dialer.nextEvent(3.seconds);
				if (e is null)
					break;
				if (cast(ev.ConnectionEstablishedEvent) e)
					established = true;
				if (auto b = cast(ev.BehaviourEvent) e)
					if (auto d = cast(EchoDone) b.event)
					{
						echoed = d.got;
						break;
					}
			}
		}
		catch (Exception e)
			logError("swarm test: %s", e.msg);
		try
			exitEventLoop();
		catch (Exception)
		{
		}
	});
	runEventLoop();

	established.should.equal(true);
	echoed.should.equal("ping"); // the responder echoed it back
	dialerBehaviour.sawConnected.should.equal(true);
}

@("swarm: the listener's behaviour is told a peer connected")
unittest
{
	scope (exit)
		drain();

	auto lb = new EchoBehaviour;
	auto listener = new Swarm(libp2pKeypair(), lb);
	listener.idleConnectionTimeout = 5.seconds;
	scope (exit)
		listener.close();
	listener.listenOn("127.0.0.1", 0);
	immutable port = portOf(listener);

	auto dialer = Swarm.generate(new EchoBehaviour);
	dialer.idleConnectionTimeout = 5.seconds;
	scope (exit)
		dialer.close();

	runTask(() nothrow{
		try
		{
			dialer.dial("127.0.0.1", port);
			foreach (_; 0 .. 20)
			{
				auto e = dialer.nextEvent(3.seconds);
				if (e is null || cast(ev.BehaviourEvent) e)
					break;
			}
			// let the listener side finish its bookkeeping
			sleep(100.msecs);
		}
		catch (Exception e)
			logError("swarm test: %s", e.msg);
		try
			exitEventLoop();
		catch (Exception)
		{
		}
	});
	runEventLoop();

	lb.sawConnected.should.equal(true);
	listener.connectedPeers().length.should.equal(1);
	listener.isConnected(dialer.localPeer).should.equal(true);
}

// ConnectionDenied from handlePendingInboundConnection must actually stop the
// connection — it is what connection limits and allow/deny lists rely on.
@("swarm: a behaviour can deny an inbound connection")
unittest
{
	scope (exit)
		drain();

	auto listener = Swarm.generate(new DenyAllBehaviour);
	scope (exit)
		listener.close();
	listener.listenOn("127.0.0.1", 0);
	immutable port = portOf(listener);

	auto dialer = Swarm.generate(new EchoBehaviour);
	dialer.idleConnectionTimeout = 5.seconds;
	scope (exit)
		dialer.close();

	runTask(() nothrow{
		try
		{
			dialer.dial("127.0.0.1", port);
			foreach (_; 0 .. 10)
			{
				auto e = dialer.nextEvent(3.seconds);
				if (e is null)
					break;
				if (cast(ev.ConnectionEstablishedEvent) e)
					break;
			}
			sleep(150.msecs);
		}
		catch (Exception e)
			logError("swarm deny test: %s", e.msg);
		try
			exitEventLoop();
		catch (Exception)
		{
		}
	});
	runEventLoop();

	// The listener never keeps a denied connection.
	listener.connectedPeers().length.should.equal(0);
}

// --- helpers ---------------------------------------------------------------

private ushort portOf(Swarm s)
{
	auto addrs = s.listenAddresses();
	assert(addrs.length > 0, "swarm is not listening");
	foreach (c; addrs[0].components)
		if (c.code == 6 && c.value.length == 2) // tcp
			return cast(ushort)((c.value[0] << 8) | c.value[1]);
	assert(false, "no tcp port in listen address");
}

private auto libp2pKeypair()
{
	import libp2p.crypto.keys : Keypair;

	return Keypair.generateEd25519;
}

// The pool is the swarm's authority on who it is connected to, and a connection
// used to be able to die without telling it. Closing locally left a ghost: still
// counted, still answering `isConnected`, still blocking the redial the peer was
// owed — while the socket was long gone.
//
// The round-2 relay test that closed a connection only ever asserted what the
// *remote* end noticed. That is the half that always worked.
@("swarm: closing a connection empties the pool and reports it")
unittest
{
	scope (exit)
		drain();

	auto listener = Swarm.generate(new EchoBehaviour);
	listener.idleConnectionTimeout = 30.seconds;
	scope (exit)
		listener.close();
	listener.listenOn("127.0.0.1", 0);
	immutable port = portOf(listener);

	auto db = new EchoBehaviour;
	auto dialer = new Swarm(libp2pKeypair(), db);
	dialer.idleConnectionTimeout = 30.seconds;
	scope (exit)
		dialer.close();

	bool connectedBefore, connectedAfter = true, reported, redialled;
	size_t peersBefore, peersAfter = size_t.max;
	runTask(() nothrow{
		try
		{
			auto peer = dialer.dialAndWait(
				DialOpts.address(Multiaddr.parse(
					"/ip4/127.0.0.1/tcp/" ~ (cast(uint) port).to!string)));
			connectedBefore = dialer.isConnected(peer);
			peersBefore = dialer.connectedPeers().length;

			dialer.closeConnections(peer);

			// The swarm must say so, not just fall silent.
			foreach (_; 0 .. 20)
			{
				auto e = dialer.nextEvent(2.seconds);
				if (e is null)
					break;
				if (cast(ev.ConnectionClosedEvent) e)
				{
					reported = true;
					break;
				}
			}

			connectedAfter = dialer.isConnected(peer);
			peersAfter = dialer.connectedPeers().length;

			// And the peer is dialable again. Under the old behaviour the pool
			// still held the connection, so `disconnectedAndNotDialing` — the
			// default — refused this.
			cast(void) dialer.dialAndWait(DialOpts.peer(peer)
					.withAddresses([
						Multiaddr.parse("/ip4/127.0.0.1/tcp/" ~ (cast(uint) port).to!string)
					]));
			redialled = true;
		}
		catch (Exception e)
			logError("swarm close test: %s", e.msg);
		try
			exitEventLoop();
		catch (Exception)
		{
		}
	});
	runEventLoop();

	connectedBefore.should.equal(true);
	peersBefore.should.equal(1);
	reported.should.equal(true); // ConnectionClosedEvent reached the application
	connectedAfter.should.equal(false); // the pool forgot it
	peersAfter.should.equal(0);
	redialled.should.equal(true); // and policy allows the redial
}

// A connection used to keep a Task reference for every inbound substream and
// every behaviour event it had ever handled, cleared only by `close()`. The
// teardown gate cannot see that: it measures the end of a process, and this is a
// leak that only exists in the middle of one.
//
// So the assertion is about a connection that is *busy and still open*: many
// substreams served, and the fiber count back where it started.
@("swarm: a busy connection does not accumulate fibers")
unittest
{
	scope (exit)
		drain();

	auto listener = Swarm.generate(new EchoBehaviour);
	listener.idleConnectionTimeout = 30.seconds;
	scope (exit)
		listener.close();
	listener.listenOn("127.0.0.1", 0);
	immutable port = portOf(listener);

	auto dialer = new Swarm(libp2pKeypair(), new EchoBehaviour);
	dialer.idleConnectionTimeout = 30.seconds;
	scope (exit)
		dialer.close();

	size_t idle, afterChurn = size_t.max;
	runTask(() nothrow{
		try
		{
			auto peer = dialer.dialAndWait(
				DialOpts.address(Multiaddr.parse(
					"/ip4/127.0.0.1/tcp/" ~ (cast(uint) port).to!string)));

			// The fibers that accumulate are the ones serving *inbound*
			// substreams, so the side to measure is the listener. Measuring the
			// dialer would have passed under the old registry too, which is the
			// kind of test that proves only that it was written after the fix.
			sleep(200.msecs);
			auto us = dialer.localPeer;
			idle = listener.liveTasksTo(us);

			// 200 substreams, opened and closed, on the one connection.
			foreach (_; 0 .. 200)
			{
				auto s = dialer.openStream(peer, [echoProtocol]);
				s.writeBytes(cast(ubyte[]) "x".dup);
				ubyte[4] buf;
				cast(void) s.readAvailable(buf[]);
				s.close();
			}

			// Wait for the served fibers to finish rather than for a duration.
			immutable deadline = MonoTime.currTime + 5.seconds;
			while (MonoTime.currTime < deadline && listener.liveTasksTo(us) > idle)
				sleep(10.msecs);
			afterChurn = listener.liveTasksTo(us);
		}
		catch (Exception e)
			logError("swarm soak test: %s", e.msg);
		try
			exitEventLoop();
		catch (Exception)
		{
		}
	});
	runEventLoop();

	// Still connected, and holding no more than when it was idle. Under the old
	// registry this would be several hundred.
	(afterChurn <= idle).should.equal(true);
}

// What the delivery change actually guarantees is ORDER, and the first version
// of this test got that wrong: it counted reentrancy depth, which stayed at one
// even with a fiber per event, because a callback that never yields cannot
// interleave on a cooperative loop. The contract is what prevents reentrancy;
// the fiber per event was breaking something else.
//
// A fiber per handler event means each is scheduled independently, so the
// behaviour sees them in whatever order the scheduler picks. A protocol that
// reports a sequence — and most do — is then reading it shuffled.
final class OrderWatcher : BaseBehaviour
{
	int[] got;

	override ConnectionHandler handleEstablishedInboundConnection(ConnectionId, PeerId,
		Multiaddr, Multiaddr)
	{
		return new CounterHandler;
	}

	override ConnectionHandler handleEstablishedOutboundConnection(ConnectionId, PeerId,
		Multiaddr, Endpoint)
	{
		return new CounterHandler;
	}

	override void onConnectionHandlerEvent(PeerId, ConnectionId, Object event)
	{
		if (auto t = cast(Ticket) event)
			got ~= t.n;
	}
}

final class Ticket
{
	int n;
	this(int n) @safe pure nothrow
	{
		this.n = n;
	}
}

/// Reports a strictly increasing sequence, as fast as it can.
final class CounterHandler : ConnectionHandler
{
	override string[] listenProtocols()
	{
		return [];
	}

	override void handleInbound(ConnectionCtx, ByteStream stream, string)
	{
		stream.close();
	}

	override void run(ConnectionCtx ctx)
	{
		foreach (i; 0 .. 100)
			ctx.notify(new Ticket(i));
	}

	override void onBehaviourEvent(Object)
	{
	}
}

@("swarm: a behaviour sees handler events in the order they were reported")
unittest
{
	scope (exit)
		drain();

	auto lb = new OrderWatcher;
	auto listener = new Swarm(libp2pKeypair(), lb);
	listener.idleConnectionTimeout = 30.seconds;
	scope (exit)
		listener.close();
	listener.listenOn("127.0.0.1", 0);
	immutable port = portOf(listener);

	auto db = new OrderWatcher;
	auto dialer = new Swarm(libp2pKeypair(), db);
	dialer.idleConnectionTimeout = 30.seconds;
	scope (exit)
		dialer.close();

	runTask(() nothrow{
		try
		{
			cast(void) dialer.dialAndWait(
				DialOpts.address(Multiaddr.parse(
					"/ip4/127.0.0.1/tcp/" ~ (cast(uint) port).to!string)));
			sleep(300.msecs);
		}
		catch (Exception e)
			logError("swarm ordering test: %s", e.msg);
		try
			exitEventLoop();
		catch (Exception)
		{
		}
	});
	runEventLoop();

	db.got.length.should.equal(100); // it was actually exercised
	foreach (i, n; db.got)
		n.should.equal(cast(int) i); // and in the order it was reported
}

// --- the idle timer ---------------------------------------------------------
//
// A scheduled shutdown used to be a `Shutdown` enum beside a `_shutdownGen`
// counter: the armed timer could not be stopped, so it was left running and
// taught to notice on waking that the generation it had captured was stale. Two
// fields and a comparison standing in for a cancellation the runtime already had,
// and the failure mode of that shape is a timer that fires on a connection
// somebody is using.
//
// The timer is a fiber now, and a claim interrupts it. This asserts both halves:
// the claim really does disarm it (the connection outlives its idle timeout by a
// wide margin), and releasing the claim really does arm a fresh one (it then dies
// on its own, with nobody closing it).
//
// LIMIT OF THIS TEST, stated rather than implied: it pins the *behaviour*, which
// had no coverage at all, and it would have passed against the generation counter
// too — that version reached the same outcome by waking a stale timer and having
// it notice. What it does not measure is the reason for the change: the old timer
// could not be stopped, so every claim/release cycle left another fiber sleeping
// out its full timeout, holding this connection reachable. On a busy long-lived
// peer those accumulate, and a gate that measures the end of a process cannot see
// them. Catching that needs a soak, not a unit test.

/// Holds the connection for `_grip`, then lets go. That is the entire protocol.
final class GripHandler : ConnectionHandler
{
	private Duration _grip;

	this(Duration grip) @safe pure nothrow
	{
		_grip = grip;
	}

	override string[] listenProtocols()
	{
		return [];
	}

	override void handleInbound(ConnectionCtx, ByteStream, string)
	{
	}

	override void run(ConnectionCtx ctx)
	{
		auto h = ctx.hold();
		scope (exit)
			h.release(); // and this is what arms the next timer
		sleep(_grip);
	}

	override void onBehaviourEvent(Object)
	{
	}
}

final class GripBehaviour : BaseBehaviour
{
	private Duration _grip;

	this(Duration grip) @safe pure nothrow
	{
		_grip = grip;
	}

	override ConnectionHandler handleEstablishedInboundConnection(ConnectionId, PeerId,
		Multiaddr, Multiaddr)
	{
		return new GripHandler(_grip);
	}

	override ConnectionHandler handleEstablishedOutboundConnection(ConnectionId, PeerId,
		Multiaddr, Endpoint)
	{
		return new GripHandler(_grip);
	}
}

@("swarm: a hold disarms the idle timer, and releasing it arms a fresh one")
unittest
{
	scope (exit)
		drain();

	auto listener = Swarm.generate(new EchoBehaviour);
	listener.idleConnectionTimeout = 5.seconds;
	scope (exit)
		listener.close();
	listener.listenOn("127.0.0.1", 0);
	immutable port = portOf(listener);

	auto dialer = Swarm.generate(new GripBehaviour(500.msecs));
	scope (exit)
		dialer.close();
	// Far shorter than the grip, so an armed timer that survived the claim would
	// fire well before the handler is finished.
	dialer.idleConnectionTimeout = 100.msecs;

	bool heldOpen, closedItself;
	runTask(() nothrow{
		try
		{
			dialer.dial("127.0.0.1", port);
			sleep(300.msecs); // three idle timeouts, and still claimed
			heldOpen = dialer.connectedPeers().length == 1;

			// Nobody closes it here. The handler lets go, the timer is armed
			// afresh, and it expires.
			foreach (_; 0 .. 60)
			{
				if (dialer.connectedPeers().length == 0)
				{
					closedItself = true;
					break;
				}
				sleep(50.msecs);
			}
		}
		catch (Exception e)
			logError("idle timer test: %s", e.msg);
		try
			exitEventLoop();
		catch (Exception)
		{
		}
	});
	runEventLoop();

	heldOpen.should.equal(true); // the claim disarmed it
	closedItself.should.equal(true); // and releasing armed a fresh one
}
