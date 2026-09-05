module tests.behaviour.gossipsub_test;

import fluent.asserts;

import core.time : msecs, seconds, Duration, MonoTime;
import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;
import vibe.core.log : logError;

import std.conv : to;

import libp2p.crypto.keys : Keypair;
import libp2p.host : Host;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.swarm.swarm : Swarm;
import libp2p.behaviour.gossipsub : GossipsubBehaviour, GossipMessage, GossipPeerGone;
import ev = libp2p.swarm.events;

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

private ushort portOf(Swarm s)
{
	foreach (c; s.listenAddresses()[0].components)
		if (c.code == 6 && c.value.length == 2)
			return cast(ushort)((c.value[0] << 8) | c.value[1]);
	assert(false, "no tcp port");
}

private struct Node
{
	Swarm swarm;
	GossipsubBehaviour gs;
}

private Node makeNode()
{
	auto key = Keypair.generateEd25519;
	auto gs = new GossipsubBehaviour(key);
	auto s = new Swarm(new Host(key), gs);
	s.idleConnectionTimeout = 30.seconds; // pubsub peers are long-lived
	return Node(s, gs);
}

/// Block until `cond` holds, or give up. Tests wait for the thing they need,
/// never for a duration: a fixed sleep turns "slower than I guessed" into
/// "broken", and that mistake cost this file a full debugging session.
private bool waitUntil(bool delegate() cond, Duration limit = 10.seconds)
{
	immutable deadline = MonoTime.currTime + limit;
	while (MonoTime.currTime < deadline)
	{
		if (cond())
			return true;
		sleep(5.msecs);
	}
	return false;
}

/// Drain a swarm's events into `got` until `stop` or the deadline.
private void collect(Swarm s, ref string[] got, size_t rounds)
{
	foreach (_; 0 .. rounds)
	{
		auto e = s.nextEvent(2.seconds);
		if (e is null)
			return;
		if (auto b = cast(ev.BehaviourEvent) e)
			if (auto m = cast(GossipMessage) b.event)
				got ~= cast(string) m.data.idup;
	}
}

// A publishes, B receives — the whole pubsub path over the swarm: connection,
// meshsub stream, subscription exchange, mesh grafting, message delivery.
@("gossipsub behaviour: a published message reaches a subscribed peer")
unittest
{
	scope (exit)
		drain();

	enum topic = "news";

	auto b = makeNode();
	scope (exit)
		b.swarm.close();
	b.swarm.listenOn("127.0.0.1", 0);
	immutable port = portOf(b.swarm);
	b.gs.subscribe(topic);

	auto a = makeNode();
	scope (exit)
		a.swarm.close();
	a.gs.subscribe(topic);

	string[] received;
	runTask(() nothrow{
		try
		{
			a.swarm.dial("127.0.0.1", port);
			// Wait for the mesh to actually form. Sleeping a guessed duration and
			// asserting is how a slow path reads as a broken one — which is
			// exactly what happened here.
			waitUntil(() => a.gs.node.state(topic)[1] > 0 && b.gs.node.state(topic)[1] > 0);
			a.gs.publish(topic, cast(const(ubyte)[]) "breaking news");
			collect(b.swarm, received, 10);
		}
		catch (Exception e)
			logError("gossipsub behaviour test: %s", e.msg);
		try
			exitEventLoop();
		catch (Exception)
		{
		}
	});
	runEventLoop();

	received.length.should.be.greaterThan(0);
	received[0].should.equal("breaking news");
}

// Only one side opens the meshsub stream, or the router would see the same peer
// twice and count it twice in the mesh.
@("gossipsub behaviour: a connection yields exactly one meshsub peer per side")
unittest
{
	scope (exit)
		drain();

	enum topic = "news";

	auto b = makeNode();
	scope (exit)
		b.swarm.close();
	b.swarm.listenOn("127.0.0.1", 0);
	immutable port = portOf(b.swarm);
	b.gs.subscribe(topic);

	auto a = makeNode();
	scope (exit)
		a.swarm.close();
	a.gs.subscribe(topic);

	size_t[2] aState, bState;
	runTask(() nothrow{
		try
		{
			a.swarm.dial("127.0.0.1", port);
			waitUntil(() => a.gs.node.state(topic)[0] > 0);
			waitUntil(() => b.gs.node.state(topic)[0] > 0);
			aState = a.gs.node.state(topic);
			bState = b.gs.node.state(topic);
		}
		catch (Exception e)
			logError("gossipsub peer-count test: %s", e.msg);
		try
			exitEventLoop();
		catch (Exception)
		{
		}
	});
	runEventLoop();

	// state() is [peers-in-topic, mesh-size]; each side knows exactly one peer.
	aState[0].should.equal(1);
	bState[0].should.equal(1);
}

// Three nodes in a line: A—B—C. A publishes; C must receive it through B, which
// is what makes this gossip rather than direct delivery.
@("gossipsub behaviour: a message propagates A -> B -> C")
unittest
{
	scope (exit)
		drain();

	enum topic = "news";

	auto hub = makeNode();
	scope (exit)
		hub.swarm.close();
	hub.swarm.listenOn("127.0.0.1", 0);
	immutable port = portOf(hub.swarm);
	hub.gs.subscribe(topic);

	auto a = makeNode();
	scope (exit)
		a.swarm.close();
	a.gs.subscribe(topic);

	auto c = makeNode();
	scope (exit)
		c.swarm.close();
	c.gs.subscribe(topic);

	string[] cGot;
	runTask(() nothrow{
		try
		{
			a.swarm.dial("127.0.0.1", port);
			c.swarm.dial("127.0.0.1", port);
			waitUntil(() => a.gs.node.state(topic)[1] > 0 && c.gs.node.state(topic)[1] > 0
					&& hub.gs.node.state(topic)[1] > 1);
			a.gs.publish(topic, cast(const(ubyte)[]) "through the hub");
			collect(c.swarm, cGot, 10);
		}
		catch (Exception e)
			logError("gossipsub propagation test: %s", e.msg);
		try
			exitEventLoop();
		catch (Exception)
		{
		}
	});
	runEventLoop();

	cGot.length.should.be.greaterThan(0);
	cGot[0].should.equal("through the hub");
}

// One peer per THREAD, each with its own event loop.
//
// The tests above put both peers on one loop, which is the harder case and the
// one that fails. This isolates whether the failure is inherent to the wiring or
// an artifact of sharing a loop: if two peers work when they cannot interleave
// on the same scheduler, the bug is a race between the two sides' fibers, not in
// the protocol path.
@("gossipsub behaviour: two peers, one thread each")
unittest
{
	import core.thread : Thread;
	import core.atomic : atomicStore, atomicLoad;

	enum topic = "news";
	shared ushort listenPort;
	shared bool listenerReady, listenerGot, stopListener;

	auto listenerThread = new Thread({
		auto key = Keypair.generateEd25519;
		auto gs = new GossipsubBehaviour(key);
		auto s = new Swarm(new Host(key), gs);
		s.idleConnectionTimeout = 30.seconds;
		s.listenOn("127.0.0.1", 0);
		gs.subscribe(topic);
		atomicStore(listenPort, portOf(s));
		atomicStore(listenerReady, true);

		runTask(() nothrow{
			try
			{
				foreach (_; 0 .. 100)
				{
					auto e = s.nextEvent(100.msecs);
					if (auto b = cast(ev.BehaviourEvent) e)
						if (cast(GossipMessage) b.event)
						{
							atomicStore(listenerGot, true);
							break;
						}
					if (atomicLoad(stopListener))
						break;
				}
			}
			catch (Exception)
			{
			}
			try
				exitEventLoop();
			catch (Exception)
			{
			}
		});
		runEventLoop();
		s.close();
	});
	listenerThread.start();

	auto a = makeNode();
	scope (exit)
		a.swarm.close();
	a.gs.subscribe(topic);

	runTask(() nothrow{
		try
		{
			// Wait for the other thread to bind. A vibe sleep, so this yields.
			foreach (_; 0 .. 100)
			{
				if (atomicLoad(listenerReady))
					break;
				sleep(20.msecs);
			}
			a.swarm.dial("127.0.0.1", atomicLoad(listenPort));
			sleep(600.msecs); // let the meshsub stream and subscriptions settle
			a.gs.publish(topic, cast(const(ubyte)[]) "cross-thread");
			sleep(600.msecs);
			atomicStore(stopListener, true);
		}
		catch (Exception e)
			logError("gossipsub cross-thread test: %s", e.msg);
		try
			exitEventLoop();
		catch (Exception)
		{
		}
	});
	runEventLoop();
	listenerThread.join();

	atomicLoad(listenerGot).should.equal(true);
}

// The handler holds the connection open because the router owns the meshsub
// stream and would otherwise be closed out from under it. But a hold that is
// never released is not "held for the life of the peer" — it is held forever.
// When the stream died the router dropped the peer, the protocol did not reopen,
// and the connection stayed up with the hold in place: idle timeout disarmed,
// nothing on the wire, and no event to say the protocol was dead on it.
//
// LIMIT OF THIS TEST, stated rather than implied: it asserts the *report*, not
// the release. Here the peer goes away, so the connection dies with it whether
// or not the hold was dropped — reintroducing the leak deliberately does not
// make this fail. What it does prove is the path that carries the release: the
// router's read loop ending runs the callback that both releases and reports,
// so a report arriving means the release ran. Asserting the release on its own
// needs a peer that stays up while only its meshsub stream dies, which this
// harness cannot arrange from outside.
@("gossipsub behaviour: losing the meshsub stream releases the connection")
unittest
{
	scope (exit)
		drain();

	enum topic = "news";

	auto b = makeNode();
	scope (exit)
		b.swarm.close();
	b.swarm.listenOn("127.0.0.1", 0);
	immutable port = portOf(b.swarm);
	b.gs.subscribe(topic);

	auto a = makeNode();
	scope (exit)
		a.swarm.close();
	a.gs.subscribe(topic);
	// Short enough that an unreleased hold is the only thing that could keep the
	// connection alive past the stream's death.
	a.swarm.idleConnectionTimeout = 300.msecs;

	bool meshed, reported, closed;
	runTask(() nothrow{
		try
		{
			a.swarm.dial("127.0.0.1", port);
			meshed = waitUntil(() => a.gs.node.state(topic)[0] > 0);

			// Kill the peer's side, which ends the router's read loop on ours.
			b.swarm.close();

			foreach (_; 0 .. 40)
			{
				auto e = a.swarm.nextEvent(1.seconds);
				if (e is null)
					break;
				if (auto be = cast(ev.BehaviourEvent) e)
					if (cast(GossipPeerGone) be.event)
						reported = true;
				if (cast(ev.ConnectionClosedEvent) e)
					closed = true;
				if (reported && closed)
					break;
			}
		}
		catch (Exception e)
			logError("gossipsub hold test: %s", e.msg);
		try
			exitEventLoop();
		catch (Exception)
		{
		}
	});
	runEventLoop();

	meshed.should.equal(true);
	reported.should.equal(true); // somebody was told gossip stopped flowing
	closed.should.equal(true); // and the connection was allowed to go
}
