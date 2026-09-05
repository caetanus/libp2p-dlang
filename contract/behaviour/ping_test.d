module tests.behaviour.ping_test;

import fluent.asserts;

import core.time : msecs, seconds;
import vibe.core.core : runTask, runEventLoop, exitEventLoop;
import vibe.core.log : logError;

import libp2p.swarm.swarm : Swarm;
import libp2p.swarm.composite : CompositeBehaviour;
import libp2p.behaviour.ping : PingBehaviour, PingHandler, PingConfig, PingEvent;
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

/// Drive `dialer` until it reports a ping, or give up.
private PingEvent awaitPing(Swarm dialer)
{
	PingEvent got;
	runTask(() nothrow{
		try
		{
			foreach (_; 0 .. 10)
			{
				auto e = dialer.nextEvent(5.seconds);
				if (e is null)
					break;
				if (auto b = cast(ev.BehaviourEvent) e)
					if (auto p = cast(PingEvent) b.event)
					{
						got = p;
						break;
					}
			}
		}
		catch (Exception e)
			logError("ping behaviour test: %s", e.msg);
		try
			exitEventLoop();
		catch (Exception)
		{
		}
	});
	runEventLoop();
	return got;
}

// The point of stage 3: a protocol that was a hand-rolled loop now runs as a
// behaviour, with the swarm owning the connection and the substream.
@("ping behaviour: a swarm pings its peer and reports the round-trip time")
unittest
{
	scope (exit)
		drain();

	auto listener = Swarm.generate(new PingBehaviour);
	listener.idleConnectionTimeout = 5.seconds;
	scope (exit)
		listener.close();
	listener.listenOn("127.0.0.1", 0);
	immutable port = portOf(listener);

	auto dialer = Swarm.generate(new PingBehaviour);
	dialer.idleConnectionTimeout = 5.seconds;
	scope (exit)
		dialer.close();

	dialer.dial("127.0.0.1", port);
	auto got = awaitPing(dialer);

	got.should.not.beNull;
	got.ok.should.equal(true);
	got.peer.should.equal(listener.localPeer);
	// The RTT is a real measurement of a loopback round trip: small, but taken.
	(got.rtt < 5.seconds).should.equal(true);
}

// Ping must never be the reason a connection stays open: it runs on every
// connection, so if it kept them alive a node would never close one. There is no
// keepAlive() to ask any more — a connection is kept by a HOLD, and ping takes
// one only for the exchange itself. So the observable property is the right
// thing to assert: a connection carrying nothing but ping goes idle and closes.
@("ping behaviour: a ping-only connection still goes idle and closes")
unittest
{
	scope (exit)
		drain();

	auto listener = Swarm.generate(new PingBehaviour);
	listener.idleConnectionTimeout = 300.msecs;
	scope (exit)
		listener.close();
	listener.listenOn("127.0.0.1", 0);
	immutable port = portOf(listener);

	auto dialer = Swarm.generate(new PingBehaviour(PingConfig(30.seconds, true)));
	dialer.idleConnectionTimeout = 300.msecs;
	scope (exit)
		dialer.close();

	bool established, closed;
	runTask(() nothrow{
		try
		{
			dialer.dial("127.0.0.1", port);
			foreach (_; 0 .. 20)
			{
				auto e = dialer.nextEvent(5.seconds);
				if (e is null)
					break;
				if (cast(ev.ConnectionEstablishedEvent) e)
					established = true;
				if (cast(ev.ConnectionClosedEvent) e)
				{
					closed = true;
					break;
				}
			}
		}
		catch (Exception e)
			logError("ping idle test: %s", e.msg);
		try
			exitEventLoop();
		catch (Exception)
		{
		}
	});
	runEventLoop();

	established.should.equal(true);
	closed.should.equal(true); // ping did not hold it open
}

// It composes — which is the whole reason the swarm exists.
@("ping behaviour: composes with the composite behaviour")
unittest
{
	scope (exit)
		drain();

	auto listener = Swarm.generate(new CompositeBehaviour(new PingBehaviour));
	listener.idleConnectionTimeout = 5.seconds;
	scope (exit)
		listener.close();
	listener.listenOn("127.0.0.1", 0);
	immutable port = portOf(listener);

	auto dialer = Swarm.generate(new CompositeBehaviour(new PingBehaviour));
	dialer.idleConnectionTimeout = 5.seconds;
	scope (exit)
		dialer.close();

	dialer.dial("127.0.0.1", port);
	auto got = awaitPing(dialer);

	got.should.not.beNull;
	got.ok.should.equal(true);
}

// --- discovery feeding the swarm ---------------------------------------------

// mDNS finds a peer, and the swarm dials the address it was handed. This moved
// off `Host` — where discovery held a host purely to offer `connect(peer)` — and
// it reads better for it: discovery reports an address, dialing is the caller's,
// and the swarm already knows how to dial a `Multiaddr`.
@("mdns discovery: a peer found over multicast is dialable by the swarm")
unittest
{
	import core.time : msecs, seconds;
	import std.conv : to;
	import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;
	import vibe.core.log : logError;
	import libp2p.crypto.keys : Keypair;
	import libp2p.host : Host;
	import libp2p.multiformats.multiaddr : Multiaddr;
	import libp2p.swarm.swarm : Swarm;
	import libp2p.swarm.dial_opts : DialOpts;
	import libp2p.discovery.mdns_discovery : MdnsDiscovery;

	scope (exit)
		drain();

	static Multiaddr loopback(ushort p)
	{
		return Multiaddr.parse("/ip4/127.0.0.1/tcp/" ~ (cast(uint) p).to!string);
	}

	auto b = new Swarm(new Host(Keypair.generateEd25519), new PingBehaviour);
	scope (exit)
		b.close();
	b.listenOn("127.0.0.1", 0);
	auto bAddr = loopback(portOf(b));
	auto discB = new MdnsDiscovery(b.localPeer, [bAddr]);
	scope (exit)
		discB.close();

	auto a = new Swarm(new Host(Keypair.generateEd25519), new PingBehaviour);
	scope (exit)
		a.close();
	a.listenOn("127.0.0.1", 0);
	auto discA = new MdnsDiscovery(a.localPeer, [loopback(portOf(a))]);
	scope (exit)
		discA.close();

	discB.start();
	discA.start();

	bool discovered, connected;
	runTask(() nothrow{
		try
		{
			foreach (_; 0 .. 150) // ~3s cap on multicast
			{
				if (discA.addressesOf(b.localPeer).length)
					break;
				sleep(20.msecs);
			}
			auto found = discA.addressesOf(b.localPeer);
			discovered = found.length > 0;
			if (discovered)
			{
				// The address discovery handed over, dialed as-is.
				a.dialAndWait(DialOpts.address(found[0]));
				connected = a.isConnected(b.localPeer);
			}
		}
		catch (Exception e)
			logError("mdns swarm dial: %s", e.msg);
		try
			exitEventLoop();
		catch (Exception)
		{
		}
	});
	runEventLoop();

	discovered.should.equal(true);
	connected.should.equal(true);
}
