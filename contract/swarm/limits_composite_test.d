module tests.swarm.limits_composite_test;

import fluent.asserts;

import libp2p.core.stream : ByteStream;

import std.algorithm : canFind;
import std.conv : to;
import core.time : msecs, seconds;
import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;
import vibe.core.log : logError;

import libp2p.core.peer_id : PeerId;
import libp2p.crypto.keys : Keypair;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.swarm.swarm : Swarm;
import libp2p.swarm.behaviour : BaseBehaviour, NetworkBehaviour, SwarmCtx, ConnectionDenied;
import libp2p.swarm.dial_opts : DialOpts;
import libp2p.swarm.id : ListenerId;
import libp2p.swarm.handler : ConnectionHandler, ConnectionCtx, Hold;
import libp2p.swarm.limits : ConnectionLimits, Limits, LimitKind, LimitExceeded;
import libp2p.swarm.composite : CompositeBehaviour, CompositeHandler, Toggle, Tagged;
import libp2p.swarm.handler : DummyHandler;
import libp2p.swarm.id : ConnectionId;
import libp2p.swarm.endpoint : Endpoint, ConnectedPoint;
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

// --- limits ----------------------------------------------------------------

@("limits: an unset limit is unlimited, a set one admits exactly N")
unittest
{
	Limits l;
	// Nothing configured: everything passes, however many are already there.
	l.admits(LimitKind.establishedTotal, 1_000_000).should.equal(true);

	l.with_(LimitKind.establishedTotal, 2);
	l.admits(LimitKind.establishedTotal, 0).should.equal(true);
	l.admits(LimitKind.establishedTotal, 1).should.equal(true);
	// The check runs BEFORE counting, so a limit of 2 stops the third.
	l.admits(LimitKind.establishedTotal, 2).should.equal(false);
	l.admits(LimitKind.establishedTotal, 3).should.equal(false);
}

@("limits: counting follows established/closed, not the pending hooks")
unittest
{
	Limits l;
	l.with_(LimitKind.establishedTotal, 1);
	auto lim = new ConnectionLimits(l);

	auto peer = PeerId.fromPublicKey(Keypair.generateEd25519.publicKey);
	auto addr = Multiaddr.parse("/ip4/127.0.0.1/tcp/1");
	auto point = ConnectedPoint.listener(addr, addr);
	auto id = ConnectionId.unchecked(7);

	// A pending inbound connection is not yet a connection.
	lim.handlePendingInboundConnection(id, addr, addr);
	lim.establishedTotal.should.equal(0);

	// Establishing is what counts.
	lim.onSwarmEvent(new ev.ConnectionEstablished(peer, id, point, 1));
	lim.establishedTotal.should.equal(1);
	lim.establishedIncoming.should.equal(1);
	lim.establishedTo(peer).should.equal(1);

	// Now at the limit: the next established inbound must be refused.
	auto id2 = ConnectionId.unchecked(8);
	bool denied;
	try
		lim.handleEstablishedInboundConnection(id2, peer, addr, addr);
	catch (LimitExceeded e)
	{
		denied = true;
		e.kind.should.equal(LimitKind.establishedTotal);
	}
	denied.should.equal(true);

	// Closing frees the slot again.
	lim.onSwarmEvent(new ev.ConnectionClosed(peer, id, point, 0));
	lim.establishedTotal.should.equal(0);
	lim.establishedTo(peer).should.equal(0);
	lim.handleEstablishedInboundConnection(id2, peer, addr, addr); // no throw
}

@("limits: a failed dial releases its pending slot")
unittest
{
	Limits l;
	l.with_(LimitKind.pendingOutgoing, 1);
	auto lim = new ConnectionLimits(l);

	auto peer = PeerId.fromPublicKey(Keypair.generateEd25519.publicKey);
	auto id = ConnectionId.unchecked(1);
	lim.handlePendingOutboundConnection(id, true, peer, null, Endpoint.dialer);

	// At the limit while it is in flight.
	bool denied;
	try
		lim.handlePendingOutboundConnection(ConnectionId.unchecked(2), true, peer, null,
			Endpoint.dialer);
	catch (LimitExceeded)
		denied = true;
	denied.should.equal(true);

	// The dial fails: the slot must come back, or the node wedges after N
	// failures.
	lim.onSwarmEvent(new ev.DialFailure(peer, id, "nope"));
	lim.handlePendingOutboundConnection(ConnectionId.unchecked(3), true, peer, null,
		Endpoint.dialer); // no throw
}

// End to end: a listener that only allows one inbound connection.
@("limits: the swarm honours an inbound connection limit")
unittest
{
	scope (exit)
		drain();

	Limits l;
	l.with_(LimitKind.establishedIncoming, 1);
	// Limits deny; KeepAlive keeps what got in — composed, which is exactly how a
	// real node stacks a policy behaviour with a protocol one.
	auto listener = Swarm.generate(
		new CompositeBehaviour(new ConnectionLimits(l), new KeepAliveBehaviour));
	scope (exit)
		listener.close();
	listener.listenOn("127.0.0.1", 0);
	immutable port = portOf(listener);

	auto a = Swarm.generate(new KeepAliveBehaviour);
	scope (exit)
		a.close();
	auto b = Swarm.generate(new KeepAliveBehaviour);
	scope (exit)
		b.close();

	runTask(() nothrow{
		try
		{
			a.dial("127.0.0.1", port);
			sleep(200.msecs);
			b.dial("127.0.0.1", port);
			sleep(300.msecs);
		}
		catch (Exception e)
			logError("limits e2e: %s", e.msg);
		try
			exitEventLoop();
		catch (Exception)
		{
		}
	});
	runEventLoop();

	// Exactly one of the two got in.
	listener.connectedPeers().length.should.equal(1);
}

// --- composition -----------------------------------------------------------

/// A behaviour whose handler asks to keep the connection, so a test can observe
/// an established connection at all: with the default zero idle timeout and a
/// handler that does not want the connection, it is closed immediately — which
/// is the correct behaviour, just not a useful one to assert against.
private final class KeepAliveBehaviour : BaseBehaviour
{
	override ConnectionHandler handleEstablishedInboundConnection(ConnectionId, PeerId,
		Multiaddr, Multiaddr)
	{
		return new StickyHandler;
	}

	override ConnectionHandler handleEstablishedOutboundConnection(ConnectionId, PeerId,
		Multiaddr, Endpoint)
	{
		return new StickyHandler;
	}
}

private final class StickyHandler : ConnectionHandler
{
	override string[] listenProtocols()
	{
		return null;
	}

	override void handleInbound(ConnectionCtx, ByteStream stream, string)
	{
		stream.close();
	}

	/// Claim the connection and never let go. Keeping a connection alive is a
	/// hold, not an answer to a question asked later.
	override void run(ConnectionCtx ctx)
	{
		ctx.hold(); // deliberately never released
	}

	override void onBehaviourEvent(Object)
	{
	}
}

/// A SwarmCtx that records what a behaviour asked of it.
private final class RecordingSwarm : SwarmCtx
{
	Object[] notified;
	Object[] emitted;

	override PeerId localPeer()
	{
		return PeerId.init;
	}

	override bool isConnected(PeerId)
	{
		return false;
	}

	override ConnectionId dial(DialOpts)
	{
		return ConnectionId.init;
	}

	override PeerId dialAndWait(DialOpts)
	{
		throw new Exception("not dialing in this test");
	}

	override ListenerId listenOn(string, ushort)
	{
		return ListenerId.init;
	}

	override bool removeListener(ListenerId)
	{
		return false;
	}

	override void emit(Object e) nothrow
	{
		emitted ~= e;
	}

	override ByteStream openStream(PeerId, string[])
	{
		throw new Exception("not opening streams in this test");
	}

	override void notifyHandler(PeerId, ev.HandlerSelector, Object e)
	{
		notified ~= e;
	}

	override void notifyHandler(PeerId, ConnectionId, Object e)
	{
		notified ~= e;
	}

	override void closeConnections(PeerId)
	{
	}

	override void closeConnection(PeerId, ConnectionId)
	{
	}

	override void newExternalAddrCandidate(Multiaddr)
	{
	}

	override void addExternalAddress(Multiaddr)
	{
	}

	override void removeExternalAddress(Multiaddr)
	{
	}
	/// The test never blocks in a callback, so this just runs it — inline, and
	/// swallowing nothing quietly: an unexpected throw here should be visible.
	void spawn(void delegate() work, string what = "behaviour work") nothrow
	{
		try
			work();
		catch (Exception e)
			logError("test swarm: %s: %s", what, e.msg);
	}

}

/// Records what it was told, so composition routing can be asserted.
private final class SpyBehaviour : BaseBehaviour
{
	string name;
	size_t swarmEvents;
	Object[] handlerEvents;
	Multiaddr[] contribute;

	this(string name) @safe pure nothrow
	{
		this.name = name;
	}



	override void onSwarmEvent(ev.FromSwarm)
	{
		swarmEvents++;
	}

	override void onConnectionHandlerEvent(PeerId, ConnectionId, Object e)
	{
		handlerEvents ~= e;
	}

	override Multiaddr[] handlePendingOutboundConnection(ConnectionId, bool, PeerId,
		const(Multiaddr)[], Endpoint)
	{
		return contribute;
	}

	/// Drive the one action this test needs: a message down to our handler.
	void sendToHandler(PeerId peer, Object payload)
	{
		swarm.notifyHandler(peer, ev.HandlerSelector.all, payload);
	}

}

@("composite: every child sees swarm events")
unittest
{
	auto a = new SpyBehaviour("a");
	auto b = new SpyBehaviour("b");
	auto c = new CompositeBehaviour(a, b);

	auto peer = PeerId.fromPublicKey(Keypair.generateEd25519.publicKey);
	auto addr = Multiaddr.parse("/ip4/127.0.0.1/tcp/1");
	c.onSwarmEvent(new ev.ConnectionEstablished(peer, ConnectionId.unchecked(1),
			ConnectedPoint.dialer(addr), 1));

	a.swarmEvents.should.equal(1);
	b.swarmEvents.should.equal(1);
}

@("composite: addresses from all children are pooled for a dial")
unittest
{
	auto a = new SpyBehaviour("a");
	auto b = new SpyBehaviour("b");
	a.contribute = [Multiaddr.parse("/ip4/1.1.1.1/tcp/1")];
	b.contribute = [Multiaddr.parse("/ip4/2.2.2.2/tcp/2")];
	auto c = new CompositeBehaviour(a, b);

	auto peer = PeerId.fromPublicKey(Keypair.generateEd25519.publicKey);
	auto got = c.handlePendingOutboundConnection(ConnectionId.unchecked(1), true, peer,
		null, Endpoint.dialer);

	got.length.should.equal(2);
}

// The routing that matters: a handler event from child i must reach child i,
// and no other child may see it.
@("composite: a handler event is routed to the child that owns the handler")
unittest
{
	auto a = new SpyBehaviour("a");
	auto b = new SpyBehaviour("b");
	auto c = new CompositeBehaviour(a, b);

	auto peer = PeerId.fromPublicKey(Keypair.generateEd25519.publicKey);
	auto payload = new Object;
	// Index 1 == child b.
	c.onConnectionHandlerEvent(peer, ConnectionId.unchecked(1), new Tagged(1, payload));

	a.handlerEvents.length.should.equal(0);
	b.handlerEvents.length.should.equal(1);
	(b.handlerEvents[0] is payload).should.equal(true);
}

// (The old "actions are taken round-robin across children" test is gone with the
// thing it tested: behaviours used to RETURN commands for the swarm to drain, so
// the composite had to scan its children fairly. They now call the swarm
// directly, so there is no scan, no ordering to be unfair about, and nothing
// left to starve.)

// A message a child sends DOWN to a handler still has to reach that child's
// sub-handler, so the ctx a child is given tags it. This is the one direction
// where a token is genuinely needed: it crosses the swarm, so the stack cannot
// carry the correlation.
@("composite: a child's notifyHandler is tagged for that child's sub-handler")
unittest
{
	auto a = new SpyBehaviour("a");
	auto b = new SpyBehaviour("b");
	auto c = new CompositeBehaviour(a, b);

	auto rec = new RecordingSwarm;
	c.onInstall(rec);

	auto peer = PeerId.fromPublicKey(Keypair.generateEd25519.publicKey);
	auto payload = new Object;
	b.sendToHandler(peer, payload); // child index 1

	rec.notified.length.should.equal(1);
	auto tagged = cast(Tagged) rec.notified[0];
	tagged.should.not.beNull;
	tagged.index.should.equal(1);
	(tagged.payload is payload).should.equal(true);
}

@("composite handler: the union of protocols is offered, without duplicates")
unittest
{
	auto h = new CompositeHandler([
		cast(ConnectionHandler) new ProtoHandler(["/x/1", "/shared/1"]),
		cast(ConnectionHandler) new ProtoHandler(["/y/1", "/shared/1"]),
	]);

	auto ps = h.listenProtocols();
	ps.length.should.equal(3);
}

private final class ProtoHandler : ConnectionHandler
{
	string[] protos;

	this(string[] protos) @safe pure nothrow
	{
		this.protos = protos;
	}

	override string[] listenProtocols()
	{
		return protos;
	}

	override void handleInbound(ConnectionCtx, ByteStream stream, string)
	{
		stream.close();
	}

	override void run(ConnectionCtx)
	{
	}

	override void onBehaviourEvent(Object)
	{
	}
}

// --- toggle ----------------------------------------------------------------

@("toggle: a disabled behaviour is completely inert")
unittest
{
	auto inner = new SpyBehaviour("inner");
	auto off = new Toggle(null);
	auto on = new Toggle(inner);

	off.enabled.should.equal(false);
	on.enabled.should.equal(true);

	auto peer = PeerId.fromPublicKey(Keypair.generateEd25519.publicKey);
	auto addr = Multiaddr.parse("/ip4/127.0.0.1/tcp/1");

	// Disabled: builds no handler, emits nothing, denies nothing.
	(off.handleEstablishedInboundConnection(ConnectionId.unchecked(1), peer, addr, addr) is null)
		.should.equal(true);
	off.handlePendingInboundConnection(ConnectionId.unchecked(1), addr, addr); // no throw
	off.onInstall(new RecordingSwarm); // does not reach the (absent) inner
	off.onSwarmEvent(new ev.NewExternalAddrCandidate(addr)); // no throw

	// Enabled: passes through.
	on.onSwarmEvent(new ev.NewExternalAddrCandidate(addr));
	inner.swarmEvents.should.equal(1);
}

// --- external addresses ----------------------------------------------------

@("swarm: external addresses are recorded once and can expire")
unittest
{
	scope (exit)
		drain();

	auto spy = new SpyBehaviour("spy");
	auto s = Swarm.generate(spy);
	scope (exit)
		s.close();

	auto addr = Multiaddr.parse("/ip4/9.9.9.9/tcp/4001");
	s.addExternalAddress(addr);
	s.addExternalAddress(addr); // duplicate: ignored
	s.externalAddresses().length.should.equal(1);
	spy.swarmEvents.should.equal(1); // told exactly once

	s.removeExternalAddress(addr);
	s.externalAddresses().length.should.equal(0);
	spy.swarmEvents.should.equal(2);

	s.removeExternalAddress(addr); // unknown: no event
	spy.swarmEvents.should.equal(2);
}

// `ConnectionLimits` is a behaviour, so it only sees what the swarm asks it. The
// policy hook used to be called only when `extendAddressesThroughBehaviour` was
// set — and `DialOpts.address`, the constructor for a bare address, clears it.
// So the most ordinary dial there is went straight past every limit.
@("limits: a dial by bare address is subject to the outgoing limit")
unittest
{
	scope (exit)
		drain();

	auto limits = new ConnectionLimits(Limits().with_(LimitKind.pendingOutgoing, 0));
	auto s = new Swarm(Keypair.generateEd25519, limits);
	scope (exit)
		s.close();

	string err;
	runTask(() nothrow{
		try
		{
			// Nothing is listening; the point is that we never get that far.
			cast(void) s.dialAndWait(
				DialOpts.address(Multiaddr.parse("/ip4/127.0.0.1/tcp/1")));
		}
		catch (Exception e)
			err = e.msg;
		try
			exitEventLoop();
		catch (Exception)
		{
		}
	});
	runEventLoop();

	// Refused by the limit, not by a failed connection.
	(err.length > 0).should.equal(true);
	err.should.contain("denied");
}

// A blocking dial that fails must report it like any other, or the pending it
// took is never given back: ConnectionLimits decrements on an established
// connection or a DialFailure, and nothing else. A run of failures used to eat
// the process's own quota permanently — which is exactly what DCUtR's retry loop
// does when a hole punch misses.
@("limits: a failed blocking dial gives its pending slot back")
unittest
{
	scope (exit)
		drain();

	auto limits = new ConnectionLimits(Limits().with_(LimitKind.pendingOutgoing, 1));
	auto s = new Swarm(Keypair.generateEd25519, limits);
	scope (exit)
		s.close();

	auto ghost = PeerId.fromPublicKey(Keypair.generateEd25519.publicKey);
	size_t failures;
	runTask(() nothrow{
		try
		{
			// Three attempts at a port nothing answers on. With a quota of one,
			// the second would be refused if the first never released its slot.
			foreach (_; 0 .. 3)
			{
				try
					cast(void) s.dialAndWait(DialOpts.peer(ghost)
							.withAddresses([Multiaddr.parse("/ip4/127.0.0.1/tcp/1")]));
				catch (Exception e)
				{
					if (e.msg.length && !e.msg.canFind("denied"))
						failures++;
				}
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

	// All three got as far as trying, which they only can if each one's slot was
	// released when it failed.
	failures.should.equal(3);
}

// The admission decision has to happen on a raw socket, before multistream,
// Noise and the muxer. It used to happen after all three, so the limit counted a
// window that opened only once every expensive thing had been paid for — the
// opposite of what a limit is for.
//
// The proof is what the *dialer* sees: refused before the handshake, its Noise
// negotiation finds a closed socket rather than a peer that then hangs up.
@("limits: an inbound connection is refused before the handshake runs")
unittest
{
	scope (exit)
		drain();

	auto limits = new ConnectionLimits(Limits().with_(LimitKind.pendingIncoming, 0));
	auto listener = new Swarm(Keypair.generateEd25519, limits);
	scope (exit)
		listener.close();
	listener.listenOn("127.0.0.1", 0);
	immutable port = portOf(listener);

	auto dialer = new Swarm(Keypair.generateEd25519, new class BaseBehaviour {});
	scope (exit)
		dialer.close();

	bool refused;
	size_t established;
	runTask(() nothrow{
		try
		{
			try
				cast(void) dialer.dialAndWait(
					DialOpts.address(Multiaddr.parse(
						"/ip4/127.0.0.1/tcp/" ~ (cast(uint) port).to!string)));
			catch (Exception)
				refused = true;
			sleep(100.msecs);
			established = listener.connectedPeers().length;
		}
		catch (Exception e)
			logError("inbound admission test: %s", e.msg);
		try
			exitEventLoop();
		catch (Exception)
		{
		}
	});
	runEventLoop();

	refused.should.equal(true);
	established.should.equal(0); // nothing was ever upgraded
}

// Every inbound used to be reported with `_listenAddrs[0]`, so with two
// listeners the second's connections carried the first's address — wrong in
// ConnectedPoint, wrong for behaviours, indistinguishable in a log. And stopping
// a listener left its address in `listenAddresses()`, advertising a dead
// endpoint to identify, AutoNAT and anyone else who asks where to reach us.
@("swarm: two listeners keep separate addresses, and removal expires one")
unittest
{
	scope (exit)
		drain();

	auto s = new Swarm(Keypair.generateEd25519, new class BaseBehaviour {});
	scope (exit)
		s.close();

	auto first = s.listenOn("127.0.0.1", 0);
	auto second = s.listenOn("127.0.0.1", 0);

	auto both = s.listenAddresses();
	both.length.should.equal(2);
	(both[0].toString() != both[1].toString()).should.equal(true);
	immutable survivor = both[1].toString();

	s.removeListener(first).should.equal(true);

	auto left = s.listenAddresses();
	left.length.should.equal(1);
	left[0].toString().should.equal(survivor); // the dead one is gone, not the live one
}
