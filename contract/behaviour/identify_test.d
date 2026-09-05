module tests.behaviour.identify_test;

import fluent.asserts;

import libp2p.swarm.behaviour : BaseBehaviour;

import core.time : msecs, seconds;
import vibe.core.core : runTask, runEventLoop, exitEventLoop;
import vibe.core.log : logError;

import libp2p.crypto.keys : Keypair, PublicKey;
import libp2p.core.peer_id : PeerId;
import libp2p.host : Host;
import libp2p.swarm.swarm : Swarm;
import libp2p.swarm.composite : CompositeBehaviour;
import libp2p.behaviour.identify : IdentifyBehaviour, IdentifyConfig, IdentifyReceived,
	IdentifySent, identifyPushProtocol;
import libp2p.protocol.identify : identifyProtocol;
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

/// Build a swarm whose identity we keep, so the test can check what identify says.
private struct Node
{
	Swarm swarm;
	Keypair key;
}

private Node makeNode(IdentifyConfig cfg = IdentifyConfig.init)
{
	auto key = Keypair.generateEd25519;
	auto b = new IdentifyBehaviour(key.publicKey, cfg);
	auto s = new Swarm(new Host(key), b);
	s.idleConnectionTimeout = 5.seconds;
	return Node(s, key);
}

// The core of identify: the dialer opens the stream and READS, the listener
// sends. Getting that backwards deadlocks both sides, so this test is the one
// that matters.
@("identify behaviour: the dialer learns the listener's identity")
unittest
{
	scope (exit)
		drain();

	auto listener = makeNode();
	scope (exit)
		listener.swarm.close();
	listener.swarm.listenOn("127.0.0.1", 0);
	immutable port = portOf(listener.swarm);

	auto dialer = makeNode();
	scope (exit)
		dialer.swarm.close();

	IdentifyReceived got;
	runTask(() nothrow{
		try
		{
			dialer.swarm.dial("127.0.0.1", port);
			foreach (_; 0 .. 20)
			{
				auto e = dialer.swarm.nextEvent(5.seconds);
				if (e is null)
					break;
				if (auto b = cast(ev.BehaviourEvent) e)
					if (auto r = cast(IdentifyReceived) b.event)
					{
						got = r;
						break;
					}
			}
		}
		catch (Exception e)
			logError("identify test: %s", e.msg);
		try
			exitEventLoop();
		catch (Exception)
		{
		}
	});
	runEventLoop();

	got.should.not.beNull;
	got.peer.should.equal(listener.swarm.localPeer);
	// The advertised public key must be the listener's real one — this is what
	// makes identify an identity protocol and not a rumour.
	PeerId.fromPublicKey(PublicKey.fromProtobuf(got.info.publicKey))
		.should.equal(listener.swarm.localPeer);
	got.info.agentVersion.should.equal(IdentifyConfig.init.agentVersion);
	// Both identify protocols are advertised.
	bool hasId, hasPush;
	foreach (p; got.info.protocols)
	{
		if (p == identifyProtocol)
			hasId = true;
		if (p == identifyPushProtocol)
			hasPush = true;
	}
	hasId.should.equal(true);
	hasPush.should.equal(true);
}

// The reason identify is wired into the swarm at all: the listener tells the
// dialer the address it observed, which is how a NATed node learns its own.
@("identify behaviour: the observed address comes back as an external candidate")
unittest
{
	scope (exit)
		drain();

	auto listener = makeNode();
	scope (exit)
		listener.swarm.close();
	listener.swarm.listenOn("127.0.0.1", 0);
	immutable port = portOf(listener.swarm);

	// A behaviour that just records the candidates the swarm reports.
	auto spy = new CandidateSpy;
	auto key = Keypair.generateEd25519;
	auto dialer = new Swarm(new Host(key),
		new CompositeBehaviour(new IdentifyBehaviour(key.publicKey), spy));
	dialer.idleConnectionTimeout = 5.seconds;
	scope (exit)
		dialer.close();

	runTask(() nothrow{
		try
		{
			dialer.dial("127.0.0.1", port);
			foreach (_; 0 .. 20)
			{
				auto e = dialer.nextEvent(5.seconds);
				if (e is null)
					break;
				if (auto b = cast(ev.BehaviourEvent) e)
					if (cast(IdentifyReceived) b.event)
						break;
			}
		}
		catch (Exception e)
			logError("identify observed test: %s", e.msg);
		try
			exitEventLoop();
		catch (Exception)
		{
		}
	});
	runEventLoop();

	spy.candidates.length.should.be.greaterThan(0);
	// It is the address the listener saw us dial FROM: our loopback address with
	// the ephemeral source port, not the port we (never) listened on.
	spy.candidates[0].toString().should.contain("/ip4/127.0.0.1/tcp/");
}

// The listener side reports that it told someone who it is.
@("identify behaviour: the listener reports having sent its identity")
unittest
{
	scope (exit)
		drain();

	auto listener = makeNode();
	scope (exit)
		listener.swarm.close();
	listener.swarm.listenOn("127.0.0.1", 0);
	immutable port = portOf(listener.swarm);

	auto dialer = makeNode();
	scope (exit)
		dialer.swarm.close();

	bool sent;
	runTask(() nothrow{
		try
		{
			dialer.swarm.dial("127.0.0.1", port);
			foreach (_; 0 .. 20)
			{
				auto e = listener.swarm.nextEvent(5.seconds);
				if (e is null)
					break;
				if (auto b = cast(ev.BehaviourEvent) e)
					if (cast(IdentifySent) b.event)
					{
						sent = true;
						break;
					}
			}
		}
		catch (Exception e)
			logError("identify sent test: %s", e.msg);
		try
			exitEventLoop();
		catch (Exception)
		{
		}
	});
	runEventLoop();

	sent.should.equal(true);
}

// --- helpers ---------------------------------------------------------------

private final class CandidateSpy : BaseBehaviour
{
	import libp2p.multiformats.multiaddr : Multiaddr;

	Multiaddr[] candidates;

	override void onSwarmEvent(ev.FromSwarm event)
	{
		if (auto c = cast(ev.NewExternalAddrCandidate) event)
			candidates ~= c.addr;
	}
}

// A dial whose answer the caller needs is a blocking call, not an action plus an
// event to correlate later. AutoNAT's dial-back is the case that forced it.
@("swarm: dialAndWait returns the peer it reached, or throws")
unittest
{
	scope (exit)
		drain();

	auto listener = makeNode();
	scope (exit)
		listener.swarm.close();
	listener.swarm.listenOn("127.0.0.1", 0);
	immutable port = portOf(listener.swarm);

	auto dialer = makeNode();
	scope (exit)
		dialer.swarm.close();

	PeerId reached;
	bool refused;
	runTask(() nothrow{
		try
		{
			import libp2p.swarm.dial_opts : DialOpts;
			import libp2p.multiformats.multiaddr : Multiaddr;
			import std.conv : to;

			auto ok = Multiaddr.parse("/ip4/127.0.0.1/tcp/" ~ (cast(uint) port).to!string);
			reached = dialer.swarm.dialAndWait(DialOpts.address(ok));

			// A port with nothing on it must throw, here, not later.
			auto dead = Multiaddr.parse("/ip4/127.0.0.1/tcp/1");
			try
				dialer.swarm.dialAndWait(DialOpts.address(dead));
			catch (Exception)
				refused = true;
		}
		catch (Exception e)
			logError("dialAndWait test: %s", e.msg);
		try
			exitEventLoop();
		catch (Exception)
		{
		}
	});
	runEventLoop();

	reached.should.equal(listener.swarm.localPeer);
	refused.should.equal(true);
}
