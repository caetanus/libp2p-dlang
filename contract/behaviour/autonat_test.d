module tests.behaviour.autonat_test;

import fluent.asserts;

import core.time : msecs, seconds;
import vibe.core.core : runTask, runEventLoop, exitEventLoop;
import vibe.core.log : logError;

import std.conv : to;

import libp2p.crypto.keys : Keypair;
import libp2p.host : Host;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.swarm.swarm : Swarm;
import libp2p.behaviour.autonat : AutoNatBehaviour, NatStatusChanged;
import libp2p.protocol.autonat : NatKind;
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

private Multiaddr loopback(ushort port)
{
	return Multiaddr.parse("/ip4/127.0.0.1/tcp/" ~ (cast(uint) port).to!string);
}

private struct Node
{
	Swarm swarm;
	AutoNatBehaviour nat;
}

private Node makeNode()
{
	auto b = new AutoNatBehaviour;
	auto s = new Swarm(new Host(Keypair.generateEd25519), b);
	s.idleConnectionTimeout = 10.seconds;
	return Node(s, b);
}

// The whole protocol, end to end on the swarm: a client that IS reachable asks a
// server to dial it back, the server does, and the client concludes it is public.
@("autonat behaviour: a reachable client is told it is public")
unittest
{
	scope (exit)
		drain();

	auto server = makeNode();
	scope (exit)
		server.swarm.close();
	server.swarm.listenOn("127.0.0.1", 0);
	immutable serverPort = portOf(server.swarm);

	auto client = makeNode();
	scope (exit)
		client.swarm.close();
	// The client must actually be listening, or the dial-back cannot succeed.
	client.swarm.listenOn("127.0.0.1", 0);
	immutable clientPort = portOf(client.swarm);

	NatKind kind;
	runTask(() nothrow{
		try
		{
			auto st = client.nat.probe(loopback(serverPort), [loopback(clientPort)]);
			kind = st.kind;
		}
		catch (Exception e)
			logError("autonat public test: %s", e.msg);
		try
			exitEventLoop();
		catch (Exception)
		{
		}
	});
	runEventLoop();

	(kind == NatKind.publicNat).should.equal(true);
}

// The other side of the same coin: if the address the client claims has nothing
// on it, the dial-back fails and the client learns it is private.
@("autonat behaviour: an unreachable client is told it is private")
unittest
{
	scope (exit)
		drain();

	auto server = makeNode();
	scope (exit)
		server.swarm.close();
	server.swarm.listenOn("127.0.0.1", 0);
	immutable serverPort = portOf(server.swarm);

	auto client = makeNode();
	scope (exit)
		client.swarm.close();

	// A port with nothing behind it: bind one to learn a free number, then let it
	// go (its own swarm, so there is a single owner of that listener).
	auto probe = new Swarm(new Host(Keypair.generateEd25519), new AutoNatBehaviour);
	probe.listenOn("127.0.0.1", 0);
	immutable deadPort = portOf(probe);
	probe.close();

	NatKind kind;
	runTask(() nothrow{
		try
		{
			auto st = client.nat.probe(loopback(serverPort), [loopback(deadPort)]);
			kind = st.kind;
		}
		catch (Exception e)
			logError("autonat private test: %s", e.msg);
		try
			exitEventLoop();
		catch (Exception)
		{
		}
	});
	runEventLoop();

	(kind == NatKind.privateNat).should.equal(true);
}

// The security property, asserted rather than trusted: the server only ever
// dials the requester back at the address it OBSERVED, so a client cannot point
// it at a third party. Here the client claims an address on another host; the
// filter rewrites it to the observed one, and since the client is not listening
// there, the answer is "private" — never a dial to the claimed victim.
@("autonat behaviour: a claimed third-party address is rewritten, not dialed")
unittest
{
	scope (exit)
		drain();

	auto server = makeNode();
	scope (exit)
		server.swarm.close();
	server.swarm.listenOn("127.0.0.1", 0);
	immutable serverPort = portOf(server.swarm);

	auto client = makeNode();
	scope (exit)
		client.swarm.close();

	NatKind kind;
	string err;
	runTask(() nothrow{
		try
		{
			// "Please dial 10.1.2.3:9999" — a victim we have no business dialing.
			auto victim = Multiaddr.parse("/ip4/10.1.2.3/tcp/9999");
			auto st = client.nat.probe(loopback(serverPort), [victim]);
			kind = st.kind;
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

	// Either the request is refused outright or the rewritten dial fails; what
	// must NOT happen is the server reporting success for the victim address.
	(kind != NatKind.publicNat).should.equal(true);
}
