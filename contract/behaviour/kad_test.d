module tests.behaviour.kad_test;

import fluent.asserts;

import core.time : msecs, seconds;
import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;
import vibe.core.log : logError;

import std.algorithm : any;
import std.conv : to;

import libp2p.crypto.keys : Keypair;
import libp2p.host : Host;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.swarm.swarm : Swarm;
import libp2p.behaviour.kad : KadBehaviour;
import libp2p.protocol.kad.store : Record, RecordKey;

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
	KadBehaviour kad;
	Multiaddr addr;
}

/// A listening kad node on the swarm. It advertises the address the swarm bound,
/// which is what it hands out in provider records.
private Node makeNode()
{
	auto kad = new KadBehaviour; // learns its advertised address from the swarm
	auto s = new Swarm(new Host(Keypair.generateEd25519), kad);
	s.idleConnectionTimeout = 10.seconds;
	s.listenOn("127.0.0.1", 0);
	return Node(s, kad, loopback(portOf(s)));
}

// The multi-hop heart of a DHT lookup, now over the swarm: A knows only B, B
// knows C, and A's iterative FIND_NODE must reach C through B.
@("kad behaviour: node A finds node C via node B")
unittest
{
	scope (exit)
		drain();

	auto b = makeNode();
	scope (exit)
		b.swarm.close();
	auto c = makeNode();
	scope (exit)
		c.swarm.close();

	// B knows C.
	b.kad.node.addAddress(c.swarm.localPeer, c.addr);

	auto a = makeNode();
	scope (exit)
		a.swarm.close();

	bool foundC;
	runTask(() nothrow{
		try
		{
			// A knows only B.
			a.kad.node.addAddress(b.swarm.localPeer, b.addr);
			auto closest = a.kad.node.getClosestPeers(c.swarm.localPeer.bytes);
			foundC = closest.any!(pi => pi.peerId == c.swarm.localPeer);
		}
		catch (Exception e)
			logError("kad behaviour find test: %s", e.msg);
		try
			exitEventLoop();
		catch (Exception)
		{
		}
	});
	runEventLoop();

	foundC.should.equal(true);
}

// The write and read paths: A stores a record on B, and a third node G that also
// knows B retrieves it over the network.
@("kad behaviour: put a record via A, get it back via G")
unittest
{
	scope (exit)
		drain();

	auto b = makeNode();
	scope (exit)
		b.swarm.close();
	auto a = makeNode();
	scope (exit)
		a.swarm.close();
	auto g = makeNode();
	scope (exit)
		g.swarm.close();

	ubyte[] key = [0xDE, 0xAD, 0xBE, 0xEF];
	ubyte[] val = [1, 2, 3, 4, 5];

	bool stored, got;
	ubyte[] gotVal;
	runTask(() nothrow{
		try
		{
			a.kad.node.addAddress(b.swarm.localPeer, b.addr);
			auto writes = a.kad.node.putRecord(Record(RecordKey.from(key), val.dup));
			stored = writes >= 1 && b.kad.node.store.get(RecordKey.from(key)) !is null;

			g.kad.node.addAddress(b.swarm.localPeer, b.addr);
			auto found = g.kad.node.getRecord(key);
			if (found !is null)
			{
				got = true;
				gotVal = found.value;
			}
		}
		catch (Exception e)
			logError("kad behaviour put/get test: %s", e.msg);
		try
			exitEventLoop();
		catch (Exception)
		{
		}
	});
	runEventLoop();

	stored.should.equal(true);
	got.should.equal(true);
	gotVal.should.equal(val);
}

// A lookup must teach the routing table: after one query, A knows both the peer
// it started from and the one it discovered.
@("kad behaviour: a lookup self-populates the routing table")
unittest
{
	scope (exit)
		drain();

	import libp2p.protocol.kad.key : Key;

	auto b = makeNode();
	scope (exit)
		b.swarm.close();
	auto c = makeNode();
	scope (exit)
		c.swarm.close();
	b.kad.node.addAddress(c.swarm.localPeer, c.addr);

	auto a = makeNode();
	scope (exit)
		a.swarm.close();

	bool learnedB, learnedC;
	runTask(() nothrow{
		try
		{
			a.kad.node.addAddress(b.swarm.localPeer, b.addr);
			a.kad.node.getClosestPeers(c.swarm.localPeer.bytes);
			learnedB = a.kad.node.table.contains(Key.fromPeer(b.swarm.localPeer));
			learnedC = a.kad.node.table.contains(Key.fromPeer(c.swarm.localPeer));
		}
		catch (Exception e)
			logError("kad behaviour self-populate test: %s", e.msg);
		try
			exitEventLoop();
		catch (Exception)
		{
		}
	});
	runEventLoop();

	learnedB.should.equal(true);
	learnedC.should.equal(true);
}

// --- the DHT operations that only ran over a bare Host ------------------------
//
// These four moved here from vibe_probe_test, where they drove `KadNode` bound
// to a `Host`. That was a second integration path for the same engine, and the
// swarm is the one the library actually offers — `KadBehaviour.node` exposes the
// whole engine, so nothing had to change but who owns the socket.

// Providing is two round trips that have to agree: A announces to B, and G — who
// knows only B — has to get A back as the provider.
@("kad behaviour: announce a provider via B, discover it via G")
unittest
{
	scope (exit)
		drain();

	auto b = makeNode();
	scope (exit)
		b.swarm.close();

	ubyte[] provKey = [0xCA, 0xFE, 0xBA, 0xBE];
	bool announced, discovered;
	runTask(() nothrow{
		try
		{
			auto a = makeNode();
			scope (exit)
				a.swarm.close();
			a.kad.node.addAddress(b.swarm.localPeer, b.addr);
			announced = a.kad.node.startProviding(provKey) >= 1;

			// ADD_PROVIDER is fire-and-forget; give B's server a beat to store it.
			sleep(50.msecs);

			auto g = makeNode();
			scope (exit)
				g.swarm.close();
			g.kad.node.addAddress(b.swarm.localPeer, b.addr);
			discovered = g.kad.node.getProviders(provKey)
				.any!(pi => pi.peerId == a.swarm.localPeer);
		}
		catch (Exception e)
			logError("kad providers: %s", e.msg);
		try
			exitEventLoop();
		catch (Exception)
		{
		}
	});
	runEventLoop();

	announced.should.equal(true);
	discovered.should.equal(true);
}

// The replicate job is the only thing here that acts on its own: nobody asks for
// this push, a timer does.
@("kad behaviour: the replicate job pushes a stored record on its own")
unittest
{
	import core.time : hours;

	scope (exit)
		drain();

	auto b = makeNode();
	scope (exit)
		b.swarm.close();

	ubyte[] recKey = [0x10, 0x20, 0x30];
	bool replicated;
	runTask(() nothrow{
		try
		{
			auto a = makeNode();
			scope (exit)
				a.swarm.close();
			a.kad.node.addAddress(b.swarm.localPeer, b.addr);
			a.kad.node.store.put(Record(RecordKey.from(recKey), [7, 7, 7]));
			a.kad.node.runJobs(200.msecs, 1.hours, 1.hours, 48.hours);
			sleep(2000.msecs);
			replicated = b.kad.node.store.get(RecordKey.from(recKey)) !is null;
		}
		catch (Exception e)
			logError("kad replicate job: %s", e.msg);
		try
			exitEventLoop();
		catch (Exception)
		{
		}
	});
	runEventLoop();

	replicated.should.equal(true);
}

// An expiry that does not survive the wire is worse than none: the record looks
// permanent to everyone who fetched it.
@("kad behaviour: a record's expiry survives the put/get round-trip")
unittest
{
	import core.time : MonoTime;

	scope (exit)
		drain();

	auto b = makeNode();
	scope (exit)
		b.swarm.close();

	ubyte[] recKey = [0x77, 0x88];
	bool hasExpiry, plausible;
	runTask(() nothrow{
		try
		{
			auto a = makeNode();
			scope (exit)
				a.swarm.close();
			a.kad.node.addAddress(b.swarm.localPeer, b.addr);

			auto rec = Record(RecordKey.from(recKey), [1, 2]);
			rec.hasExpires = true;
			rec.expires = MonoTime.currTime + 100.seconds;
			a.kad.node.putRecord(rec);

			auto g = makeNode();
			scope (exit)
				g.swarm.close();
			g.kad.node.addAddress(b.swarm.localPeer, b.addr);
			if (auto got = g.kad.node.getRecord(recKey))
			{
				hasExpiry = got.hasExpires;
				plausible = got.hasExpires && got.expires > MonoTime.currTime + 50.seconds;
			}
		}
		catch (Exception e)
			logError("kad ttl: %s", e.msg);
		try
			exitEventLoop();
		catch (Exception)
		{
		}
	});
	runEventLoop();

	hasExpiry.should.equal(true);
	plausible.should.equal(true); // and it did not arrive already expired
}

// Bootstrap is what turns one known address into a populated routing table.
@("kad behaviour: bootstrap grows the routing table from one entry point")
unittest
{
	import libp2p.core.peer_id : PeerId;
	import libp2p.protocol.kad.key : Key;

	scope (exit)
		drain();

	auto r = makeNode();
	scope (exit)
		r.swarm.close();

	// Three peers the rendezvous node knows about, and A does not.
	PeerId[] peerIds;
	Node[] peers;
	scope (exit)
		foreach (p; peers)
			p.swarm.close();
	foreach (i; 0 .. 3)
	{
		auto p = makeNode();
		peers ~= p;
		r.kad.node.addAddress(p.swarm.localPeer, p.addr);
		peerIds ~= p.swarm.localPeer;
	}

	size_t tableSize;
	bool allDiscovered;
	runTask(() nothrow{
		try
		{
			auto a = makeNode();
			scope (exit)
				a.swarm.close();
			a.kad.node.addAddress(r.swarm.localPeer, r.addr);

			tableSize = a.kad.node.bootstrap();
			allDiscovered = true;
			foreach (pid; peerIds)
				if (!a.kad.node.table.contains(Key.fromPeer(pid)))
					allDiscovered = false;
		}
		catch (Exception e)
			logError("kad bootstrap: %s", e.msg);
		try
			exitEventLoop();
		catch (Exception)
		{
		}
	});
	runEventLoop();

	tableSize.should.be.greaterThan(0UL);
	allDiscovered.should.equal(true); // every peer R knew, A now knows too
}
