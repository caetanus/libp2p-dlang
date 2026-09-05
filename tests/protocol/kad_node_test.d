/**
 * Kademlia over real hosts on loopback: the behaviours the old kad tests pinned,
 * asserted in the new shape. A knows only B, B knows C; lookups, records,
 * providers, replication and bootstrap have to cross that hop.
 */
module tests.protocol.kad_node_test;

import core.time : msecs, seconds, hours, MonoTime;
import std.algorithm.searching : any;

import vibe.core.core : sleep;

import fluent.asserts;

import libp2p.core.peer_id : PeerId;
import libp2p.host.host;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.protocol.kad.kad;
import tests.util.loop;

private struct Node
{
	Host host;
	Kademlia kad;

	PeerId id()
	{
		return host.id;
	}

	Multiaddr addr()
	{
		return host.addrs[0];
	}

	void close() nothrow
	{
		kad.close();
		host.close();
	}
}

private Node makeNode()
{
	auto h = Host.create();
	h.listen(Multiaddr.parse("/ip4/127.0.0.1/tcp/0"));
	return Node(h, new Kademlia(h));
}

// The multi-hop heart of a DHT lookup: A knows only B, B knows C, and A's
// iterative FIND_NODE must reach C through B.
@("kad: node A finds node C via node B")
unittest
{
	bool foundC;
	onLoop({
		auto b = makeNode();
		scope (exit)
			b.close();
		auto c = makeNode();
		scope (exit)
			c.close();
		b.kad.addAddress(c.id, c.addr);

		auto a = makeNode();
		scope (exit)
			a.close();
		a.kad.addAddress(b.id, b.addr);

		auto closest = a.kad.getClosestPeers(c.id.bytes);
		foundC = closest.any!(pi => pi.peerId == c.id);
	});
	foundC.should.equal(true);
}

// The write and read paths: A stores a record on B, and a third node G that also
// knows B retrieves it over the network.
@("kad: put a record via A, get it back via G")
unittest
{
	ubyte[] key = [0xDE, 0xAD, 0xBE, 0xEF];
	ubyte[] val = [1, 2, 3, 4, 5];
	bool stored, got;
	ubyte[] gotVal;
	onLoop({
		auto b = makeNode();
		scope (exit)
			b.close();
		auto a = makeNode();
		scope (exit)
			a.close();
		auto g = makeNode();
		scope (exit)
			g.close();

		a.kad.addAddress(b.id, b.addr);
		auto writes = a.kad.putRecord(Record(RecordKey.from(key), val.dup));
		stored = writes >= 1 && b.kad.store.get(RecordKey.from(key)) !is null;

		g.kad.addAddress(b.id, b.addr);
		auto found = g.kad.getRecord(key);
		if (found !is null)
		{
			got = true;
			gotVal = found.value;
		}
	});
	stored.should.equal(true);
	got.should.equal(true);
	gotVal.should.equal(val);
}

// A lookup must teach the routing table: after one query, A knows both the peer
// it started from and the one it discovered.
@("kad: a lookup self-populates the routing table")
unittest
{
	bool learnedB, learnedC;
	onLoop({
		auto b = makeNode();
		scope (exit)
			b.close();
		auto c = makeNode();
		scope (exit)
			c.close();
		b.kad.addAddress(c.id, c.addr);

		auto a = makeNode();
		scope (exit)
			a.close();
		a.kad.addAddress(b.id, b.addr);
		a.kad.getClosestPeers(c.id.bytes);
		learnedB = a.kad.table.contains(Key.fromPeer(b.id));
		learnedC = a.kad.table.contains(Key.fromPeer(c.id));
	});
	learnedB.should.equal(true);
	learnedC.should.equal(true);
}

// Providing is two round trips that have to agree: A announces to B, and G — who
// knows only B — has to get A back as the provider.
@("kad: announce a provider via B, discover it via G")
unittest
{
	ubyte[] provKey = [0xCA, 0xFE, 0xBA, 0xBE];
	bool announced, discovered;
	onLoop({
		auto b = makeNode();
		scope (exit)
			b.close();
		auto a = makeNode();
		scope (exit)
			a.close();
		a.kad.addAddress(b.id, b.addr);
		announced = a.kad.startProviding(provKey) >= 1;

		// ADD_PROVIDER is fire-and-forget; give B's server a beat to store it.
		sleep(50.msecs);

		auto g = makeNode();
		scope (exit)
			g.close();
		g.kad.addAddress(b.id, b.addr);
		discovered = g.kad.getProviders(provKey).any!(pi => pi.peerId == a.id);
	});
	announced.should.equal(true);
	discovered.should.equal(true);
}

// The replicate job is the only thing here that acts on its own: nobody asks for
// this push, a timer does.
@("kad: the replicate job pushes a stored record on its own")
unittest
{
	ubyte[] recKey = [0x10, 0x20, 0x30];
	bool replicated;
	onLoop({
		auto b = makeNode();
		scope (exit)
			b.close();
		auto a = makeNode();
		scope (exit)
			a.close();
		a.kad.addAddress(b.id, b.addr);
		a.kad.store.put(Record(RecordKey.from(recKey), [7, 7, 7]));
		a.kad.runJobs(200.msecs, 1.hours, 1.hours, 48.hours);

		immutable deadline = MonoTime.currTime + 3.seconds;
		while (b.kad.store.get(RecordKey.from(recKey)) is null && MonoTime.currTime < deadline)
			sleep(20.msecs);
		replicated = b.kad.store.get(RecordKey.from(recKey)) !is null;
	});
	replicated.should.equal(true);
}

// An expiry that does not survive the wire is worse than none: the record looks
// permanent to everyone who fetched it.
@("kad: a record's expiry survives the put/get round-trip")
unittest
{
	ubyte[] recKey = [0x77, 0x88];
	bool hasExpiry, plausible;
	onLoop({
		auto b = makeNode();
		scope (exit)
			b.close();
		auto a = makeNode();
		scope (exit)
			a.close();
		a.kad.addAddress(b.id, b.addr);

		auto rec = Record(RecordKey.from(recKey), [1, 2]);
		rec.hasExpires = true;
		rec.expires = MonoTime.currTime + 100.seconds;
		a.kad.putRecord(rec);

		auto g = makeNode();
		scope (exit)
			g.close();
		g.kad.addAddress(b.id, b.addr);
		if (auto got = g.kad.getRecord(recKey))
		{
			hasExpiry = got.hasExpires;
			plausible = got.hasExpires && got.expires > MonoTime.currTime + 50.seconds;
		}
	});
	hasExpiry.should.equal(true);
	plausible.should.equal(true); // and it did not arrive already expired
}

// Bootstrap is what turns one known address into a populated routing table.
@("kad: bootstrap grows the routing table from one entry point")
unittest
{
	size_t tableSize;
	bool allDiscovered;
	onLoop({
		auto r = makeNode();
		scope (exit)
			r.close();

		// Three peers the rendezvous node knows about, and A does not.
		Node[] peers;
		scope (exit)
			foreach (p; peers)
				p.close();
		foreach (i; 0 .. 3)
		{
			auto p = makeNode();
			peers ~= p;
			r.kad.addAddress(p.id, p.addr);
		}

		auto a = makeNode();
		scope (exit)
			a.close();
		a.kad.addAddress(r.id, r.addr);

		tableSize = a.kad.bootstrap();
		allDiscovered = true;
		foreach (p; peers)
			if (!a.kad.table.contains(Key.fromPeer(p.id)))
				allDiscovered = false;
	});
	tableSize.should.be.greaterThan(0UL);
	allDiscovered.should.equal(true); // every peer R knew, A now knows too
}
