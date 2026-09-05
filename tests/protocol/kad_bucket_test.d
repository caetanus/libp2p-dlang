module tests.protocol.kad_bucket_test;

import core.time : MonoTime, Duration, seconds;
import std.random : Random, uniform;

import libp2p.crypto.keys : Keypair;
import libp2p.core.peer_id : PeerId;
import libp2p.protocol.kad.key : Key;
import libp2p.protocol.kad.bucket;
import fluent.asserts;

private Key randomKey()
{
	return Key.fromPeer(PeerId.fromPublicKey(Keypair.generateEd25519.publicKey));
}

private Node!int mk()
{
	return Node!int(randomKey(), 0);
}

// Laundered from rust `kbucket/bucket.rs::tests::full_bucket`: a full bucket of
// disconnected nodes rejects more disconnected ones, queues each connected
// newcomer as pending (naming the head to check), and on timeout evicts the head
// and installs the newcomer as most-recently connected.
@("kad bucket: full bucket queues connected as pending then evicts the head")
unittest
{
	auto bucket = KBucket!int(kValue);
	MonoTime base = MonoTime.currTime;
	Duration off;
	bucket.testClock(() @safe nothrow => base + off);

	foreach (_; 0 .. kValue)
		bucket.insert(mk(), NodeStatus.disconnected).kind.should.equal(InsertKind.inserted);
	bucket.numEntries.should.equal(kValue);

	// Another disconnected node cannot fit.
	bucket.insert(mk(), NodeStatus.disconnected).kind.should.equal(InsertKind.full);

	foreach (i; 0 .. kValue)
	{
		auto head = bucket.nodeAt(0);
		bucket.status(0).should.equal(NodeStatus.disconnected);

		auto node = mk();
		auto pr = bucket.insert(node, NodeStatus.connected);
		pr.kind.should.equal(InsertKind.pending);
		(pr.disconnected == head.key).should.equal(true);

		// A second connected node fails (pending slot taken).
		bucket.insert(mk(), NodeStatus.connected).kind.should.equal(InsertKind.full);
		bucket.hasPendingKey(node.key).should.equal(true);

		// After the timeout, apply: evict the head, install the newcomer.
		off += 61.seconds;
		Node!int inserted, evicted;
		bool hasEvicted;
		bucket.applyPending(inserted, hasEvicted, evicted).should.equal(true);
		(inserted.key == node.key).should.equal(true);
		hasEvicted.should.equal(true);
		(evicted.key == head.key).should.equal(true);
		(bucket.nodeAt(bucket.numEntries - 1).key == node.key).should.equal(true);
		bucket.status(bucket.numEntries - 1).should.equal(NodeStatus.connected);
	}

	bucket.numEntries.should.equal(kValue);
	// Now full of connected nodes: a connected node fails outright.
	bucket.insert(mk(), NodeStatus.connected).kind.should.equal(InsertKind.full);
}

// Laundered from `full_bucket_discard_pending`: if the head reconnects while a
// node is pending, the pending node is discarded and the head becomes the most-
// recently connected node.
@("kad bucket: reconnecting the head discards the pending node")
unittest
{
	auto bucket = KBucket!int(kValue);
	foreach (_; 0 .. kValue)
		bucket.insert(mk(), NodeStatus.disconnected);

	auto head = bucket.nodeAt(0);
	auto node = mk();
	bucket.insert(node, NodeStatus.connected).kind.should.equal(InsertKind.pending);
	bucket.hasPendingKey(node.key).should.equal(true);

	bucket.update(head.key, NodeStatus.connected);

	bucket.hasPendingKey(node.key).should.equal(false);
	bucket.contains(node.key).should.equal(false);
	(bucket.nodeAt(bucket.numEntries - 1).key == head.key).should.equal(true);
	bucket.status(bucket.numEntries - 1).should.equal(NodeStatus.connected);
}

// Laundered from `ordering`: disconnected nodes always precede connected ones
// (the bucket keeps the two status groups partitioned).
@("kad bucket: disconnected nodes precede connected ones")
unittest
{
	auto rng = Random(12_345);
	auto bucket = KBucket!int(kValue);
	foreach (_; 0 .. 60)
	{
		immutable st = uniform(0, 2, rng) ? NodeStatus.connected : NodeStatus.disconnected;
		bucket.insert(mk(), st);
	}
	bool seenConnected;
	foreach (i; 0 .. bucket.numEntries)
	{
		if (bucket.status(i) == NodeStatus.connected)
			seenConnected = true;
		else
			seenConnected.should.equal(false); // no disconnected after a connected
	}
}

// Laundered from `test_custom_bucket_size`.
@("kad bucket: honours a custom capacity")
unittest
{
	foreach (size; [size_t(2), size_t(20), size_t(200)])
	{
		auto bucket = KBucket!int(size);
		foreach (_; 0 .. size)
			bucket.insert(mk(), NodeStatus.disconnected).kind.should.equal(InsertKind.inserted);
		bucket.numEntries.should.equal(size);
		bucket.insert(mk(), NodeStatus.disconnected).kind.should.equal(InsertKind.full);
	}
}

// Laundered from rust `kbucket/bucket.rs::tests::bucket_update`: updating a
// node's status moves it to the correct position (end for Connected, just before
// the first connected for Disconnected) while preserving the relative order and
// status of every other node.
@("kad bucket: update repositions a node and preserves the rest")
unittest
{
	import std.algorithm : count;

	auto rng = Random(4242);
	foreach (trial; 0 .. 50)
	{
		auto bucket = KBucket!int(kValue);
		foreach (_; 0 .. uniform(2, kValue + 1, rng))
		{
			auto st = uniform(0, 2, rng) ? NodeStatus.connected : NodeStatus.disconnected;
			bucket.insert(mk(), st); // insert() places into the valid partition
		}
		immutable num = bucket.numEntries;
		if (num == 0)
			continue;

		Key[] keys;
		NodeStatus[] status;
		foreach (i; 0 .. num)
		{
			keys ~= bucket.nodeAt(i).key;
			status ~= bucket.status(i);
		}

		immutable pos = uniform(0, num, rng);
		auto key = keys[pos];
		immutable newStatus = uniform(0, 2, rng) ? NodeStatus.connected : NodeStatus.disconnected;
		immutable keyWasConnected = status[pos] == NodeStatus.connected;

		bucket.update(key, newStatus);

		// Expected position of the moved node.
		size_t expectedPos;
		if (newStatus == NodeStatus.connected)
			expectedPos = num - 1;
		else
		{
			immutable connAfter = status.count(NodeStatus.connected) - (keyWasConnected ? 1 : 0);
			expectedPos = (num - connAfter) - 1;
		}

		// Build the expected (key,status) sequence: remove `key`, reinsert at pos.
		auto ek = keys.dup;
		auto es = status.dup;
		ek = ek[0 .. pos] ~ ek[pos + 1 .. $];
		es = es[0 .. pos] ~ es[pos + 1 .. $];
		ek = ek[0 .. expectedPos] ~ key ~ ek[expectedPos .. $];
		es = es[0 .. expectedPos] ~ newStatus ~ es[expectedPos .. $];

		foreach (i; 0 .. num)
		{
			(bucket.nodeAt(i).key == ek[i]).should.equal(true);
			bucket.status(i).should.equal(es[i]);
		}
	}
}
