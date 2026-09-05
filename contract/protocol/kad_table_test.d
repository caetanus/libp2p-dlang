module tests.protocol.kad_table_test;

import std.algorithm : sort;

import libp2p.crypto.keys : Keypair;
import libp2p.core.peer_id : PeerId;
import libp2p.protocol.kad.key : Key;
import libp2p.protocol.kad.bucket : NodeStatus, InsertKind;
import libp2p.protocol.kad.table : KBucketsTable;
import fluent.asserts;

private Key randomKey()
{
	return Key.fromPeer(PeerId.fromPublicKey(Keypair.generateEd25519.publicKey));
}

// Laundered from rust `kbucket.rs::tests::entry_self`: the local key has
// distance 0 and belongs to no bucket, so it can't be inserted.
@("kad table: the local key belongs to no bucket")
unittest
{
	auto local = randomKey();
	auto table = KBucketsTable!int(local);
	table.bucketIndex(local).should.equal(-1L);
	table.insert(local, 0, NodeStatus.connected).kind.should.equal(InsertKind.full);
	table.count.should.equal(0);
}

// Laundered from `entry_inserted`: an inserted key is present and is the sole
// result of closestKeys.
@("kad table: an inserted key is found by closest")
unittest
{
	auto local = randomKey();
	auto other = randomKey();
	auto table = KBucketsTable!int(local);
	table.insert(other, 0, NodeStatus.connected).kind.should.equal(InsertKind.inserted);
	table.contains(other).should.equal(true);

	auto res = table.closestKeys(other);
	res.length.should.equal(1);
	(res[0] == other).should.equal(true);
}

// Laundered from `closest`: closestKeys(target) must equal a full-table scan
// sorted by distance to the target, for many random targets.
@("kad table: closestKeys matches a full-table distance sort")
unittest
{
	auto local = randomKey();
	auto table = KBucketsTable!int(local);

	Key[] inserted;
	while (inserted.length < 100)
	{
		auto k = randomKey();
		if (table.insert(k, 0, NodeStatus.connected).kind == InsertKind.inserted)
			inserted ~= k;
	}

	foreach (_; 0 .. 10)
	{
		auto target = randomKey();
		auto keys = table.closestKeys(target);

		auto expected = inserted.dup;
		expected.sort!((a, b) => a.distance(target) < b.distance(target));

		keys.length.should.equal(expected.length);
		foreach (i; 0 .. keys.length)
			(keys[i] == expected[i]).should.equal(true);
	}
}

// Laundered from rust `kbucket.rs::tests::applied_pending`: a connected node
// inserted into a full bucket becomes pending; once the head's pending timeout
// elapses, the NEXT table access applies it lazily — evicting the disconnected
// head and installing the pending node.
@("kad table: a pending node is applied lazily on the next access after timeout")
unittest
{
	import core.time : MonoTime, Duration, seconds;

	auto local = randomKey();
	auto table = KBucketsTable!int(local, 2); // bucket size 2
	MonoTime base = MonoTime.currTime;
	Duration off;
	table.testClock(() @safe nothrow => base + off);

	// Collect three keys that fall into the same bucket.
	Key[] group;
	long targetBucket = -1;
	while (group.length < 3)
	{
		auto k = randomKey();
		immutable idx = table.bucketIndex(k);
		if (idx == -1)
			continue;
		if (targetBucket == -1)
		{
			targetBucket = idx;
			group ~= k;
		}
		else if (idx == targetBucket)
			group ~= k;
	}

	auto head = group[0], second = group[1], pending = group[2];
	// Fill the bucket with two disconnected nodes (head is the oldest).
	table.insert(head, 0, NodeStatus.disconnected).kind.should.equal(InsertKind.inserted);
	table.insert(second, 0, NodeStatus.disconnected).kind.should.equal(InsertKind.inserted);
	// A connected newcomer into the full bucket is queued as pending.
	table.insert(pending, 0, NodeStatus.connected).kind.should.equal(InsertKind.pending);

	// Before the timeout the pending node is not yet in the table.
	table.contains(pending).should.equal(false);
	table.contains(head).should.equal(true);

	// Past the pending timeout, the next access applies the pending node.
	off = 61.seconds;
	table.contains(pending).should.equal(true); // applied lazily on access
	table.contains(head).should.equal(false); // head evicted
	table.contains(second).should.equal(true);
}
