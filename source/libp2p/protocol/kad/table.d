/**
 * The routing table: 256 k-buckets indexed by the most significant bit of the
 * XOR distance to the local key. The local key has distance zero and belongs to
 * no bucket. Pending newcomers are applied lazily, on the next access to their
 * bucket, the way rust-libp2p does it.
 */
module libp2p.protocol.kad.table;

import std.algorithm.sorting : sort;

import libp2p.protocol.kad.bucket;
import libp2p.protocol.kad.key;

struct KBucketsTable(T)
{
	private Key local;
	private KBucket!T[256] buckets;
	private Clock clock;

	this(Key local, size_t bucketSize = kValue)
	{
		this.local = local;
		foreach (ref b; buckets)
			b = KBucket!T(bucketSize);
	}

	void testClock(Clock c) @safe nothrow
	{
		clock = c;
		foreach (ref b; buckets)
			b.testClock(c);
	}

	Key localKey() @safe pure nothrow
	{
		return local;
	}

	/// Which bucket `key` falls in; -1 for the local key.
	long bucketIndex(const Key key) const @safe pure nothrow @nogc
	{
		return local.distance(key).ilog2;
	}

	InsertResult insert(Key key, T value, NodeStatus status)
	{
		immutable i = bucketIndex(key);
		if (i < 0)
			return InsertResult(InsertKind.full);
		if (auto v = buckets[i].get(key))
		{
			*v = value;
			buckets[i].update(key, status);
			return InsertResult(InsertKind.inserted);
		}
		return buckets[i].insert(Node!T(key, value), status);
	}

	bool contains(const Key key)
	{
		immutable i = bucketIndex(key);
		if (i < 0)
			return false;
		settle(i);
		return buckets[i].contains(key);
	}

	T* get(const Key key)
	{
		immutable i = bucketIndex(key);
		if (i < 0)
			return null;
		settle(i);
		return buckets[i].get(key);
	}

	void update(const Key key, NodeStatus status)
	{
		immutable i = bucketIndex(key);
		if (i < 0)
			return;
		settle(i);
		buckets[i].update(key, status);
	}

	bool remove(const Key key)
	{
		immutable i = bucketIndex(key);
		if (i < 0)
			return false;
		return buckets[i].remove(key);
	}

	size_t count()
	{
		size_t n;
		foreach (i; 0 .. 256)
		{
			settle(i);
			n += buckets[i].numEntries;
		}
		return n;
	}

	/// Every key in the table, closest to `target` first.
	Key[] closestKeys(const ref Key target)
	{
		Key[] keys;
		foreach (i; 0 .. 256)
		{
			settle(i);
			foreach (ref n; buckets[i].entries)
				keys ~= n.key;
		}
		keys.sort!((a, b) => a.distance(target) < b.distance(target));
		return keys;
	}

	/// The `n` closest entries to `target`, with their values.
	Node!T[] closest(const ref Key target, size_t n)
	{
		Node!T[] all;
		foreach (i; 0 .. 256)
		{
			settle(i);
			all ~= buckets[i].entries;
		}
		all.sort!((a, b) => a.key.distance(target) < b.key.distance(target));
		return all.length > n ? all[0 .. n] : all;
	}

	/// Every entry, in bucket order.
	Node!T[] entries()
	{
		Node!T[] all;
		foreach (i; 0 .. 256)
		{
			settle(i);
			all ~= buckets[i].entries;
		}
		return all;
	}

	/// Bucket indices that hold at least one node.
	size_t[] occupiedBuckets()
	{
		size_t[] out_;
		foreach (i; 0 .. 256)
			if (buckets[i].numEntries > 0)
				out_ ~= i;
		return out_;
	}

	private void settle(size_t i)
	{
		Node!T ins, ev;
		bool hasEv;
		cast(void) buckets[i].applyPending(ins, hasEv, ev);
	}
}
