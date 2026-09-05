/**
 * One k-bucket: up to `capacity` nodes at the same distance range, ordered
 * least-recently connected first, with disconnected nodes always ahead of
 * connected ones. A full bucket does not evict on sight: a connected newcomer
 * waits as `pending` while the least-recently connected node (the head) gets a
 * grace period to prove it is still there. If it reconnects the newcomer is
 * dropped; if the timeout passes the head is evicted and the newcomer takes the
 * most-recently connected slot.
 */
module libp2p.protocol.kad.bucket;

import core.time : Duration, MonoTime, seconds;

import libp2p.protocol.kad.key : Key;

enum size_t kValue = 20;
enum Duration pendingTimeout = 60.seconds;

enum NodeStatus
{
	connected,
	disconnected,
}

enum InsertKind
{
	inserted,
	pending,
	full,
}

struct InsertResult
{
	InsertKind kind;
	/// For `pending`: the disconnected head whose slot the newcomer will take.
	Key disconnected;
}

struct Node(T)
{
	Key key;
	T value;
}

alias Clock = MonoTime delegate() @safe nothrow;

struct KBucket(T)
{
	private Node!T[] nodes;
	private size_t capacity;
	/// Index of the first connected node; `nodes.length` if none.
	private size_t firstConnected;

	private bool hasPending;
	private Node!T pendingNode;
	private NodeStatus pendingStatus;
	private MonoTime pendingReplace;

	private Clock clock;

	this(size_t capacity)
	{
		this.capacity = capacity;
	}

	/// Inject a clock (tests). Null means the real one.
	void testClock(Clock c) @safe nothrow
	{
		clock = c;
	}

	private MonoTime now() @safe nothrow
	{
		return clock is null ? MonoTime.currTime : clock();
	}

	size_t numEntries() const @safe pure nothrow
	{
		return nodes.length;
	}

	Node!T nodeAt(size_t i)
	{
		return nodes[i];
	}

	NodeStatus status(size_t i) const @safe pure nothrow
	{
		return i >= firstConnected ? NodeStatus.connected : NodeStatus.disconnected;
	}

	bool contains(const Key key) const @safe pure nothrow
	{
		return position(key) >= 0;
	}

	bool hasPendingKey(const Key key) const @safe pure nothrow
	{
		return hasPending && pendingNode.key == key;
	}

	/// The value stored for `key`, or null.
	T* get(const Key key) @safe pure nothrow
	{
		immutable p = position(key);
		return p < 0 ? null : &nodes[p].value;
	}

	/// Give a pending node whose grace period has elapsed its slot. Returns true
	/// if something was inserted; `evicted` says whether a head went with it.
	bool applyPending(out Node!T inserted, out bool hasEvicted, out Node!T evicted)
	{
		if (!hasPending || now() < pendingReplace)
			return false;
		auto node = pendingNode;
		immutable status = pendingStatus;
		hasPending = false;

		if (nodes.length >= capacity)
		{
			if (firstConnected == 0)
				return false; // every node is connected: nothing to evict
			hasEvicted = true;
			evicted = nodes[0];
			nodes = nodes[1 .. $];
			firstConnected--;
		}
		place(node, status);
		inserted = node;
		return true;
	}

	InsertResult insert(Node!T node, NodeStatus status)
	{
		Node!T i, e;
		bool ev;
		cast(void) applyPending(i, ev, e);

		if (nodes.length < capacity)
		{
			place(node, status);
			return InsertResult(InsertKind.inserted);
		}
		// Full. A connected newcomer may wait for a disconnected head to lapse.
		if (status == NodeStatus.connected && !hasPending && firstConnected > 0)
		{
			hasPending = true;
			pendingNode = node;
			pendingStatus = status;
			pendingReplace = now() + pendingTimeout;
			return InsertResult(InsertKind.pending, nodes[0].key);
		}
		return InsertResult(InsertKind.full);
	}

	/// Change a node's status, moving it to the right end of its group. A head
	/// that reconnects cancels the pending newcomer waiting for its slot.
	void update(const Key key, NodeStatus status)
	{
		immutable p = position(key);
		if (p < 0)
			return;
		auto node = nodes[p];
		if (p == 0 && status == NodeStatus.connected)
			hasPending = false;
		removeAt(p);
		place(node, status);
	}

	/// Drop a node outright.
	bool remove(const Key key)
	{
		immutable p = position(key);
		if (p < 0)
			return false;
		removeAt(p);
		return true;
	}

	/// Every node, least-recently connected first.
	Node!T[] entries() @safe pure nothrow
	{
		return nodes;
	}

	private long position(const Key key) const @safe pure nothrow
	{
		foreach (i, ref n; nodes)
			if (n.key == key)
				return i;
		return -1;
	}

	private void removeAt(size_t p)
	{
		nodes = nodes[0 .. p] ~ nodes[p + 1 .. $];
		if (p < firstConnected)
			firstConnected--;
	}

	/// Connected nodes go to the end; disconnected ones to the end of the
	/// disconnected group.
	private void place(Node!T node, NodeStatus status)
	{
		if (status == NodeStatus.connected)
			nodes ~= node;
		else
		{
			nodes = nodes[0 .. firstConnected] ~ node ~ nodes[firstConnected .. $];
			firstConnected++;
		}
	}
}
