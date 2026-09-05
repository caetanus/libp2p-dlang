/**
 * The message cache: the last `historyLength` heartbeats' worth of messages,
 * in windows, so IWANT can be served and IHAVE offered. Only the newest
 * `gossip` windows are offered as gossip; every window can be served.
 */
module libp2p.protocol.gossipsub.mcache;

import std.algorithm.searching : canFind;

import libp2p.core.peer_id : PeerId;
import libp2p.protocol.gossipsub.wire : Message;

private struct Entry
{
	string id;
	string topic;
}

private struct Cached
{
	Message message;
	bool validated;
	PeerId[] iwantedBy; /// who has asked, and how often (one entry per ask)
}

struct MessageCache
{
	private size_t gossip;
	private Entry[][] history;
	private Cached[string] msgs;

	this(size_t gossip, size_t historyLength)
	{
		assert(gossip <= historyLength);
		this.gossip = gossip;
		history = new Entry[][historyLength];
	}

	/// Store a message in the current window. Returns false if it was already there.
	bool put(string id, Message m, bool validated)
	{
		if (id in msgs)
			return false;
		msgs[id] = Cached(m, validated);
		history[0] ~= Entry(id, m.topic);
		return true;
	}

	/// Mark a message validated (it may be gossiped from now on).
	void validate(string id)
	{
		if (auto c = id in msgs)
			c.validated = true;
	}

	bool contains(string id) const @safe pure nothrow
	{
		return (id in msgs) !is null;
	}

	Message* get(string id)
	{
		auto c = id in msgs;
		return c is null ? null : &c.message;
	}

	/// The message, and how many times `peer` has asked for it including now;
	/// null if we do not have it.
	Message* getWithIwantCount(string id, PeerId peer, out size_t count)
	{
		auto c = id in msgs;
		if (c is null)
			return null;
		c.iwantedBy ~= peer;
		foreach (p; c.iwantedBy)
			if (p == peer)
				count++;
		return &c.message;
	}

	/// Ids of validated messages on `topic` within the gossip window.
	ubyte[][] gossipMessageIds(string topic)
	{
		ubyte[][] out_;
		foreach (window; history[0 .. gossip])
			foreach (e; window)
				if (e.topic == topic)
					if (auto c = e.id in msgs)
						if (c.validated)
							out_ ~= cast(ubyte[]) e.id.dup;
		return out_;
	}

	/// Age every window by one heartbeat; the oldest falls off.
	void shift()
	{
		foreach (e; history[$ - 1])
			msgs.remove(e.id);
		foreach_reverse (i; 1 .. history.length)
			history[i] = history[i - 1];
		history[0] = null;
	}

	void remove(string id)
	{
		msgs.remove(id);
	}

	size_t windowLen(size_t i) const @safe pure nothrow
	{
		return history[i].length;
	}

	size_t messageCount() const @safe pure nothrow
	{
		return msgs.length;
	}
}
