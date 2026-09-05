/**
 * Connection limits as leases.
 *
 * A slot is a claim that must be given back, so it is a struct with a
 * destructor: a pending lease lives on the stack of the fiber doing the
 * handshake and is returned when that fiber leaves, however it leaves; an
 * established lease is owned by the connection and returned when it closes.
 * The limiter never has to be told about a failure, because a failure is an
 * unwind and the unwind returns the slot.
 *
 * A limit of 0 means unlimited. The check runs before counting, so a limit of
 * N admits exactly N.
 */
module libp2p.swarm.limiter;

import libp2p.core.peer_id : PeerId;
import libp2p.core.upgrade : Endpoint;

enum LimitKind
{
	pendingInbound,
	pendingOutbound,
	establishedInbound,
	establishedOutbound,
	establishedTotal,
	establishedPerPeer,
}

struct Limits
{
	uint pendingInbound;
	uint pendingOutbound;
	uint establishedInbound;
	uint establishedOutbound;
	uint establishedTotal;
	uint establishedPerPeer;

	/// True if one more of `kind` fits given `current` already counted.
	bool admits(LimitKind kind, uint current) const @safe pure nothrow
	{
		immutable limit = of(kind);
		return limit == 0 || current < limit;
	}

	uint of(LimitKind kind) const @safe pure nothrow
	{
		final switch (kind)
		{
		case LimitKind.pendingInbound:
			return pendingInbound;
		case LimitKind.pendingOutbound:
			return pendingOutbound;
		case LimitKind.establishedInbound:
			return establishedInbound;
		case LimitKind.establishedOutbound:
			return establishedOutbound;
		case LimitKind.establishedTotal:
			return establishedTotal;
		case LimitKind.establishedPerPeer:
			return establishedPerPeer;
		}
	}
}

final class LimitExceeded : Exception
{
	LimitKind kind;

	this(LimitKind kind, string file = __FILE__, size_t line = __LINE__) @safe pure
	{
		import std.conv : to;

		this.kind = kind;
		super("connection limit reached: " ~ kind.to!string, file, line);
	}
}

/// A slot in the limiter. Returned when it goes out of scope or on `release`.
struct Lease
{
	private Limiter limiter;
	private Endpoint role;
	private bool established;
	private PeerId peer;

	@disable this(this);

	~this() nothrow
	{
		release();
	}

	bool active() const @safe pure nothrow
	{
		return limiter !is null;
	}

	void release() nothrow
	{
		if (limiter is null)
			return;
		limiter.give(role, established, peer);
		limiter = null;
	}
}

final class Limiter
{
	private Limits limits;
	private uint pendingIn, pendingOut, estIn, estOut;
	private uint[PeerId] perPeer;

	this(Limits limits = Limits.init)
	{
		this.limits = limits;
	}

	/// A slot for a connection being set up. Throws `LimitExceeded`.
	Lease pending(Endpoint role)
	{
		if (role == Endpoint.listener)
		{
			check(LimitKind.pendingInbound, pendingIn);
			pendingIn++;
		}
		else
		{
			check(LimitKind.pendingOutbound, pendingOut);
			pendingOut++;
		}
		return Lease(this, role, false, PeerId.init);
	}

	/// A slot for a connection that completed its handshake. Throws `LimitExceeded`.
	Lease established(Endpoint role, PeerId peer)
	{
		check(LimitKind.establishedTotal, estIn + estOut);
		check(role == Endpoint.listener ? LimitKind.establishedInbound : LimitKind.establishedOutbound,
			role == Endpoint.listener ? estIn : estOut);
		check(LimitKind.establishedPerPeer, count(peer));
		if (role == Endpoint.listener)
			estIn++;
		else
			estOut++;
		perPeer[peer] = count(peer) + 1;
		return Lease(this, role, true, peer);
	}

	uint establishedTotal() const @safe pure nothrow
	{
		return estIn + estOut;
	}

	uint establishedInbound() const @safe pure nothrow
	{
		return estIn;
	}

	uint establishedOutbound() const @safe pure nothrow
	{
		return estOut;
	}

	uint pendingInbound() const @safe pure nothrow
	{
		return pendingIn;
	}

	uint pendingOutbound() const @safe pure nothrow
	{
		return pendingOut;
	}

	uint establishedTo(PeerId peer) const @safe pure nothrow
	{
		return count(peer);
	}

	private uint count(PeerId peer) const @safe pure nothrow
	{
		if (auto n = peer in perPeer)
			return *n;
		return 0;
	}

	private void check(LimitKind kind, uint current)
	{
		if (!limits.admits(kind, current))
			throw new LimitExceeded(kind);
	}

	private void give(Endpoint role, bool established, PeerId peer) nothrow
	{
		if (!established)
		{
			if (role == Endpoint.listener)
				pendingIn--;
			else
				pendingOut--;
			return;
		}
		if (role == Endpoint.listener)
			estIn--;
		else
			estOut--;
		immutable n = count(peer);
		if (n <= 1)
			perPeer.remove(peer);
		else
			perPeer[peer] = n - 1;
	}
}
