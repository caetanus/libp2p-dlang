/**
 * The iterative lookup, in two halves.
 *
 * `ClosestPeersIter` is the algorithm with its state written down: which peers
 * are known, sorted by distance to the target; which are being contacted, have
 * answered, failed or timed out; when the search has converged. It does no
 * I/O. `runQuery` is the driver: α fibers each ask the iterator for the next
 * peer, contact it with the caller's function, and report back, so α requests
 * are genuinely in flight at once and never more. The caller sees one blocking
 * call that returns the closest peers found.
 *
 * `FixedPeersIter` is the degenerate case — a known set, contacted once each —
 * used to write a record to the peers a lookup returned.
 */
module libp2p.protocol.kad.query;

import core.time : Duration, MonoTime, seconds, msecs;
import std.algorithm.sorting : sort;

import vibe.core.sync : LocalManualEvent, createManualEvent;
import vibe.core.task : InterruptException;

import libp2p.core.peer_id : PeerId;
import libp2p.protocol.kad.bucket : kValue;
import libp2p.protocol.kad.key : Key, Distance;
import libp2p.util.select : waitAll;

enum Duration peerTimeout = 10.seconds;

enum IterStateKind
{
	waiting, /// a peer to contact (if `hasPeer`), or nothing new right now
	waitingAtCapacity, /// as many in flight as allowed
	finished,
}

struct IterState
{
	IterStateKind kind;
	bool hasPeer;
	PeerId peer;
}

private enum PeerState
{
	notContacted,
	waiting,
	succeeded,
	failed,
	unresponsive,
}

private struct Entry
{
	Distance distance;
	PeerId peer;
	PeerState state;
	MonoTime timeout;
}

final class ClosestPeersIter
{
	private Key target;
	private Entry[] peers; // sorted by distance, ascending
	private size_t parallelism, numResults;
	private size_t numWaiting_;

	private enum State
	{
		iterating,
		stalled,
		finished,
	}

	private State state;
	private size_t noProgress;

	this(Key target, PeerId[] known, size_t parallelism, size_t numResults)
	{
		this.target = target;
		this.parallelism = parallelism;
		this.numResults = numResults;
		foreach (p; known)
		{
			if (peers.length >= kValue)
				break;
			insert(p);
		}
	}

	size_t numWaiting() const @safe pure nothrow
	{
		return numWaiting_;
	}

	bool isFinished() const @safe pure nothrow
	{
		return state == State.finished;
	}

	/// Stop handing out peers. Contacts in flight may still report.
	void finish() @safe pure nothrow
	{
		state = State.finished;
	}

	IterState next(MonoTime now)
	{
		if (state == State.finished)
			return IterState(IterStateKind.finished);

		// Results counted so far; null once a closer peer is still pending, since
		// the search can only finish when `numResults` of the closest answered.
		bool counting = true;
		size_t count;
		immutable atCapacity = this.atCapacity;

		foreach (ref e; peers)
		{
			final switch (e.state)
			{
			case PeerState.waiting:
				if (now >= e.timeout)
				{
					numWaiting_--;
					e.state = PeerState.unresponsive;
				}
				else if (atCapacity)
					return IterState(IterStateKind.waitingAtCapacity);
				else
					counting = false;
				break;
			case PeerState.succeeded:
				if (counting && ++count >= numResults)
				{
					state = State.finished;
					return IterState(IterStateKind.finished);
				}
				break;
			case PeerState.notContacted:
				if (atCapacity)
					return IterState(IterStateKind.waitingAtCapacity);
				e.state = PeerState.waiting;
				e.timeout = now + peerTimeout;
				numWaiting_++;
				return IterState(IterStateKind.waiting, true, e.peer);
			case PeerState.unresponsive:
			case PeerState.failed:
				break;
			}
		}

		if (numWaiting_ > 0)
			return IterState(IterStateKind.waiting, false);
		state = State.finished;
		return IterState(IterStateKind.finished);
	}

	bool onSuccess(PeerId peer, PeerId[] closer)
	{
		if (state == State.finished)
			return false;
		auto e = find(peer);
		if (e is null)
			return false;
		switch (e.state)
		{
		case PeerState.waiting:
			numWaiting_--;
			e.state = PeerState.succeeded;
			break;
		case PeerState.unresponsive:
			e.state = PeerState.succeeded;
			break;
		default:
			return false;
		}

		immutable numBefore = peers.length;
		bool progress;
		foreach (c; closer)
		{
			immutable d = Key.fromPeer(c).distance(target);
			if (find(c) is null)
				insert(c);
			// Progress: the newcomer is the closest seen, or we have not yet
			// accumulated enough peers to speak of convergence.
			progress = peers[0].distance == d || numBefore < numResults;
		}

		final switch (state)
		{
		case State.iterating:
			noProgress = progress ? 0 : noProgress + 1;
			if (noProgress >= parallelism)
				state = State.stalled;
			break;
		case State.stalled:
			if (progress)
			{
				state = State.iterating;
				noProgress = 0;
			}
			break;
		case State.finished:
			break;
		}
		return true;
	}

	bool onFailure(PeerId peer)
	{
		if (state == State.finished)
			return false;
		auto e = find(peer);
		if (e is null)
			return false;
		switch (e.state)
		{
		case PeerState.waiting:
			numWaiting_--;
			e.state = PeerState.failed;
			return true;
		case PeerState.unresponsive:
			e.state = PeerState.failed;
			return true;
		default:
			return false;
		}
	}

	/// The closest peers that answered, up to `numResults`, closest first.
	PeerId[] intoResult()
	{
		PeerId[] out_;
		foreach (ref e; peers)
		{
			if (e.state != PeerState.succeeded)
				continue;
			out_ ~= e.peer;
			if (out_.length >= numResults)
				break;
		}
		return out_;
	}

	private bool atCapacity() const @safe pure nothrow
	{
		final switch (state)
		{
		case State.stalled:
			// A stalled search fans out to break the deadlock.
			return numWaiting_ >= (numResults > parallelism ? numResults : parallelism);
		case State.iterating:
			return numWaiting_ >= parallelism;
		case State.finished:
			return true;
		}
	}

	private Entry* find(PeerId peer)
	{
		foreach (ref e; peers)
			if (e.peer == peer)
				return &e;
		return null;
	}

	private void insert(PeerId peer)
	{
		immutable d = Key.fromPeer(peer).distance(target);
		size_t pos = peers.length;
		foreach (i, ref e; peers)
			if (d < e.distance)
			{
				pos = i;
				break;
			}
		peers = peers[0 .. pos] ~ Entry(d, peer, PeerState.notContacted) ~ peers[pos .. $];
	}
}

final class FixedPeersIter
{
	private PeerId[] pending;
	private PeerId[] succeeded, failed;
	private size_t parallelism;
	private size_t numWaiting_;
	private bool finished;

	this(PeerId[] peers, size_t parallelism)
	{
		this.pending = peers.dup;
		this.parallelism = parallelism;
		if (peers.length == 0)
			finished = true;
	}

	bool isFinished() const @safe pure nothrow
	{
		return finished;
	}

	void finish() @safe pure nothrow
	{
		finished = true;
	}

	IterState next()
	{
		if (finished)
			return IterState(IterStateKind.finished);
		if (numWaiting_ >= parallelism)
			return IterState(IterStateKind.waitingAtCapacity);
		if (pending.length > 0)
		{
			auto p = pending[0];
			pending = pending[1 .. $];
			numWaiting_++;
			return IterState(IterStateKind.waiting, true, p);
		}
		if (numWaiting_ > 0)
			return IterState(IterStateKind.waiting, false);
		finished = true;
		return IterState(IterStateKind.finished);
	}

	bool onSuccess(PeerId peer)
	{
		if (finished)
			return false;
		numWaiting_--;
		succeeded ~= peer;
		return true;
	}

	bool onFailure(PeerId peer)
	{
		if (finished)
			return false;
		numWaiting_--;
		failed ~= peer;
		return true;
	}

	PeerId[] intoResult()
	{
		return succeeded.dup;
	}
}

/**
 * Drive `it` with `parallelism` fibers, each contacting one peer at a time
 * through `contact`, which returns the closer peers that peer reported and
 * throws on failure. Returns when the search has converged or `deadline` has
 * passed (contacts in flight finish first; no fiber outlives the call).
 */
PeerId[] runQuery(ClosestPeersIter it, size_t parallelism, PeerId[] delegate(PeerId) contact,
	Duration deadline = Duration.zero)
{
	auto changed = createManualEvent();
	immutable end = deadline > Duration.zero ? MonoTime.currTime + deadline : MonoTime.max;

	void worker()
	{
		auto seen = changed.emitCount;
		for (;;)
		{
			immutable now = MonoTime.currTime;
			if (now >= end)
				it.finish();
			auto s = it.next(now);
			if (s.kind == IterStateKind.finished)
				return;
			if (s.hasPeer)
			{
				PeerId[] closer;
				bool ok;
				try
				{
					closer = contact(s.peer);
					ok = true;
				}
				catch (InterruptException e)
					throw e; // the owner is stopping the query, not a peer timeout
				catch (Exception)
				{
				} // the peer did not answer; the iterator records it and moves on
				if (ok)
					it.onSuccess(s.peer, closer);
				else
					it.onFailure(s.peer);
				changed.emit();
				seen = changed.emitCount;
				continue;
			}
			// Nothing to hand out yet: wait for a result to land, or for the next
			// tick so peer timeouts are noticed.
			seen = changed.wait(100.msecs, seen);
		}
	}

	void delegate()[] workers;
	foreach (_; 0 .. parallelism)
		workers ~= &worker;
	waitAll(workers);
	return it.intoResult;
}

/// The same driver for a fixed set: `contact` returns nothing, throws on failure.
PeerId[] runFixed(FixedPeersIter it, size_t parallelism, void delegate(PeerId) contact)
{
	auto changed = createManualEvent();

	void worker()
	{
		auto seen = changed.emitCount;
		for (;;)
		{
			auto s = it.next();
			if (s.kind == IterStateKind.finished)
				return;
			if (s.hasPeer)
			{
				bool ok;
				try
				{
					contact(s.peer);
					ok = true;
				}
				catch (InterruptException e)
					throw e; // the owner is stopping the query, not a peer timeout
				catch (Exception)
				{
				}
				if (ok)
					it.onSuccess(s.peer);
				else
					it.onFailure(s.peer);
				changed.emit();
				seen = changed.emitCount;
				continue;
			}
			// A fixed set has no per-peer timeout, so there is nothing to poll for:
			// wait for another worker's result rather than spinning every 100ms.
			seen = changed.wait(seen);
		}
	}

	void delegate()[] workers;
	foreach (_; 0 .. parallelism)
		workers ~= &worker;
	waitAll(workers);
	return it.intoResult;
}
