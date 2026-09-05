module tests.protocol.kad_query_test;

import core.time : MonoTime;

import libp2p.crypto.keys : Keypair;
import libp2p.core.peer_id : PeerId;
import libp2p.protocol.kad.key : Key;
import libp2p.protocol.kad.query;
import tests.util.loop : onLoop;
import fluent.asserts;

private PeerId rp()
{
	return PeerId.fromPublicKey(Keypair.generateEd25519.publicKey);
}

// The iterator hands out up to `parallelism` peers before signalling capacity,
// and finishes once `numResults` of the closest have succeeded.
@("kad query: yields alpha peers in parallel then finishes after numResults")
unittest
{
	PeerId[] known;
	foreach (_; 0 .. 5)
		known ~= rp();
	auto it = new ClosestPeersIter(Key.fromPeer(rp()), known, 3, 3);
	auto now = MonoTime.currTime;

	PeerId[] contacted;
	foreach (_; 0 .. 3)
	{
		auto s = it.next(now);
		s.kind.should.equal(IterStateKind.waiting);
		s.hasPeer.should.equal(true);
		contacted ~= s.peer;
	}
	it.numWaiting.should.equal(3UL);
	it.next(now).kind.should.equal(IterStateKind.waitingAtCapacity);

	foreach (p; contacted)
		it.onSuccess(p, null).should.equal(true);

	it.next(now).kind.should.equal(IterStateKind.finished);
	it.isFinished.should.equal(true);
	it.intoResult.length.should.equal(3UL);
}

// Peers learned via onSuccess become contactable in later rounds.
@("kad query: peers learned via onSuccess become contactable")
unittest
{
	auto seed = rp();
	auto it = new ClosestPeersIter(Key.fromPeer(rp()), [seed], 3, 20);
	auto now = MonoTime.currTime;

	auto s = it.next(now);
	s.hasPeer.should.equal(true);
	(s.peer == seed).should.equal(true);

	auto n1 = rp(), n2 = rp();
	it.onSuccess(seed, [n1, n2]).should.equal(true);

	auto s2 = it.next(now);
	s2.kind.should.equal(IterStateKind.waiting);
	s2.hasPeer.should.equal(true);
	(s2.peer == n1 || s2.peer == n2).should.equal(true);
}

// A failed peer stops counting towards parallelism and the search moves on.
@("kad query: a failed peer is skipped and frees capacity")
unittest
{
	auto it = new ClosestPeersIter(Key.fromPeer(rp()), [rp(), rp()], 1, 20);
	auto now = MonoTime.currTime;

	auto s = it.next(now);
	s.hasPeer.should.equal(true);
	it.numWaiting.should.equal(1UL);
	it.next(now).kind.should.equal(IterStateKind.waitingAtCapacity); // parallelism 1

	it.onFailure(s.peer).should.equal(true);
	it.numWaiting.should.equal(0UL);

	auto s2 = it.next(now);
	s2.hasPeer.should.equal(true);
	(s2.peer == s.peer).should.equal(false); // the other peer now
}

// A peer that doesn't answer within peer_timeout becomes unresponsive, freeing
// a parallelism slot.
@("kad query: an unresponsive peer frees a parallelism slot")
unittest
{
	import core.time : seconds;

	auto it = new ClosestPeersIter(Key.fromPeer(rp()), [rp(), rp()], 1, 20);
	MonoTime base = MonoTime.currTime;

	auto s = it.next(base);
	s.hasPeer.should.equal(true);
	it.numWaiting.should.equal(1UL);

	// Past the 10s timeout the waiting peer is dropped from the wait count. Note
	// `at_capacity` is captured at the top of `next`, so this call still reports
	// WaitingAtCapacity (rust semantics); the freed slot is used next call.
	auto later = base + 11.seconds;
	auto s2 = it.next(later);
	s2.kind.should.equal(IterStateKind.waitingAtCapacity);
	it.numWaiting.should.equal(0UL);

	auto s3 = it.next(later);
	s3.kind.should.equal(IterStateKind.waiting);
	s3.hasPeer.should.equal(true);
	(s3.peer == s.peer).should.equal(false); // the other peer now
}

// --- ported from rust closest.rs quickcheck properties ---

import core.time : seconds;
import std.algorithm : sort, map, all, count, canFind;
import std.array : array;
import std.random : Random, uniform;
import libp2p.protocol.kad.key : Distance;

private PeerId[] randomPeers(size_t n)
{
	PeerId[] ps;
	foreach (_; 0 .. n)
		ps ~= rp();
	return ps;
}

// Peers sorted by increasing distance to `target`.
private PeerId[] sortedByDistance(PeerId[] peers, Key target)
{
	auto ps = peers.dup;
	ps.sort!((a, b) => Key.fromPeer(a).distance(target) < Key.fromPeer(b).distance(target));
	return ps;
}

private bool isSorted(PeerId[] peers, Key target)
{
	foreach (i; 1 .. peers.length)
		if (Key.fromPeer(peers[i]).distance(target) < Key.fromPeer(peers[i - 1]).distance(target))
			return false;
	return true;
}

// rust `new_iter`: a fresh iterator has nothing in progress and no results, and
// hands out peers closest-first (distance-sorted).
@("kad query: a new iterator is empty and yields closest-first")
unittest
{
	foreach (it_; 0 .. 5)
	{
		auto known = randomPeers(uniform(1, 12));
		auto target = Key.fromPeer(rp());
		auto it = new ClosestPeersIter(target, known, 20, 20); // high α, all yielded
		auto now = MonoTime.currTime;

		it.numWaiting.should.equal(0UL);
		it.intoResult.length.should.equal(0UL);

		// Drain the peers, failing each, and record the order they were handed out.
		PeerId[] order;
		for (;;)
		{
			auto s = it.next(now);
			if (s.kind == IterStateKind.finished)
				break;
			if (!s.hasPeer)
				break;
			order ~= s.peer;
			it.onFailure(s.peer);
		}
		isSorted(order, target).should.equal(true); // closest-first
	}
}

// rust `without_success_try_up_to_k_peers`: with only failures the iterator
// contacts every seed peer (up to K) and then finishes.
@("kad query: with only failures, contacts up to K peers then finishes")
unittest
{
	foreach (it_; 0 .. 5)
	{
		auto known = randomPeers(uniform(1, 12));
		auto it = new ClosestPeersIter(Key.fromPeer(rp()), known, 3, 20);
		auto now = MonoTime.currTime;

		immutable expect = known.length < 20 ? known.length : 20;
		foreach (_; 0 .. expect)
		{
			auto s = it.next(now);
			s.kind.should.equal(IterStateKind.waiting);
			s.hasPeer.should.equal(true);
			it.onFailure(s.peer);
		}
		it.next(now).kind.should.equal(IterStateKind.finished);
	}
}

// rust `no_duplicates`: a "closer" peer reported by two different in-flight peers
// (and twice by the same peer) is only ever inserted once — so it is handed out
// for contact exactly once.
@("kad query: a closer peer reported twice is contacted only once")
unittest
{
	foreach (it_; 0 .. 5)
	{
		auto known = randomPeers(uniform(2, 8));
		auto target = Key.fromPeer(rp());
		auto it = new ClosestPeersIter(target, known, 20, 20); // never at capacity
		auto now = MonoTime.currTime;

		auto closer = rp();

		auto s1 = it.next(now);
		s1.hasPeer.should.equal(true);
		it.onSuccess(s1.peer, [closer]);
		it.onSuccess(s1.peer, [closer]); // duplicate from the same peer

		// Drive to completion; a second distinct peer also reports the same closer.
		// Count every time the closer is handed out for contact.
		size_t closerContacts;
		bool reportedAgain;
		for (;;)
		{
			auto s = it.next(now);
			if (s.kind == IterStateKind.finished || !s.hasPeer)
				break;
			if (s.peer == closer)
			{
				closerContacts++;
				it.onSuccess(s.peer, null);
			}
			else if (!reportedAgain)
			{
				reportedAgain = true;
				it.onSuccess(s.peer, [closer]); // second peer reports the closer
			}
			else
				it.onSuccess(s.peer, null);
		}
		closerContacts.should.equal(1UL); // inserted once ⇒ contacted exactly once
	}
}

// rust `timeout`: a peer that exceeds peer_timeout becomes Unresponsive; while
// the iterator is not yet finished, a late success from that peer still counts.
@("kad query: an unresponsive peer can still deliver a result")
unittest
{
	auto known = randomPeers(2);
	auto target = Key.fromPeer(rp());
	auto it = new ClosestPeersIter(target, known, 1, 20); // parallelism 1
	auto base = MonoTime.currTime;

	auto s = it.next(base);
	s.hasPeer.should.equal(true);
	auto slow = s.peer;

	// Past the peer timeout, advancing marks the slow peer Unresponsive. (This
	// call reports WaitingAtCapacity — at_capacity is captured at the top of
	// next() — but the peer's state has still transitioned.)
	auto later = base + 11.seconds;
	it.next(later);

	// With a second peer still to contact the iterator is not finished, so the
	// unresponsive peer's late success still contributes a result (rust `timeout`).
	immutable finished = it.isFinished;
	it.onSuccess(slow, null).should.equal(true);
	if (!finished)
		it.intoResult.canFind(slow).should.equal(true);
}

// rust `termination_and_parallelism`: drive the iterator round by round with a
// random mix of successes (adding closer peers) and failures, checking that each
// round hands out the expected closest peers in order, num_waiting tracks
// exactly, and on finish the results are distance-sorted and obey the
// fewer-than-num_results ⇒ (few-known ∨ failures) ∧ all-contacted invariant.
@("kad query: termination and bounded parallelism (property)")
unittest
{
	auto rng = Random(20_260_723);
	foreach (iter_; 0 .. 8)
	{
		immutable numKnown = uniform(1, 12, rng);
		immutable parallelism = uniform(1, 4, rng);
		immutable numResults = uniform(1, numKnown + 1, rng);
		auto known = randomPeers(numKnown);
		auto target = Key.fromPeer(rp());
		auto it = new ClosestPeersIter(target, known, parallelism, numResults);
		auto now = MonoTime.currTime;

		// The seed is capped at K(20); here numKnown < 20 so all are kept.
		auto expected = sortedByDistance(known, target);
		immutable maxPar = parallelism < expected.length ? parallelism : expected.length;
		size_t numFailures;
		bool finished;

		while (expected.length && !finished)
		{
			auto round = expected.length < maxPar ? expected : expected[0 .. maxPar];
			auto remaining = expected.length < maxPar ? cast(PeerId[]) null : expected[maxPar .. $].dup;

			// Advance for the round: each next must yield the expected peer in order.
			foreach (k; round)
			{
				auto s = it.next(now);
				if (s.kind == IterStateKind.finished)
				{
					finished = true;
					break;
				}
				s.hasPeer.should.equal(true);
				(s.peer == k).should.equal(true); // closest-first
			}
			if (finished)
				break;
			it.numWaiting.should.equal(round.length);

			// Report results: 75% success (adding random closers), else failure.
			foreach (i, k; round)
			{
				if (uniform(0, 4, rng) != 0)
				{
					auto closers = randomPeers(uniform(0, numResults + 1, rng));
					remaining ~= closers;
					it.onSuccess(k, closers);
				}
				else
				{
					numFailures++;
					it.onFailure(k);
				}
				it.numWaiting.should.equal(round.length - (i + 1));
			}
			expected = sortedByDistance(remaining, target);
		}

		it.next(now).kind.should.equal(IterStateKind.finished);
		it.isFinished.should.equal(true);

		auto closest = it.intoResult;
		isSorted(closest, target).should.equal(true);
		if (closest.length < numResults)
			(numKnown < numResults || numFailures > 0).should.equal(true);
		else
			closest.length.should.equal(numResults);
	}
}

// --- the fixed set --------------------------------------------------------------

// A failure frees a parallelism slot.
@("kad fixed-iter: a failure frees a parallelism slot")
unittest
{
	auto it = new FixedPeersIter([rp(), rp()], 1);

	auto s = it.next();
	s.kind.should.equal(IterStateKind.waiting);
	s.hasPeer.should.equal(true);
	it.onFailure(s.peer).should.equal(true);

	// The freed slot must let the next peer through (not WaitingAtCapacity).
	auto s2 = it.next();
	s2.kind.should.equal(IterStateKind.waiting);
	s2.hasPeer.should.equal(true);
}

// A fixed iterator finishes once every contacted peer has answered, and reports
// exactly the succeeded peers.
@("kad fixed-iter: finishes after all peers answer, yields succeeded")
unittest
{
	auto a = rp(), b = rp();
	auto it = new FixedPeersIter([a, b], 3);

	auto s1 = it.next();
	s1.hasPeer.should.equal(true);
	auto s2 = it.next();
	s2.hasPeer.should.equal(true);
	// both in flight; nothing new to hand out yet
	it.next().hasPeer.should.equal(false);

	it.onSuccess(s1.peer).should.equal(true);
	it.onFailure(s2.peer).should.equal(true);

	it.next().kind.should.equal(IterStateKind.finished);
	it.isFinished.should.equal(true);
	auto res = it.intoResult();
	res.length.should.equal(1UL);
	(res[0] == s1.peer).should.equal(true);
}

@("kad fixed-iter: empty set finishes immediately")
unittest
{
	auto it = new FixedPeersIter([], 3);
	it.next().kind.should.equal(IterStateKind.finished);
}

// --- the driver: α that is really α ---------------------------------------------
//
// Kademlia's whole latency argument rests on α requests being in flight at
// once. The iterator only decides; the driver has to actually overlap the
// contacts, and never more than α of them.
@("kad query: runQuery contacts alpha peers at once, and never more than alpha")
unittest
{
	import core.time : msecs;
	import vibe.core.core : sleep;

	enum alpha = 3;
	PeerId[] known;
	foreach (_; 0 .. 8)
		known ~= rp();

	size_t live, peak, contacted;
	onLoop({
		auto it = new ClosestPeersIter(Key.fromPeer(rp()), known, alpha, 20);
		runQuery(it, alpha, (PeerId p) {
			live++;
			if (live > peak)
				peak = live;
			contacted++;
			sleep(20.msecs); // the network turnaround, in miniature
			live--;
			return PeerId[].init; // knows nobody new: the search converges
		});
	});

	peak.should.be.greaterThan(1); // they genuinely overlapped...
	peak.should.be.lessThan(alpha + 1); // ...and the limit still held
	contacted.should.be.greaterThan(alpha); // the search really ran
	live.should.equal(0); // nothing outlived the call
}

// The deadline stops the search from handing out new peers. It does not abandon
// the contacts in flight — no fiber outlives the call — so the assertion is that
// the search was cut short, not that it returned instantly.
@("kad query: runQuery stops handing out peers once its deadline passes")
unittest
{
	import core.time : msecs;
	import vibe.core.core : sleep;

	PeerId[] known;
	foreach (_; 0 .. 12)
		known ~= rp();

	size_t contacted;
	bool finished;
	onLoop({
		// numResults above the peers we know keeps the search iterating, where
		// the parallelism limit is α; a stalled search fans out on purpose.
		auto it = new ClosestPeersIter(Key.fromPeer(rp()), known, 2, 30);
		runQuery(it, 2, (PeerId p) {
			contacted++;
			sleep(40.msecs); // slower than the deadline allows for twelve
			return PeerId[].init;
		}, 60.msecs);
		finished = it.isFinished;
	});

	contacted.should.be.greaterThan(0); // it did start
	contacted.should.be.lessThan(known.length); // and it did not finish the set
	finished.should.equal(true); // the deadline ended the query, not exhaustion
}

// A contact that throws is a failure for that peer and nothing more.
@("kad query: a contact that throws fails that peer and the search goes on")
unittest
{
	PeerId[] known;
	foreach (_; 0 .. 4)
		known ~= rp();
	size_t asked;
	PeerId[] result;
	onLoop({
		auto it = new ClosestPeersIter(Key.fromPeer(rp()), known, 2, 20);
		result = runQuery(it, 2, (PeerId p) {
			asked++;
			if (asked % 2 == 0)
				throw new Exception("unreachable");
			return PeerId[].init;
		});
	});
	asked.should.equal(4);
	result.length.should.equal(2); // the ones that answered
}
