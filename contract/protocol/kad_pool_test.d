module tests.protocol.kad_pool_test;

import core.time : MonoTime, seconds;

import libp2p.crypto.keys : Keypair;
import libp2p.core.peer_id : PeerId;
import libp2p.protocol.kad.key : Key;
import libp2p.protocol.kad.query : FixedPeersIter, IterStateKind;
import libp2p.protocol.kad.pool;
import fluent.asserts;

private PeerId rp()
{
	return PeerId.fromPublicKey(Keypair.generateEd25519.publicKey);
}

// rust `query::peers::fixed::test::decrease_num_waiting_on_failure`.
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

// An empty fixed iterator is immediately finished.
@("kad fixed-iter: empty set finishes immediately")
unittest
{
	auto it = new FixedPeersIter([], 3);
	it.next().kind.should.equal(IterStateKind.finished);
}

// QueryStats.merge accumulates counters and takes min-start / max-end.
@("kad pool: QueryStats.merge accumulates counters and clamps instants")
unittest
{
	auto base = MonoTime.currTime;
	QueryStats a;
	a.requests = 3;
	a.success = 2;
	a.failure = 1;
	a.hasStart = true;
	a.start = base + 5.seconds;
	a.hasEnd = true;
	a.end = base + 10.seconds;

	QueryStats b;
	b.requests = 4;
	b.success = 1;
	b.failure = 0;
	b.hasStart = true;
	b.start = base + 2.seconds; // earlier
	b.hasEnd = true;
	b.end = base + 20.seconds; // later

	auto m = a.merge(b);
	m.numRequests.should.equal(7U);
	m.numSuccesses.should.equal(3U);
	m.numFailures.should.equal(1U);
	m.numPending.should.equal(3U); // 7 - (3 + 1)
	(m.start == base + 2.seconds).should.equal(true);
	(m.end == base + 20.seconds).should.equal(true);
}

// --- the α that was never α -------------------------------------------------
//
// `ClosestPeersIter` is a faithful port of rust's, parallelism limit and all —
// and until `Query.map` existed, that limit was decoration. The only driver we
// had contacted a peer, blocked until it answered, and only then asked what to
// do next, so `numWaiting` never passed one and `waitingAtCapacity` was
// unreachable outside the tests above.
//
// Kademlia's whole latency argument rests on α requests being in flight at once.
// This asserts that they are: the contacts overlap, and never more than α of
// them do.
@("kad query: map contacts alpha peers at once, and never more than alpha")
unittest
{
	import core.time : msecs;
	import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;

	enum alpha = 3;
	PeerId[] known;
	foreach (_; 0 .. 8)
		known ~= rp();

	QueryConfig cfg;
	cfg.parallelism = alpha;
	auto pool = new QueryPool(cfg);
	auto id = pool.addIterClosest(Key.fromPeer(rp()), known, QueryInfo(QueryInfoKind.bootstrap, 20));
	auto query = pool.get(id);
	foreach (p; known)
		query.addresses[p] = [];

	size_t live, peak, contacted;
	runTask(() nothrow{
		try
		{
			query.map((PeerId p) {
				live++;
				if (live > peak)
					peak = live;
				contacted++;
				sleep(20.msecs); // the network turnaround, in miniature
				live--;
				return PeerId[].init; // knows nobody new: the search converges
			});
		}
		catch (Exception)
		{
		}
		try
			exitEventLoop();
		catch (Exception)
		{
		}
	});
	runEventLoop();

	peak.should.be.greaterThan(1); // they genuinely overlapped...
	peak.should.be.lessThan(alpha + 1); // ...and the limit still held
	contacted.should.be.greaterThan(alpha); // the search really ran
	live.should.equal(0); // nothing outlived the call
}

// A lookup used to leave its query in the pool. `poll` removed finished queries
// on its way past, and when `map` replaced the poll loop nothing did — one
// leaked query per lookup, on a node whose whole job is to keep looking things
// up. No test caught it, because no test had ever asked what the pool held
// afterwards. This one asks.
@("kad pool: a query that has run is retired, not left behind")
unittest
{
	import vibe.core.core : runTask, runEventLoop, exitEventLoop;

	QueryConfig cfg;
	cfg.parallelism = 2;
	auto pool = new QueryPool(cfg);

	PeerId[] known;
	foreach (_; 0 .. 4)
		known ~= rp();
	auto id = pool.addIterClosest(Key.fromPeer(rp()), known,
		QueryInfo(QueryInfoKind.getClosestPeers, 4));
	auto query = pool.get(id);
	foreach (p; known)
		query.addresses[p] = [];
	pool.size.should.equal(1UL);

	size_t after;
	runTask(() nothrow{
		try
		{
			query.map((PeerId p) { return PeerId[].init; });
			pool.retire(id, MonoTime.currTime);
			after = pool.size;
		}
		catch (Exception)
		{
		}
		try
			exitEventLoop();
		catch (Exception)
		{
		}
	});
	runEventLoop();

	after.should.equal(0UL);
	query.stats.hasEnd.should.equal(true); // and it knows when it ended
}

// The deadline that `pool.poll` used to enforce from outside, now enforced by
// the query itself. Note what it does and does not promise: it stops handing
// out new peers, and it does not abandon the contacts already in flight —
// `map` cannot return while a fiber still holds a reference to the caller's
// `contact`. So the assertion is that the search was cut short, not that it
// returned instantly.
@("kad query: map stops handing out peers once its deadline passes")
unittest
{
	import core.time : msecs;
	import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;

	QueryConfig cfg;
	cfg.parallelism = 2;
	auto pool = new QueryPool(cfg);

	PeerId[] known;
	foreach (_; 0 .. 12)
		known ~= rp();
	// numResults deliberately above the peers we know: it keeps the search in
	// `iterating`, where the parallelism limit is `parallelism`. Once a search
	// *stalls*, rust raises the limit to `max(numResults, parallelism)` on
	// purpose — a stalled lookup fans out to break the deadlock — and this
	// deadline would then have nothing to hold back.
	auto id = pool.addIterClosest(Key.fromPeer(rp()), known,
		QueryInfo(QueryInfoKind.getClosestPeers, 30));
	auto query = pool.get(id);
	foreach (p; known)
		query.addresses[p] = [];

	size_t contacted;
	bool finished;
	runTask(() nothrow{
		try
		{
			query.map((PeerId p) {
				contacted++;
				sleep(40.msecs); // slower than the deadline allows for twelve
				return PeerId[].init;
			}, 60.msecs);
			finished = query.isFinished;
		}
		catch (Exception)
		{
		}
		try
			exitEventLoop();
		catch (Exception)
		{
		}
	});
	runEventLoop();

	contacted.should.be.greaterThan(0); // it did start
	contacted.should.be.lessThan(known.length); // and it did not finish the set
	finished.should.equal(true); // the deadline ended the query, not exhaustion
}
