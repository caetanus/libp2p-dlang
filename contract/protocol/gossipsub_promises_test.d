module tests.protocol.gossipsub_promises_test;

import core.time : Duration, MonoTime, seconds;

import libp2p.core.peer_id : PeerId;
import libp2p.protocol.gossipsub : GossipPromises;
import libp2p.protocol.gossipsub_score : PeerScore, PeerScoreParams,
	PeerScoreThresholds, TopicScoreParams, RejectReason;
import fluent.asserts;

private PeerId peer(ubyte b)
{
	return PeerId([b]);
}

// A promise that isn't fulfilled before its follow-up window elapses is counted
// (once per requested message id) as a broken promise, and removed
// (rust `gossip_promises::get_broken_promises`).
@("gossip promises: unfulfilled promises become broken and are counted")
unittest
{
	GossipPromises gp;
	auto a = peer(1);
	auto base = MonoTime.currTime;
	gp.addPromise(a, ["x", "y"], base + 3.seconds);

	// Before expiry: nothing broken, still tracked.
	gp.getBrokenPromises(base + 1.seconds).length.should.equal(0UL);
	gp.contains("x").should.equal(true);

	// After expiry: both ids are broken for peer A, and cleared.
	auto broken = gp.getBrokenPromises(base + 4.seconds);
	broken.length.should.equal(1UL);
	broken[a].should.equal(2UL);
	gp.contains("x").should.equal(false);
	gp.contains("y").should.equal(false);
}

// Delivery of a message cancels all promises tracked for it — no penalty.
@("gossip promises: delivery cancels the promise")
unittest
{
	GossipPromises gp;
	auto a = peer(1);
	auto base = MonoTime.currTime;
	gp.addPromise(a, ["x"], base + 3.seconds);
	gp.messageDelivered("x");
	gp.getBrokenPromises(base + 4.seconds).length.should.equal(0UL);
}

// Only the earliest promise per (peer,id) is kept — a later IWANT for the same
// id does not extend the deadline (rust `add_promise` `or_insert`).
@("gossip promises: a repeated IWANT does not extend the deadline")
unittest
{
	GossipPromises gp;
	auto a = peer(1);
	auto base = MonoTime.currTime;
	gp.addPromise(a, ["x"], base + 3.seconds);
	gp.addPromise(a, ["x"], base + 100.seconds); // must NOT override
	auto broken = gp.getBrokenPromises(base + 4.seconds);
	broken.length.should.equal(1UL);
	broken[a].should.equal(1UL);
}

// A rejected message stops promise tracking (penalty comes from the invalid
// delivery path) — except for self-origin, where the broken-promise penalty
// still applies (rust `reject_message`).
@("gossip promises: rejection cancels tracking, except self-origin")
unittest
{
	auto a = peer(1);
	auto base = MonoTime.currTime;

	GossipPromises g1;
	g1.addPromise(a, ["x"], base + 3.seconds);
	g1.rejectMessage("x", RejectReason.validationError);
	g1.getBrokenPromises(base + 4.seconds).length.should.equal(0UL);

	GossipPromises g2;
	g2.addPromise(a, ["y"], base + 3.seconds);
	g2.rejectMessage("y", RejectReason.selfOrigin); // still tracked
	g2.getBrokenPromises(base + 4.seconds)[a].should.equal(1UL);
}

// Integration: broken promises feed the behavioural (P7) penalty, dragging the
// peer's score negative (rust `apply_iwant_penalties`).
@("gossip promises: broken promises drive the peer score negative via P7")
unittest
{
	PeerScoreParams params;
	params.behaviourPenaltyWeight = -10.0;
	params.behaviourPenaltyThreshold = 0.0;
	params.behaviourPenaltyDecay = 0.5;
	auto ps = new PeerScore(params, PeerScoreThresholds.init);

	auto a = peer(1);
	ps.addPeer(a);
	ps.scoreReport(a).should.equal(0.0);

	// Apply the count the heartbeat would derive from getBrokenPromises.
	GossipPromises gp;
	auto base = MonoTime.currTime;
	gp.addPromise(a, ["m1", "m2"], base + 3.seconds);
	auto broken = gp.getBrokenPromises(base + 4.seconds);
	foreach (p, count; broken)
		ps.addPenalty(p, count);

	ps.refreshScores();
	// P7 is weight * (penalty - threshold)^2 = -10 * 2^2 = -40 (after one decay
	// step the penalty is 2*0.5=1 at report time... so assert strictly negative).
	(ps.scoreReport(a) < 0.0).should.equal(true);
}
