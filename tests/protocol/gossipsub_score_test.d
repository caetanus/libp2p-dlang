module tests.protocol.gossipsub_score_test;

import core.time : Duration, MonoTime, msecs, seconds;
import std.conv : to;
import std.math : isClose;

import libp2p.core.peer_id : PeerId;
import libp2p.protocol.gossipsub.score;
import fluent.asserts;

private PeerId peer(ubyte b)
{
	return PeerId([b]);
}

// Laundered from rust `peer_score/tests.rs::test_score_time_in_mesh` (real sleep
// replaced with a deterministic injected clock).
@("peer score: P1 time in mesh grows with grafted time")
unittest
{
	PeerScoreParams params;
	params.topicScoreCap = 1000.0;
	TopicScoreParams tp;
	tp.topicWeight = 0.5;
	tp.timeInMeshWeight = 1.0;
	tp.timeInMeshQuantum = 1.msecs;
	tp.timeInMeshCap = 3600.0;
	params.topics["test"] = tp;

	auto ps = new PeerScore(params, PeerScoreThresholds.init);
	MonoTime base = MonoTime.currTime;
	Duration off;
	ps.testClock(() @safe nothrow => base + off);

	auto a = peer(1);
	ps.addPeer(a);
	ps.scoreReport(a).should.equal(0.0);

	ps.graft(a, "test");
	off = 200.msecs; // 200 * quantum
	ps.refreshScores();

	immutable expected = tp.topicWeight * tp.timeInMeshWeight * 200.0;
	(ps.scoreReport(a) >= expected).should.equal(true);
}

// Laundered from `test_score_first_message_deliveries`.
@("peer score: P2 first message deliveries")
unittest
{
	PeerScoreParams params;
	TopicScoreParams tp;
	tp.topicWeight = 1.0;
	tp.firstMessageDeliveriesWeight = 1.0;
	tp.firstMessageDeliveriesDecay = 1.0; // no decay
	tp.firstMessageDeliveriesCap = 2000.0;
	tp.timeInMeshWeight = 0.0;
	params.topics["test"] = tp;

	auto ps = new PeerScore(params, PeerScoreThresholds.init);
	auto a = peer(1);
	ps.addPeer(a);
	ps.graft(a, "test");

	foreach (seq; 0 .. 100)
	{
		auto id = "m" ~ seq.to!string;
		ps.validateMessage(a, id, "test");
		ps.deliverMessage(a, id, "test");
	}
	ps.refreshScores();

	ps.scoreReport(a).should.equal(tp.topicWeight * tp.firstMessageDeliveriesWeight * 100.0);
}

// Laundered from `test_score_time_in_mesh_cap` (sleep -> injected clock).
@("peer score: P1 time in mesh is capped")
unittest
{
	PeerScoreParams params;
	TopicScoreParams tp;
	tp.topicWeight = 0.5;
	tp.timeInMeshWeight = 1.0;
	tp.timeInMeshQuantum = 1.msecs;
	tp.timeInMeshCap = 10.0;
	params.topics["test"] = tp;

	auto ps = new PeerScore(params, PeerScoreThresholds.init);
	MonoTime base = MonoTime.currTime;
	Duration off;
	ps.testClock(() @safe nothrow => base + off);

	auto a = peer(1);
	ps.addPeer(a);
	ps.graft(a, "test");
	off = 40.msecs; // 40 quanta, but the cap is 10
	ps.refreshScores();

	ps.scoreReport(a).should.equal(tp.topicWeight * tp.timeInMeshWeight * tp.timeInMeshCap);
}

// Laundered from `test_score_first_message_deliveries_decay`.
@("peer score: P2 first message deliveries decay each interval")
unittest
{
	PeerScoreParams params;
	TopicScoreParams tp;
	tp.topicWeight = 1.0;
	tp.firstMessageDeliveriesWeight = 1.0;
	tp.firstMessageDeliveriesDecay = 0.9;
	tp.firstMessageDeliveriesCap = 2000.0;
	tp.timeInMeshWeight = 0.0;
	params.topics["test"] = tp;

	auto ps = new PeerScore(params, PeerScoreThresholds.init);
	auto a = peer(1);
	ps.addPeer(a);
	ps.graft(a, "test");

	foreach (seq; 0 .. 100)
	{
		auto id = "m" ~ seq.to!string;
		ps.validateMessage(a, id, "test");
		ps.deliverMessage(a, id, "test");
	}

	ps.refreshScores();
	double expected = tp.topicWeight * tp.firstMessageDeliveriesWeight
		* tp.firstMessageDeliveriesDecay * 100.0;
	ps.scoreReport(a).should.equal(expected);

	foreach (_; 0 .. 10)
	{
		ps.refreshScores();
		expected *= tp.firstMessageDeliveriesDecay;
	}
	ps.scoreReport(a).should.equal(expected);
}

// Laundered from `test_score_mesh_message_deliveries`: P3 rewards in-window
// deliveries and penalizes a peer that only delivers outside the window, after
// the activation time.
@("peer score: P3 mesh delivery window and activation")
unittest
{
	PeerScoreParams params;
	TopicScoreParams tp;
	tp.topicWeight = 1.0;
	tp.meshMessageDeliveriesWeight = -1.0;
	tp.meshMessageDeliveriesActivation = 1.seconds;
	tp.meshMessageDeliveriesWindow = 10.msecs;
	tp.meshMessageDeliveriesThreshold = 20.0;
	tp.meshMessageDeliveriesCap = 100.0;
	tp.meshMessageDeliveriesDecay = 1.0;
	tp.firstMessageDeliveriesWeight = 0.0;
	tp.timeInMeshWeight = 0.0;
	tp.meshFailurePenaltyWeight = 0.0;
	params.topics["test"] = tp;

	auto ps = new PeerScore(params, PeerScoreThresholds.init);
	MonoTime base = MonoTime.currTime;
	Duration off;
	ps.testClock(() @safe nothrow => base + off);

	auto a = peer(1), b = peer(2), c = peer(3);
	foreach (p; [a, b, c])
	{
		ps.addPeer(p);
		ps.graft(p, "test");
	}

	// no penalty before the activation time.
	ps.refreshScores();
	foreach (p; [a, b, c])
		(ps.scoreReport(p) >= 0).should.equal(true);

	off = 1001.msecs; // past activation
	// A delivers first; B duplicates within the window (same instant).
	foreach (seq; 0 .. 100)
	{
		auto id = "m" ~ seq.to!string;
		ps.validateMessage(a, id, "test");
		ps.deliverMessage(a, id, "test");
		ps.duplicatedMessage(b, id, "test");
	}
	// C duplicates only after the window closes.
	off = 1001.msecs + 10.msecs + 20.msecs;
	foreach (seq; 0 .. 100)
		ps.duplicatedMessage(c, "m" ~ seq.to!string, "test");

	ps.refreshScores();
	(ps.scoreReport(a) >= 0).should.equal(true);
	(ps.scoreReport(b) >= 0).should.equal(true);
	// C never delivered in-window: penalty = threshold^2 * weight.
	ps.scoreReport(c).should.equal(tp.topicWeight * tp.meshMessageDeliveriesWeight * (20.0 * 20.0));
}

// Laundered from `test_score_mesh_message_deliveries_decay`: the P3 deficit is
// recomputed as the delivery counter decays below the threshold.
@("peer score: P3 deficit grows as mesh deliveries decay")
unittest
{
	PeerScoreParams params;
	TopicScoreParams tp;
	tp.topicWeight = 1.0;
	tp.meshMessageDeliveriesWeight = -1.0;
	tp.meshMessageDeliveriesActivation = 0.seconds;
	tp.meshMessageDeliveriesWindow = 10.msecs;
	tp.meshMessageDeliveriesThreshold = 20.0;
	tp.meshMessageDeliveriesCap = 100.0;
	tp.meshMessageDeliveriesDecay = 0.9;
	tp.firstMessageDeliveriesWeight = 0.0;
	tp.timeInMeshWeight = 0.0;
	tp.meshFailurePenaltyWeight = 0.0;
	params.topics["test"] = tp;

	auto ps = new PeerScore(params, PeerScoreThresholds.init);
	MonoTime base = MonoTime.currTime;
	Duration off;
	ps.testClock(() @safe nothrow => base + off);

	auto a = peer(1);
	ps.addPeer(a);
	ps.graft(a, "test");
	foreach (seq; 0 .. 100)
	{
		auto id = "m" ~ seq.to!string;
		ps.validateMessage(a, id, "test");
		ps.deliverMessage(a, id, "test");
	}

	off = 1.msecs; // advance so mesh time > activation (0) and the counter tracks
	ps.refreshScores(); // counter 100 -> 90, above threshold -> no penalty yet
	(ps.scoreReport(a) >= 0).should.equal(true);

	double decayed = 100.0 * tp.meshMessageDeliveriesDecay;
	foreach (_; 0 .. 20)
	{
		ps.refreshScores();
		decayed *= tp.meshMessageDeliveriesDecay;
	}

	immutable deficit = tp.meshMessageDeliveriesThreshold - decayed;
	ps.scoreReport(a).should.equal(tp.topicWeight * tp.meshMessageDeliveriesWeight
			* (deficit * deficit));
}

// Laundered from `test_score_mesh_failure_penalty`: pruning a peer whose mesh
// deliveries are under threshold applies the sticky P3b penalty.
@("peer score: P3b sticky mesh-failure penalty on prune")
unittest
{
	PeerScoreParams params;
	TopicScoreParams tp;
	tp.topicWeight = 1.0;
	tp.meshMessageDeliveriesWeight = 0.0;
	tp.meshMessageDeliveriesActivation = 0.seconds;
	tp.meshMessageDeliveriesWindow = 10.msecs;
	tp.meshMessageDeliveriesThreshold = 20.0;
	tp.meshMessageDeliveriesCap = 100.0;
	tp.meshMessageDeliveriesDecay = 1.0;
	tp.firstMessageDeliveriesWeight = 0.0;
	tp.timeInMeshWeight = 0.0;
	tp.meshFailurePenaltyWeight = -1.0;
	tp.meshFailurePenaltyDecay = 1.0;
	params.topics["test"] = tp;

	auto ps = new PeerScore(params, PeerScoreThresholds.init);
	MonoTime base = MonoTime.currTime;
	Duration off;
	ps.testClock(() @safe nothrow => base + off);

	auto a = peer(1), b = peer(2);
	foreach (p; [a, b])
	{
		ps.addPeer(p);
		ps.graft(p, "test");
	}
	foreach (seq; 0 .. 100)
	{
		auto id = "m" ~ seq.to!string;
		ps.validateMessage(a, id, "test");
		ps.deliverMessage(a, id, "test");
	}

	off = 1.msecs; // advance so mesh time > activation (0): the peer is "active"
	ps.refreshScores(); // activates mesh delivery tracking
	(ps.scoreReport(a) >= 0).should.equal(true);
	(ps.scoreReport(b) >= 0).should.equal(true);

	ps.prune(b, "test"); // B delivered nothing -> sticky penalty
	ps.refreshScores();

	ps.scoreReport(a).should.equal(0.0);
	ps.scoreReport(b).should.equal(tp.topicWeight * tp.meshFailurePenaltyWeight * (20.0 * 20.0));
}

// Laundered from `test_score_invalid_message_deliveris_decay`.
@("peer score: P4 invalid message deliveries decay (squared)")
unittest
{
	PeerScoreParams params;
	TopicScoreParams tp;
	tp.topicWeight = 1.0;
	tp.meshMessageDeliveriesWeight = 0.0;
	tp.firstMessageDeliveriesWeight = 0.0;
	tp.timeInMeshWeight = 0.0;
	tp.meshFailurePenaltyWeight = 0.0;
	tp.invalidMessageDeliveriesWeight = -1.0;
	tp.invalidMessageDeliveriesDecay = 0.9;
	params.topics["test"] = tp;

	auto ps = new PeerScore(params, PeerScoreThresholds.init);
	auto a = peer(1);
	ps.addPeer(a);
	ps.graft(a, "test");

	foreach (seq; 0 .. 100)
		ps.rejectMessage(a, "m" ~ seq.to!string, "test", RejectReason.validationFailed);

	ps.refreshScores();
	immutable decayed = tp.invalidMessageDeliveriesDecay * 100.0;
	double expected = tp.topicWeight * tp.invalidMessageDeliveriesWeight * decayed * decayed;
	ps.scoreReport(a).should.equal(expected);

	foreach (_; 0 .. 10)
	{
		ps.refreshScores();
		expected *= tp.invalidMessageDeliveriesDecay * tp.invalidMessageDeliveriesDecay;
	}
	ps.scoreReport(a).should.equal(expected);
}

// Laundered from `test_score_first_message_deliveries_cap`.
@("peer score: P2 first message deliveries are capped")
unittest
{
	PeerScoreParams params;
	TopicScoreParams tp;
	tp.topicWeight = 1.0;
	tp.firstMessageDeliveriesWeight = 1.0;
	tp.firstMessageDeliveriesDecay = 1.0;
	tp.firstMessageDeliveriesCap = 50.0;
	tp.timeInMeshWeight = 0.0;
	params.topics["test"] = tp;

	auto ps = new PeerScore(params, PeerScoreThresholds.init);
	auto a = peer(1);
	ps.addPeer(a);
	ps.graft(a, "test");

	foreach (seq; 0 .. 100)
	{
		auto id = "m" ~ seq.to!string;
		ps.validateMessage(a, id, "test");
		ps.deliverMessage(a, id, "test");
	}
	ps.refreshScores();

	ps.scoreReport(a).should.equal(tp.topicWeight * tp.firstMessageDeliveriesWeight * 50.0);
}

// Laundered from `test_score_invalid_message_deliveries`.
@("peer score: P4 invalid message deliveries are squared")
unittest
{
	PeerScoreParams params;
	TopicScoreParams tp;
	tp.topicWeight = 1.0;
	tp.meshMessageDeliveriesWeight = 0.0;
	tp.firstMessageDeliveriesWeight = 0.0;
	tp.timeInMeshWeight = 0.0;
	tp.meshFailurePenaltyWeight = 0.0;
	tp.invalidMessageDeliveriesWeight = -1.0;
	tp.invalidMessageDeliveriesDecay = 1.0;
	params.topics["test"] = tp;

	auto ps = new PeerScore(params, PeerScoreThresholds.init);
	auto a = peer(1);
	ps.addPeer(a);
	ps.graft(a, "test");

	foreach (seq; 0 .. 100)
		ps.rejectMessage(a, "m" ~ seq.to!string, "test", RejectReason.validationFailed);
	ps.refreshScores();

	ps.scoreReport(a).should.equal(tp.topicWeight * tp.invalidMessageDeliveriesWeight * (100.0 * 100.0));
}

// Laundered from `test_score_reject_message_deliveries`: invalid rejection also
// penalizes peers who forwarded us the message as a duplicate.
@("peer score: a rejected message penalizes duplicate forwarders too")
unittest
{
	PeerScoreParams params;
	TopicScoreParams tp;
	tp.topicWeight = 1.0;
	tp.meshMessageDeliveriesWeight = 0.0;
	tp.firstMessageDeliveriesWeight = 0.0;
	tp.meshFailurePenaltyWeight = 0.0;
	tp.timeInMeshWeight = 0.0;
	tp.timeInMeshQuantum = 1.seconds;
	tp.invalidMessageDeliveriesWeight = -1.0;
	tp.invalidMessageDeliveriesDecay = 1.0;
	params.topics["test"] = tp;

	auto ps = new PeerScore(params, PeerScoreThresholds.init);
	auto a = peer(1);
	auto b = peer(2);
	ps.addPeer(a);
	ps.addPeer(b);

	// A record exists; B forwards a duplicate; then A's message is rejected.
	ps.validateMessage(a, "m1", "test");
	ps.rejectMessage(a, "m1", "test", RejectReason.validationFailed);
	ps.duplicatedMessage(b, "m1", "test");
	ps.refreshScores();

	ps.scoreReport(a).should.equal(-1.0);
	ps.scoreReport(b).should.equal(-1.0);
}

// Laundered from `test_application_score`.
@("peer score: P5 application-specific score")
unittest
{
	immutable appWeight = 0.5;
	PeerScoreParams params;
	params.appSpecificWeight = appWeight;
	TopicScoreParams tp;
	tp.topicWeight = 1.0;
	tp.meshMessageDeliveriesWeight = 0.0;
	tp.firstMessageDeliveriesWeight = 0.0;
	tp.meshFailurePenaltyWeight = 0.0;
	tp.timeInMeshWeight = 0.0;
	tp.timeInMeshQuantum = 1.seconds;
	tp.invalidMessageDeliveriesWeight = 0.0;
	params.topics["test"] = tp;

	auto ps = new PeerScore(params, PeerScoreThresholds.init);
	auto a = peer(1);
	ps.addPeer(a);
	ps.graft(a, "test");

	foreach (i; [-100, -1, 0, 1, 50, 99])
	{
		ps.setApplicationScore(a, cast(double) i);
		ps.refreshScores();
		ps.scoreReport(a).should.equal(cast(double) i * appWeight);
	}
}

// Laundered from `test_score_ip_colocation`.
@("peer score: P6 IP colocation penalizes peers sharing an IP")
unittest
{
	PeerScoreParams params;
	params.ipColocationFactorWeight = -1.0;
	params.ipColocationFactorThreshold = 1.0;
	TopicScoreParams tp;
	tp.topicWeight = 1.0;
	tp.meshMessageDeliveriesWeight = 0.0;
	tp.firstMessageDeliveriesWeight = 0.0;
	tp.meshFailurePenaltyWeight = 0.0;
	tp.timeInMeshWeight = 0.0;
	tp.timeInMeshQuantum = 1.seconds;
	tp.invalidMessageDeliveriesWeight = 0.0;
	params.topics["test"] = tp;

	auto ps = new PeerScore(params, PeerScoreThresholds.init);
	auto a = peer(1), b = peer(2), c = peer(3), d = peer(4);
	foreach (p; [a, b, c, d])
	{
		ps.addPeer(p);
		ps.graft(p, "test");
	}

	ps.addIp(a, "1.2.3.4");
	ps.addIp(b, "2.3.4.5");
	ps.addIp(c, "2.3.4.5");
	ps.addIp(c, "3.4.5.6");
	ps.addIp(d, "2.3.4.5");
	ps.refreshScores();

	ps.scoreReport(a).should.equal(0.0);
	// three peers share 2.3.4.5: surplus = 3 - 1 = 2, penalty = 4, weight -1.
	immutable expected = -1.0 * (2.0 * 2.0);
	ps.scoreReport(b).should.equal(expected);
	ps.scoreReport(c).should.equal(expected);
	ps.scoreReport(d).should.equal(expected);
}

// Laundered from `test_score_behaviour_penalty`.
@("peer score: P7 behavioural penalty is squared and decays")
unittest
{
	PeerScoreParams params;
	params.behaviourPenaltyWeight = -1.0;
	params.behaviourPenaltyDecay = 0.99;
	TopicScoreParams tp;
	tp.topicWeight = 1.0;
	tp.meshMessageDeliveriesWeight = 0.0;
	tp.firstMessageDeliveriesWeight = 0.0;
	tp.meshFailurePenaltyWeight = 0.0;
	tp.timeInMeshWeight = 0.0;
	tp.timeInMeshQuantum = 1.seconds;
	tp.invalidMessageDeliveriesWeight = 0.0;
	params.topics["test"] = tp;

	auto ps = new PeerScore(params, PeerScoreThresholds.init);
	auto a = peer(1);

	// penalty on an unknown peer has no effect.
	ps.addPenalty(a, 1);
	ps.scoreReport(a).should.equal(0.0);

	ps.addPeer(a);
	ps.addPenalty(a, 1);
	ps.scoreReport(a).should.equal(-1.0); // 1^2 * -1
	ps.addPenalty(a, 1);
	ps.scoreReport(a).should.equal(-4.0); // 2^2 * -1

	ps.refreshScores(); // penalty *= 0.99 -> 1.98, score = -1.98^2
	isClose(ps.scoreReport(a), -3.9204).should.equal(true);
}

// Laundered from `test_score_retention` (real sleep -> injected clock).
@("peer score: a disconnected peer's negative score is retained then reset")
unittest
{
	PeerScoreParams params;
	params.appSpecificWeight = 1.0;
	params.retainScore = 1.seconds;
	TopicScoreParams tp;
	tp.topicWeight = 0.0;
	tp.meshMessageDeliveriesWeight = 0.0;
	tp.meshMessageDeliveriesActivation = 0.seconds;
	tp.firstMessageDeliveriesWeight = 0.0;
	tp.timeInMeshWeight = 0.0;
	params.topics["test"] = tp;

	auto ps = new PeerScore(params, PeerScoreThresholds.init);
	MonoTime base = MonoTime.currTime;
	Duration off;
	ps.testClock(() @safe nothrow => base + off);

	auto a = peer(1);
	ps.addPeer(a);
	ps.graft(a, "test");
	ps.setApplicationScore(a, -1000.0);

	ps.refreshScores();
	ps.scoreReport(a).should.equal(-1000.0);

	// disconnect; after half the retention the negative score is still there.
	ps.removePeer(a);
	off = 500.msecs;
	ps.refreshScores();
	ps.scoreReport(a).should.equal(-1000.0);

	// after the full retention (plus slop) the score resets to zero.
	off = 1050.msecs;
	ps.refreshScores();
	ps.scoreReport(a).should.equal(0.0);
}

// Laundered from rust `test_score_reject_message_deliveries` phase 5 (the "dark
// corner" the existing reject test omits): when a duplicate arrives BEFORE the
// message is rejected, both the originator and the duplicate-forwarder are
// penalized as invalid deliveries — score −4 (weight · 2²), exercising the
// invalid branch of duplicatedMessage.
@("peer score: a message rejected after a duplicate penalizes both -4")
unittest
{
	PeerScoreParams params;
	TopicScoreParams tp;
	tp.topicWeight = 1.0;
	tp.meshMessageDeliveriesWeight = 0.0;
	tp.firstMessageDeliveriesWeight = 0.0;
	tp.meshFailurePenaltyWeight = 0.0;
	tp.timeInMeshWeight = 0.0;
	tp.timeInMeshQuantum = 1.seconds;
	tp.invalidMessageDeliveriesWeight = -1.0;
	tp.invalidMessageDeliveriesDecay = 1.0;
	params.topics["test"] = tp;

	auto ps = new PeerScore(params, PeerScoreThresholds.init);
	auto a = peer(1);
	auto b = peer(2);
	ps.addPeer(a);
	ps.addPeer(b);

	// Phase 4 (reject THEN duplicate): b is penalized via duplicatedMessage's
	// Invalid branch. Each ends at invalid-count 1.
	ps.validateMessage(a, "m1", "test");
	ps.rejectMessage(a, "m1", "test", RejectReason.validationFailed);
	ps.duplicatedMessage(b, "m1", "test");

	// Phase 5 (duplicate THEN reject): b, recorded while the message was still
	// being validated, is still penalized when the reject drains the recorded
	// peers. The invalid counter accumulates (peer stats aren't cleared between
	// messages), so both reach count 2 ⇒ weight·2² = −4 (rust
	// `test_score_reject_message_deliveries` phases 4+5).
	ps.validateMessage(a, "m2", "test");
	ps.duplicatedMessage(b, "m2", "test");
	ps.rejectMessage(a, "m2", "test", RejectReason.validationFailed);

	ps.refreshScores();
	ps.scoreReport(a).should.equal(-4.0);
	ps.scoreReport(b).should.equal(-4.0);
}
