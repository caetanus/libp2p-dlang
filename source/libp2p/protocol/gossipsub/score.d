/**
 * Peer scoring, as gossipsub v1.1 specifies it and rust-libp2p computes it:
 *
 *   P1 time in mesh, P2 first deliveries, P3 mesh-delivery deficit, P3b sticky
 *   mesh failure, P4 invalid deliveries (squared) — per topic, weighted and
 *   capped; P5 application score; P6 IP colocation; P7 behavioural penalty.
 *
 * Counters decay every `refreshScores`; a disconnected peer's negative score
 * is retained for `retainScore` so it cannot reset by reconnecting.
 */
module libp2p.protocol.gossipsub.score;

import core.time : Duration, MonoTime, seconds, msecs;
import std.algorithm.searching : canFind;

import libp2p.core.peer_id : PeerId;

alias Clock = MonoTime delegate() @safe nothrow;

struct TopicScoreParams
{
	double topicWeight = 0.5;
	// P1
	double timeInMeshWeight = 1.0;
	Duration timeInMeshQuantum = 1.msecs;
	double timeInMeshCap = 3600.0;
	// P2
	double firstMessageDeliveriesWeight = 1.0;
	double firstMessageDeliveriesDecay = 0.5;
	double firstMessageDeliveriesCap = 2000.0;
	// P3
	double meshMessageDeliveriesWeight = -1.0;
	double meshMessageDeliveriesDecay = 0.5;
	double meshMessageDeliveriesCap = 100.0;
	double meshMessageDeliveriesThreshold = 20.0;
	Duration meshMessageDeliveriesWindow = 10.msecs;
	Duration meshMessageDeliveriesActivation = 5.seconds;
	// P3b
	double meshFailurePenaltyWeight = -1.0;
	double meshFailurePenaltyDecay = 0.5;
	// P4
	double invalidMessageDeliveriesWeight = -1.0;
	double invalidMessageDeliveriesDecay = 0.3;
}

struct PeerScoreParams
{
	TopicScoreParams[string] topics;
	double topicScoreCap = 3600.0;
	double appSpecificWeight = 10.0;
	double ipColocationFactorWeight = -5.0;
	double ipColocationFactorThreshold = 10.0;
	string[] ipColocationFactorWhitelist;
	double behaviourPenaltyWeight = -10.0;
	double behaviourPenaltyThreshold = 0.0;
	double behaviourPenaltyDecay = 0.2;
	Duration decayInterval = 1.seconds;
	double decayToZero = 0.1;
	Duration retainScore = 3600.seconds;
}

struct PeerScoreThresholds
{
	double gossipThreshold = -10.0;
	double publishThreshold = -50.0;
	double graylistThreshold = -80.0;
	double acceptPxThreshold = 10.0;
	double opportunisticGraftThreshold = 20.0;
}

enum RejectReason
{
	validationError, /// the message itself is malformed: only the sender pays
	validationFailed, /// the application rejected it: sender and forwarders pay
	validationIgnored, /// neither valid nor invalid: nobody pays
	selfOrigin, /// it claims to be ours: only the sender pays
	blackListedPeer,
	blackListedSource,
}

private struct TopicStats
{
	bool inMesh;
	MonoTime graftTime;
	Duration meshTime;
	double firstMessageDeliveries = 0;
	bool meshMessageDeliveriesActive;
	double meshMessageDeliveries = 0;
	double meshFailurePenalty = 0;
	double invalidMessageDeliveries = 0;
}

private struct PeerStats
{
	bool connected = true;
	MonoTime expire;
	TopicStats[string] topics;
	string[] knownIps;
	double behaviourPenalty = 0;
	double applicationScore = 0;
}

private enum DeliveryStatus
{
	unknown,
	valid,
	invalid,
	ignored,
}

private struct DeliveryRecord
{
	DeliveryStatus status;
	MonoTime validated;
	PeerId[] peers; /// who else delivered it
}

final class PeerScore
{
	private PeerScoreParams params;
	private PeerScoreThresholds thresholds;
	private PeerStats[PeerId] peers;
	private PeerId[][string] peerIps;
	private DeliveryRecord[string] deliveries;
	private Clock clock;

	this(PeerScoreParams params, PeerScoreThresholds thresholds)
	{
		this.params = params;
		this.thresholds = thresholds;
	}

	void testClock(Clock c) @safe nothrow
	{
		clock = c;
	}

	private MonoTime now() @safe nothrow
	{
		return clock is null ? MonoTime.currTime : clock();
	}

	PeerScoreThresholds thresholdsOf() const @safe pure nothrow
	{
		return thresholds;
	}

	// --- the score ------------------------------------------------------------------------

	double scoreReport(PeerId peer)
	{
		auto ps = peer in peers;
		if (ps is null)
			return 0;
		double score = 0;
		foreach (topic, ref ts; ps.topics)
		{
			auto tp = topic in params.topics;
			if (tp is null)
				continue;
			double topicScore = 0;
			if (ts.inMesh)
			{
				immutable v = cast(double) ts.meshTime.total!"hnsecs" / cast(double) tp.timeInMeshQuantum.total!"hnsecs";
				topicScore += (v < tp.timeInMeshCap ? v : tp.timeInMeshCap) * tp.timeInMeshWeight;
			}
			immutable p2 = ts.firstMessageDeliveries < tp.firstMessageDeliveriesCap
				? ts.firstMessageDeliveries : tp.firstMessageDeliveriesCap;
			topicScore += p2 * tp.firstMessageDeliveriesWeight;
			if (ts.meshMessageDeliveriesActive && ts.meshMessageDeliveries < tp.meshMessageDeliveriesThreshold
				&& tp.meshMessageDeliveriesWeight != 0)
			{
				immutable deficit = tp.meshMessageDeliveriesThreshold - ts.meshMessageDeliveries;
				topicScore += deficit * deficit * tp.meshMessageDeliveriesWeight;
			}
			topicScore += ts.meshFailurePenalty * tp.meshFailurePenaltyWeight;
			topicScore += ts.invalidMessageDeliveries * ts.invalidMessageDeliveries * tp.invalidMessageDeliveriesWeight;
			score += topicScore * tp.topicWeight;
		}
		if (params.topicScoreCap > 0 && score > params.topicScoreCap)
			score = params.topicScoreCap;

		score += ps.applicationScore * params.appSpecificWeight;

		foreach (ip; ps.knownIps)
		{
			if (params.ipColocationFactorWhitelist.canFind(ip))
				continue;
			immutable n = cast(double) peerIps.get(ip, null).length;
			if (n > params.ipColocationFactorThreshold && params.ipColocationFactorWeight != 0)
			{
				immutable surplus = n - params.ipColocationFactorThreshold;
				score += surplus * surplus * params.ipColocationFactorWeight;
			}
		}

		if (ps.behaviourPenalty > params.behaviourPenaltyThreshold)
		{
			immutable excess = ps.behaviourPenalty - params.behaviourPenaltyThreshold;
			score += excess * excess * params.behaviourPenaltyWeight;
		}
		return score;
	}

	// --- peers ----------------------------------------------------------------------------

	void addPeer(PeerId peer)
	{
		if (peer !in peers)
			peers[peer] = PeerStats.init;
		else
			peers[peer].connected = true;
	}

	/// A peer left. A positive score is forgotten; a negative one is kept for
	/// `retainScore`, so leaving and coming back does not launder it.
	void removePeer(PeerId peer)
	{
		if (scoreReport(peer) > 0)
		{
			if (auto ps = peer in peers)
				forgetIps(*ps, peer);
			peers.remove(peer);
			return;
		}
		auto ps = peer in peers;
		if (ps is null)
			return;
		foreach (topic, ref ts; ps.topics)
		{
			ts.firstMessageDeliveries = 0;
			if (auto tp = topic in params.topics)
				if (ts.inMesh && ts.meshMessageDeliveriesActive
					&& ts.meshMessageDeliveries < tp.meshMessageDeliveriesThreshold)
				{
					immutable deficit = tp.meshMessageDeliveriesThreshold - ts.meshMessageDeliveries;
					ts.meshFailurePenalty += deficit * deficit;
				}
			ts.inMesh = false;
			ts.meshMessageDeliveriesActive = false;
		}
		ps.connected = false;
		ps.expire = now() + params.retainScore;
	}

	void addIp(PeerId peer, string ip)
	{
		auto ps = peer in peers;
		if (ps is null)
			return;
		if (!ps.knownIps.canFind(ip))
			ps.knownIps ~= ip;
		auto list = peerIps.get(ip, null);
		if (!list.canFind(peer))
			list ~= peer;
		peerIps[ip] = list;
	}

	void removeIp(PeerId peer, string ip)
	{
		import std.algorithm.mutation : remove;

		if (auto ps = peer in peers)
			ps.knownIps = ps.knownIps.remove!(x => x == ip);
		if (auto list = ip in peerIps)
		{
			*list = (*list).remove!(x => x == peer);
			if (list.length == 0)
				peerIps.remove(ip);
		}
	}

	private void forgetIps(ref PeerStats ps, PeerId peer)
	{
		foreach (ip; ps.knownIps.dup)
			removeIp(peer, ip);
	}

	// --- mesh ------------------------------------------------------------------------------

	void graft(PeerId peer, string topic)
	{
		if (auto ts = stats(peer, topic))
		{
			ts.inMesh = true;
			ts.graftTime = now();
			ts.meshTime = Duration.zero;
			ts.meshMessageDeliveriesActive = false;
		}
	}

	void prune(PeerId peer, string topic)
	{
		auto ts = stats(peer, topic);
		if (ts is null)
			return;
		immutable threshold = params.topics[topic].meshMessageDeliveriesThreshold;
		if (ts.meshMessageDeliveriesActive && ts.meshMessageDeliveries < threshold)
		{
			immutable deficit = threshold - ts.meshMessageDeliveries;
			ts.meshFailurePenalty += deficit * deficit;
		}
		ts.meshMessageDeliveriesActive = false;
		ts.inMesh = false;
	}

	// --- deliveries ------------------------------------------------------------------------

	/// A message arrived and is being validated.
	void validateMessage(PeerId from, string id, string topic)
	{
		if (id !in deliveries)
			deliveries[id] = DeliveryRecord.init;
	}

	/// The message turned out valid: the sender made a first delivery, and
	/// everyone who delivered it meanwhile made a (possibly in-window) duplicate.
	void deliverMessage(PeerId from, string id, string topic)
	{
		markFirstMessageDelivery(from, topic);
		auto rec = record(id);
		if (rec.status != DeliveryStatus.unknown)
			return;
		rec.status = DeliveryStatus.valid;
		rec.validated = now();
		foreach (p; rec.peers.dup)
			if (p != from)
				markDuplicateMessageDelivery(p, topic, false, MonoTime.init);
	}

	void rejectMessage(PeerId from, string id, string topic, RejectReason reason)
	{
		final switch (reason)
		{
		case RejectReason.validationError:
		case RejectReason.selfOrigin:
			markInvalidMessageDelivery(from, topic);
			return;
		case RejectReason.blackListedPeer:
		case RejectReason.blackListedSource:
			return;
		case RejectReason.validationFailed:
		case RejectReason.validationIgnored:
			break;
		}
		auto rec = record(id);
		if (rec.status != DeliveryStatus.unknown)
			return;
		if (reason == RejectReason.validationIgnored)
		{
			rec.status = DeliveryStatus.ignored;
			rec.peers = null;
			return;
		}
		rec.status = DeliveryStatus.invalid;
		auto others = rec.peers;
		rec.peers = null;
		markInvalidMessageDelivery(from, topic);
		foreach (p; others)
			markInvalidMessageDelivery(p, topic);
	}

	/// A message we already had arrived again from `from`.
	void duplicatedMessage(PeerId from, string id, string topic)
	{
		auto rec = record(id);
		if (rec.peers.canFind(from))
			return;
		final switch (rec.status)
		{
		case DeliveryStatus.unknown:
			rec.peers ~= from;
			break;
		case DeliveryStatus.valid:
			rec.peers ~= from;
			markDuplicateMessageDelivery(from, topic, true, rec.validated);
			break;
		case DeliveryStatus.invalid:
			markInvalidMessageDelivery(from, topic);
			break;
		case DeliveryStatus.ignored:
			break;
		}
	}

	void addPenalty(PeerId peer, size_t count)
	{
		if (auto ps = peer in peers)
			ps.behaviourPenalty += cast(double) count;
	}

	bool setApplicationScore(PeerId peer, double score)
	{
		auto ps = peer in peers;
		if (ps is null)
			return false;
		ps.applicationScore = score;
		return true;
	}

	/// Decay every counter once; drop retained peers whose time is up.
	void refreshScores()
	{
		immutable t = now();
		PeerId[] gone;
		foreach (peer, ref ps; peers)
		{
			if (!ps.connected)
			{
				if (t > ps.expire)
					gone ~= peer;
				continue;
			}
			foreach (topic, ref ts; ps.topics)
			{
				auto tp = topic in params.topics;
				if (tp is null)
					continue;
				ts.firstMessageDeliveries = decay(ts.firstMessageDeliveries, tp.firstMessageDeliveriesDecay);
				ts.meshMessageDeliveries = decay(ts.meshMessageDeliveries, tp.meshMessageDeliveriesDecay);
				ts.meshFailurePenalty = decay(ts.meshFailurePenalty, tp.meshFailurePenaltyDecay);
				ts.invalidMessageDeliveries = decay(ts.invalidMessageDeliveries, tp.invalidMessageDeliveriesDecay);
				if (ts.inMesh)
				{
					ts.meshTime = t - ts.graftTime;
					if (ts.meshTime > tp.meshMessageDeliveriesActivation)
						ts.meshMessageDeliveriesActive = true;
				}
			}
			ps.behaviourPenalty = decay(ps.behaviourPenalty, params.behaviourPenaltyDecay);
		}
		foreach (peer; gone)
		{
			forgetIps(peers[peer], peer);
			peers.remove(peer);
		}
	}

	/// Forget delivery records older than `ttl` (the router's duplicate window).
	void forgetDeliveriesOlderThan(Duration ttl)
	{
		immutable t = now();
		string[] old;
		foreach (id, ref rec; deliveries)
			if (rec.status == DeliveryStatus.valid && t - rec.validated > ttl)
				old ~= id;
		foreach (id; old)
			deliveries.remove(id);
	}

	// --- internals -------------------------------------------------------------------------

	private double decay(double v, double factor) const @safe pure nothrow
	{
		v *= factor;
		return v < params.decayToZero ? 0 : v;
	}

	private DeliveryRecord* record(string id)
	{
		if (id !in deliveries)
			deliveries[id] = DeliveryRecord.init;
		return id in deliveries;
	}

	/// Stats for a peer in a topic: created if the topic is scored, otherwise
	/// only if they already exist.
	private TopicStats* stats(PeerId peer, string topic)
	{
		auto ps = peer in peers;
		if (ps is null)
			return null;
		if (topic in params.topics)
		{
			if (topic !in ps.topics)
				ps.topics[topic] = TopicStats.init;
			return topic in ps.topics;
		}
		return topic in ps.topics;
	}

	private void markInvalidMessageDelivery(PeerId peer, string topic)
	{
		if (auto ts = stats(peer, topic))
			ts.invalidMessageDeliveries += 1;
	}

	private void markFirstMessageDelivery(PeerId peer, string topic)
	{
		auto ts = stats(peer, topic);
		if (ts is null)
			return;
		auto tp = params.topics[topic];
		ts.firstMessageDeliveries = ts.firstMessageDeliveries + 1 > tp.firstMessageDeliveriesCap
			? tp.firstMessageDeliveriesCap : ts.firstMessageDeliveries + 1;
		if (ts.inMesh)
			ts.meshMessageDeliveries = ts.meshMessageDeliveries + 1 > tp.meshMessageDeliveriesCap
				? tp.meshMessageDeliveriesCap : ts.meshMessageDeliveries + 1;
	}

	private void markDuplicateMessageDelivery(PeerId peer, string topic, bool timed, MonoTime validated)
	{
		auto ts = stats(peer, topic);
		if (ts is null || !ts.inMesh)
			return;
		auto tp = params.topics[topic];
		bool inWindow = true;
		if (timed && now() > validated + tp.meshMessageDeliveriesWindow)
			inWindow = false;
		if (inWindow)
			ts.meshMessageDeliveries = ts.meshMessageDeliveries + 1 > tp.meshMessageDeliveriesCap
				? tp.meshMessageDeliveriesCap : ts.meshMessageDeliveries + 1;
	}
}
