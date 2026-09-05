/**
 * The gossipsub router: the protocol's state and decisions, with no I/O.
 *
 * It is fed what arrives (`onReceive`), what the application does (`subscribe`,
 * `publish`) and time (`heartbeat`), and answers each with the RPCs to send,
 * addressed by peer. The service around it owns the streams and the clock;
 * the tests drive it directly with hand-made RPCs. Everything gossipsub v1.1/1.2
 * decides lives here: the mesh (JOIN, LEAVE, GRAFT, PRUNE, backoff), forwarding
 * and flood publish, the message cache with IHAVE/IWANT, IDONTWANT, the
 * duplicate cache, and — when enabled — peer scoring and the gates it drives.
 *
 * Constants are rust-libp2p's defaults.
 */
module libp2p.protocol.gossipsub.router;

import core.time : Duration, MonoTime, seconds, msecs;
import std.algorithm.iteration : filter, map;
import std.algorithm.mutation : remove;
import std.algorithm.searching : canFind;
import std.algorithm.sorting : sort;
import std.array : array;
import std.random : Random, randomShuffle, unpredictableSeed, uniform;

import libp2p.core.peer_id : PeerId;
import libp2p.crypto.keys : Keypair;
import libp2p.protocol.gossipsub.mcache;
import libp2p.protocol.gossipsub.promises;
import libp2p.protocol.gossipsub.score;
import libp2p.protocol.gossipsub.wire;
import libp2p.wire.protobuf : encode;

enum size_t meshN = 6;
enum size_t meshNLow = 5;
enum size_t meshNHigh = 12;
enum size_t meshOutboundMin = 2;
enum size_t retainScores = 4;
enum size_t gossipLazy = 6;
enum double gossipFactor = 0.25;
enum size_t historyLength = 5;
enum size_t historyGossip = 3;
enum size_t gossipRetransmission = 3;
enum size_t maxIhaveLength = 5000;
enum size_t maxIhaveMessages = 10;
enum Duration iwantFollowupTime = 3.seconds;
enum Duration pruneBackoff = 60.seconds;
enum Duration unsubscribeBackoff = 10.seconds;
enum Duration heartbeatInterval = 1.seconds;
enum size_t backoffSlack = 1;
enum size_t opportunisticGraftTicks = 60;
enum size_t opportunisticGraftPeers = 2;
enum Duration duplicateCacheTime = 60.seconds;
enum size_t idontwantMessageSizeThreshold = 1000;
enum size_t idontwantCap = 10_000;
enum Duration idontwantTimeout = 3.seconds;
enum size_t maxTransmitSize = 65_536;
enum size_t maxPublishMessages = 500;
enum size_t maxControlSize = 16 * 1024;

/// An RPC to send, and to whom.
struct Out
{
	PeerId peer;
	Rpc rpc;
}

alias Clock = MonoTime delegate() @safe nothrow;

private struct PeerState
{
	bool outbound; /// we dialed them
	string[] topics; /// what they told us they subscribe to
	string[] dontSend; /// message ids they asked us not to forward
	MonoTime[] dontSendAt;
	size_t ihaveReceived, iwantSent; /// this heartbeat
}

final class GossipSub
{
	private PeerId local;
	private bool signing;
	private Keypair keypair;
	private ulong seqno;

	private PeerState[PeerId] peers;
	private string[] subscriptions;
	private PeerId[][string] mesh;
	private MonoTime[PeerId][string] backoffs;
	private MonoTime[string] seen; // duplicate cache: id → when
	private MessageCache mcache;
	private GossipPromises promises;
	private PeerScore score;
	private size_t ticks;
	private Random rng;
	private Clock clock;

	/// Delivered messages: topic and payload (the source is on the message).
	void delegate(string topic, const(ubyte)[] data) onMessage;
	/// The same, with the whole message.
	void delegate(PeerId from, Message m) onMessageFull;

	/// An anonymous router: publishes unsigned, accepts unsigned.
	this(PeerId local)
	{
		this.local = PeerId(local.bytes.dup);
		mcache = MessageCache(historyGossip, historyLength);
		rng = Random(unpredictableSeed);
	}

	/// A signing router: publishes signed messages and drops unsigned ones.
	this(Keypair kp)
	{
		this(PeerId.fromPublicKey(kp.publicKey));
		signing = true;
		keypair = kp;
	}

	void testSeed(uint seed)
	{
		rng = Random(seed);
	}

	void testClock(Clock c) @safe nothrow
	{
		clock = c;
		if (score !is null)
			score.testClock(c);
	}

	private MonoTime now() @safe nothrow
	{
		return clock is null ? MonoTime.currTime : clock();
	}

	// --- scoring -------------------------------------------------------------------------

	void withPeerScore(PeerScoreParams params, PeerScoreThresholds thresholds)
	{
		score = new PeerScore(params, thresholds);
		if (clock !is null)
			score.testClock(clock);
		foreach (p, _; peers)
			score.addPeer(p);
	}

	bool setApplicationScore(PeerId peer, double value)
	{
		return score !is null && score.setApplicationScore(peer, value);
	}

	private double scoreOf(PeerId peer)
	{
		return score is null ? 0 : score.scoreReport(peer);
	}

	private bool below(PeerId peer, double threshold)
	{
		return score !is null && score.scoreReport(peer) < threshold;
	}

	// --- peers ---------------------------------------------------------------------------

	void addPeer(PeerId peer, bool outbound = false)
	{
		if (peer !in peers)
			peers[peer] = PeerState(outbound);
		if (score !is null)
			score.addPeer(peer);
	}

	/// The peer is gone: out of every mesh and topic.
	void removePeer(PeerId peer)
	{
		foreach (topic, ref m; mesh)
		{
			if (m.canFind(peer) && score !is null)
				score.prune(peer, topic);
			m = m.remove!(p => p == peer);
		}
		peers.remove(peer);
		if (score !is null)
			score.removePeer(peer);
	}

	PeerId[] knownPeers()
	{
		return peers.keys;
	}

	/// Our subscriptions, as the RPC a new peer should be told.
	Rpc helloRpc()
	{
		Rpc rpc;
		foreach (t; subscriptions)
			rpc.subscriptions ~= SubOpts(true, t);
		return rpc;
	}

	// --- observation ---------------------------------------------------------------------

	size_t meshSize(string topic)
	{
		return mesh.get(topic, null).length;
	}

	/// [peers subscribed to the topic, mesh size].
	size_t[2] state(string topic)
	{
		return [topicPeers(topic).length, meshSize(topic)];
	}

	bool isSubscribed(string topic) const @safe pure nothrow
	{
		return subscriptions.canFind(topic);
	}

	string[] topics() const
	{
		return subscriptions.dup;
	}

	// --- the application ---------------------------------------------------------------------

	/// JOIN: announce, and graft up to meshN of the topic's peers.
	Out[] subscribe(string topic)
	{
		Out[] outs;
		if (isSubscribed(topic))
			return outs;
		subscriptions ~= topic;

		// Everyone hears we joined.
		Rpc announce;
		announce.subscriptions ~= SubOpts(true, topic);
		foreach (p, _; peers)
			outs ~= Out(p, announce);

		// The mesh: from the topic's peers, those that may be grafted.
		auto candidates = graftable(topic, meshN);
		foreach (p; candidates)
			outs ~= graftPeer(topic, p);
		return outs;
	}

	/// LEAVE: prune the mesh with the unsubscribe backoff, and announce.
	Out[] unsubscribe(string topic)
	{
		Out[] outs;
		if (!isSubscribed(topic))
			return outs;
		subscriptions = subscriptions.remove!(t => t == topic);
		foreach (p; mesh.get(topic, null).dup)
			outs ~= prunePeer(topic, p, unsubscribeBackoff);
		mesh.remove(topic);
		Rpc announce;
		announce.subscriptions ~= SubOpts(false, topic);
		foreach (p, _; peers)
			outs ~= Out(p, announce);
		return outs;
	}

	/// Publish to every peer subscribed to the topic (flood publish).
	Out[] publish(string topic, const(ubyte)[] data)
	{
		Message m;
		if (signing)
			m = buildSignedMessage(keypair, topic, data, nextSeqno());
		else
		{
			m.from = local.bytes.dup;
			m.data = data.dup;
			m.topic = topic;
			immutable n = nextSeqno();
			m.seqno = new ubyte[8];
			foreach (i; 0 .. 8)
				m.seqno[i] = cast(ubyte)(n >> (8 * (7 - i)));
		}
		immutable id = cast(string) m.id;
		seen[id] = now();
		mcache.put(id, m, true);

		Out[] outs;
		Rpc rpc;
		rpc.messages ~= m;
		auto recipients = topicPeers(topic);
		if (score !is null)
			recipients = recipients.filter!(p => !below(p, score.thresholdsOf.publishThreshold)).array;
		foreach (p; recipients)
			outs ~= Out(p, rpc);
		return outs;
	}

	// --- the wire -------------------------------------------------------------------------

	Out[] onReceive(PeerId from, Rpc rpc)
	{
		if (from !in peers)
			addPeer(from);
		Out[] outs;

		foreach (s; rpc.subscriptions)
			outs ~= onSubscription(from, s);

		foreach (m; rpc.messages)
			outs ~= onMessageReceived(from, m);

		foreach (g; rpc.control.graft)
			outs ~= onGraft(from, g.topic);
		foreach (p; rpc.control.prune)
			onPrune(from, p);
		foreach (d; rpc.control.idontwant)
			onIDontWant(from, d);
		outs ~= onIHave(from, rpc.control.ihave);
		outs ~= onIWant(from, rpc.control.iwant);
		return outs;
	}

	private Out[] onSubscription(PeerId from, SubOpts s)
	{
		Out[] outs;
		auto ps = from in peers;
		if (s.subscribe)
		{
			if (!ps.topics.canFind(s.topic))
				ps.topics ~= s.topic;
			// A topic we are in with a thin mesh takes them straight in.
			if (isSubscribed(s.topic) && meshSize(s.topic) < meshNLow && !mesh.get(s.topic, null).canFind(from)
				&& !isBackedOff(s.topic, from) && !below(from, 0))
				outs ~= graftPeer(s.topic, from);
		}
		else
		{
			ps.topics = ps.topics.remove!(t => t == s.topic);
			if (mesh.get(s.topic, null).canFind(from))
			{
				mesh[s.topic] = mesh[s.topic].remove!(p => p == from);
				if (score !is null)
					score.prune(from, s.topic);
			}
		}
		return outs;
	}

	private Out[] onGraft(PeerId from, string topic)
	{
		Out[] outs;
		if (!isSubscribed(topic))
		{
			outs ~= prunePeer(topic, from, pruneBackoff, false);
			return outs;
		}
		if (mesh.get(topic, null).canFind(from))
			return outs;
		if (isBackedOff(topic, from))
		{
			if (score !is null)
				score.addPenalty(from, 1);
			outs ~= prunePeer(topic, from, pruneBackoff, false);
			return outs;
		}
		if (below(from, 0) || meshSize(topic) >= meshNHigh)
		{
			outs ~= prunePeer(topic, from, pruneBackoff, false);
			return outs;
		}
		mesh[topic] = mesh.get(topic, null) ~ from;
		if (score !is null)
			score.graft(from, topic);
		return outs;
	}

	private void onPrune(PeerId from, Prune p)
	{
		if (mesh.get(p.topic, null).canFind(from))
		{
			mesh[p.topic] = mesh[p.topic].remove!(x => x == from);
			if (score !is null)
				score.prune(from, p.topic);
		}
		immutable backoff = p.backoff > 0 ? p.backoff.seconds : pruneBackoff;
		setBackoff(p.topic, from, backoff);
	}

	private void onIDontWant(PeerId from, IDontWant d)
	{
		auto ps = from in peers;
		foreach (id; d.messageIds)
		{
			if (ps.dontSend.length >= idontwantCap)
				break;
			ps.dontSend ~= cast(string) id.idup;
			ps.dontSendAt ~= now();
		}
	}

	private Out[] onIHave(PeerId from, IHave[] ihaves)
	{
		Out[] outs;
		if (ihaves.length == 0)
			return outs;
		if (score !is null && below(from, score.thresholdsOf.gossipThreshold))
			return outs;
		auto ps = from in peers;
		if (ps.ihaveReceived >= maxIhaveMessages)
			return outs;
		ps.ihaveReceived++;

		string[] want;
		foreach (h; ihaves)
		{
			if (!isSubscribed(h.topic))
				continue;
			foreach (raw; h.messageIds)
			{
				immutable id = cast(string) raw.idup;
				if (id in seen || promises.contains(id) || want.canFind(id))
					continue;
				want ~= id;
			}
		}
		if (want.length == 0)
			return outs;
		immutable room = maxIhaveLength > ps.iwantSent ? maxIhaveLength - ps.iwantSent : 0;
		if (room == 0)
			return outs;
		if (want.length > room)
		{
			randomShuffle(want, rng);
			want = want[0 .. room];
		}
		ps.iwantSent += want.length;
		promises.addPromise(from, want, now() + iwantFollowupTime);

		Rpc rpc;
		IWant iw;
		foreach (id; want)
			iw.messageIds ~= cast(ubyte[]) id.dup;
		rpc.control.iwant ~= iw;
		outs ~= Out(from, rpc);
		return outs;
	}

	private Out[] onIWant(PeerId from, IWant[] iwants)
	{
		Out[] outs;
		if (iwants.length == 0)
			return outs;
		if (score !is null && below(from, score.thresholdsOf.gossipThreshold))
			return outs;
		Rpc rpc;
		foreach (w; iwants)
			foreach (raw; w.messageIds)
			{
				size_t count;
				auto m = mcache.getWithIwantCount(cast(string) raw.idup, from, count);
				if (m is null || count > gossipRetransmission)
					continue;
				rpc.messages ~= *m;
			}
		if (rpc.messages.length > 0)
			outs ~= Out(from, rpc);
		return outs;
	}

	private Out[] onMessageReceived(PeerId from, Message m)
	{
		Out[] outs;
		immutable id = cast(string) m.id;

		// Already have it: a duplicate, which scoring wants to know about.
		if (id in seen)
		{
			if (score !is null)
				score.duplicatedMessage(from, id, m.topic);
			return outs;
		}
		if (score !is null)
			score.validateMessage(from, id, m.topic);

		// Validation: a signing router accepts only signed messages.
		if (signing && !verifySignature(m))
		{
			if (score !is null)
				score.rejectMessage(from, id, m.topic, RejectReason.validationError);
			promises.rejectMessage(id, RejectReason.validationError);
			return outs;
		}
		if (m.from.length > 0 && m.from == local.bytes)
		{
			if (score !is null)
				score.rejectMessage(from, id, m.topic, RejectReason.selfOrigin);
			promises.rejectMessage(id, RejectReason.selfOrigin);
			return outs;
		}

		seen[id] = now();
		promises.messageDelivered(id);
		if (score !is null)
			score.deliverMessage(from, id, m.topic);
		mcache.put(id, m, true);

		// A large message: tell the rest of the mesh we have it, so they need not send it.
		if (encode(m).length > idontwantMessageSizeThreshold)
		{
			Rpc idw;
			IDontWant d;
			d.messageIds ~= cast(ubyte[]) id.dup;
			idw.control.idontwant ~= d;
			foreach (p; mesh.get(m.topic, null))
				if (p != from && !(m.from.length > 0 && p.bytes == m.from))
					outs ~= Out(p, idw);
		}

		if (isSubscribed(m.topic))
		{
			if (onMessage !is null)
				onMessage(m.topic, m.data);
			if (onMessageFull !is null)
				onMessageFull(from, m);
		}

		// Forward along the mesh, minus the sender, the publisher and anyone who
		// said they do not want it.
		Rpc fwd;
		fwd.messages ~= m;
		foreach (p; mesh.get(m.topic, null))
		{
			if (p == from || (m.from.length > 0 && p.bytes == m.from))
				continue;
			if (auto ps = p in peers)
				if (ps.dontSend.canFind(id))
					continue;
			outs ~= Out(p, fwd);
		}
		return outs;
	}

	// --- the heartbeat ------------------------------------------------------------------------

	Out[] heartbeat()
	{
		Out[] outs;
		ticks++;
		immutable t = now();

		// Peers who promised and did not deliver.
		if (score !is null)
		{
			foreach (p, count; promises.getBrokenPromises(t))
				score.addPenalty(p, count);
			score.refreshScores();
		}
		else
			cast(void) promises.getBrokenPromises(t);

		// Backoffs that lapsed.
		foreach (topic, ref byPeer; backoffs)
		{
			PeerId[] done;
			foreach (p, until; byPeer)
				if (t >= until)
					done ~= p;
			foreach (p; done)
				byPeer.remove(p);
		}

		// Mesh maintenance, per topic we are in.
		foreach (topic; subscriptions)
		{
			auto m = mesh.get(topic, null);

			// Peers whose score went negative leave.
			if (score !is null)
				foreach (p; m.dup)
					if (scoreOf(p) < 0)
					{
						outs ~= prunePeer(topic, p, pruneBackoff);
						m = mesh.get(topic, null);
					}

			// Too few: graft up to meshN.
			if (m.length < meshNLow)
			{
				foreach (p; graftable(topic, meshN - m.length))
					outs ~= graftPeer(topic, p);
				m = mesh.get(topic, null);
			}

			// Too many (at the high mark counts): prune down to meshN, worst scores
			// first, best protected.
			if (m.length >= meshNHigh)
			{
				auto ordered = m.dup;
				if (score !is null)
				{
					randomShuffle(ordered, rng);
					ordered.sort!((a, b) => scoreOf(a) > scoreOf(b)); // best first
					auto protected_ = ordered[0 .. retainScores < ordered.length ? retainScores : ordered.length];
					auto rest = ordered[protected_.length .. $].dup;
					randomShuffle(rest, rng);
					// Keep the outbound peers we can: they are the eclipse defence.
					auto outboundRest = rest.filter!(p => isOutbound(p)).array;
					auto inboundRest = rest.filter!(p => !isOutbound(p)).array;
					ordered = protected_ ~ outboundRest ~ inboundRest;
				}
				else
					randomShuffle(ordered, rng);
				immutable excess = m.length - meshN;
				auto toPrune = ordered[$ - excess .. $];
				foreach (p; toPrune)
					outs ~= prunePeer(topic, p, pruneBackoff);
				m = mesh.get(topic, null);
			}

			// Enough peers, but too few of them are ones we dialed.
			if (m.length >= meshNLow)
			{
				immutable outbound = m.filter!(p => isOutbound(p)).array.length;
				if (outbound < meshOutboundMin)
				{
					auto cands = graftable(topic, size_t.max).filter!(p => isOutbound(p)).array;
					foreach (p; cands[0 .. cands.length < meshOutboundMin - outbound ? cands.length : meshOutboundMin - outbound])
						outs ~= graftPeer(topic, p);
					m = mesh.get(topic, null);
				}
			}

			// Opportunistic grafting: a mesh with a poor median gets better peers.
			if (score !is null && ticks % opportunisticGraftTicks == 0 && m.length > 1)
			{
				auto scores = m.map!(p => scoreOf(p)).array;
				scores.sort();
				immutable median = scores[scores.length / 2];
				if (median < score.thresholdsOf.opportunisticGraftThreshold)
				{
					auto cands = graftable(topic, size_t.max).filter!(p => scoreOf(p) > median).array;
					randomShuffle(cands, rng);
					foreach (p; cands[0 .. cands.length < opportunisticGraftPeers ? cands.length : opportunisticGraftPeers])
						outs ~= graftPeer(topic, p);
				}
			}
		}

		// Gossip: offer what we have to peers outside the mesh.
		foreach (topic; subscriptions)
		{
			auto ids = mcache.gossipMessageIds(topic);
			if (ids.length == 0)
				continue;
			if (ids.length > maxIhaveLength)
			{
				randomShuffle(ids, rng);
				ids = ids[0 .. maxIhaveLength];
			}
			auto m = mesh.get(topic, null);
			auto cands = topicPeers(topic).filter!(p => !m.canFind(p)
					&& !(score !is null && below(p, score.thresholdsOf.gossipThreshold))).array;
			size_t n = cast(size_t)(gossipFactor * cands.length);
			if (n < gossipLazy)
				n = gossipLazy;
			randomShuffle(cands, rng);
			if (cands.length > n)
				cands = cands[0 .. n];
			foreach (p; cands)
			{
				Rpc rpc;
				IHave h;
				h.topic = topic;
				h.messageIds = ids.dup;
				rpc.control.ihave ~= h;
				outs ~= Out(p, rpc);
			}
		}

		// Housekeeping.
		mcache.shift();
		foreach (p, ref ps; peers)
		{
			ps.ihaveReceived = 0;
			ps.iwantSent = 0;
			while (ps.dontSendAt.length > 0 && t - ps.dontSendAt[0] > idontwantTimeout)
			{
				ps.dontSend = ps.dontSend[1 .. $];
				ps.dontSendAt = ps.dontSendAt[1 .. $];
			}
		}
		string[] old;
		foreach (id, when; seen)
			if (t - when > duplicateCacheTime)
				old ~= id;
		foreach (id; old)
			seen.remove(id);
		if (score !is null)
			score.forgetDeliveriesOlderThan(duplicateCacheTime);

		return outs;
	}

	// --- helpers -----------------------------------------------------------------------------

	private PeerId[] topicPeers(string topic)
	{
		PeerId[] out_;
		foreach (p, ref ps; peers)
			if (ps.topics.canFind(topic))
				out_ ~= p;
		return out_;
	}

	private bool isOutbound(PeerId p)
	{
		auto ps = p in peers;
		return ps !is null && ps.outbound;
	}

	/// Topic peers not in the mesh, not backed off, not negatively scored — up to `n`, shuffled.
	private PeerId[] graftable(string topic, size_t n)
	{
		auto m = mesh.get(topic, null);
		auto cands = topicPeers(topic).filter!(p => !m.canFind(p) && !isBackedOff(topic, p) && !below(p, 0)).array;
		randomShuffle(cands, rng);
		return cands.length > n ? cands[0 .. n] : cands;
	}

	private Out graftPeer(string topic, PeerId p)
	{
		mesh[topic] = mesh.get(topic, null) ~ p;
		if (score !is null)
			score.graft(p, topic);
		Rpc rpc;
		rpc.control.graft ~= Graft(topic);
		return Out(p, rpc);
	}

	private Out prunePeer(string topic, PeerId p, Duration backoff, bool inMesh = true)
	{
		if (inMesh)
		{
			mesh[topic] = mesh.get(topic, null).remove!(x => x == p);
			if (score !is null)
				score.prune(p, topic);
		}
		setBackoff(topic, p, backoff);
		Rpc rpc;
		rpc.control.prune ~= Prune(topic, null, backoff.total!"seconds");
		return Out(p, rpc);
	}

	private void setBackoff(string topic, PeerId p, Duration backoff)
	{
		auto byPeer = backoffs.get(topic, null);
		byPeer[p] = now() + backoff + heartbeatInterval * backoffSlack;
		backoffs[topic] = byPeer;
	}

	private bool isBackedOff(string topic, PeerId p)
	{
		auto byPeer = topic in backoffs;
		if (byPeer is null)
			return false;
		auto until = p in *byPeer;
		return until !is null && now() < *until;
	}

	private ulong nextSeqno()
	{
		if (seqno == 0)
			seqno = uniform!ulong(rng);
		return seqno++;
	}
}
