module tests.protocol.gossipsub_test;

import core.time : MonoTime, Duration, seconds;
import libp2p.core.peer_id : PeerId;
import libp2p.crypto.keys : Keypair;
import gs = libp2p.protocol.gossipsub; // qualified: gs.Message clashes with fluent's Message
import libp2p.protocol.gossipsub.score : PeerScoreParams, PeerScoreThresholds;
import fluent.asserts;

private gs.Rpc subRpc(bool subscribe, string topic)
{
	gs.Rpc rpc;
	rpc.subscriptions ~= gs.SubOpts(subscribe, topic);
	return rpc;
}

private gs.Rpc graftRpc(string topic)
{
	gs.Rpc rpc;
	rpc.control.graft ~= gs.Graft(topic);
	return rpc;
}

// Analogue of rust mcache.rs::gen_testm: a distinct message per `x`.
private gs.Message genMsg(ulong x, string topic)
{
	gs.Message m;
	m.from = [cast(ubyte)(x + 1)];
	m.seqno = [0, 0, 0, 0, 0, 0, 0, cast(ubyte) x];
	m.data = [cast(ubyte) x];
	m.topic = topic;
	return m;
}

@("gossipsub RPC codec round-trips subscriptions, a message and control")
unittest
{
	ubyte[] from = [0xaa, 0xbb];
	ubyte[] seqno = [0, 0, 0, 0, 0, 0, 0, 1];
	ubyte[] payload = [1, 2, 3, 4];

	gs.Rpc rpc;
	rpc.subscriptions ~= gs.SubOpts(true, "topicA");
	rpc.subscriptions ~= gs.SubOpts(false, "topicB");
	rpc.messages ~= gs.Message(from, payload, seqno, "topicA");
	rpc.control.graft ~= gs.Graft("topicA");
	rpc.control.prune ~= gs.Prune("topicB");

	auto back = gs.decodeRpc(gs.encodeRpc(rpc));

	back.subscriptions.length.should.equal(2);
	back.subscriptions[0].subscribe.should.equal(true);
	back.subscriptions[0].topic.should.equal("topicA");
	back.subscriptions[1].subscribe.should.equal(false);
	back.subscriptions[1].topic.should.equal("topicB");

	back.messages.length.should.equal(1);
	back.messages[0].from.should.equal(from);
	back.messages[0].data.should.equal(payload);
	back.messages[0].seqno.should.equal(seqno);
	back.messages[0].topic.should.equal("topicA");

	back.control.graft.length.should.equal(1);
	back.control.graft[0].topic.should.equal("topicA");
	back.control.prune.length.should.equal(1);
	back.control.prune[0].topic.should.equal("topicB");
}

// Laundered from rust `protocol.rs::tests::encode_decode`: a signed message
// survives an encode/decode round-trip through the RPC codec unchanged, and its
// signature still verifies.
@("gossipsub signed message round-trips through the codec and still verifies")
unittest
{
	auto kp = Keypair.generateEd25519();
	auto msg = gs.buildSignedMessage(kp, "test-topic", cast(ubyte[]) "payload", 42);

	gs.verifySignature(msg).should.equal(true);

	gs.Rpc rpc;
	rpc.messages ~= msg;
	auto back = gs.decodeRpc(gs.encodeRpc(rpc));

	back.messages.length.should.equal(1);
	auto got = back.messages[0];
	got.from.should.equal(msg.from);
	got.data.should.equal(msg.data);
	got.seqno.should.equal(msg.seqno);
	got.topic.should.equal(msg.topic);
	got.signature.should.equal(msg.signature);
	// Ed25519 key is inlined in the PeerId, so the `key` field is omitted.
	got.key.length.should.equal(0);
	gs.verifySignature(got).should.equal(true);
}

@("gossipsub signature verification rejects tampering and the wrong key")
unittest
{
	auto kp = Keypair.generateEd25519();
	auto msg = gs.buildSignedMessage(kp, "t", cast(ubyte[]) "hello", 7);
	gs.verifySignature(msg).should.equal(true);

	// Tampered payload no longer matches the signature.
	auto tampered = msg;
	tampered.data = cast(ubyte[]) "hellp";
	gs.verifySignature(tampered).should.equal(false);

	// A source PeerId that doesn't match the (inlined) signing key is rejected.
	auto other = Keypair.generateEd25519();
	auto forged = msg;
	forged.from = PeerId.fromPublicKey(other.publicKey).bytes;
	gs.verifySignature(forged).should.equal(false);

	// No signature at all: rejected under strict verification.
	auto unsigned = msg;
	unsigned.signature = null;
	gs.verifySignature(unsigned).should.equal(false);
}

// Laundered from rust `config.rs`'s default `message_id_fn`:
// `base58(source) ++ decimal(seqno_u64)`, with `PeerId([0,1,0])`/0 as fallbacks.
@("gossipsub default message-id is base58(source) ++ decimal(seqno)")
unittest
{
	auto pid = PeerId([0x12, 0x20, 0x01, 0x02, 0x03]);
	ubyte[] seqno = [0, 0, 0, 0, 0, 0, 0, 42];
	auto m = gs.Message(pid.bytes.dup, cast(ubyte[]) "x", seqno, "topic");
	(cast(string) m.id).should.equal(pid.toBase58 ~ "42");

	// Missing source hashes as PeerId([0,1,0]); missing seqno as 0.
	gs.Message empty;
	empty.topic = "topic";
	(cast(string) empty.id).should.equal(PeerId([0, 1, 0]).toBase58 ~ "0");
}

@("gossipsub delivers a published message to a subscribed peer and forms a mesh")
unittest
{
	ubyte[] bytesA = [0x01];
	ubyte[] bytesB = [0x02];
	auto pidA = PeerId(bytesA);
	auto pidB = PeerId(bytesB);

	auto a = new gs.GossipSub(pidA);
	auto b = new gs.GossipSub(pidB);

	string gotTopic;
	string gotData;
	b.onMessage = (topic, data) { gotTopic = topic; gotData = cast(string) data.idup; };

	// Introduce the peers to each other.
	a.addPeer(pidB);
	b.addPeer(pidA);

	// Both subscribe, then exchange the SUBSCRIBE announcements.
	auto aSubs = a.subscribe("chat");
	auto bSubs = b.subscribe("chat");
	foreach (o; aSubs)
		if (o.peer == pidB)
			b.onReceive(pidA, o.rpc);
	foreach (o; bSubs)
		if (o.peer == pidA)
			a.onReceive(pidB, o.rpc);

	// A publishes; deliver the forwarded frames to B.
	auto pub = a.publish("chat", cast(const(ubyte)[]) "hello mesh");
	pub.length.should.equal(1); // A grafted B into its mesh, so exactly one forward
	pub[0].peer.should.equal(pidB);
	foreach (o; pub)
		if (o.peer == pidB)
			b.onReceive(pidA, o.rpc);

	gotTopic.should.equal("chat");
	gotData.should.equal("hello mesh");
}

// Laundered from rust `protocol.rs::tests::max_publish_messages`: an RPC with
// more than max_publish_messages published messages is rejected on decode.
@("gossipsub codec rejects an RPC with too many publish messages")
unittest
{
	gs.Rpc rpc;
	foreach (i; 0 .. 501)
		rpc.messages ~= gs.Message([0x01], [1], null, "t");
	auto frame = gs.encodeRpc(rpc);
	auto err = gs.validateRpcLimits(frame, uint.max, 500, uint.max);
	err.should.equal("too many publish messages");
}

// Laundered from `protocol.rs::tests::max_cumulative_control_size`.
@("gossipsub codec rejects control messages over the cumulative size limit")
unittest
{
	gs.Rpc rpc;
	foreach (i; 0 .. 5)
	{
		gs.IHave h;
		h.topic = "topic-" ~ (cast(char)('0' + i));
		foreach (j; 0 .. 10)
			h.messageIds ~= [cast(ubyte) j];
		rpc.control.ihave ~= h;
	}
	auto frame = gs.encodeRpc(rpc);
	auto err = gs.validateRpcLimits(frame, uint.max, 500, 100); // 100-byte control cap
	err.should.equal("rpc control size exceeds max control message size");
}

// Laundered from `protocol.rs::tests::rpc_valid_limits`: an RPC exactly at the
// limits (500 messages + a small control) passes validation.
@("gossipsub codec accepts an RPC within the limits")
unittest
{
	gs.Rpc rpc;
	foreach (i; 0 .. 500)
		rpc.messages ~= gs.Message([0x01], [1], null, "t");
	gs.IHave h;
	h.topic = "test-topic";
	foreach (j; 0 .. 10)
		h.messageIds ~= [cast(ubyte) j];
	rpc.control.ihave ~= h;

	auto frame = gs.encodeRpc(rpc);
	auto err = gs.validateRpcLimits(frame, uint.max, 500, 5120);
	(err is null).should.equal(true);
	gs.decodeRpc(frame).messages.length.should.equal(500);
}

// Laundered from rust `behaviour.rs` JOIN: subscribing forms the mesh by
// grafting up to mesh_n of the known topic peers.
@("gossipsub subscribe grafts up to mesh_n topic peers into the mesh")
unittest
{
	auto a = new gs.GossipSub(PeerId([0xff]));
	a.testSeed(1);

	// 8 peers announce they are subscribed to "t" before we join.
	foreach (i; 0 .. 8)
		a.onReceive(PeerId([cast(ubyte) i]), subRpc(true, "t"));

	auto outs = a.subscribe("t");

	// mesh_n == 6, so exactly 6 peers are grafted.
	a.meshSize("t").should.equal(gs.meshN);
	size_t grafts;
	foreach (o; outs)
		grafts += o.rpc.control.graft.length;
	grafts.should.equal(gs.meshN);
}

// Laundered from rust `handle_graft`: a GRAFT is refused with a PRUNE once the
// mesh is at the upper bound (mesh_n_high).
@("gossipsub refuses a GRAFT past mesh_n_high with a PRUNE")
unittest
{
	auto a = new gs.GossipSub(PeerId([0xff]));
	a.subscribe("t"); // subscribed, mesh empty (no peers yet)

	// Fill the mesh to mesh_n_high via GRAFTs.
	foreach (i; 0 .. gs.meshNHigh)
		a.onReceive(PeerId([cast(ubyte) i]), graftRpc("t"));
	a.meshSize("t").should.equal(gs.meshNHigh);

	// One more GRAFT is over the bound: expect a PRUNE back, no mesh growth.
	auto outs = a.onReceive(PeerId([0xAA]), graftRpc("t"));
	a.meshSize("t").should.equal(gs.meshNHigh);
	size_t prunes;
	foreach (o; outs)
		foreach (p; o.rpc.control.prune)
			if (p.topic == "t")
				prunes++;
	prunes.should.equal(1);
}

// Laundered from rust `backoff.rs` + `handle_graft`: after a PRUNE the peer is
// backed off and a GRAFT within the backoff window is refused; once the backoff
// (plus slack) elapses, the GRAFT is honoured.
@("gossipsub backoff blocks re-graft until it expires")
unittest
{
	auto a = new gs.GossipSub(PeerId([0xff]));
	MonoTime base = MonoTime.currTime;
	Duration off;
	a.testClock(() @safe nothrow => base + off);

	a.subscribe("t");
	auto p = PeerId([0x01]);

	// Peer PRUNEs us with a 60s backoff.
	gs.Rpc prune;
	prune.control.prune ~= gs.Prune("t", null, 60);
	a.onReceive(p, prune);

	// A GRAFT inside the backoff window is refused (PRUNE back, not added).
	auto refused = a.onReceive(p, graftRpc("t"));
	a.meshSize("t").should.equal(0);
	size_t prunes;
	foreach (o; refused)
		prunes += o.rpc.control.prune.length;
	prunes.should.equal(1);

	// After the backoff (plus slack) elapses, the GRAFT is honoured.
	off = 62.seconds;
	a.onReceive(p, graftRpc("t"));
	a.meshSize("t").should.equal(1);
}

// Laundered from rust `mcache.rs::test_shift`.
@("gossipsub mcache shift rolls history and keeps the messages")
unittest
{
	auto mc = gs.MessageCache(1, 5);
	foreach (i; 0 .. 10)
	{
		auto m = genMsg(i, "topic1");
		mc.put(cast(string) m.id, m, false);
	}
	mc.shift();
	mc.windowLen(0).should.equal(0);
	mc.windowLen(1).should.equal(10);
	mc.messageCount.should.equal(10);
}

// Laundered from rust `mcache.rs::test_remove_last_from_shift`.
@("gossipsub mcache drops messages once they age past the history")
unittest
{
	auto mc = gs.MessageCache(4, 5);
	foreach (i; 0 .. 10)
	{
		auto m = genMsg(i, "t");
		mc.put(cast(string) m.id, m, false);
	}
	foreach (_; 0 .. 4)
		mc.shift();
	mc.windowLen(4).should.equal(10);
	mc.shift();
	mc.windowLen(4).should.equal(0);
	mc.windowLen(0).should.equal(0);
	mc.messageCount.should.equal(0);
}

// mcache only offers messages within the gossip window (history[..gossip]).
@("gossipsub mcache gossips a validated message only within the gossip window")
unittest
{
	auto mc = gs.MessageCache(2, 4); // gossip window = 2
	auto m = genMsg(1, "t");
	mc.put(cast(string) m.id, m, true);
	mc.gossipMessageIds("t").length.should.equal(1);
	mc.shift();
	mc.gossipMessageIds("t").length.should.equal(1); // window 1, still gossiped
	mc.shift();
	mc.gossipMessageIds("t").length.should.equal(0); // window 2, past the gossip window
}

// Laundered from rust `emit_gossip`/`handle_ihave`/`handle_iwant`: a message
// forwarded only along the mesh still reaches a non-mesh peer via IHAVE→IWANT.
@("gossipsub gossip: IHAVE offers a forwarded message and IWANT retrieves it")
unittest
{
	auto pidB = PeerId([0xB0]);
	auto pidC = PeerId([0xC0]);

	auto b = new gs.GossipSub(pidB);
	b.testSeed(1);
	b.subscribe("t");
	// Fill B's mesh to mesh_n_low with 5 peers so C can't be meshed.
	foreach (i; 0 .. gs.meshNLow)
		b.onReceive(PeerId([cast(ubyte) i]), subRpc(true, "t"));
	b.meshSize("t").should.equal(gs.meshNLow);
	// C connects and subscribes, but the mesh is full → gossip-only.
	b.onReceive(pidC, subRpc(true, "t"));
	b.meshSize("t").should.equal(gs.meshNLow);

	// A mesh peer delivers a message; B forwards along the mesh (not to C).
	gs.Message msg;
	msg.from = [0x99];
	msg.seqno = [0, 0, 0, 0, 0, 0, 0, 1];
	msg.data = cast(ubyte[]) "hi";
	msg.topic = "t";
	gs.Rpc mrpc;
	mrpc.messages ~= msg;
	b.onReceive(PeerId([0]), mrpc);

	// Heartbeat: B gossips IHAVE(t, [id]) to the non-mesh peer C.
	gs.Rpc ihaveRpc;
	bool foundIhave;
	foreach (o; b.heartbeat())
		if (o.peer == pidC && o.rpc.control.ihave.length)
		{
			ihaveRpc = o.rpc;
			foundIhave = true;
		}
	foundIhave.should.equal(true);
	ihaveRpc.control.ihave[0].topic.should.equal("t");
	ihaveRpc.control.ihave[0].messageIds.should.equal([cast(ubyte[]) msg.id]);

	// C asks for the advertised message with an IWANT.
	auto c = new gs.GossipSub(pidC);
	c.testSeed(2);
	c.subscribe("t");
	gs.Rpc iwantRpc;
	bool foundIwant;
	foreach (o; c.onReceive(pidB, ihaveRpc))
		if (o.peer == pidB && o.rpc.control.iwant.length)
		{
			iwantRpc = o.rpc;
			foundIwant = true;
		}
	foundIwant.should.equal(true);

	// B serves the IWANT from its message cache.
	bool served;
	foreach (o; b.onReceive(pidC, iwantRpc))
		if (o.peer == pidC && o.rpc.messages.length && o.rpc.messages[0].topic == "t")
			served = true;
	served.should.equal(true);
}

// Laundered from rust IDONTWANT handling + `forward_msg`: a peer that sent us
// IDONTWANT for a message id is skipped when we forward that message.
@("gossipsub IDONTWANT makes forwarding skip that peer")
unittest
{
	auto a = new gs.GossipSub(PeerId([0xff]));
	a.subscribe("t");
	auto p1 = PeerId([0x01]);
	auto p2 = PeerId([0x02]);
	auto p3 = PeerId([0x03]);
	foreach (p; [p1, p2, p3])
		a.onReceive(p, graftRpc("t")); // all three in the mesh

	gs.Message msg;
	msg.from = [0x99];
	msg.seqno = [0, 0, 0, 0, 0, 0, 0, 5];
	msg.data = cast(ubyte[]) "hi";
	msg.topic = "t";
	auto id = cast(ubyte[]) msg.id;

	// p1 tells us it doesn't want this id.
	gs.Rpc idw;
	gs.IDontWant d;
	d.messageIds ~= id;
	idw.control.idontwant ~= d;
	a.onReceive(p1, idw);

	// p3 delivers the message: we forward to mesh minus source(p3) minus
	// publisher(0x99) minus IDONTWANT(p1) → only p2.
	gs.Rpc mrpc;
	mrpc.messages ~= msg;
	PeerId[] got;
	foreach (o; a.onReceive(p3, mrpc))
		if (o.rpc.messages.length)
			got ~= o.peer;
	got.length.should.equal(1);
	got[0].should.equal(p2);
}

// Laundered from rust `handle_received_message`: receiving a large NEW message
// broadcasts IDONTWANT for it to the other mesh peers.
@("gossipsub a large new message broadcasts IDONTWANT to other mesh peers")
unittest
{
	auto a = new gs.GossipSub(PeerId([0xff]));
	a.subscribe("t");
	auto p1 = PeerId([0x01]);
	auto p2 = PeerId([0x02]);
	auto p3 = PeerId([0x03]);
	foreach (p; [p1, p2, p3])
		a.onReceive(p, graftRpc("t"));

	gs.Message big;
	big.from = p1.bytes.dup; // publisher == p1 (the sender)
	big.seqno = [0, 0, 0, 0, 0, 0, 0, 9];
	big.data = new ubyte[1100]; // over idontwant_message_size_threshold (1000)
	big.topic = "t";
	auto id = cast(ubyte[]) big.id;

	gs.Rpc mrpc;
	mrpc.messages ~= big;

	PeerId[] idontwanted;
	foreach (o; a.onReceive(p1, mrpc))
		foreach (dd; o.rpc.control.idontwant)
			if (dd.messageIds == [id])
				idontwanted ~= o.peer;

	// IDONTWANT goes to the mesh minus the sender/publisher p1 → p2 and p3.
	idontwanted.length.should.equal(2);
	import std.algorithm : canFind;

	canFind(idontwanted, p2).should.equal(true);
	canFind(idontwanted, p3).should.equal(true);
}

// Scoring wired into the router: a mesh peer whose score goes negative is
// pruned from the mesh on the next heartbeat (rust heartbeat mesh maintenance).
@("gossipsub heartbeat prunes a negative-score peer from the mesh")
unittest
{
	auto a = new gs.GossipSub(PeerId([0xff]));
	a.withPeerScore(PeerScoreParams.init, PeerScoreThresholds.init);
	a.subscribe("t");

	auto p = PeerId([0x01]);
	a.addPeer(p); // registers p with the score engine
	a.onReceive(p, graftRpc("t")); // p grafts into the mesh
	a.meshSize("t").should.equal(1);

	// app_specific_weight defaults to 10, so -100 app score => -1000 total.
	a.setApplicationScore(p, -100.0).should.equal(true);
	a.heartbeat();
	a.meshSize("t").should.equal(0);
}

// Scoring gate: IHAVE from a peer below the gossip threshold is ignored (no
// IWANT), while an equal-scored peer's IHAVE is honoured.
@("gossipsub ignores IHAVE gossip from a peer below the gossip threshold")
unittest
{
	auto a = new gs.GossipSub(PeerId([0xff]));
	a.withPeerScore(PeerScoreParams.init, PeerScoreThresholds.init);
	a.subscribe("t");

	gs.Rpc ih;
	gs.IHave h;
	h.topic = "t";
	h.messageIds ~= cast(ubyte[]) "someid";
	ih.control.ihave ~= h;

	// low-score peer: -2 app * 10 weight = -20, below gossip_threshold (-10).
	auto low = PeerId([0x01]);
	a.addPeer(low);
	a.setApplicationScore(low, -2.0);
	bool lowAsked;
	foreach (o; a.onReceive(low, ih))
		if (o.rpc.control.iwant.length)
			lowAsked = true;
	lowAsked.should.equal(false);

	// ok-score peer: same IHAVE is honoured with an IWANT.
	auto ok = PeerId([0x02]);
	a.addPeer(ok);
	bool okAsked;
	foreach (o; a.onReceive(ok, ih))
		if (o.rpc.control.iwant.length)
			okAsked = true;
	okAsked.should.equal(true);
}

@("gossipsub dedups a message seen twice")
unittest
{
	ubyte[] bytesA = [0x01];
	ubyte[] bytesB = [0x02];
	auto pidA = PeerId(bytesA);
	auto pidB = PeerId(bytesB);
	auto b = new gs.GossipSub(pidB);

	int deliveries;
	b.onMessage = (topic, data) { deliveries++; };
	b.addPeer(pidA);
	b.subscribe("chat");

	gs.Rpc aSub;
	aSub.subscriptions ~= gs.SubOpts(true, "chat");
	b.onReceive(pidA, aSub); // A announces its subscription

	ubyte[] from = [0x01];
	ubyte[] seqno = [0, 0, 0, 0, 0, 0, 0, 7];
	gs.Rpc msg;
	msg.messages ~= gs.Message(from, cast(ubyte[]) "dup", seqno, "chat");

	b.onReceive(pidA, msg);
	b.onReceive(pidA, msg); // same id again

	deliveries.should.equal(1);
}

// Laundered from rust `heartbeat` opportunistic grafting: when the median score
// of a mesh is below the opportunistic-graft threshold, the heartbeat (every
// opportunistic_graft_ticks) grafts a few better-than-median peers to improve it.
@("gossipsub opportunistically grafts a better-than-median peer")
unittest
{
	PeerScoreParams params; // appSpecificWeight defaults to 10; no topic params, so
	// mesh peers accrue no time-in-mesh score and sit at 0.
	auto a = new gs.GossipSub(PeerId([0xff]));
	a.testSeed(1);
	a.withPeerScore(params, PeerScoreThresholds.init);

	// Six peers join the mesh (score 0 each): mesh_n_low(5) <= 6 < mesh_n_high(12),
	// so neither the low-mesh graft nor the high-mesh prune fires — isolating the
	// opportunistic path.
	foreach (i; 0 .. 6)
	{
		auto p = PeerId([cast(ubyte) i]);
		a.addPeer(p);
		a.onReceive(p, subRpc(true, "t"));
	}
	a.subscribe("t");
	a.meshSize("t").should.equal(6UL);

	// A seventh peer is subscribed but NOT in the mesh, with a high application
	// score (P5 = 100 * appSpecificWeight = 1000), well above the median of 0.
	auto cand = PeerId([0x42]);
	a.addPeer(cand);
	a.onReceive(cand, subRpc(true, "t"));
	a.setApplicationScore(cand, 100.0).should.equal(true);

	// The median mesh score (0) is below the threshold (20); on the 60th heartbeat
	// the candidate is opportunistically grafted.
	foreach (_; 0 .. gs.opportunisticGraftTicks)
		a.heartbeat();

	a.meshSize("t").should.equal(7UL);
}

// Laundered from rust `heartbeat` mesh-high prune: when a mesh exceeds
// mesh_n_high the excess is trimmed WORST-score-first, and the top
// `retain_scores` peers are protected. (Outbound protection is not modelled —
// no connection-direction tracking.)
@("gossipsub prunes the worst-scoring peers first, protecting the best")
unittest
{
	PeerScoreParams params; // appSpecificWeight defaults to 10
	auto a = new gs.GossipSub(PeerId([0xff]));
	a.testSeed(7);
	a.withPeerScore(params, PeerScoreThresholds.init);
	a.subscribe("t");

	// Graft mesh_n_high(12) peers into the mesh.
	foreach (i; 0 .. gs.meshNHigh)
	{
		auto p = PeerId([cast(ubyte) i]);
		a.addPeer(p);
		a.onReceive(p, graftRpc("t"));
	}
	a.meshSize("t").should.equal(gs.meshNHigh);

	// Give peers 0..3 a high application score; the rest sit at 0.
	PeerId[] best;
	foreach (i; 0 .. 4)
	{
		auto p = PeerId([cast(ubyte) i]);
		a.setApplicationScore(p, 100.0);
		best ~= p;
	}

	// Heartbeat trims the excess (12 -> mesh_n 6). The 4 best must survive.
	auto outs = a.heartbeat();
	a.meshSize("t").should.equal(gs.meshN);

	bool[PeerId] pruned;
	size_t pruneCount;
	foreach (o; outs)
		foreach (pr; o.rpc.control.prune)
			if (pr.topic == "t")
			{
				pruned[o.peer] = true;
				pruneCount++;
			}
	pruneCount.should.equal(gs.meshNHigh - gs.meshN); // 6 pruned
	foreach (p; best)
		(p in pruned).should.equal(null); // none of the top scorers pruned
}

// Laundered from rust `heartbeat` outbound quota: a mesh that is not below
// mesh_n_low but short on OUTBOUND peers grafts more outbound ones, so the mesh
// keeps at least mesh_outbound_min peers we dialed (eclipse-attack resistance).
@("gossipsub grafts outbound peers to keep the mesh_outbound_min quota")
unittest
{
	auto a = new gs.GossipSub(PeerId([0xff]));
	a.testSeed(3);
	a.subscribe("t");

	// Five INBOUND mesh peers (grafted by them → we never dialed them).
	foreach (i; 0 .. gs.meshNLow)
	{
		auto p = PeerId([cast(ubyte) i]);
		a.onReceive(p, graftRpc("t"));
	}
	a.meshSize("t").should.equal(gs.meshNLow);

	// Two OUTBOUND candidates subscribed to the topic but not yet in the mesh.
	PeerId[] outs_;
	foreach (i; 0 .. 2)
	{
		auto p = PeerId([cast(ubyte)(100 + i)]);
		a.addPeer(p, true); // outbound = we dialed it
		a.onReceive(p, subRpc(true, "t"));
		outs_ ~= p;
	}

	// Mesh (5) is at mesh_n_low with 0 outbound < mesh_outbound_min(2): the
	// heartbeat must graft the two outbound candidates.
	auto outsRpc = a.heartbeat();
	a.meshSize("t").should.equal(gs.meshNLow + 2);

	bool[PeerId] grafted;
	foreach (o; outsRpc)
		foreach (g; o.rpc.control.graft)
			if (g.topic == "t")
				grafted[o.peer] = true;
	foreach (p; outs_)
		((p in grafted) !is null).should.equal(true); // both outbound peers grafted
}
