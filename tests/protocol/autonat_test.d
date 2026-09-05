module tests.protocol.autonat_test;

import libp2p.protocol.autonat;
import libp2p.core.peer_id : PeerId;
import libp2p.crypto.keys : Keypair;
import libp2p.multiformats.multiaddr : Multiaddr;
import wire = libp2p.protocol.autonat.wire;
import fluent.asserts;

private PeerId randomPeer()
{
	return PeerId.fromPublicKey(Keypair.generateEd25519.publicKey);
}

// Laundered from rust `v1/protocol.rs::tests::test_request_encode_decode`.
@("autonat DialRequest encode/decode round-trips")
unittest
{
	DialRequest req;
	req.peerId = randomPeer();
	req.addresses = [
		Multiaddr.parse("/ip4/8.8.8.8/tcp/30333"),
		Multiaddr.parse("/ip4/192.168.1.42/tcp/30333"),
	];
	auto back = DialRequest.decode(req.encode);
	back.peerId.should.equal(req.peerId);
	back.addresses.should.equal(req.addresses);
}

// Laundered from `test_response_ok_encode_decode`.
@("autonat DialResponse OK round-trips with the observed address")
unittest
{
	DialResponse resp;
	resp.ok = true;
	resp.addr = Multiaddr.parse("/ip4/8.8.8.8/tcp/30333");
	auto back = DialResponse.decode(resp.encode);
	back.ok.should.equal(true);
	back.addr.should.equal(resp.addr);
	back.statusText.should.equal("");
}

// Laundered from `test_response_err_encode_decode`.
@("autonat DialResponse error round-trips with status text")
unittest
{
	DialResponse resp;
	resp.ok = false;
	resp.error = ResponseError.dialError;
	resp.statusText = "dial failed";
	auto back = DialResponse.decode(resp.encode);
	back.ok.should.equal(false);
	back.error.should.equal(ResponseError.dialError);
	back.statusText.should.equal("dial failed");
}

// Laundered from `test_skip_unparsable_multiaddr`: a DIAL carrying one valid and
// one unparseable address decodes to just the valid one.
@("autonat decode skips an unparseable multiaddr")
unittest
{
	auto valid = Multiaddr.parse("/ip6/2001:db8::/tcp/1234");
	auto peer = randomPeer();

	// Build the generated Message wire form, injecting one bad address bytes blob
	// alongside the valid one (PeerInfo.addrs is raw `bytes`).
	wire.Message msg;
	msg.type = cast(uint) wire.MessageType.DIAL;
	wire.PeerInfo pi;
	pi.id = peer.bytes.dup;
	pi.addrs = [
		valid.encode,
		cast(ubyte[])[255, 255, 255, 255, 255, 255, 255, 255],
	];
	wire.Dial d;
	d.peer = pi;
	msg.dial = d;

	auto req = DialRequest.decode(msg.encode);
	req.addresses.should.equal([valid]);
}

// --- NAT-status confidence state machine (laundered from as_client.rs) ------

private auto addrA()
{
	return Multiaddr.parse("/ip4/1.1.1.1/tcp/1");
}

private auto addrB()
{
	return Multiaddr.parse("/ip4/2.2.2.2/tcp/2");
}

// The first probe result sets the status; repeated agreement grows confidence
// up to the cap without ever re-flipping.
@("autonat confidence grows on agreement and caps at confidence_max")
unittest
{
	NatState st;
	NatStatus old;

	// From Unknown, the first Public report flips us to Public.
	st.handleReported(NatStatus.makePublic(addrA), old).should.equal(true);
	old.kind.should.equal(NatKind.unknown);
	st.status.isPublic.should.equal(true);
	st.confidence.should.equal(0UL);

	// Agreement grows confidence, no further flips, capped at 3.
	foreach (_; 0 .. 5)
		st.handleReported(NatStatus.makePublic(addrA), old).should.equal(false);
	st.confidence.should.equal(3UL);
	st.status.isPublic.should.equal(true);
}

// A contradicting report only erodes confidence; the status flips solely once
// confidence has reached zero (so a maxed status survives confidence_max
// contradictions before flipping on the next one).
@("autonat status flips only after confidence is exhausted")
unittest
{
	NatState st;
	NatStatus old;

	// Establish Private at max confidence.
	st.handleReported(NatStatus.makePrivate(), old); // Unknown -> Private (flip)
	foreach (_; 0 .. 3)
		st.handleReported(NatStatus.makePrivate(), old);
	st.confidence.should.equal(3UL);

	// Public reports erode confidence 3 -> 2 -> 1 -> 0 without flipping.
	foreach (_; 0 .. 3)
		st.handleReported(NatStatus.makePublic(addrA), old).should.equal(false);
	st.confidence.should.equal(0UL);
	(st.status.kind == NatKind.privateNat).should.equal(true);

	// The next contradicting report finally flips the status.
	st.handleReported(NatStatus.makePublic(addrA), old).should.equal(true);
	old.kind.should.equal(NatKind.privateNat);
	st.status.isPublic.should.equal(true);
}

// A different public address just switches the observed address — not a flip.
@("autonat switching public address is not a flip")
unittest
{
	NatState st;
	NatStatus old;
	st.handleReported(NatStatus.makePublic(addrA), old); // -> Public(A)
	st.handleReported(NatStatus.makePublic(addrA), old); // confidence 1

	auto flipped = st.handleReported(NatStatus.makePublic(addrB), old);
	flipped.should.equal(false);
	st.status.addr.should.equal(addrB);
	st.confidence.should.equal(1UL); // unchanged
}

// An Unknown report tells us nothing and is ignored.
@("autonat ignores an Unknown probe result")
unittest
{
	NatState st;
	NatStatus old;
	st.handleReported(NatStatus.makePublic(addrA), old);
	st.handleReported(NatStatus.makePublic(addrA), old); // confidence 1

	st.handleReported(NatStatus.init, old).should.equal(false); // Unknown
	st.confidence.should.equal(1UL);
	st.status.isPublic.should.equal(true);
}

// fromResponse maps probe results to statuses (OK->Public, DialError->Private,
// other errors->Unknown).
@("autonat maps probe responses to NAT statuses")
unittest
{
	DialResponse okr;
	okr.ok = true;
	okr.addr = addrA;
	NatStatus.fromResponse(okr).kind.should.equal(NatKind.publicNat);

	DialResponse de;
	de.ok = false;
	de.error = ResponseError.dialError;
	NatStatus.fromResponse(de).kind.should.equal(NatKind.privateNat);

	DialResponse re;
	re.ok = false;
	re.error = ResponseError.dialRefused;
	NatStatus.fromResponse(re).kind.should.equal(NatKind.unknown);
}

// --- as-server amplification protection -------------------------------------

// Laundered from rust `v1/behaviour/as_server.rs::test::filter_addresses`: the
// demanded IP is replaced with the observed one; a mismatched /p2p and a relayed
// address are dropped; a bare address gets /p2p/<peer> appended.
@("autonat filter_valid_addrs replaces the ip and enforces the peer id")
unittest
{
	import std.algorithm : map;
	import std.array : array;

	auto peer = randomPeer();
	auto other = randomPeer();
	auto observed = Multiaddr.parse("/ip4/1.2.3.4/tcp/10/p2p/" ~ peer.toBase58);
	auto demanded = [
		Multiaddr.parse("/ip4/9.9.9.9/tcp/20/p2p/" ~ peer.toBase58), // valid
		Multiaddr.parse("/ip4/9.9.9.9/tcp/21/p2p/" ~ other.toBase58), // wrong peer
		Multiaddr.parse("/ip4/9.9.9.9/tcp/30"), // valid, no /p2p
		Multiaddr.parse("/ip4/9.9.9.9/tcp/40/p2p/" ~ other.toBase58
				~ "/p2p-circuit/p2p/" ~ peer.toBase58), // relayed
	];

	auto got = filterValidAddrs(peer, demanded, observed).map!(a => a.toString).array;
	got.should.equal([
		"/ip4/1.2.3.4/tcp/20/p2p/" ~ peer.toBase58,
		"/ip4/1.2.3.4/tcp/30/p2p/" ~ peer.toBase58,
	]);
}

// resolveInboundRequest: peer-id mismatch is a BadRequest; an all-filtered-out
// request is DialRefused; a good request yields the dial-back addresses.
@("autonat resolveInboundRequest validates the DIAL request")
unittest
{
	auto peer = randomPeer();
	auto other = randomPeer();
	auto observed = Multiaddr.parse("/ip4/1.2.3.4/tcp/10");

	// peer id in the request must match the sender.
	DialRequest mism;
	mism.peerId = other;
	mism.addresses = [Multiaddr.parse("/ip4/9.9.9.9/tcp/20")];
	auto r1 = resolveInboundRequest(peer, mism, observed);
	r1.ok.should.equal(false);
	r1.error.should.equal(ResponseError.badRequest);

	// a request whose addresses all get filtered out is refused.
	DialRequest noaddr;
	noaddr.peerId = peer;
	noaddr.addresses = [Multiaddr.parse("/ip4/9.9.9.9/tcp/40/p2p/" ~ other.toBase58
			~ "/p2p-circuit")];
	auto r2 = resolveInboundRequest(peer, noaddr, observed);
	r2.ok.should.equal(false);
	r2.error.should.equal(ResponseError.dialRefused);

	// a valid request yields the (ip-rewritten) dial-back address.
	DialRequest good;
	good.peerId = peer;
	good.addresses = [Multiaddr.parse("/ip4/9.9.9.9/tcp/20")];
	auto r3 = resolveInboundRequest(peer, good, observed);
	r3.ok.should.equal(true);
	r3.addrs.length.should.equal(1);
	r3.addrs[0].toString.should.equal("/ip4/1.2.3.4/tcp/20/p2p/" ~ peer.toBase58);
}

// AutoNatThrottle: at most peerMax per peer and globalMax total within a rolling
// period; expired entries free up capacity (rust `throttle_clients_*`).
@("autonat throttle limits requests per peer and globally")
unittest
{
	import core.time : MonoTime, seconds;

	auto a = randomPeer();
	auto b = randomPeer();
	auto c = randomPeer();
	auto base = MonoTime.currTime;

	// Per-peer cap of 2.
	AutoNatThrottle t;
	t.peerMax = 2;
	t.globalMax = 100;
	(t.check(a, base) is null).should.equal(true);
	(t.check(a, base) is null).should.equal(true);
	t.check(a, base).should.equal("too many dials for peer");
	// A different peer is unaffected.
	(t.check(b, base) is null).should.equal(true);

	// Global cap of 2 across peers.
	AutoNatThrottle g;
	g.globalMax = 2;
	g.peerMax = 100;
	(g.check(a, base) is null).should.equal(true);
	(g.check(b, base) is null).should.equal(true);
	g.check(c, base).should.equal("too many total dials");

	// Entries older than the period expire, freeing capacity.
	(g.check(c, base + 2.seconds) is null).should.equal(true);
}

// OngoingDials: one dial-back per peer at a time (rust ongoing_inbound gate).
@("autonat allows only one in-flight dial-back per peer")
unittest
{
	auto a = randomPeer();
	auto b = randomPeer();
	OngoingDials og;

	og.active(a).should.equal(false);
	og.start(a);
	og.active(a).should.equal(true); // a second DIAL from a would be refused
	og.active(b).should.equal(false); // a different peer is unaffected
	og.finish(a);
	og.active(a).should.equal(false); // freed once the dial-back completes
}
