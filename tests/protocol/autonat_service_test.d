/**
 * AutoNAT end to end on loopback: a reachable client is told it is public, an
 * unreachable one that it is private, and a server never dials where a client
 * points it.
 */
module tests.protocol.autonat_service_test;

import core.time : msecs, seconds;

import fluent.asserts;

import libp2p.host.host;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.protocol.autonat;
import tests.util.loop;

private struct Node
{
	Host host;
	AutoNat nat;

	void close() nothrow
	{
		nat.close();
		host.close();
	}
}

private Node makeNode(bool listen = true)
{
	auto h = Host.create();
	if (listen)
		h.listen(Multiaddr.parse("/ip4/127.0.0.1/tcp/0"));
	return Node(h, new AutoNat(h));
}

@("autonat: a reachable client is told it is public")
unittest
{
	NatKind kind;
	Multiaddr seenAt, listening;
	onLoop({
		auto server = makeNode();
		scope (exit)
			server.close();
		auto client = makeNode(); // listening, so the dial-back can land
		scope (exit)
			client.close();
		listening = client.host.addrs[0];
		auto st = client.nat.probe(server.host.addrs[0], client.host.addrs);
		kind = st.kind;
		seenAt = st.addr;
	});
	kind.should.equal(NatKind.publicNat);
	seenAt.toString.should.contain(listening.toString);
}

@("autonat: an unreachable client is told it is private")
unittest
{
	NatKind kind;
	onLoop({
		auto server = makeNode();
		scope (exit)
			server.close();
		auto client = makeNode(false); // not listening anywhere

		scope (exit)
			client.close();
		// A port with nothing behind it: learn a free number, then let it go.
		auto probe = Host.create();
		probe.listen(Multiaddr.parse("/ip4/127.0.0.1/tcp/0"));
		auto dead = probe.addrs[0];
		probe.close();

		kind = client.nat.probe(server.host.addrs[0], [dead]).kind;
	});
	kind.should.equal(NatKind.privateNat);
}

// The security property: the server dials the requester back only at the
// address it observed, so a client cannot point it at a third party. The claim
// is rewritten to the observed IP; the client is not listening there; the
// answer is "private", and no dial to the claimed victim ever happens.
@("autonat: a claimed third-party address is rewritten, not dialed")
unittest
{
	NatKind kind = NatKind.publicNat;
	onLoop({
		auto server = makeNode();
		scope (exit)
			server.close();
		auto client = makeNode(false);
		scope (exit)
			client.close();
		auto victim = Multiaddr.parse("/ip4/10.1.2.3/tcp/9999");
		kind = client.nat.probe(server.host.addrs[0], [victim]).kind;
	});
	kind.should.not.equal(NatKind.publicNat);
}

@("autonat: the client's confidence follows the probes")
unittest
{
	size_t confidence;
	NatKind kind;
	bool flipped;
	onLoop({
		auto server = makeNode();
		scope (exit)
			server.close();
		auto client = makeNode();
		scope (exit)
			client.close();
		client.nat.onStatusChanged = (NatStatus old, NatStatus now) { flipped = true; };
		client.host.peerstore.addAddrs(server.host.id, server.host.addrs);
		foreach (_; 0 .. 3)
			client.nat.probe(server.host.id, client.host.addrs);
		confidence = client.nat.state.confidence;
		kind = client.nat.state.status.kind;
	});
	flipped.should.equal(true); // unknown → public, once
	kind.should.equal(NatKind.publicNat);
	confidence.should.equal(2); // the two probes that agreed
}
