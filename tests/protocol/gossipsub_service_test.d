/**
 * gossipsub over real hosts on loopback: the behaviours the old service tests
 * pinned. A publishes and B receives through the whole path; a connection
 * yields exactly one meshsub peer per side; a message crosses a hub A → B → C;
 * a peer whose stream dies leaves the router and lets go of the connection.
 */
module tests.protocol.gossipsub_service_test;

import core.time : msecs, seconds, MonoTime, Duration;
import vibe.core.core : sleep;

import fluent.asserts;

import libp2p.core.peer_id : PeerId;
import libp2p.crypto.keys : Keypair;
import libp2p.host.host;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.protocol.gossipsub.service;
import tests.util.loop;

private struct Node
{
	Host host;
	Gossipsub gs;

	void close() nothrow
	{
		gs.close();
		host.close();
	}
}

private Node makeNode(HostConfig cfg = HostConfig.init)
{
	auto key = Keypair.generateEd25519;
	auto h = new Host(key, [new libp2p.transport.tcp.TcpTransport], cfg);
	h.listen(Multiaddr.parse("/ip4/127.0.0.1/tcp/0"));
	return Node(h, new Gossipsub(h, key));
}

import libp2p.transport.tcp;

/// Wait for the thing we need, never for a guessed duration.
private bool waitUntil(bool delegate() cond, Duration limit = 5.seconds)
{
	immutable deadline = MonoTime.currTime + limit;
	while (MonoTime.currTime < deadline)
	{
		if (cond())
			return true;
		sleep(5.msecs);
	}
	return false;
}

@("gossipsub: a published message reaches a subscribed peer")
unittest
{
	enum topic = "news";
	string[] received;
	bool meshed;
	onLoop({
		auto b = makeNode();
		scope (exit)
			b.close();
		b.gs.subscribe(topic);
		b.gs.onMessage = (PeerId from, string t, const(ubyte)[] data) { received ~= cast(string) data.idup; };

		auto a = makeNode();
		scope (exit)
			a.close();
		a.gs.subscribe(topic);

		a.host.connect(b.host.id, b.host.addrs);
		meshed = waitUntil(() => a.gs.state(topic)[1] > 0 && b.gs.state(topic)[1] > 0);
		a.gs.publish(topic, cast(const(ubyte)[]) "breaking news");
		waitUntil(() => received.length > 0);
	});
	meshed.should.equal(true);
	received.length.should.equal(1);
	received[0].should.equal("breaking news");
}

// Only one side's stream carries each direction, or the router would see the
// same peer twice and count it twice in the mesh.
@("gossipsub: a connection yields exactly one meshsub peer per side")
unittest
{
	enum topic = "news";
	size_t[2] aState, bState;
	onLoop({
		auto b = makeNode();
		scope (exit)
			b.close();
		b.gs.subscribe(topic);
		auto a = makeNode();
		scope (exit)
			a.close();
		a.gs.subscribe(topic);

		a.host.connect(b.host.id, b.host.addrs);
		waitUntil(() => a.gs.state(topic)[0] > 0 && b.gs.state(topic)[0] > 0);
		sleep(50.msecs); // room for a second peer to appear, if one were going to
		aState = a.gs.state(topic);
		bState = b.gs.state(topic);
	});
	aState[0].should.equal(1);
	bState[0].should.equal(1);
	aState[1].should.equal(1);
	bState[1].should.equal(1);
}

// Three nodes in a line: A—hub—C. A publishes; C must receive it through the
// hub, which is what makes this gossip rather than direct delivery.
@("gossipsub: a message propagates A -> hub -> C")
unittest
{
	enum topic = "news";
	string[] cGot;
	onLoop({
		auto hub = makeNode();
		scope (exit)
			hub.close();
		hub.gs.subscribe(topic);
		auto a = makeNode();
		scope (exit)
			a.close();
		a.gs.subscribe(topic);
		auto c = makeNode();
		scope (exit)
			c.close();
		c.gs.subscribe(topic);
		c.gs.onMessage = (PeerId from, string t, const(ubyte)[] data) { cGot ~= cast(string) data.idup; };

		a.host.connect(hub.host.id, hub.host.addrs);
		c.host.connect(hub.host.id, hub.host.addrs);
		waitUntil(() => a.gs.state(topic)[1] > 0 && c.gs.state(topic)[1] > 0 && hub.gs.state(topic)[1] > 1);
		a.gs.publish(topic, cast(const(ubyte)[]) "through the hub");
		waitUntil(() => cGot.length > 0);
	});
	cGot.length.should.equal(1);
	cGot[0].should.equal("through the hub");
}

// The service holds the connection while the peer is in the router. When the
// peer's stream dies the hold goes with it: the router reports the peer gone
// and the connection, idle now, closes on its own.
@("gossipsub: losing the meshsub stream releases the connection")
unittest
{
	enum topic = "news";
	bool meshed, reported, closed;
	onLoop({
		auto b = makeNode();
		scope (exit)
			b.close();
		b.gs.subscribe(topic);

		HostConfig cfg;
		cfg.swarm.idleTimeout = 300.msecs; // an unreleased hold is the only thing that could keep it up
		auto a = makeNode(cfg);
		scope (exit)
			a.close();
		a.gs.subscribe(topic);
		a.gs.onPeerGone = (PeerId gone) { reported = true; };

		a.host.connect(b.host.id, b.host.addrs);
		meshed = waitUntil(() => a.gs.state(topic)[0] > 0);
		sleep(400.msecs); // longer than the idle timeout: the hold is what keeps it alive
		closed = !a.host.swarm.isConnected(b.host.id);
		closed.should.equal(false);

		b.close(); // the peer's side dies, and with it the stream we read
		waitUntil(() => reported && !a.host.swarm.isConnected(b.host.id));
		closed = !a.host.swarm.isConnected(b.host.id);
	});
	meshed.should.equal(true);
	reported.should.equal(true);
	closed.should.equal(true);
}

@("gossipsub: unsigned messages are dropped by a strict peer")
unittest
{
	enum topic = "news";
	string[] received;
	onLoop({
		auto b = makeNode();
		scope (exit)
			b.close();
		b.gs.subscribe(topic);
		b.gs.onMessage = (PeerId from, string t, const(ubyte)[] data) { received ~= cast(string) data.idup; };

		// An anonymous publisher.
		auto key = Keypair.generateEd25519;
		GossipsubConfig gc;
		gc.strictSigning = false;
		auto ah = new Host(key, [new TcpTransport]);
		auto a = Node(ah, new Gossipsub(ah, key, gc));
		scope (exit)
			a.close();
		a.gs.subscribe(topic);

		a.host.connect(b.host.id, b.host.addrs);
		waitUntil(() => a.gs.state(topic)[1] > 0 && b.gs.state(topic)[1] > 0);
		a.gs.publish(topic, cast(const(ubyte)[]) "anonymous");
		sleep(100.msecs);
	});
	received.length.should.equal(0);
}
