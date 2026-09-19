/**
 * Circuit relay and DCUtR over real hosts on loopback. A relay that only lets a
 * peer reserve for itself, refuses circuits to peers that never reserved,
 * bounds and expires its table, and — the point of it all — carries a whole
 * libp2p connection between two peers that only know the relay.
 */
module tests.protocol.relay_service_test;

import core.time : msecs, seconds, hours, Duration, MonoTime;
import vibe.core.core : sleep;

import fluent.asserts;

import libp2p.core.peer_id : PeerId;
import libp2p.core.stream;
import libp2p.host.host;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.protocol.ping;
import libp2p.protocol.relay;
import tests.util.loop;

private struct Node
{
	Host host;
	Relay relay;

	void close() nothrow
	{
		relay.close();
		host.close();
	}
}

private Node makeNode(HostConfig cfg = HostConfig.init)
{
	auto h = Host.create(cfg);
	h.listen(Multiaddr.parse("/ip4/127.0.0.1/tcp/0"));
	return Node(h, new Relay(h));
}

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

/// RESERVE by hand and read the status back.
private Status rawReserve(Host client, PeerId relay)
{
	auto s = client.newStream(relay, hopProtocol);
	scope (exit)
		s.close();
	HopMessage m;
	m.type = HopMessage.Type.RESERVE;
	s.writeLengthPrefixed(m.encode);
	return HopMessage.decode(s.readLengthPrefixed(4096)).status;
}

// A relay must only ever let a peer reserve for ITSELF: the table is keyed by
// the authenticated peer, whatever the message says.
@("relay: a peer reserves a slot, under its authenticated id")
unittest
{
	bool ok, listed;
	onLoop({
		auto relay = makeNode();
		scope (exit)
			relay.close();
		auto client = makeNode();
		scope (exit)
			client.close();
		client.host.peerstore.addAddrs(relay.host.id, relay.host.addrs);

		auto info = client.relay.reserve(relay.host.id);
		ok = info.expire > 0;
		listed = relay.relay.reservationCount == 1 && relay.relay.hasReservation(client.host.id);
	});
	ok.should.equal(true);
	listed.should.equal(true);
}

// A CONNECT for a peer that never reserved must be refused, or the relay is an
// open proxy.
@("relay: a circuit to an unreserved peer is refused")
unittest
{
	bool refused;
	string why;
	onLoop({
		auto relay = makeNode();
		scope (exit)
			relay.close();
		auto client = makeNode();
		scope (exit)
			client.close();
		auto stranger = makeNode();
		scope (exit)
			stranger.close();
		client.host.peerstore.addAddrs(relay.host.id, relay.host.addrs);
		try
			client.relay.connectVia(relay.host.id, stranger.host.id);
		catch (Exception e)
		{
			refused = true;
			why = e.msg;
		}
	});
	refused.should.equal(true);
	why.should.contain("NO_RESERVATION");
}

// A slot with no deadline is a promise to keep it forever. The response carries
// the deadline too, or a client cannot renew before it lapses.
@("relay: a reservation lapses on its own, and says when")
unittest
{
	ulong expireAt;
	bool heldAfterAck, lapsed;
	onLoop({
		auto relay = makeNode();
		scope (exit)
			relay.close();
		relay.relay.limits.reservationDuration = 200.msecs;
		auto client = makeNode();
		scope (exit)
			client.close();
		client.host.peerstore.addAddrs(relay.host.id, relay.host.addrs);

		expireAt = client.relay.reserve(relay.host.id).expire;
		heldAfterAck = relay.relay.reservationCount == 1;
		lapsed = waitUntil(() => relay.relay.reservationCount == 0, 3.seconds);
	});
	heldAfterAck.should.equal(true);
	lapsed.should.equal(true); // it went away without anyone asking it to
	(expireAt > 0).should.equal(true);
}

@("relay: reservations past the per-peer ceiling are refused")
unittest
{
	Status[] got;
	onLoop({
		auto relay = makeNode();
		scope (exit)
			relay.close();
		relay.relay.limits.maxReservationsPerPeer = 2;
		auto client = makeNode();
		scope (exit)
			client.close();
		client.host.peerstore.addAddrs(relay.host.id, relay.host.addrs);
		foreach (_; 0 .. 3)
			got ~= rawReserve(client.host, relay.host.id);
	});
	got.should.equal([Status.OK, Status.OK, Status.RESERVATION_REFUSED]);
}

// A reservation asks to be reachable through this link. When the link goes, so
// does the promise.
@("relay: a reservation dies with the connection it was made on")
unittest
{
	bool reserved, dropped;
	onLoop({
		auto relay = makeNode();
		scope (exit)
			relay.close();
		auto client = makeNode();
		scope (exit)
			client.close();
		client.host.peerstore.addAddrs(relay.host.id, relay.host.addrs);

		client.relay.reserve(relay.host.id);
		reserved = relay.relay.reservationCount == 1;
		client.host.swarm.connection(relay.host.id).close();
		dropped = waitUntil(() => relay.relay.reservationCount == 0);
	});
	reserved.should.equal(true);
	dropped.should.equal(true);
}

// A ceiling bounds what a relay holds; a peer that stays under it and churns —
// reserve, drop, reserve — costs us a handshake each time. The rate limit is
// what makes that expensive for the sender.
@("relay: a peer that churns reservations runs out of tokens")
unittest
{
	Status[] got;
	onLoop({
		auto relay = makeNode();
		scope (exit)
			relay.close();
		relay.relay.limits.reservationsPerPeer = RateLimit(3, 1.hours);
		auto client = makeNode();
		scope (exit)
			client.close();
		client.host.peerstore.addAddrs(relay.host.id, relay.host.addrs);
		foreach (_; 0 .. 4)
		{
			got ~= rawReserve(client.host, relay.host.id);
			relay.relay.forget(client.host.id); // free the slot: only the rate can refuse now
		}
	});
	got.should.equal([Status.OK, Status.OK, Status.OK, Status.RESERVATION_REFUSED]);
}

// A client told it has a reservation but not what to advertise cannot be
// dialed through us.
@("relay: a reservation carries the relay's addresses")
unittest
{
	Multiaddr[] advertised;
	Multiaddr[] circuit;
	PeerId relayId, clientId;
	onLoop({
		auto relay = makeNode();
		scope (exit)
			relay.close();
		relay.relay.setObservedAddrs([Multiaddr.parse("/ip4/7.7.7.7/tcp/4001").encode]);
		auto client = makeNode();
		scope (exit)
			client.close();
		client.host.peerstore.addAddrs(relay.host.id, relay.host.addrs);

		auto info = client.relay.reserve(relay.host.id);
		advertised = info.addrs;
		circuit = client.relay.circuitAddrs(relay.host.id, info);
		relayId = relay.host.id;
		clientId = client.host.id;
	});
	advertised.length.should.equal(1);
	advertised[0].toString.should.equal("/ip4/7.7.7.7/tcp/4001");
	circuit[0].toString.should.equal("/ip4/7.7.7.7/tcp/4001/p2p/" ~ relayId.toBase58 ~ "/p2p-circuit/p2p/" ~ clientId.toBase58);
}

// The point of a relay: two peers that know only the relay get a real libp2p
// connection to each other, upgraded like any other, and a protocol runs on it.
@("relay: a whole connection crosses a circuit and a protocol runs on it")
unittest
{
	Duration rtt = Duration.min;
	bool aSeesB, bSeesA, viaCircuit;
	onLoop({
		auto relay = makeNode();
		scope (exit)
			relay.close();
		auto a = makeNode();
		scope (exit)
			a.close();
		auto b = makeNode();
		scope (exit)
			b.close();
		new Ping(b.host);
		a.host.peerstore.addAddrs(relay.host.id, relay.host.addrs);
		b.host.peerstore.addAddrs(relay.host.id, relay.host.addrs);

		// B is reachable through the relay; A dials the circuit address.
		auto info = b.relay.reserve(relay.host.id);
		auto addr = Multiaddr(relay.host.addrs[0].bytes.dup)
			~ Multiaddr.parse("/p2p/" ~ relay.host.id.toBase58 ~ "/p2p-circuit/p2p/" ~ b.host.id.toBase58);
		auto c = a.host.connect(b.host.id, [addr]);
		aSeesB = c.remotePeer == b.host.id;
		viaCircuit = c.remoteAddr.toString.canFind("/p2p-circuit/");
		bSeesA = waitUntil(() => b.host.swarm.isConnected(a.host.id));

		auto s = c.newStream(pingProtocol);
		scope (exit)
			s.close();
		rtt = ping(s);
		relay.relay.circuitCount.should.equal(1);
	});
	aSeesB.should.equal(true);
	bSeesA.should.equal(true);
	viaCircuit.should.equal(true);
	(rtt >= Duration.zero).should.equal(true);
}

import std.algorithm.searching : canFind;

@("relay: a circuit is cut when it exceeds its byte budget")
unittest
{
	bool ended;
	onLoop({
		auto relay = makeNode();
		scope (exit)
			relay.close();
		relay.relay.limits.maxCircuitBytes = 64 * 1024;
		auto a = makeNode();
		scope (exit)
			a.close();
		auto b = makeNode();
		scope (exit)
			b.close();
		b.host.setStreamHandler("/test/sink/1.0.0", (Stream s, Connection, string) {
			scope (exit)
				s.close();
			auto buf = new ubyte[4096];
			try
				for (;;)
					s.read(buf);
			catch (Exception)
			{
			}
		});
		a.host.peerstore.addAddrs(relay.host.id, relay.host.addrs);
		b.host.peerstore.addAddrs(relay.host.id, relay.host.addrs);
		b.relay.reserve(relay.host.id);

		auto c = a.relay.connectVia(relay.host.id, b.host.id);
		auto s = c.newStream("/test/sink/1.0.0");
		scope (exit)
			s.close();
		auto chunk = new ubyte[16 * 1024];
		try
		{
			foreach (_; 0 .. 64) // a megabyte, against a 64 KiB budget
			{
				s.write(chunk);
				sleep(1.msecs);
			}
		}
		catch (Exception)
			ended = true;
		ended = ended || waitUntil(() => c.isClosed, 3.seconds);
	});
	ended.should.equal(true);
}

// DCUtR over the swarm: a peer asks another for the addresses to hole punch
// to, and gets them.
@("dcutr: a hole-punch exchange returns the peer's addresses")
unittest
{
	ubyte[][] theirAddrs;
	onLoop({
		auto b = makeNode();
		scope (exit)
			b.close();
		b.relay.setObservedAddrs([Multiaddr.parse("/ip4/9.9.9.9/tcp/4001").encode]);
		auto a = makeNode();
		scope (exit)
			a.close();
		a.relay.setObservedAddrs([Multiaddr.parse("/ip4/8.8.8.8/tcp/4001").encode]);

		a.host.connect(b.host.id, b.host.addrs);
		theirAddrs = a.relay.holePunchExchange(b.host.id).peerAddrs;
		waitUntil(() => b.relay.punchCount == 0); // B's dial at 8.8.8.8 fails and finishes
	});
	theirAddrs.length.should.equal(1);
	Multiaddr.decode(theirAddrs[0]).toString.should.equal("/ip4/9.9.9.9/tcp/4001");
}

// The other half of DCUtR: both sides dial at the same moment. On loopback there
// is no NAT to punch, so what this proves is the orchestration — the exchange is
// followed by a real direct connection, authenticated as the peer we meant.
@("dcutr: a hole punch ends with a direct connection to the peer")
unittest
{
	PeerId got, expected;
	onLoop({
		auto b = makeNode();
		scope (exit)
			b.close();
		b.relay.setObservedAddrs([b.host.addrs[0].encode]);
		auto a = makeNode();
		scope (exit)
			a.close();
		a.relay.setObservedAddrs([a.host.addrs[0].encode]);

		a.host.connect(b.host.id, b.host.addrs);
		expected = b.host.id;
		got = a.relay.holePunch(b.host.id);
		// Both sides dial, so both have to finish before the hosts go away.
		waitUntil(() => b.relay.punchCount == 0);
	});
	(got == expected).should.equal(true);
}

// auto-DCUtR: the same upgrade, but nobody calls holePunch. A dials B through
// the relay; Relay.connected() sees the relayed dial and runs the exchange +
// punch on its own (autoHolePunch, on by default). On loopback the punch is
// orchestration only, as above — the point here is that it fires with no
// explicit trigger and lands a second, non-relayed connection.
@("dcutr: auto-DCUtR upgrades a relayed connection with no explicit punch")
unittest
{
	bool direct;
	onLoop({
		auto relay = makeNode();
		scope (exit)
			relay.close();
		auto a = makeNode();
		scope (exit)
			a.close();
		auto b = makeNode();
		scope (exit)
			b.close();
		a.relay.setObservedAddrs([a.host.addrs[0].encode]);
		b.relay.setObservedAddrs([b.host.addrs[0].encode]);
		a.host.peerstore.addAddrs(relay.host.id, relay.host.addrs);
		b.host.peerstore.addAddrs(relay.host.id, relay.host.addrs);

		b.relay.reserve(relay.host.id);
		// A relayed dial, and nothing else — no holePunch call in the test.
		a.relay.connectVia(relay.host.id, b.host.id);
		direct = waitUntil(() => a.host.swarm.connectionsTo(b.host.id)
				.canFind!(c => !c.remoteAddr.toString.canFind("/p2p-circuit")));
		waitUntil(() => b.relay.punchCount == 0);
	});
	direct.should.equal(true);
}
