module tests.behaviour.relay_test;

import fluent.asserts;

import core.time : msecs, seconds, hours, Duration, MonoTime;
import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;
import vibe.core.log : logError;

import std.conv : to;

import libp2p.crypto.keys : Keypair;
import libp2p.host : Host;
import libp2p.core.peer_id : PeerId;
import libp2p.core.stream : ByteStream;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.swarm.swarm : Swarm;
import libp2p.swarm.dial_opts : DialOpts;
import libp2p.behaviour.relay : RelayBehaviour, ReservationAccepted, RelayLimits;
import libp2p.protocol.relay : hopProtocol, HopMessage, Status;
import libp2p.protocol.dcutr : dcutrProtocol;
import libp2p.util.protobuf : readDelimited, writeDelimited;
import ev = libp2p.swarm.events;

private void drain()
{
	runTask(() nothrow{
		try
			exitEventLoop();
		catch (Exception)
		{
		}
	});
	runEventLoop();
}

private ushort portOf(Swarm s)
{
	foreach (c; s.listenAddresses()[0].components)
		if (c.code == 6 && c.value.length == 2)
			return cast(ushort)((c.value[0] << 8) | c.value[1]);
	assert(false, "no tcp port");
}

/// Wait for a condition rather than for a duration.
private bool waitUntil(bool delegate() cond, Duration limit = 10.seconds)
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

private struct Node
{
	Swarm swarm;
	RelayBehaviour relay;
}

private Node makeNode()
{
	auto r = new RelayBehaviour;
	auto s = new Swarm(new Host(Keypair.generateEd25519), r);
	s.idleConnectionTimeout = 30.seconds;
	return Node(s, r);
}

/// Send a RESERVE on an already-open hop stream and read the status back.
private bool reserve(Swarm s, PeerId relayPeer)
{
	auto st = s.openStream(relayPeer, [hopProtocol]);
	scope (exit)
		st.close();
	HopMessage m;
	m.type = HopMessage.Type.RESERVE;
	writeDelimited(st, m.encode);
	auto resp = HopMessage.decode(readDelimited(st));
	return resp.hasStatus && resp.status == Status.OK;
}

// A relay must only ever let a peer reserve for ITSELF. The behaviour keys the
// table by the authenticated peer and ignores the id in the message, so this is
// really asserting that the reservation lands under the right identity.
@("relay behaviour: a peer reserves a slot, under its authenticated id")
unittest
{
	scope (exit)
		drain();

	auto relay = makeNode();
	scope (exit)
		relay.swarm.close();
	relay.swarm.listenOn("127.0.0.1", 0);
	immutable port = portOf(relay.swarm);

	auto client = makeNode();
	scope (exit)
		client.swarm.close();

	bool ok;
	runTask(() nothrow{
		try
		{
			auto relayPeer = client.swarm.dialAndWait(
				DialOpts.address(Multiaddr.parse(
					"/ip4/127.0.0.1/tcp/" ~ (cast(uint) port).to!string)));
			ok = reserve(client.swarm, relayPeer);
		}
		catch (Exception e)
			logError("relay reserve test: %s", e.msg);
		try
			exitEventLoop();
		catch (Exception)
		{
		}
	});
	runEventLoop();

	ok.should.equal(true);
	cast(void) waitUntil(() => relay.relay.reservationCount == 1);
	relay.relay.reservationCount.should.equal(1);
	relay.relay.hasReservation(client.swarm.localPeer).should.equal(true);
}

// A CONNECT for a peer that never reserved must be refused — otherwise the relay
// is an open proxy.
@("relay behaviour: a circuit to an unreserved peer is refused")
unittest
{
	scope (exit)
		drain();

	auto relay = makeNode();
	scope (exit)
		relay.swarm.close();
	relay.swarm.listenOn("127.0.0.1", 0);
	immutable port = portOf(relay.swarm);

	auto client = makeNode();
	scope (exit)
		client.swarm.close();
	auto stranger = makeNode();
	scope (exit)
		stranger.swarm.close();

	Status got;
	runTask(() nothrow{
		try
		{
			auto relayPeer = client.swarm.dialAndWait(
				DialOpts.address(Multiaddr.parse(
					"/ip4/127.0.0.1/tcp/" ~ (cast(uint) port).to!string)));

			auto st = client.swarm.openStream(relayPeer, [hopProtocol]);
			scope (exit)
				st.close();
			HopMessage m;
			m.type = HopMessage.Type.CONNECT;
			m.peer.id = stranger.swarm.localPeer.bytes.dup; // never reserved
			writeDelimited(st, m.encode);
			auto resp = HopMessage.decode(readDelimited(st));
			got = resp.status;
		}
		catch (Exception e)
			logError("relay refuse test: %s", e.msg);
		try
			exitEventLoop();
		catch (Exception)
		{
		}
	});
	runEventLoop();

	(got == Status.NO_RESERVATION).should.equal(true);
}

// A reservation is a promise to keep a slot; a slot with no deadline is a
// promise to keep it forever, which is how a table fills with peers that never
// came back. The response has to carry the deadline too, or a client cannot
// renew before it lapses.
@("relay behaviour: a reservation lapses on its own, and says when")
unittest
{
	scope (exit)
		drain();

	auto relay = makeNode();
	scope (exit)
		relay.swarm.close();
	relay.relay.limits.reservationDuration = 200.msecs;
	relay.swarm.listenOn("127.0.0.1", 0);
	immutable port = portOf(relay.swarm);

	auto client = makeNode();
	scope (exit)
		client.swarm.close();

	ulong expireAt;
	bool heldAfterAck, heldAfterLapse = true;
	runTask(() nothrow{
		try
		{
			auto relayPeer = client.swarm.dialAndWait(
				DialOpts.address(Multiaddr.parse(
					"/ip4/127.0.0.1/tcp/" ~ (cast(uint) port).to!string)));
			auto st = client.swarm.openStream(relayPeer, [hopProtocol]);
			scope (exit)
				st.close();
			HopMessage m;
			m.type = HopMessage.Type.RESERVE;
			writeDelimited(st, m.encode);
			auto resp = HopMessage.decode(readDelimited(st));
			if (resp.hasReservation)
				expireAt = resp.reservation.expire;
			heldAfterAck = waitUntil(() => relay.relay.reservationCount == 1);
			heldAfterLapse = waitUntil(() => relay.relay.reservationCount == 0, 5.seconds)
				? false : true;
		}
		catch (Exception e)
			logError("relay expiry test: %s", e.msg);
		try
			exitEventLoop();
		catch (Exception)
		{
		}
	});
	runEventLoop();

	heldAfterAck.should.equal(true);
	heldAfterLapse.should.equal(false); // it went away without anyone asking it to
	(expireAt > 0).should.equal(true); // and the client was told when
}

// Past the ceiling a reservation is refused rather than filed. An unbounded
// table is the difference between a relay and a service anyone can fill up.
@("relay behaviour: reservations past the per-peer ceiling are refused")
unittest
{
	scope (exit)
		drain();

	auto relay = makeNode();
	scope (exit)
		relay.swarm.close();
	relay.relay.limits.maxReservationsPerPeer = 2;
	relay.swarm.listenOn("127.0.0.1", 0);
	immutable port = portOf(relay.swarm);

	auto client = makeNode();
	scope (exit)
		client.swarm.close();

	Status[] got;
	runTask(() nothrow{
		try
		{
			auto relayPeer = client.swarm.dialAndWait(
				DialOpts.address(Multiaddr.parse(
					"/ip4/127.0.0.1/tcp/" ~ (cast(uint) port).to!string)));
			foreach (_; 0 .. 3)
			{
				auto st = client.swarm.openStream(relayPeer, [hopProtocol]);
				scope (exit)
					st.close();
				HopMessage m;
				m.type = HopMessage.Type.RESERVE;
				writeDelimited(st, m.encode);
				got ~= HopMessage.decode(readDelimited(st)).status;
			}
		}
		catch (Exception e)
			logError("relay ceiling test: %s", e.msg);
		try
			exitEventLoop();
		catch (Exception)
		{
		}
	});
	runEventLoop();

	got.length.should.equal(3);
	(got[0] == Status.OK).should.equal(true);
	(got[1] == Status.OK).should.equal(true);
	(got[2] == Status.RESERVATION_REFUSED).should.equal(true);
}

// A reservation asks to be reachable *through this link*. When the link goes,
// so does the promise — otherwise the table outlives every connection in it.
@("relay behaviour: a reservation dies with the connection it was made on")
unittest
{
	scope (exit)
		drain();

	auto relay = makeNode();
	scope (exit)
		relay.swarm.close();
	relay.swarm.listenOn("127.0.0.1", 0);
	immutable port = portOf(relay.swarm);

	auto client = makeNode();
	scope (exit)
		client.swarm.close();

	bool reserved, dropped;
	runTask(() nothrow{
		try
		{
			auto relayPeer = client.swarm.dialAndWait(
				DialOpts.address(Multiaddr.parse(
					"/ip4/127.0.0.1/tcp/" ~ (cast(uint) port).to!string)));
			reserved = reserve(client.swarm, relayPeer)
				&& waitUntil(() => relay.relay.reservationCount == 1);
			client.swarm.closeConnections(relayPeer);
			dropped = waitUntil(() => relay.relay.reservationCount == 0);
		}
		catch (Exception e)
			logError("relay disconnect test: %s", e.msg);
		try
			exitEventLoop();
		catch (Exception)
		{
		}
	});
	runEventLoop();

	reserved.should.equal(true);
	dropped.should.equal(true);
}

// DCUtR over the swarm: a peer asks another for the addresses to hole punch to,
// and gets them. This is the exchange that lets a relayed pair go direct.
@("dcutr behaviour: a hole-punch exchange returns the peer's addresses")
unittest
{
	scope (exit)
		drain();

	auto b = makeNode();
	scope (exit)
		b.swarm.close();
	b.swarm.listenOn("127.0.0.1", 0);
	immutable port = portOf(b.swarm);
	// What B offers as its reachable addresses.
	b.relay.setObservedAddrs([Multiaddr.parse("/ip4/9.9.9.9/tcp/4001").encode]);

	auto a = makeNode();
	scope (exit)
		a.swarm.close();
	a.relay.setObservedAddrs([Multiaddr.parse("/ip4/8.8.8.8/tcp/4001").encode]);

	ubyte[][] theirAddrs;
	runTask(() nothrow{
		try
		{
			auto bPeer = a.swarm.dialAndWait(
				DialOpts.address(Multiaddr.parse(
					"/ip4/127.0.0.1/tcp/" ~ (cast(uint) port).to!string)));
			auto res = a.relay.holePunchExchange(bPeer);
			theirAddrs = res.peerAddrs;
		}
		catch (Exception e)
			logError("dcutr test: %s", e.msg);
		try
			exitEventLoop();
		catch (Exception)
		{
		}
	});
	runEventLoop();

	theirAddrs.length.should.equal(1);
	Multiaddr.decode(theirAddrs[0]).toString().should.equal("/ip4/9.9.9.9/tcp/4001");
}

// A ceiling bounds what a relay holds; it says nothing about a peer that stays
// under it and churns — reserve, drop, reserve — which costs the sender nothing
// and costs us a handshake each time. The bucket is what makes that expensive
// for the sender instead.
@("relay behaviour: a peer that churns reservations runs out of tokens")
unittest
{
	import libp2p.util.rate_limiter : RateLimit;

	scope (exit)
		drain();

	auto relay = makeNode();
	scope (exit)
		relay.swarm.close();
	// Three reservations, then nothing for an hour.
	relay.relay.limits.reservationsPerPeer = RateLimit(3, 1.hours);
	relay.swarm.listenOn("127.0.0.1", 0);
	immutable port = portOf(relay.swarm);

	auto client = makeNode();
	scope (exit)
		client.swarm.close();

	Status[] got;
	runTask(() nothrow{
		try
		{
			auto relayPeer = client.swarm.dialAndWait(
				DialOpts.address(Multiaddr.parse(
					"/ip4/127.0.0.1/tcp/" ~ (cast(uint) port).to!string)));
			foreach (_; 0 .. 4)
			{
				auto st = client.swarm.openStream(relayPeer, [hopProtocol]);
				scope (exit)
					st.close();
				HopMessage m;
				m.type = HopMessage.Type.RESERVE;
				writeDelimited(st, m.encode);
				got ~= HopMessage.decode(readDelimited(st)).status;
				// Free the slot again, so only the rate can refuse the next one.
				relay.relay.forget(client.swarm.localPeer);
			}
		}
		catch (Exception e)
			logError("relay rate-limit test: %s", e.msg);
		try
			exitEventLoop();
		catch (Exception)
		{
		}
	});
	runEventLoop();

	got.length.should.equal(4);
	(got[0] == Status.OK).should.equal(true);
	(got[1] == Status.OK).should.equal(true);
	(got[2] == Status.OK).should.equal(true);
	(got[3] == Status.RESERVATION_REFUSED).should.equal(true); // ceiling was free
}

// A client that is told it has a reservation but not what to advertise cannot be
// dialed through us, which makes the reservation useless to it.
@("relay behaviour: a reservation carries the relay's addresses")
unittest
{
	scope (exit)
		drain();

	auto relay = makeNode();
	scope (exit)
		relay.swarm.close();
	relay.relay.setObservedAddrs([Multiaddr.parse("/ip4/7.7.7.7/tcp/4001").encode]);
	relay.swarm.listenOn("127.0.0.1", 0);
	immutable port = portOf(relay.swarm);

	auto client = makeNode();
	scope (exit)
		client.swarm.close();

	ubyte[][] advertised;
	runTask(() nothrow{
		try
		{
			auto relayPeer = client.swarm.dialAndWait(
				DialOpts.address(Multiaddr.parse(
					"/ip4/127.0.0.1/tcp/" ~ (cast(uint) port).to!string)));
			auto st = client.swarm.openStream(relayPeer, [hopProtocol]);
			scope (exit)
				st.close();
			HopMessage m;
			m.type = HopMessage.Type.RESERVE;
			writeDelimited(st, m.encode);
			auto resp = HopMessage.decode(readDelimited(st));
			if (resp.hasReservation)
				advertised = resp.reservation.addrs;
		}
		catch (Exception e)
			logError("relay addrs test: %s", e.msg);
		try
			exitEventLoop();
		catch (Exception)
		{
		}
	});
	runEventLoop();

	advertised.length.should.equal(1);
	Multiaddr.decode(advertised[0]).toString().should.equal("/ip4/7.7.7.7/tcp/4001");
}

// The exchange is only half of DCUtR. The other half is that both sides dial at
// the same moment — one as dialer, one with its role overridden to listener — so
// that each side's SYN opens the hole the other's comes through. On loopback
// there is no NAT to punch, so what this proves is the orchestration: that the
// exchange is followed by a real direct connection which is not the relayed one.
@("dcutr behaviour: a hole punch ends with a direct connection to the peer")
unittest
{
	scope (exit)
		drain();

	auto b = makeNode();
	scope (exit)
		b.swarm.close();
	b.swarm.listenOn("127.0.0.1", 0);
	immutable bPort = portOf(b.swarm);
	// The address B offers as its direct one — here, the one it really listens on.
	b.relay.setObservedAddrs([b.swarm.listenAddresses()[0].encode]);

	auto a = makeNode();
	scope (exit)
		a.swarm.close();
	a.swarm.listenOn("127.0.0.1", 0);
	a.relay.setObservedAddrs([a.swarm.listenAddresses()[0].encode]);

	bool punched;
	PeerId got, expected;
	runTask(() nothrow{
		try
		{
			auto bPeer = a.swarm.dialAndWait(
				DialOpts.address(Multiaddr.parse(
					"/ip4/127.0.0.1/tcp/" ~ (cast(uint) bPort).to!string)));
			expected = bPeer;
			got = a.relay.holePunch(bPeer);
			punched = true;
			// Both sides dial, so both have to finish before the swarms are torn
			// down — otherwise the responder's dial outlives its own swarm.
			waitUntil(() => b.relay.circuitCount == 0);
			sleep(100.msecs);
		}
		catch (Exception e)
			logError("dcutr punch test: %s", e.msg);
		try
			exitEventLoop();
		catch (Exception)
		{
		}
	});
	runEventLoop();

	punched.should.equal(true);
	// The direct connection authenticated as the peer we meant to reach, which
	// is what makes it a hole punch rather than a connection to somebody.
	(got == expected).should.equal(true);
}
