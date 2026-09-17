/**
 * Circuit relay v2, both sides, plus DCUtR.
 *
 * As a relay: a peer RESERVEs a slot over its connection to us, and while the
 * reservation stands anyone may CONNECT to it through us. We open a STOP
 * stream to the reserved peer over the connection it reserved on, and pipe
 * bytes both ways within the circuit's byte and time limits. Reservations are
 * bounded (total, per peer, per peer per period), expire on their own, and die
 * with the connection they were made on.
 *
 * As a client: `reserve` asks a relay for a slot; `connectVia` reaches a peer
 * through a relay and hands the circuit to the swarm as a raw connection, which
 * upgrades it like any other; and the service is a `Transport` for
 * `/p2p-circuit` addresses, so the swarm can dial them. A STOP that arrives is
 * an inbound raw connection, admitted the same way.
 *
 * DCUtR turns a relayed connection into a direct one: the two sides swap
 * addresses and time the round trip, then dial each other at the same moment.
 */
module libp2p.protocol.relay.service;

import core.time : Duration, MonoTime, seconds, minutes, hours, msecs;
import std.algorithm.iteration : filter;
import std.algorithm.searching : canFind, countUntil;
import std.array : array;
import std.datetime.systime : Clock;
import std.exception : enforce;
import std.typecons : Nullable, nullable;

import vibe.core.core : sleep;
import vibe.core.log : logDebug;
import vibe.core.sync : LocalManualEvent, createManualEvent;
import vibe.core.task : InterruptException;

import libp2p.core.ending : Ending;
import libp2p.core.peer_id : PeerId;
import libp2p.core.stream;
import libp2p.host.host;
import libp2p.multiformats.multiaddr : Multiaddr, Component;
import libp2p.protocol.dcutr;
import libp2p.protocol.relay.wire;
import libp2p.transport.transport;
import libp2p.util.fibers : FiberGroup;
import libp2p.util.ratelimit;
import libp2p.util.select : waitAll;
import libp2p.util.timeout : withTimeout, Timeout;

public import libp2p.protocol.relay.wire;
public import libp2p.util.ratelimit : RateLimit;

enum maxRelayMessage = 4 * 1024;

struct RelayLimits
{
	size_t maxReservations = 128;
	size_t maxReservationsPerPeer = 4;
	Duration reservationDuration = 1.hours;
	RateLimit reservationsPerPeer = RateLimit(4, 2.minutes);
	size_t maxCircuits = 16;
	size_t maxCircuitsPerPeer = 4;
	Duration maxCircuitDuration = 2.minutes;
	ulong maxCircuitBytes = 128 * 1024;
	Duration stopTimeout = 10.seconds;
}

/// What a relay granted us.
struct ReservationInfo
{
	ulong expire; /// unix seconds
	Multiaddr[] addrs; /// the relay's addresses, to advertise with /p2p-circuit appended
	Limit limit;
}

private struct Held
{
	PeerId peer;
	Connection conn;
	MonoTime expires;
}

final class Relay : Notifiee, Transport
{
	private Host host;
	RelayLimits limits;
	private Held[] reservations;
	private LocalManualEvent reservationChanged; // wakes the expiry sweeper
	private RateLimiter!PeerId reservationRate;
	private size_t circuits;
	private size_t[PeerId] circuitsBy;
	private size_t punches;
	private ubyte[][] observed;
	private FiberGroup fibers;

	this(Host host, RelayLimits limits = RelayLimits.init)
	{
		this.host = host;
		this.limits = limits;
		reservationChanged = createManualEvent();
		fibers = new FiberGroup((Exception e) nothrow { logDebug("libp2p: relay work failed: %s", e.msg); });
		fibers.spawn(&expireReservations);
		host.setStreamHandler(hopProtocol, &serveHop);
		host.setStreamHandler(stopProtocol, &serveStop);
		host.setStreamHandler(dcutrProtocol, &serveDcutr);
		host.addNotifiee(this);
		host.swarm.addTransport(this);
	}

	void close() nothrow
	{
		try
		{
			host.removeNotifiee(this);
			host.removeStreamHandler(hopProtocol);
			host.removeStreamHandler(stopProtocol);
			host.removeStreamHandler(dcutrProtocol);
		}
		catch (Exception)
		{
		}
		fibers.stopAll();
		reservations = null;
	}

	/// The addresses we tell others about: as a relay, what reservers advertise;
	/// in DCUtR, where we can be reached directly.
	void setObservedAddrs(ubyte[][] addrs)
	{
		observed = addrs;
	}

	private ubyte[][] advertised()
	{
		if (observed.length > 0)
			return observed;
		ubyte[][] out_;
		foreach (a; host.addrs)
			out_ ~= a.encode;
		return out_;
	}

	// Addresses to offer in a DCUtR exchange: our dialable addresses plus any
	// reflexive webrtc-direct address, so a two-NAT peer has a candidate to punch to.
	private ubyte[][] punchAddrs()
	{
		auto out_ = advertised();
		foreach (a; host.reflexiveAddrs())
			out_ ~= a.encode;
		return out_;
	}

	// --- as a relay: reservations --------------------------------------------------------------

	size_t reservationCount() const @safe pure nothrow
	{
		return reservations.length;
	}

	bool hasReservation(PeerId peer)
	{
		return reservations.canFind!(r => r.peer == peer);
	}

	/// Drop every reservation `peer` holds.
	void forget(PeerId peer)
	{
		reservations = reservations.filter!(r => r.peer != peer).array;
	}

	size_t circuitCount() const @safe pure nothrow
	{
		return circuits;
	}

	/// Hole punches in progress on the responding side.
	size_t punchCount() const @safe pure nothrow
	{
		return punches;
	}

	void connected(Connection)
	{
	}

	/// A reservation asks to be reachable through this link; when the link
	/// goes, so does the promise.
	void disconnected(Connection c)
	{
		reservations = reservations.filter!(r => r.conn !is c).array;
	}

	private void serveHop(Stream s, Connection c, string)
	{
		auto msg = HopMessage.decode(s.readLengthPrefixed(maxRelayMessage));
		final switch (msg.type)
		{
		case HopMessage.Type.RESERVE:
			scope (exit)
				s.close();
			s.writeLengthPrefixed(reserveFor(c).encode);
			break;
		case HopMessage.Type.CONNECT:
			circuit(s, c, msg);
			break;
		case HopMessage.Type.STATUS:
			scope (exit)
				s.close();
			s.writeLengthPrefixed(HopMessage.statusReply(Status.UNEXPECTED_MESSAGE).encode);
			break;
		}
	}

	private HopMessage reserveFor(Connection c)
	{
		auto peer = c.remotePeer;
		immutable now = MonoTime.currTime;
		reservationRate.limit = limits.reservationsPerPeer;
		if (!reservationRate.allow(peer, now))
			return HopMessage.statusReply(Status.RESERVATION_REFUSED);
		if (reservations.length >= limits.maxReservations)
			return HopMessage.statusReply(Status.RESERVATION_REFUSED);
		size_t mine;
		foreach (r; reservations)
			if (r.peer == peer)
				mine++;
		if (mine >= limits.maxReservationsPerPeer)
			return HopMessage.statusReply(Status.RESERVATION_REFUSED);

		reservations ~= Held(peer, c, now + limits.reservationDuration);
		reservationChanged.emit(); // one sweeper expires them all; wake it for the new deadline

		auto reply = HopMessage.statusReply(Status.OK);
		reply.hasReservation = true;
		reply.reservation.expire = cast(ulong)(Clock.currTime.toUnixTime + limits.reservationDuration.total!"seconds");
		reply.reservation.addrs = advertised();
		reply.hasLimit = true;
		reply.limit = Limit(cast(uint) limits.maxCircuitDuration.total!"seconds", limits.maxCircuitBytes);
		return reply;
	}

	// One fiber expires reservations by their deadline. A timer per reservation
	// would outlive an early forget/disconnect — sleeping out its full duration
	// while a churning peer piled up more — so the ceiling bounded the table but
	// not the fibers. This sweeps the earliest deadline and re-arms when a
	// reservation is added.
	private void expireReservations()
	{
		auto seen = reservationChanged.emitCount;
		for (;;)
		{
			immutable now = MonoTime.currTime;
			reservations = reservations.filter!(r => r.expires > now).array;
			MonoTime next;
			bool have;
			foreach (r; reservations)
				if (!have || r.expires < next)
				{
					next = r.expires;
					have = true;
				}
			if (have)
				seen = reservationChanged.wait(next - now, seen); // the soonest expiry, or a new reservation
			else
				seen = reservationChanged.wait(seen); // nothing to expire; wait for one
		}
	}

	// --- as a relay: circuits ---------------------------------------------------------------------

	private void circuit(Stream src, Connection from, HopMessage msg)
	{
		scope (exit)
			src.close();
		if (!msg.hasPeer)
		{
			src.writeLengthPrefixed(HopMessage.statusReply(Status.MALFORMED_MESSAGE).encode);
			return;
		}
		PeerId dst;
		try
			dst = PeerId.fromBytes(msg.peer.id);
		catch (Exception)
		{
			src.writeLengthPrefixed(HopMessage.statusReply(Status.MALFORMED_MESSAGE).encode);
			return;
		}
		immutable i = reservations.countUntil!(r => r.peer == dst);
		if (i < 0)
		{
			src.writeLengthPrefixed(HopMessage.statusReply(Status.NO_RESERVATION).encode);
			return;
		}
		if (circuits >= limits.maxCircuits || circuitsBy.get(from.remotePeer, 0) >= limits.maxCircuitsPerPeer)
		{
			src.writeLengthPrefixed(HopMessage.statusReply(Status.RESOURCE_LIMIT_EXCEEDED).encode);
			return;
		}
		auto target = reservations[i].conn;

		// Ask the destination.
		Stream dstStream;
		try
		{
			dstStream = target.newStream(stopProtocol);
			StopMessage connect;
			connect.type = StopMessage.Type.CONNECT;
			connect.hasPeer = true;
			connect.peer.id = from.remotePeer.bytes.dup;
			connect.hasLimit = true;
			connect.limit = Limit(cast(uint) limits.maxCircuitDuration.total!"seconds", limits.maxCircuitBytes);
			withTimeout(limits.stopTimeout, "relay stop", {
				dstStream.writeLengthPrefixed(connect.encode);
				auto answer = StopMessage.decode(dstStream.readLengthPrefixed(maxRelayMessage));
				enforce(answer.type == StopMessage.Type.STATUS && answer.hasStatus && answer.status == Status.OK,
					"destination refused");
			});
		}
		catch (InterruptException e)
		{
			if (dstStream !is null)
				dstStream.reset(); // still clean up, but do not disguise the stop as a failure
			throw e;
		}
		catch (Exception e)
		{
			if (dstStream !is null)
				dstStream.reset();
			src.writeLengthPrefixed(HopMessage.statusReply(Status.CONNECTION_FAILED).encode);
			return;
		}
		scope (exit)
			dstStream.close();

		auto ok = HopMessage.statusReply(Status.OK);
		ok.hasLimit = true;
		ok.limit = Limit(cast(uint) limits.maxCircuitDuration.total!"seconds", limits.maxCircuitBytes);
		src.writeLengthPrefixed(ok.encode);

		circuits++;
		circuitsBy[from.remotePeer] = circuitsBy.get(from.remotePeer, 0) + 1;
		scope (exit)
		{
			circuits--;
			circuitsBy[from.remotePeer] = circuitsBy[from.remotePeer] - 1;
		}
		// Bytes both ways until one side ends, a limit is hit, or time is up.
		try
			withTimeout(limits.maxCircuitDuration, "relay circuit", {
				waitAll({ pipe(src, dstStream, limits.maxCircuitBytes); }, {
					pipe(dstStream, src, limits.maxCircuitBytes);
				});
			});
		catch (InterruptException e)
			throw e; // the relay is shutting down; the scope guards close both ends
		catch (Exception)
		{
		} // the circuit is over, whichever way; both ends are closed below
	}

	private static void pipe(Stream from, Stream to, ulong budget)
	{
		ubyte[4096] buf;
		try
		{
			while (budget > 0)
			{
				immutable n = from.read(buf[0 .. budget < buf.length ? cast(size_t) budget : buf.length]);
				to.write(buf[0 .. n]);
				budget -= n;
			}
		}
		catch (Ending)
		{
		}
		to.close();
	}

	// --- as a client -----------------------------------------------------------------------------

	/// Ask `relay` for a reservation; throws if it refuses.
	ReservationInfo reserve(PeerId relay)
	{
		auto c = host.connect(relay);
		auto s = c.newStream(hopProtocol);
		scope (exit)
			s.close();
		HopMessage m;
		m.type = HopMessage.Type.RESERVE;
		s.writeLengthPrefixed(m.encode);
		auto reply = HopMessage.decode(s.readLengthPrefixed(maxRelayMessage));
		enforce(reply.type == HopMessage.Type.STATUS && reply.hasStatus, "relay: malformed reply");
		enforce(reply.status == Status.OK, "relay: reservation refused: " ~ statusName(reply.status));
		ReservationInfo info;
		if (reply.hasReservation)
		{
			info.expire = reply.reservation.expire;
			foreach (raw; reply.reservation.addrs)
				info.addrs ~= Multiaddr.decode(raw);
		}
		if (reply.hasLimit)
			info.limit = reply.limit;
		return info;
	}

	/// The addresses to advertise after a reservation at `relay`.
	Multiaddr[] circuitAddrs(PeerId relay, ReservationInfo info)
	{
		Multiaddr[] out_;
		foreach (a; info.addrs)
			out_ ~= a ~ Multiaddr.parse("/p2p/" ~ relay.toBase58 ~ "/p2p-circuit/p2p/" ~ host.id.toBase58);
		return out_;
	}

	/// A connection to `dst` through `relay`, upgraded and in the pool.
	Connection connectVia(PeerId relay, PeerId dst)
	{
		auto raw = openCircuit(relay, dst);
		return host.swarm.admitOutbound(raw, nullable(dst));
	}

	private RawConn openCircuit(PeerId relay, PeerId dst)
	{
		auto c = host.connect(relay);
		auto s = c.newStream(hopProtocol);
		scope (failure)
			s.reset();
		HopMessage m;
		m.type = HopMessage.Type.CONNECT;
		m.hasPeer = true;
		m.peer.id = dst.bytes.dup;
		s.writeLengthPrefixed(m.encode);
		auto reply = HopMessage.decode(s.readLengthPrefixed(maxRelayMessage));
		enforce(reply.type == HopMessage.Type.STATUS && reply.hasStatus, "relay: malformed reply");
		enforce(reply.status == Status.OK, "relay: circuit refused: " ~ statusName(reply.status));
		auto remote = c.remoteAddr ~ Multiaddr.parse("/p2p/" ~ relay.toBase58 ~ "/p2p-circuit/p2p/" ~ dst.toBase58);
		return new StreamRawConn(s, c.localAddr, remote);
	}

	/// An incoming circuit: the relay says who is calling; we answer OK and the
	/// stream becomes an inbound connection.
	private void serveStop(Stream s, Connection relayConn, string)
	{
		scope (failure)
			s.reset();
		auto msg = StopMessage.decode(s.readLengthPrefixed(maxRelayMessage));
		if (msg.type != StopMessage.Type.CONNECT || !msg.hasPeer)
		{
			s.writeLengthPrefixed(StopMessage.statusReply(Status.UNEXPECTED_MESSAGE).encode);
			s.close();
			return;
		}
		auto src = PeerId.fromBytes(msg.peer.id);
		s.writeLengthPrefixed(StopMessage.statusReply(Status.OK).encode);
		auto remote = relayConn.remoteAddr ~ Multiaddr.parse("/p2p/" ~ relayConn.remotePeer.toBase58
				~ "/p2p-circuit/p2p/" ~ src.toBase58);
		auto raw = new StreamRawConn(s, relayConn.localAddr, remote);
		host.swarm.admitInboundRaw(raw); // from here the swarm owns it
	}

	// --- Transport: dialing /p2p-circuit addresses -------------------------------------------------

	bool canHandle(const Multiaddr addr)
	{
		try
			return addr.components.canFind!(c => c.name == "p2p-circuit");
		catch (Exception)
			return false;
	}

	/// `<relay addr>/p2p/<relay>/p2p-circuit/p2p/<dst>`.
	RawConn dial(const Multiaddr addr)
	{
		auto comps = Multiaddr(addr.bytes.dup).components;
		immutable circuitAt = comps.countUntil!(c => c.name == "p2p-circuit");
		enforce(circuitAt >= 1 && comps[circuitAt - 1].name == "p2p", "relay: address does not name its relay");
		enforce(circuitAt + 2 == comps.length && comps[$ - 1].name == "p2p", "relay: address does not name its destination");
		auto relay = PeerId.fromBytes(comps[circuitAt - 1].value);
		auto dst = PeerId.fromBytes(comps[$ - 1].value);
		Multiaddr relayAddr;
		foreach (c; comps[0 .. circuitAt - 1])
			relayAddr = relayAddr ~ Multiaddr.parse("/" ~ c.name ~ (c.protocol.size != 0 ? "/" ~ c.text : ""));
		if (relayAddr.bytes.length > 0)
			host.peerstore.addAddrs(relay, [relayAddr]);
		return openCircuit(relay, dst);
	}

	Listener listen(const Multiaddr)
	{
		throw new Exception("relay: listening is a reservation, not a listener");
	}

	// --- DCUtR ----------------------------------------------------------------------------------

	/// Swap addresses with `peer` over the connection we have; no dialing.
	DcutrResult holePunchExchange(PeerId peer)
	{
		auto c = host.connect(peer);
		auto s = c.newStream(dcutrProtocol);
		scope (exit)
			s.close();
		return initiateHolePunch(s, punchAddrs());
	}

	/// Swap addresses, wait half a round trip, dial `peer` directly. Returns the
	/// peer the direct connection authenticated as.
	PeerId holePunch(PeerId peer)
	{
		auto res = holePunchExchange(peer);
		sleep(res.rtt / 2);
		Exception last;
		foreach (raw; res.peerAddrs)
		{
			try
			{
				auto addr = Multiaddr.decode(raw);
				if (!addr.components.canFind!(c => c.name == "p2p"))
					addr = addr ~ Multiaddr.parse("/p2p/" ~ peer.toBase58);
				auto direct = host.swarm.dial(addr);
				return direct.remotePeer;
			}
			catch (InterruptException e)
				throw e; // the hole punch was cancelled, not this address failing
			catch (Exception e)
				last = e;
		}
		throw new Exception("dcutr: no direct address of " ~ peer.toString ~ " answered", last);
	}

	/// The other side: answer with our addresses, then dial theirs at once.
	private void serveDcutr(Stream s, Connection c, string)
	{
		scope (exit)
			s.close();
		auto theirs = respondHolePunch(s, punchAddrs());
		auto peer = c.remotePeer;
		punches++;
		fibers.spawn({
			scope (exit)
				punches--;
			foreach (raw; theirs)
			{
				try
				{
					auto addr = Multiaddr.decode(raw);
					if (!addr.components.canFind!(x => x.name == "p2p"))
						addr = addr ~ Multiaddr.parse("/p2p/" ~ peer.toBase58);
					host.swarm.dial(addr);
					return;
				}
				catch (InterruptException e)
					throw e; // the punch fiber is being stopped, not this address failing
				catch (Exception)
				{
				} // the next address may work; if none does, the relayed connection stays
			}
		});
	}
}

private string statusName(Status s)
{
	import std.conv : to;

	return s.to!string;
}
