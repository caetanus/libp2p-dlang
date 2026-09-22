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
import vibe.core.log : logDebug, logInfo;
import vibe.core.sync : LocalManualEvent, createManualEvent;
import vibe.core.task : InterruptException, Task;

import libp2p.core.ending : Ending;
import libp2p.core.peer_id : PeerId;
import libp2p.core.upgrade : Endpoint;
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
	/// When set, a relayed connection we dialed auto-triggers DCUtR to upgrade
	/// it to a direct one (the responder side already answers automatically).
	bool autoHolePunch = true;
	private bool[PeerId] autoPunching; // initiator punches in flight, one per peer
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

	// Addresses to offer in a DCUtR exchange: our dialable addresses, any
	// reflexive (STUN) address a capable transport gathered, and — for the raw
	// transports — our observed public IP paired with each listen port, the
	// address a TCP simultaneous open must aim at. Explicit setObservedAddrs
	// replaces all of it.
	private ubyte[][] punchAddrs()
	{
		ubyte[][] out_;
		foreach (a; dcutrAddrs())
			out_ ~= a.encode;
		return out_;
	}

	/// The addresses this node offers a peer to punch to (what punchAddrs encodes).
	///
	/// The libp2p-standard punch candidate is identify's Observed-Address + reuseport:
	/// a peer never needs to know its own IP — whoever it connected to already saw its
	/// public source IP:port and reported it via identify's `observedAddr`. So the
	/// PRIMARY candidate is that observed public IP paired with each of our listen
	/// ports (a port-preserving / cone NAT maps the listener to the same external
	/// port — the go-libp2p reuseport recipe). Behind a VPN the observed IP is the
	/// tunnel exit's PUBLIC address (what the relay saw), which is exactly the punch
	/// target — never the local 100.84.x tunnel IP, and no STUN round-trip. The STUN
	/// server-reflexive address is a last-resort FALLBACK, offered only when identify
	/// gave us no public address at all (so Android with the VPN down never depends on
	/// STUN). Explicit setObservedAddrs replaces all of it.
	Multiaddr[] dcutrAddrs()
	{
		Multiaddr[] out_;
		void add(Multiaddr a)
		{
			if (!out_.canFind(a))
				out_ ~= a;
		}
		if (observed.length > 0)
		{
			foreach (raw; observed)
				add(Multiaddr.decode(raw));
			return out_; // an explicit override is exactly what we offer
		}

		bool haveDirectPublic = false;
		auto observedSeen = host.observedAddrs();
		// PRIMARY (libp2p standard): the public IP a peer OBSERVED us at, paired with
		// each of our listen ports. The port identify saw is the ephemeral source of
		// that outbound connection, not our listener's, so we keep the listener's port
		// and full transport suffix — for EVERY transport (/tcp/P, /udp/P/quic-v1,
		// /udp/P/webrtc-direct/certhash/…, /udp/P/quic-v1/webtransport/…), not just TCP.
		foreach (seen; observedSeen)
		{
			auto sc = seen.components;
			if (sc.length == 0 || (sc[0].name != "ip4" && sc[0].name != "ip6"))
				continue;
			if (sc.canFind!(c => c.name == "p2p-circuit"))
				continue;
			if (!isRoutable(seen))
				continue; // a VPN tunnel / private observation is not punchable
			immutable ipText = "/" ~ sc[0].name ~ "/" ~ sc[0].text;
			foreach (l; host.addrs)
			{
				auto lc = l.components;
				if (lc.length < 2 || lc[0].name != sc[0].name)
					continue; // observed IP's family must match this listener's
				if (lc[1].name != "tcp" && lc[1].name != "udp")
					continue; // need a real port to reuse
				string rest;
				foreach (c; lc[1 .. $])
					rest ~= "/" ~ c.name ~ (c.protocol.size != 0 ? "/" ~ c.text : "");
				try
				{
					add(Multiaddr.parse(ipText ~ rest));
					haveDirectPublic = true;
				}
				catch (Exception)
				{
				}
			}
		}
		// Also offer any directly-routable listen address (a genuinely public
		// listener, the no-NAT case). 0.0.0.0 / loopback / VPN-tunnel listeners are
		// real but not reachable there, so isRoutable drops them.
		foreach (a; host.addrs)
			if (isRoutable(a))
			{
				add(a);
				haveDirectPublic = true;
			}
		// FALLBACK ONLY: the STUN server-reflexive address, used solely when identify
		// and our listeners gave us no public address at all. This keeps the
		// proactive-gather machinery as a safety net rather than the primary path (and
		// off the critical path on Android with the VPN down).
		if (!haveDirectPublic)
			foreach (a; host.reflexiveAddrs())
				if (isRoutable(a))
					add(a);
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

	void connected(Connection c)
	{
		// The side that dialed through the relay is the DCUtR initiator; the side
		// that accepted answers in serveDcutr. A direct connection (including the
		// one a punch just made) is not relayed, so it never re-triggers this.
		if (!c.remoteAddr.components.canFind!(x => x.name == "p2p-circuit"))
			return;
		// Spawn the auto-punch FIRST, so nothing after it can keep it from firing.
		if (autoHolePunch && c.role == Endpoint.dialer && c.remotePeer !in autoPunching)
		{
			auto peer = c.remotePeer;
			autoPunching[peer] = true;
			fibers.spawn({
				scope (exit)
					autoPunching.remove(peer);
				try
					holePunch(peer);
				catch (InterruptException)
				{
				} // shutting down
				catch (Exception e)
					logDebug("libp2p: auto-DCUtR to %s did not complete: %s",
						peer.toString, e.msg); // the relayed link stays as the fallback
			});
		}
		// Then, strictly additive: nudge our server-reflexive address warm so a
		// DCUtR offer carries a public candidate (behind a VPN the tunnel IP is
		// filtered out). warmReflexiveAddrs() is nothrow and non-blocking, and the
		// srflx is already warming since listen(), so this can never abort or delay
		// the punch above — even with STUN unreachable (VPN down / no internet).
		host.warmReflexiveAddrs();
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

	/// The rendezvous end to end: meet `dst` through `relay`, hole-punch, and hand
	/// back the DIRECT connection. The relay is only where the two met — the
	/// relayed connection is closed once the direct one is up (or the punch
	/// fails), so nothing opened later can ride the circuit's small byte budget
	/// by accident. Throws when no direct path formed: direct or nothing.
	Connection connectDirect(PeerId relay, PeerId dst)
	{
		connectVia(relay, dst);
		return ensureDirect(dst);
	}

	/// The direct connection to `peer`, punching one if all we have is relayed.
	/// Returns an existing direct connection as is; otherwise runs DCUtR (or waits
	/// for the auto-DCUtR already in flight), closes the relayed connection(s) and
	/// returns the direct one. Throws if none formed — and the relayed connection is
	/// closed then too: the relay was the meeting point, not the pipe.
	Connection ensureDirect(PeerId peer)
	{
		if (auto c = directConnection(peer))
			return c;
		scope (exit)
			foreach (c; host.swarm.connectionsTo(peer))
				if (isRelayed(c))
					c.close();
		if (peer in autoPunching)
		{
			// connected() is already punching this peer; let that finish.
			immutable deadline = MonoTime.currTime + host.swarm.config.dialTimeout
				+ host.swarm.config.handshakeTimeout;
			while (peer in autoPunching && MonoTime.currTime < deadline)
				sleep(20.msecs);
		}
		else
			holePunch(peer);
		if (auto c = directConnection(peer))
			return c;
		throw new Exception("dcutr: no direct connection to " ~ peer.toString);
	}

	private Connection directConnection(PeerId peer)
	{
		foreach (c; host.swarm.connectionsTo(peer))
			if (!isRelayed(c) && !c.isClosed)
				return c;
		return null;
	}

	private static bool isRelayed(Connection c)
	{
		return c.remoteAddr.components.canFind!(x => x.name == "p2p-circuit");
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
		// A limited-relay-v2 voucher caps the circuit: once `data` bytes have crossed
		// (or `duration` elapses) the relay tears the circuit down. Public relays hand
		// out tiny budgets (~128 KiB) meant only to bootstrap a direct upgrade, so a
		// data transfer over one dies mid-file — log the budget to make that visible.
		if (reply.hasLimit)
			logInfo("libp2p: circuit to %s via %s is LIMITED: %s bytes / %s s",
				dst.toString, relay.toString, reply.limit.data, reply.limit.duration);
		else
			logInfo("libp2p: circuit to %s via %s advertised no limit", dst.toString, relay.toString);
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

	/// Reach `peer` at one of the addresses it offered. A plain address is dialed
	/// (TCP simultaneous-open); a webrtc-direct reflexive address is punched,
	/// where the two peers split one asymmetric role — `asDialer` from our DCUtR
	/// side (initiator dials, responder listens). Either way the direct
	/// connection lands in the pool.
	private Connection dialOrPunch(const(ubyte)[] raw, PeerId peer, bool asDialer)
	{
		auto addr = Multiaddr.decode(raw);
		// webrtc-direct and quic-v1 both carry their own security+muxing and reuse a
		// gathered srflx socket, so they punch; anything else is a plain (TCP)
		// simultaneous-open dial.
		immutable punchable = addr.components.canFind!(c => c.name == "webrtc-direct"
				|| c.name == "quic-v1");
		if (!addr.components.canFind!(c => c.name == "p2p"))
			addr = addr ~ Multiaddr.parse("/p2p/" ~ peer.toBase58);
		// TCP (and other raw transports) punch by simultaneous-open: dial from our
		// own listen port with address reuse so the peer's NAT mapping matches.
		return punchable ? host.punch(addr, peer, asDialer) : host.swarm.dialPunch(addr, peer);
	}

	/// Swap addresses, wait half a round trip, reach `peer` directly. Returns the
	/// peer the direct connection authenticated as.
	PeerId holePunch(PeerId peer)
	{
		auto res = holePunchExchange(peer);
		logInfo("libp2p: dcutr with %s: rtt %s, their addrs [%s], ours [%s]", peer.toString, res.rtt,
			addrList(res.peerAddrs), addrList(punchAddrs()));
		sleep(res.rtt / 2);
		Exception last;
		if (auto c = punchAll(res.peerAddrs, peer, true, last)) // initiator: the DTLS client
			return c.remotePeer;
		// Our connect can lose to the peer's: when its SYN reaches our listener first
		// (same LAN, no NAT in between) the kernel accepts it there, and our own dial
		// from that port then fails on the taken 4-tuple. The direct connection is
		// still forming — inbound, through the ordinary accept path — so wait for it.
		if (auto c = awaitDirect(peer, host.swarm.config.handshakeTimeout))
			return c.remotePeer;
		throw new Exception("dcutr: no direct address of " ~ peer.toString ~ " answered", last);
	}

	/// Punch every candidate at once — reflexive (STUN) addresses first, since
	/// they are the ones a NAT'd peer can actually be reached at — and keep the
	/// first connection that comes up; the rest are interrupted. Both sides do
	/// this, so their sends overlap on every candidate pair: punched one at a
	/// time with 15 s timeouts, the only real candidate came up 20 s after the
	/// peer had already stopped punching. `last` receives a failure to blame.
	private Connection punchAll(const(ubyte[][]) raws, PeerId peer, bool asDialer, out Exception last)
	{
		import vibe.core.core : runTask;
		import vibe.core.task : Task;

		auto ordered = orderCandidates(raws);
		auto race = new PunchRace;
		race.changed = createManualEvent();
		foreach (raw; ordered)
			race.tasks ~= runTask((PunchRace r, ubyte[] a, PeerId p, bool dialer) nothrow {
				Connection c;
				Exception failure;
				try
					c = dialOrPunch(a, p, dialer);
				catch (InterruptException)
				{
				}
				catch (Exception e)
					failure = e;
				if (c !is null && (r.done || r.winner !is null))
				{
					c.close(); // one direct connection is enough
					c = null;
				}
				if (r.done)
					return;
				if (c !is null)
					r.winner = c;
				else if (failure !is null)
				{
					r.last = failure;
					try
						logInfo("libp2p: dcutr punch%s of %s failed: %s", dialer ? "" : "-back",
							addrList([a]), causeChain(failure));
					catch (Exception)
					{
					}
				}
				r.finished++;
				try
					r.changed.emit();
				catch (Exception)
				{
				}
			}, race, raw.dup, peer, asDialer);
		try
		{
			while (race.winner is null && race.finished < race.tasks.length)
			{
				auto ec = race.changed.emitCount;
				race.changed.wait(ec);
			}
		}
		finally
		{
			race.done = true;
			auto me = Task.getThis();
			foreach (t; race.tasks)
				if (t != me && t.running)
					t.interrupt();
		}
		last = race.last;
		return race.winner;
	}

	// Reflexive/punchable addresses (quic-v1, webrtc-direct) first, then the rest.
	// What the peer offers is its call (on one LAN, or in a test, that is loopback);
	// only our own offer is filtered, in dcutrAddrs.
	private static ubyte[][] orderCandidates(const(ubyte[][]) raws)
	{
		ubyte[][] first, rest;
		foreach (raw; raws)
		{
			Multiaddr a;
			try
				a = Multiaddr.decode(raw);
			catch (Exception)
				continue;
			if (a.components.canFind!(c => c.name == "quic-v1" || c.name == "webrtc-direct"))
				first ~= raw.dup;
			else
				rest ~= raw.dup;
		}
		return first ~ rest;
	}

	/// A pooled, non-relayed connection to `peer`, waiting up to `budget` for one
	/// to be admitted.
	private Connection awaitDirect(PeerId peer, Duration budget)
	{
		immutable deadline = MonoTime.currTime + budget;
		while (true)
		{
			foreach (c; host.swarm.connectionsTo(peer))
				if (!c.remoteAddr.components.canFind!(x => x.name == "p2p-circuit"))
					return c;
			if (MonoTime.currTime >= deadline)
				return null;
			sleep(20.msecs);
		}
	}

	/// The other side: answer with our addresses, then dial theirs at once.
	private void serveDcutr(Stream s, Connection c, string)
	{
		scope (exit)
			s.close();
		auto theirs = respondHolePunch(s, punchAddrs());
		auto peer = c.remotePeer;
		logInfo("libp2p: dcutr from %s: their addrs [%s], ours [%s]", peer.toString, addrList(theirs),
			addrList(punchAddrs()));
		punches++;
		fibers.spawn({
			scope (exit)
				punches--;
			Exception last;
			punchAll(theirs, peer, false, last); // responder: the DTLS server; if none lands, the relayed connection stays
		});
	}
}

/// Shared state of one concurrent punch (see Relay.punchAll): heap-owned so a
/// late punch task never touches a frame that is gone.
private final class PunchRace
{
	Connection winner;
	Exception last;
	size_t finished;
	Task[] tasks;
	bool done;
	LocalManualEvent changed;
}

/// An address a peer could conceivably reach us at: not unspecified, not
/// loopback, not link-local. A listener on 0.0.0.0 is real, its address is not.
private bool isRoutable(const Multiaddr a)
{
	import std.string : startsWith;

	auto c = a.components;
	if (c.length == 0)
		return false;
	if (c[0].name == "ip4")
	{
		immutable ip = c[0].text;
		if (ip == "0.0.0.0" || ip.startsWith("127.") || ip.startsWith("169.254."))
			return false;
		// RFC1918 private ranges: 10/8, 172.16/12, 192.168/16.
		if (ip.startsWith("10.") || ip.startsWith("192.168."))
			return false;
		if (ip.startsWith("172."))
		{
			immutable o2 = ip4Octet(ip, 1);
			if (o2 >= 16 && o2 <= 31)
				return false;
		}
		// CGNAT / RFC 6598: 100.64.0.0/10 — only 100.64.x–100.127.x (100.0–63 and
		// 100.128+ are public). The WireGuard tunnel range that leaked into the
		// punch list; a naive startsWith("100.") would wrongly reject public IPs.
		if (ip.startsWith("100."))
		{
			immutable o2 = ip4Octet(ip, 1);
			if (o2 >= 64 && o2 <= 127)
				return false;
		}
		return true;
	}
	if (c[0].name == "ip6")
	{
		import std.uni : toLower;

		immutable ip = c[0].text;
		if (ip == "::" || ip == "::1" || ip.startsWith("fe80:"))
			return false;
		// ULA fc00::/7 — first hextet begins fc.. or fd.. (not publicly routed).
		immutable lo = ip.length >= 2 ? ip[0 .. 2].toLower : ip;
		if (lo == "fc" || lo == "fd")
			return false;
		return true;
	}
	return true; // dns, circuit, …: let the dial decide
}

// The n-th (0-based) dotted-decimal octet of an ip4 text, or -1 if malformed.
private int ip4Octet(string ip, size_t n) nothrow
{
	import std.array : split;
	import std.conv : to;

	try
	{
		auto parts = ip.split('.');
		if (n >= parts.length)
			return -1;
		return parts[n].to!int;
	}
	catch (Exception)
		return -1;
}

// Multiaddrs for a log line; an undecodable one shows as its byte count.
private string addrList(const(ubyte[][]) raws)
{
	import std.conv : to;

	string out_;
	foreach (i, raw; raws)
	{
		if (i)
			out_ ~= ", ";
		try
			out_ ~= Multiaddr.decode(raw).toString;
		catch (Exception)
			out_ ~= "<" ~ raw.length.to!string ~ " bytes>";
	}
	return out_;
}

// An exception and everything it was thrown because of, innermost last.
private string causeChain(Throwable e)
{
	string out_;
	for (Throwable t = e; t !is null; t = t.next)
		out_ ~= (out_.length ? " <- " : "") ~ t.msg;
	return out_;
}

private string statusName(Status s)
{
	import std.conv : to;

	return s.to!string;
}
