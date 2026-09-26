/**
 * webrtc-direct: a libp2p connection over ICE + DTLS + SCTP data channels,
 * with no signalling server. The address carries everything a dialer needs:
 * where to send UDP and the server's certificate fingerprint.
 *
 *   /ip4/<ip>/udp/<port>/webrtc-direct/certhash/<multibase multihash>[/p2p/<id>]
 *
 * The engine is d-webrtc's sans-io `Connection`: it is fed datagrams and a
 * clock and drained of datagrams. Everything with a lifetime is here: one
 * UDP socket per listener shared by every remote (demultiplexed by their
 * address), a reader fiber per socket, a session per remote with a ticker
 * fiber for retransmission timers, and data channels presented as streams.
 * Security is DTLS; Noise runs once, on the first channel, to prove libp2p
 * identities with both fingerprints in its prologue. The result is handed to
 * the swarm already upgraded.
 *
 * Noise runs on the negotiated data channel (id 0); further libp2p streams are
 * DCEP-opened channels, and closing a stream resets its SCTP stream.
 */
module libp2p.transport.webrtc.transport;

import core.time : Duration, MonoTime, msecs, seconds;
import std.algorithm.comparison : min;
import std.algorithm.searching : canFind, countUntil;
import std.conv : to;
import std.exception : enforce;
import std.random : uniform;
import std.socket : AddressFamily;
import std.typecons : Nullable, nullable;

import vibe.core.core : runTask, sleep;
import vibe.core.task : Task, InterruptException;
import vibe.core.log : logDebug;
import vibe.core.net;
import vibe.core.sync : LocalManualEvent, createManualEvent;
import vibe.core.task : InterruptException;

import webrtc.connection.connection : Connection, Perspective, OutboundDatagram, ConnState, noiseChannel;
import webrtc.datachannel.channels : ChannelEvent, ChannelEventKind;
import webrtc.dtls.certificate : Certificate;
import webrtc.ice.agent : Agent, IceRole = Role, Credentials, TransportAddr;
import webrtc.ice.candidate : Candidate, CandidateType;
import webrtc.stun.message : isStunMessage, StunMessage = Message, attrUsername;

import libp2p.core.ending;
import libp2p.core.peer_id : PeerId;
import libp2p.core.stream : Stream;
import libp2p.crypto.keys : Keypair;
import libp2p.multiformats.multiaddr : Multiaddr, Component;
import libp2p.multiformats.multibase : multibaseEncode;
import libp2p.multiformats.multihash : Multihash;
import libp2p.muxer.muxer : Muxer;
import libp2p.swarm.swarm : CapableTransport, NetworkAware, UpgradedConn;
import libp2p.transport.webrtc.fingerprint;
import libp2p.transport.webrtc.noise;
import libp2p.transport.webrtc.sdp : randomUfrag, punchUfrag;
import libp2p.transport.webrtc.stream : WebRtcStream;
import libp2p.util.fibers : FiberGroup;
import libp2p.util.timeout : withTimeout;

/// What a dial address says.
struct DialAddr
{
	string host;
	ushort port;
	bool ipv6;
	Fingerprint fingerprint;
	Nullable!PeerId peer;
}

/// Null unless `addr` is `/ip4|ip6/../udp/../webrtc-direct/certhash/..[/p2p/..]`.
Nullable!DialAddr parseWebRTCDialAddr(Multiaddr addr)
{
	Component[] c;
	try
		c = addr.components;
	catch (Exception)
		return Nullable!DialAddr.init;
	if (c.length < 4 || (c[0].name != "ip4" && c[0].name != "ip6") || c[1].name != "udp"
		|| c[2].name != "webrtc-direct" || c[3].name != "certhash")
		return Nullable!DialAddr.init;
	DialAddr d;
	d.host = c[0].text;
	d.ipv6 = c[0].name == "ip6";
	d.port = cast(ushort)((c[1].value[0] << 8) | c[1].value[1]);
	Multihash mh;
	try
		mh = Multihash.decode(c[3].value);
	catch (Exception)
		return Nullable!DialAddr.init;
	auto fp = Fingerprint.tryFromMultihash(mh);
	if (fp.isNull)
		return Nullable!DialAddr.init;
	d.fingerprint = fp.get;
	if (c.length == 5)
	{
		if (c[4].name != "p2p")
			return Nullable!DialAddr.init;
		try
			d.peer = PeerId.fromBytes(c[4].value);
		catch (Exception)
			return Nullable!DialAddr.init;
	}
	else if (c.length > 5)
		return Nullable!DialAddr.init;
	return nullable(d);
}

struct WebRtcConfig
{
	Duration connectTimeout = 15.seconds;
	Duration tick = 50.msecs; /// how often the engine's timers are driven
	/// The most inbound handshakes a listening socket will have in flight at
	/// once. A STUN packet from a stranger starts a whole connection (an engine,
	/// a ticker fiber, DTLS/SCTP state); without a ceiling a sender rotating its
	/// source port could make unbounded numbers of them. Beyond this the packet
	/// is dropped and the peer's own STUN retransmit retries once a slot frees.
	uint maxPendingInbound = 32;
	/// STUN servers ("host:port") probed for our server-reflexive candidate, so a
	/// two-NAT peer has a reflexive address to punch to. Resolved per connection
	/// and fed to the ICE agent, which probes them out the connection's own socket.
	string[] stunServers = ["stun.l.google.com:19302", "stun.cloudflare.com:3478"];
}

final class WebRtcTransport : CapableTransport, NetworkAware
{
	private Keypair identity;
	private Certificate cert;
	private WebRtcConfig cfg;
	private UdpMux[] muxes;
	private UDPConnection punchSock; /// held open so a hole punch reuses the mapping
	private Multiaddr punchAddr; /// our gathered srflx webrtc-direct address
	private bool punchGathered;
	private bool punchWarming; /// a background srflx-warming loop is running
	private Task warmTask; /// that loop, owned: close() stops and joins it
	private bool closed;
	private MonoTime punchGatheredAt;
	private enum srflxMaxAge = 25.seconds;
	private UdpMux punchMux; /// the single persistent mux on punchSock every punch shares
	/// A STUN gather is reading punchSock: only ONE may (eventcore allows a single read
	/// callback per socket — a second concurrent reader aborts the process with
	/// "Overwriting notification callback"). A DCUtR offer and the warming loop both ask
	/// for the address; the second one waits for the first gather instead of starting its
	/// own, and a punch waits for it before putting the mux on the socket.
	private bool gathering;
	private LocalManualEvent gatherDone;

	this(Keypair identity, WebRtcConfig cfg = WebRtcConfig.init)
	{
		this.identity = identity;
		this.cfg = cfg;
		cert = new Certificate;
		gatherDone = createManualEvent();
	}

	/// The network moved: the gathered reflexive address was the old network's
	/// NAT mapping; the next offer gathers a fresh one.
	private bool gatherStale; /// the network moved while a gather ran: its answer is the old network's

	void networkChanged(bool lost) nothrow
	{
		// Only an address ADDED (a VPN, a new IPv6): a mux on the punch socket keeps its
		// mapping alive and owns the socket's one reader — leave all of it as it is (clearing
		// the gather state would let the next offer read the socket beside the mux)
		if (!lost && punchMux !is null)
			return;
		punchAddr = Multiaddr.init;
		punchGathered = false;
		// A gather running now reads the punch socket (one reader per socket: never close
		// it under that read); what it learns may be the old network's, so it is thrown away
		// when it finishes and the next offer gathers again.
		if (gathering)
		{
			gatherStale = true;
			return;
		}
		// Only a LOST address kills what rides the punch socket; an added one (a VPN, a new
		// IPv6) leaves the punched connections working.
		if (!lost)
			return;
		// Retire the punch socket: its mapping was the old network's, and once a punch put
		// the mux on it the socket can never be read for STUN again (the cached address
		// would be served for good). The punched connections on it rode the old network.
		if (punchMux !is null)
			punchMux.close(); // also drops the gather state and closes punchSock
		else if (punchSock != UDPConnection.init)
			try
				punchSock.close();
			catch (Exception)
			{
			}
		punchSock = UDPConnection.init;
		punchAddr = Multiaddr.init;
		punchGathered = false;
	}

	Fingerprint fingerprint()
	{
		return Fingerprint.raw(cert.sha256Fingerprint());
	}

	bool canHandle(const Multiaddr addr)
	{
		try
			return Multiaddr(addr.bytes.dup).components.canFind!(c => c.name == "webrtc-direct");
		catch (Exception)
			return false;
	}

	// Resolve the configured STUN servers and hand them to a connection's ICE
	// agent, which probes them out this connection's own socket to learn our
	// server-reflexive candidate (an unresolvable server just yields no srflx).
	private void applyStunServers(Connection conn)
	{
		import std.string : lastIndexOf;
		import std.conv : to;

		foreach (s; cfg.stunServers)
			try
			{
				immutable colon = s.lastIndexOf(':');
				if (colon < 0)
					continue;
				auto na = resolveHost(s[0 .. colon], AddressFamily.INET, true);
				conn.addStunServer(TransportAddr(na.toAddressString, s[colon + 1 .. $].to!ushort));
			}
			catch (InterruptException e)
				throw e; // cancellation must unwind, not read as a bad STUN entry
			catch (Exception)
			{
			}
	}

	/// Our server-reflexive webrtc-direct address, gathered once via STUN on a
	/// socket kept open so a later hole punch reuses the same NAT mapping. Returns
	/// Multiaddr.init if no STUN server answered (no reflexive address to advertise).
	Multiaddr reflexiveAddr()
	{
		import std.algorithm.searching : find;
		import std.range : empty, front;
		import std.string : lastIndexOf;
		import std.conv : to;
		import core.time : msecs;

		// A NAT forgets an idle UDP mapping in 30-120 s: a gathered address is only
		// good while its mapping lives, so re-gather a stale one (on the SAME socket,
		// so the mapping is refreshed rather than replaced). Once a punch has put
		// the mux on the socket the socket cannot be read here any more; the punch
		// traffic itself keeps that mapping alive.
		if (punchGathered && (punchMux !is null || MonoTime.currTime - punchGatheredAt < srflxMaxAge))
			return punchAddr;
		if (gathering)
		{
			waitGathered();
			return punchAddr;
		}
		punchGathered = true;
		gathering = true;
		gatherStale = false;
		scope (exit)
		{
			gathering = false;
			if (gatherStale)
			{
				// the network moved under this gather: its answer names the old mapping
				gatherStale = false;
				punchAddr = Multiaddr.init;
				punchGathered = false;
			}
			gatherDone.emit();
		}
		try
		{
			if (punchSock == UDPConnection.init)
				punchSock = listenUDP(0, "0.0.0.0");
			immutable port = punchSock.localAddress.port;
			immutable local = TransportAddr("0.0.0.0", port);
			auto pwd = randomUfrag() ~ randomUfrag() ~ randomUfrag();
			auto agent = new Agent(IceRole.controlling, Credentials(randomUfrag(), pwd), uniform!ulong());
			agent.addLocalCandidate(Candidate.host("0.0.0.0", port, false));
			foreach (sv; cfg.stunServers)
				try
				{
					immutable colon = sv.lastIndexOf(':');
					if (colon < 0)
						continue;
					auto na = resolveHost(sv[0 .. colon], AddressFamily.INET, true);
					agent.addStunServer(TransportAddr(na.toAddressString, sv[colon + 1 .. $].to!ushort));
				}
				catch (InterruptException e)
					throw e; // cancellation must unwind, not read as a bad STUN entry
				catch (Exception)
				{
				}

			foreach (i; 0 .. 50)
			{
				foreach (o; agent.gatherOutbound(i * 100))
					try
					{
						auto dst = resolveHost(o.dst.ip, AddressFamily.INET, false);
						dst.port = o.dst.port;
						punchSock.send(o.data, &dst);
					}
					catch (Exception)
					{
					}

				auto srflx = agent.gatheredCandidates.find!(c => c.typ == CandidateType.serverReflexive);
				if (!srflx.empty)
				{
					punchAddr = Multiaddr.parse("/ip4/" ~ srflx.front.address ~ "/udp/"
							~ srflx.front.port.to!string ~ "/webrtc-direct/certhash/"
							~ multibaseEncode(fingerprint().toMultihash.encode));
					punchGatheredAt = MonoTime.currTime;
					return punchAddr;
				}

				NetworkAddress from;
				ubyte[2048] buf;
				ubyte[] got;
				try
					got = punchSock.recv(100.msecs, buf[], &from);
				catch (InterruptException e)
					throw e; // cancellation must not look like a failed recv
				catch (Exception)
				{
				}
				if (got.length)
					agent.handleInbound(got, TransportAddr(from.toAddressString, from.port), local, i * 100);
			}
		}
		catch (InterruptException e)
			throw e; // a cancelled gather stays cancelled
		catch (Exception)
		{
		}
		return punchAddr; // Multiaddr.init if nothing answered
	}

	/// Wait (bounded) for the gather in flight to finish.
	private void waitGathered()
	{
		immutable until = MonoTime.currTime + 8.seconds;
		while (gathering && MonoTime.currTime < until)
		{
			auto ec = gatherDone.emitCount;
			gatherDone.wait(until - MonoTime.currTime, ec);
		}
	}

	/// Begin warming our reflexive webrtc-direct address in the BACKGROUND so a
	/// DCUtR offer reads a cached srflx instead of blocking on STUN. Idempotent,
	/// non-blocking and nothrow — it must never abort or stall the notifiee /
	/// connection path that nudges it; an unreachable STUN round (VPN down) is
	/// swallowed and retried on the next cadence.
	void startReflexive() nothrow
	{
		if (punchWarming || closed)
			return;
		punchWarming = true;
		try
			warmTask = runTask(() nothrow {
				try
					while (!closed)
					{
						reflexiveAddr();
						if (closed)
							break; // do not sleep 20 s while close() waits to join us
						sleep(20.seconds);
					}
				catch (InterruptException)
				{
				} // close() stopping us
				catch (Exception)
				{
				}
			});
		catch (Exception)
			punchWarming = false; // spawning failed; let a later call try again
	}

	// --- dialing ---------------------------------------------------------------------------

	UpgradedConn dial(const Multiaddr remote, Nullable!PeerId expected)
	{
		auto parsed = parseWebRTCDialAddr(Multiaddr(remote.bytes.dup));
		enforce(!parsed.isNull, "webrtc: not a dialable webrtc-direct address: " ~ remote.toString);
		auto target = parsed.get;
		if (!target.peer.isNull)
		{
			enforce(expected.isNull || expected.get == target.peer.get, "webrtc: address names another peer");
			expected = target.peer;
		}

		// One socket for this dial, bound where the OS likes.
		auto mux = new UdpMux(this, listenUDP(0, target.ipv6 ? "::" : "0.0.0.0"), false);
		scope (failure)
			mux.close();

		immutable ufrag = randomUfrag();
		auto creds = Credentials(ufrag, ufrag);
		auto localAddr = TransportAddr(mux.localIp(target.ipv6), mux.localPort);
		auto conn = new Connection(Perspective.dialer, cert, localAddr, creds, uniform!ulong());
		auto remoteAddr = TransportAddr(target.host, target.port);
		conn.addLocalCandidate(host(mux.localIp(target.ipv6), mux.localPort, target.ipv6));
		conn.setRemoteCredentials(creds);
		conn.addRemoteCandidate(host(target.host, target.port, target.ipv6));
		// Pin the server's certificate to the certhash in the address (fail-closed).
		conn.setExpectedFingerprint(target.fingerprint.digest);
		applyStunServers(conn); // gather our srflx out this dial's socket



		auto session = new Session(this, mux, conn, remoteAddr);
		mux.add(remoteAddr, session);
		scope (failure)
			session.close();
		session.kick();
		withTimeout(cfg.connectTimeout, "webrtc connect", { session.waitReady(); });

		// The pinned server certificate (verified during the DTLS handshake).
		auto serverFp = Fingerprint.raw(conn.peerFingerprint());

		// Noise, on the negotiated channel: we are the WebRTC client, so the responder.
		auto noiseStream = session.noiseStream();
		scope (exit)
			noiseStream.close();
		auto peer = withTimeout(cfg.connectTimeout, "webrtc noise",
			() => outbound(identity, noiseStream, serverFp, fingerprint()));
		enforce(expected.isNull || expected.get == peer, "webrtc: the peer is " ~ peer.toString ~ ", not " ~ expected.get.toString);

		UpgradedConn up;
		up.muxer = session;
		up.remotePeer = peer;
		peer.tryPublicKey(up.remoteKey);
		up.localAddr = mux.localMultiaddr(target.ipv6);
		up.remoteAddr = Multiaddr(remote.bytes.dup);
		return up;
	}

	// --- hole punch ------------------------------------------------------------------------

	/// A direct connection to a two-NAT peer, punched to its reflexive
	/// webrtc-direct address (`peerSrflx`) over the very socket our own reflexive
	/// address was gathered on — so the NAT mapping the peer aims at is the one we
	/// send from. Called by DCUtR on both sides at once; the roles are asymmetric
	/// where they must be and symmetric where they must be:
	///
	///  - ICE is symmetric — both ends send connectivity checks to open both
	///    holes — which needs a shared ufrag up front, since neither can wait to
	///    learn the other's from a first packet. Both derive `punchUfrag` from the
	///    two peer ids, so they agree without any exchange.
	///  - DTLS is asymmetric — exactly one client and one server. `asDialer`
	///    carries the split (true = DTLS client, false = DTLS server), assigned
	///    from the DCUtR initiator/responder roles. Noise follows DTLS: the DTLS
	///    client is the Noise responder, the server the initiator.
	UpgradedConn punch(const Multiaddr peerSrflx, PeerId remote, bool asDialer, Nullable!PeerId expected)
	{
		// A gathered srflx means reflexiveAddr() bound punchSock and STUN answered:
		// the socket is live and the peer has our reflexive address to aim at.
		enforce(punchAddr.bytes.length > 0, "webrtc: no gathered reflexive address to punch from (call reflexiveAddr first)");
		auto parsed = parseWebRTCDialAddr(Multiaddr(peerSrflx.bytes.dup));
		enforce(!parsed.isNull, "webrtc: peer's punch address is not webrtc-direct: " ~ peerSrflx.toString);
		auto target = parsed.get;
		immutable dialer = asDialer;
		immutable persp = dialer ? Perspective.dialer : Perspective.listener;

		// One socket, one reader: eventcore allows a single read-notification
		// callback per socket, so two muxes reading punchSock at once abort the
		// process ("Overwriting notification callback"). So punchSock has ONE
		// persistent mux that every punch shares, each adding a session keyed by
		// the peer's address; the mux's single reader demuxes to them. This lets a
		// long-lived peer be punched by many others, one after another or at once,
		// without a second reader — a per-punch mux would either crash (concurrent)
		// or, guarded, leave the socket claimed until the first connection died
		// (so only the first peer could ever punch).
		// a STUN gather still reading punchSock must finish first (one reader per socket)
		if (gathering)
			waitGathered();
		enforce(!gathering, "webrtc: the reflexive gather is still reading the punch socket");
		if (punchMux is null || punchMux.closed)
			punchMux = new UdpMux(this, punchSock, false, true);
		auto mux = punchMux;

		// One ufrag both sides compute alike, doubling as the ICE password.
		immutable ufrag = punchUfrag(PeerId.fromPublicKey(identity.publicKey).bytes, remote.bytes);
		auto creds = Credentials(ufrag, ufrag);
		immutable ipv6 = target.ipv6;
		auto localAddr = TransportAddr(mux.localIp(ipv6), mux.localPort);
		auto conn = new Connection(persp, cert, localAddr, creds, uniform!ulong());
		conn.addLocalCandidate(host(mux.localIp(ipv6), mux.localPort, ipv6));
		conn.setRemoteCredentials(creds);
		conn.addRemoteCandidate(host(target.host, target.port, ipv6));
		// The DTLS client pins the server's certificate to the certhash in the
		// peer's address; the server proves its identity over Noise, so it pins
		// nothing (mirrors dial vs. the listener's admit path).
		if (dialer)
			conn.setExpectedFingerprint(target.fingerprint.digest);

		auto remoteAddr = TransportAddr(target.host, target.port);
		auto session = new Session(this, mux, conn, remoteAddr);
		mux.add(remoteAddr, session);
		scope (failure)
			session.close();
		session.kick();
		withTimeout(cfg.connectTimeout, "webrtc punch", { session.waitReady(); });

		auto peerFp = Fingerprint.raw(conn.peerFingerprint());
		auto noiseStream = withTimeout(cfg.connectTimeout, "webrtc punch noise channel",
			() => session.noiseStream());
		scope (exit)
			noiseStream.close();
		auto peer = withTimeout(cfg.connectTimeout, "webrtc punch noise",
			() => dialer ? outbound(identity, noiseStream, peerFp, fingerprint())
				: inbound(identity, noiseStream, peerFp, fingerprint()));
		enforce(expected.isNull || expected.get == peer,
			"webrtc: the peer is " ~ peer.toString ~ ", not " ~ expected.get.toString);

		UpgradedConn up;
		up.muxer = session;
		up.remotePeer = peer;
		peer.tryPublicKey(up.remoteKey);
		up.localAddr = punchAddr.bytes.length ? punchAddr : mux.localMultiaddr(ipv6);
		up.remoteAddr = Multiaddr(peerSrflx.bytes.dup);
		return up;
	}

	// --- listening ---------------------------------------------------------------------------

	Multiaddr listen(const Multiaddr local, void delegate(UpgradedConn) onInbound)
	{
		auto c = Multiaddr(local.bytes.dup).components;
		enforce(c.length >= 3 && (c[0].name == "ip4" || c[0].name == "ip6") && c[1].name == "udp"
			&& c[2].name == "webrtc-direct", "webrtc: listen wants /ip/udp/webrtc-direct");
		immutable ipv6 = c[0].name == "ip6";
		immutable port = cast(ushort)((c[1].value[0] << 8) | c[1].value[1]);
		auto mux = new UdpMux(this, listenUDP(port, c[0].text), true);
		mux.onInbound = onInbound;
		muxes ~= mux;
		return mux.localMultiaddr(ipv6, c[0].text) ~ Multiaddr.parse("/webrtc-direct/certhash/"
				~ multibaseEncode(fingerprint().toMultihash.encode));
	}

	void close() nothrow
	{
		closed = true;
		if (warmTask != Task.init && warmTask.running)
		{
			try
				warmTask.interrupt();
			catch (Exception)
			{
			}
			warmTask.joinUninterruptible();
		}
		foreach (m; muxes)
			m.close();
		muxes = null;
		if (punchMux !is null)
			punchMux.close(); // the persistent punch mux isn't in muxes (it closes punchSock)
		else if (punchSock != UDPConnection.init)
			try
				punchSock.close(); // gathered on, never punched from: still a descriptor
			catch (Exception)
			{
			}
	}

	/// The listener's half of a new connection: the peer proved its identity
	/// over Noise, with our certificate and theirs in the prologue.
	private void admit(UdpMux mux, Session session)
	{
		// The inbound slot charged in readLoop is released here — after the peer
		// authenticates or on any failure — via this flag, so it is given back
		// once and no later than authentication (the hand-off below runs arbitrary
		// notifiees and may block; the slot must not be held across it).
		bool slotReleased;
		scope (exit)
			if (!slotReleased)
			{
				slotReleased = true;
				mux.releaseInbound();
			}
		scope (failure)
			session.close();
		withTimeout(cfg.connectTimeout, "webrtc connect", { session.waitReady(); });
		auto clientFp = Fingerprint.raw(session.conn.peerFingerprint());
		auto noiseStream = withTimeout(cfg.connectTimeout, "webrtc noise channel", () => session.noiseStream());
		scope (exit)
			noiseStream.close();
		auto peer = withTimeout(cfg.connectTimeout, "webrtc noise",
			() => inbound(identity, noiseStream, clientFp, fingerprint()));
		// Authenticated: give the inbound slot back before handing the connection
		// to the swarm, so a slow notifiee cannot hold an admission slot.
		slotReleased = true;
		mux.releaseInbound();

		UpgradedConn up;
		up.muxer = session;
		up.remotePeer = peer;
		peer.tryPublicKey(up.remoteKey);
		up.localAddr = mux.localMultiaddr(session.remote.ip.canFind(':'));
		up.remoteAddr = Multiaddr.parse("/" ~ (session.remote.ip.canFind(':') ? "ip6" : "ip4") ~ "/" ~ session.remote.ip
				~ "/udp/" ~ session.remote.port.to!string ~ "/webrtc-direct/certhash/"
				~ multibaseEncode(clientFp.toMultihash.encode));
		mux.onInbound(up);
	}
}

private Candidate host(string ip, ushort port, bool ipv6)
{
	Candidate c;
	c.typ = CandidateType.host;
	c.address = ip;
	c.port = port;
	c.ipv6 = ipv6;
	return c;
}

private long nowMs()
{
	return (MonoTime.currTime - MonoTime.zero).total!"msecs";
}

/// Bounds inbound handshakes in flight on a listening socket. A STUN packet
/// from a stranger starts a whole connection (an engine, a ticker fiber,
/// DTLS/SCTP state); the cap keeps a sender rotating its source port from
/// making unbounded numbers of them. A slot is charged when a handshake starts
/// and released the moment it authenticates or fails. A cap of 0 is unlimited.
struct InboundLimiter
{
	private uint cap;
	private uint inFlight_;

	this(uint cap) @safe pure nothrow @nogc
	{
		this.cap = cap;
	}

	/// Charge a slot if one is free; false means we are at the ceiling.
	bool tryAcquire() @safe pure nothrow @nogc
	{
		if (cap != 0 && inFlight_ >= cap)
			return false;
		inFlight_++;
		return true;
	}

	void release() @safe pure nothrow @nogc
	{
		if (inFlight_ > 0)
			inFlight_--;
	}

	uint inFlight() const @safe pure nothrow @nogc
	{
		return inFlight_;
	}
}

/// One UDP socket, many remotes.
private final class UdpMux
{
	private WebRtcTransport transport;
	private UDPConnection sock;
	private bool listening;
	private bool persistent; // keep the mux alive when its last session leaves (the punch mux)
	private Session[TransportAddr] sessions;
	private InboundLimiter admission; // caps unauthenticated inbound handshakes
	private FiberGroup fibers;
	private bool closed;
	void delegate(UpgradedConn) onInbound;

	this(WebRtcTransport transport, UDPConnection sock, bool listening, bool persistent = false)
	{
		this.transport = transport;
		this.sock = sock;
		this.listening = listening;
		this.persistent = persistent;
		admission = InboundLimiter(transport.cfg.maxPendingInbound);
		fibers = new FiberGroup((Exception e) nothrow { logDebug("libp2p: webrtc inbound not admitted: %s", e.msg); });
		fibers.spawn(&readLoop);
	}

	// Release an inbound handshake's slot. Called by admit() the moment the peer
	// authenticates or the handshake fails.
	private void releaseInbound() nothrow
	{
		admission.release();
	}

	ushort localPort()
	{
		return sock.localAddress.port;
	}

	string localIp(bool ipv6)
	{
		auto s = sock.localAddress.toAddressString;
		if (s == "0.0.0.0" || s == "::")
			return ipv6 ? "::1" : "127.0.0.1"; // a bound-anywhere socket, named for the one host we test on
		return s;
	}

	Multiaddr localMultiaddr(bool ipv6, string ip = null)
	{
		return Multiaddr.parse("/" ~ (ipv6 ? "ip6" : "ip4") ~ "/" ~ (ip !is null ? ip : localIp(ipv6)) ~ "/udp/"
				~ localPort.to!string);
	}

	void add(TransportAddr remote, Session s)
	{
		sessions[remote] = s;
	}

	void remove(TransportAddr remote) nothrow
	{
		sessions.remove(remote);
		// A persistent mux (the shared punch socket) outlives its sessions so the
		// next peer can punch; only a one-shot dial mux closes when it empties.
		if (!listening && !persistent && sessions.length == 0)
			close();
	}

	void send(OutboundDatagram d)
	{
		if (closed)
			return;
		// UDP is best-effort: one datagram to an unreachable destination (a STUN
		// server we can't route to from a loopback-bound socket, say) must never
		// throw out of the batch drain and starve the rest — the connectivity
		// checks and the srflx probe travel in the same gatherOutbound batch.
		try
		{
			auto to = resolveHost(d.dst.ip, AddressFamily.UNSPEC, false);
			to.port = d.dst.port;
			sock.send(d.data, &to);
		}
		catch (Exception)
		{
		}
	}

	void close() nothrow
	{
		if (closed)
			return;
		closed = true;
		// If this is the mux holding the punch socket, release the guard and drop
		// the gather state: closing takes punchSock down with it, so the next
		// punch must re-gather a fresh socket (as the failure path also does).
		if (transport.punchMux is this)
		{
			transport.punchMux = null;
			transport.punchGathered = false;
			transport.punchAddr = Multiaddr.init;
		}
		fibers.stopAll();
		foreach (s; sessions.values)
			s.close();
		sessions = null;
		try
			sock.close();
		catch (Exception)
		{
		}
	}

	private void readLoop()
	{
		auto buf = new ubyte[65_536];
		for (;;)
		{
			NetworkAddress from;
			auto pkt = sock.recv(buf, &from);
			auto remote = TransportAddr(from.toAddressString, from.port);
			auto s = remote in sessions;
			if (s is null)
			{
				if (!listening || !isStunMessage(pkt))
					continue; // not for anyone we know
				if (!admission.tryAcquire())
					continue; // at the ceiling: shed; the peer's STUN retransmit retries later
				Session session;
				try
				{
					session = openInbound(pkt, remote);
					if (session is null)
					{
						admission.release();
						continue;
					}
					sessions[remote] = session;
					fibers.spawn({ transport.admit(this, session); });
				}
				catch (InterruptException e)
				{
					admission.release(); // the mux is stopping; give the slot back and unwind
					throw e;
				}
				catch (Exception)
				{
					// Building the connection or starting its fiber threw after the
					// slot was charged: release it and drop this one inbound rather
					// than let a single bad packet kill the reader.
					admission.release();
					if (session !is null)
					{
						sessions.remove(remote);
						session.close();
					}
					continue;
				}
				s = remote in sessions;
			}
			(*s).onDatagram(pkt.dup, remote);
		}
	}

	/// A STUN request from a stranger carries `ufrag:ufrag` as its username:
	/// that is the whole handshake webrtc-direct needs to start ICE.
	private Session openInbound(const(ubyte)[] pkt, TransportAddr remote)
	{
		string ufrag;
		try
		{
			auto msg = StunMessage.decode(pkt);
			auto user = cast(const(char)[]) msg.get(attrUsername);
			immutable colon = user.countUntil(':');
			if (colon <= 0)
				return null;
			ufrag = user[0 .. colon].idup;
		}
		catch (Exception)
			return null;
		auto creds = Credentials(ufrag, ufrag);
		immutable ipv6 = remote.ip.canFind(':');
		auto localAddr = TransportAddr(localIp(ipv6), localPort);
		auto conn = new Connection(Perspective.listener, transport.cert, localAddr, creds, uniform!ulong());
		conn.addLocalCandidate(host(localIp(ipv6), localPort, ipv6));
		conn.setRemoteCredentials(creds);
		conn.addRemoteCandidate(host(remote.ip, remote.port, ipv6));
		transport.applyStunServers(conn); // gather our srflx out this socket
		// The listener does not pin: the client's identity is proven over Noise.
		auto session = new Session(transport, this, conn, remote);
		session.kick();
		return session;
	}
}

/// One peer connection: the engine, its ticker, and its channels as streams.
private final class Session : Muxer
{
	private WebRtcTransport transport;
	private UdpMux mux;
	Connection conn;
	TransportAddr remote;
	private FiberGroup fibers;
	private LocalManualEvent changed;
	private DcStream[ushort] streams;
	private ushort[] accepted;
	private bool closed_;
	private Exception cause;

	this(WebRtcTransport transport, UdpMux mux, Connection conn, TransportAddr remote)
	{
		this.transport = transport;
		this.mux = mux;
		this.conn = conn;
		this.remote = remote;
		changed = createManualEvent();
		fibers = new FiberGroup;
		fibers.spawn(&ticker);
	}

	/// Drive the engine's timers, and the wire, until told to stop.
	private void ticker()
	{
		for (;;)
		{
			sleep(transport.cfg.tick);
			if (closed_)
				return;
			conn.handleTimeout(nowMs());
			pump();
		}
	}

	/// Push whatever the engine wants to send, and notice what it delivered.
	void kick()
	{
		pump();
	}

	private void pump()
	{
		foreach (d; conn.gatherOutbound(nowMs()))
			mux.send(d);
		deliver();
	}

	private void deliver()
	{
		// Not yet connected (or failed): waitReady's timeout wrapper handles it.
		if (conn.state != ConnState.connected)
		{
			changed.emit();
			return;
		}
		foreach (e; conn.poll())
		{
			final switch (e.kind)
			{
			case ChannelEventKind.opened:
				ensureStream(e.channel);
				// A channel the PEER opened (remote) — not our own confirmed open, and
				// not the negotiated Noise channel 0 — is an inbound libp2p stream
				// awaiting accept().
				if (e.remote && e.channel != noiseChannel && !accepted.canFind(e.channel))
					accepted ~= e.channel;
				break;
			case ChannelEventKind.message:
				ensureStream(e.channel);
				streams[e.channel].inbound ~= e.data;
				break;
			case ChannelEventKind.closed:
				if (auto s = e.channel in streams)
					(*s).ended(new ConnClosed("webrtc: channel reset by peer"));
				break;
			}
		}
		changed.emit();
	}

	private void ensureStream(ushort sid)
	{
		if (sid !in streams)
			streams[sid] = new DcStream(this, sid);
	}

	void onDatagram(ubyte[] data, TransportAddr from)
	{
		if (closed_)
			return;
		conn.handleInbound(data, from, nowMs());
		pump();
	}

	// A failed engine (bad certhash, ICE or DTLS failure) is surfaced as a thrown
	// error, not left to look like a slow connection until the dial's timeout.
	private void throwIfFailed()
	{
		if (conn.state == ConnState.failed)
			throw new ConnClosed("webrtc: " ~ conn.failureReason());
	}

	void waitReady()
	{
		auto seen = changed.emitCount;
		while (conn.state != ConnState.connected)
		{
			if (closed_)
				throw cause;
			throwIfFailed();
			seen = changed.wait(transport.cfg.tick, seen);
		}
	}

	/// The negotiated channel (id 0) libp2p runs Noise over; open on connect.
	Stream noiseStream()
	{
		waitReady();
		ensureStream(noiseChannel);
		return new WebRtcStream(streams[noiseChannel]);
	}

	// --- Muxer -------------------------------------------------------------------------------

	Stream open()
	{
		if (closed_)
			throw cause;
		waitReady();
		immutable sid = conn.channels().open("", "");
		pump();
		auto seen = changed.emitCount;
		while (!conn.channels().isOpen(sid))
		{
			if (closed_)
				throw cause;
			throwIfFailed();
			seen = changed.wait(transport.cfg.tick, seen);
		}
		throwIfFailed(); // the channel opened, but the connection may have failed since
		ensureStream(sid);
		return new WebRtcStream(streams[sid]);
	}

	Stream accept()
	{
		auto seen = changed.emitCount;
		while (accepted.length == 0)
		{
			if (closed_)
				throw cause;
			throwIfFailed();
			seen = changed.wait(seen);
		}
		throwIfFailed(); // a channel was accepted, but the connection may have failed since
		immutable sid = accepted[0];
		accepted = accepted[1 .. $];
		ensureStream(sid);
		return new WebRtcStream(streams[sid]);
	}

	void close() nothrow
	{
		if (closed_)
			return;
		// Tell the peer we are leaving (SCTP shutdown, then DTLS close_notify) and
		// push it out, so the far end tears the connection down promptly instead of
		// waiting for a timeout. Best-effort — the socket may already be gone.
		try
		{
			conn.closeNow();
			pump(); // flush the close_notify
		}
		catch (Exception)
		{
		}
		closed_ = true;
		cause = new ConnClosed("webrtc: connection closed");
		// .byValue, not the AA directly: a plain foreach over an associative array
		// lowers to _aaApply, which isn't nothrow in some druntimes (LDC 1.41), and
		// this method is nothrow. byValue iterates without it.
		foreach (s; streams.byValue)
			s.ended(cause);
		changed.emit();
		fibers.stopAll();
		mux.remove(remote);
	}

	bool isClosed() nothrow
	{
		return closed_;
	}

	private void send(ushort sid, const(ubyte)[] data)
	{
		if (closed_)
			throw cause;
		// A full SCTP send buffer means "wait", not "fail": Stream.write blocks as needed.
		// Room is made as the peer acknowledges: the reader fiber feeds each SACK in,
		// pumps (which hands queued DATA to the wire) and emits `changed`; the ticker
		// drives the retransmission timers. The writer only waits. It must not pump
		// here: pump() emits `changed` itself, and a wait on a count taken before that
		// emit returns at once without yielding — the writer would spin, starve the
		// reader and the ticker, and no SACK (nor ICE consent) would ever be read.
		while (!conn.channels().canSend(data.length))
		{
			if (closed_)
				throw cause;
			throwIfFailed();
			changed.wait(transport.cfg.tick, changed.emitCount);
		}
		conn.channels().send(sid, data, false);
		pump();
	}
}

/// A data channel as a byte stream: what the framing sits on.
private final class DcStream : Stream
{
	private Session session;
	private ushort sid;
	ubyte[] inbound;
	private Exception cause;
	private bool closed;

	this(Session session, ushort sid)
	{
		this.session = session;
		this.sid = sid;
	}

	size_t read(ubyte[] buf)
	{
		if (buf.length == 0)
			return 0;
		auto seen = session.changed.emitCount;
		while (inbound.length == 0)
		{
			if (cause !is null)
				throw cause;
			if (closed)
				throw new ConnClosed("webrtc: channel closed locally");
			// A read during the Noise phase (before the swarm owns the session)
			// must notice the engine failing, or it waits out the whole timeout.
			session.throwIfFailed();
			seen = session.changed.wait(seen);
		}
		immutable n = min(buf.length, inbound.length);
		buf[0 .. n] = inbound[0 .. n];
		inbound = inbound[n .. $];
		return n;
	}

	void write(const(ubyte)[] data)
	{
		if (cause !is null)
			throw cause;
		if (closed)
			throw new ConnClosed("webrtc: channel closed locally");
		session.send(sid, data);
	}

	void close() nothrow
	{
		closed = true; // SCTP stream reset is d-webrtc's to add; the FIN above us did the protocol's part
	}

	void reset() nothrow
	{
		closed = true;
	}

	private void ended(Exception why) nothrow
	{
		cause = why;
	}
}
