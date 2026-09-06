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

import vibe.core.core : sleep;
import vibe.core.log : logDebug;
import vibe.core.net;
import vibe.core.sync : LocalManualEvent, createManualEvent;

import webrtc.connection.connection : Connection, Perspective, OutboundDatagram, ConnState, noiseChannel;
import webrtc.datachannel.channels : ChannelEvent, ChannelEventKind;
import webrtc.dtls.certificate : Certificate;
import webrtc.ice.agent : Credentials, TransportAddr;
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
import libp2p.swarm.swarm : CapableTransport, UpgradedConn;
import libp2p.transport.webrtc.fingerprint;
import libp2p.transport.webrtc.noise;
import libp2p.transport.webrtc.sdp : randomUfrag;
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
}

final class WebRtcTransport : CapableTransport
{
	private Keypair identity;
	private Certificate cert;
	private WebRtcConfig cfg;
	private UdpMux[] muxes;

	this(Keypair identity, WebRtcConfig cfg = WebRtcConfig.init)
	{
		this.identity = identity;
		this.cfg = cfg;
		cert = new Certificate;
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
		foreach (m; muxes)
			m.close();
		muxes = null;
	}

	/// The listener's half of a new connection: the peer proved its identity
	/// over Noise, with our certificate and theirs in the prologue.
	private void admit(UdpMux mux, Session session)
	{
		scope (failure)
			session.close();
		withTimeout(cfg.connectTimeout, "webrtc connect", { session.waitReady(); });
		auto clientFp = Fingerprint.raw(session.conn.peerFingerprint());
		auto noiseStream = withTimeout(cfg.connectTimeout, "webrtc noise channel", () => session.noiseStream());
		scope (exit)
			noiseStream.close();
		auto peer = withTimeout(cfg.connectTimeout, "webrtc noise",
			() => inbound(identity, noiseStream, clientFp, fingerprint()));

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

/// One UDP socket, many remotes.
private final class UdpMux
{
	private WebRtcTransport transport;
	private UDPConnection sock;
	private bool listening;
	private Session[TransportAddr] sessions;
	private FiberGroup fibers;
	private bool closed;
	void delegate(UpgradedConn) onInbound;

	this(WebRtcTransport transport, UDPConnection sock, bool listening)
	{
		this.transport = transport;
		this.sock = sock;
		this.listening = listening;
		fibers = new FiberGroup((Exception e) nothrow { logDebug("libp2p: webrtc inbound not admitted: %s", e.msg); });
		fibers.spawn(&readLoop);
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
		if (!listening && sessions.length == 0)
			close();
	}

	void send(OutboundDatagram d)
	{
		if (closed)
			return;
		auto to = resolveHost(d.dst.ip, AddressFamily.UNSPEC, false);
		to.port = d.dst.port;
		sock.send(d.data, &to);
	}

	void close() nothrow
	{
		if (closed)
			return;
		closed = true;
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
				auto session = openInbound(pkt, remote);
				if (session is null)
					continue;
				sessions[remote] = session;
				fibers.spawn({ transport.admit(this, session); });
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

	void waitReady()
	{
		auto seen = changed.emitCount;
		while (conn.state != ConnState.connected)
		{
			if (closed_)
				throw cause;
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
			seen = changed.wait(transport.cfg.tick, seen);
		}
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
			seen = changed.wait(seen);
		}
		immutable sid = accepted[0];
		accepted = accepted[1 .. $];
		ensureStream(sid);
		return new WebRtcStream(streams[sid]);
	}

	void close() nothrow
	{
		if (closed_)
			return;
		closed_ = true;
		cause = new ConnClosed("webrtc: connection closed");
		foreach (s; streams)
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
