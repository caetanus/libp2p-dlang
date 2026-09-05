/**
 * webrtc-direct between two hosts on loopback: the listener advertises an
 * address carrying its certificate hash, the dialer reaches it with nothing
 * else, ICE, DTLS and SCTP come up, Noise proves both identities, and ping runs
 * on a data channel like on any other connection.
 */
module tests.transport.webrtc.e2e_test;

import core.time : Duration, msecs, seconds, MonoTime;
import std.algorithm.searching : canFind;
import vibe.core.core : sleep;

import fluent.asserts;

import libp2p.core.peer_id : PeerId;
import libp2p.crypto.keys : Keypair;
import libp2p.host.host;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.protocol.ping;
import libp2p.transport.tcp : TcpTransport;
import libp2p.transport.webrtc.transport;
import tests.util.loop;

private struct Node
{
	Host host;
	WebRtcTransport rtc;
}

private Node makeNode()
{
	auto key = Keypair.generateEd25519;
	auto h = new Host(key, [new TcpTransport]);
	auto rtc = new WebRtcTransport(key);
	h.swarm.addCapableTransport(rtc);
	return Node(h, rtc);
}

@("webrtc-direct: a listener's address carries its certhash, and a dialer reaches it")
unittest
{
	Multiaddr advertised;
	bool dialed, listenerSeesDialer, viaWebrtc;
	Duration rtt = Duration.min;
	PeerId got, expected;
	onLoop({
		auto b = makeNode();
		scope (exit)
			b.host.close();
		b.host.listen(Multiaddr.parse("/ip4/127.0.0.1/udp/0/webrtc-direct"));
		new Ping(b.host);
		advertised = b.host.addrs[0];
		expected = b.host.id;

		auto a = makeNode();
		scope (exit)
			a.host.close();

		auto c = a.host.connect(b.host.id, [advertised]);
		dialed = true;
		got = c.remotePeer;
		viaWebrtc = c.remoteAddr.toString.canFind("/webrtc-direct/");

		immutable deadline = MonoTime.currTime + 5.seconds;
		while (!b.host.swarm.isConnected(a.host.id) && MonoTime.currTime < deadline)
			sleep(10.msecs);
		listenerSeesDialer = b.host.swarm.isConnected(a.host.id);

		auto s = c.newStream(pingProtocol);
		scope (exit)
			s.close();
		rtt = ping(s);
	});
	advertised.toString.should.contain("/udp/");
	advertised.toString.should.contain("/webrtc-direct/certhash/u");
	dialed.should.equal(true);
	got.should.equal(expected);
	viaWebrtc.should.equal(true);
	listenerSeesDialer.should.equal(true);
	(rtt >= Duration.zero).should.equal(true);
}

@("webrtc-direct: a dialer that is told the wrong certhash is refused")
unittest
{
	bool refused;
	string why;
	onLoop({
		auto b = makeNode();
		scope (exit)
			b.host.close();
		b.host.listen(Multiaddr.parse("/ip4/127.0.0.1/udp/0/webrtc-direct"));
		auto real_ = b.host.addrs[0].toString;
		// Somebody else's certificate hash, at the right place.
		auto other = new WebRtcTransport(Keypair.generateEd25519);
		import libp2p.multiformats.multibase : multibaseEncode;

		auto forged = Multiaddr.parse(real_[0 .. real_.lastIndexOf("/certhash/")] ~ "/certhash/"
				~ multibaseEncode(other.fingerprint.toMultihash.encode));

		auto a = makeNode();
		scope (exit)
			a.host.close();
		try
			a.host.connect(b.host.id, [forged]);
		catch (Exception e)
		{
			refused = true;
			why = e.msg;
		}
	});
	refused.should.equal(true);
	why.should.contain("certificate");
}

import std.string : lastIndexOf;
