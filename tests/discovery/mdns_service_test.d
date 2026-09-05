/**
 * mDNS between two hosts on this machine: one asks, the other answers with its
 * addresses, and the asker can dial what it heard. Both bind 5353 with port
 * reuse and join the group, the way every mDNS responder on a host does.
 */
module tests.discovery.mdns_service_test;

import core.time : msecs, seconds, MonoTime;
import vibe.core.core : sleep;

import fluent.asserts;

import libp2p.core.peer_id : PeerId;
import libp2p.discovery.mdns;
import libp2p.host.host;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.protocol.ping;
import tests.util.loop;

@("mdns: a peer found over multicast is dialable")
unittest
{
	bool found, dialed;
	PeerId heard, expected;
	onLoop({
		auto b = Host.create();
		scope (exit)
			b.close();
		b.listen(Multiaddr.parse("/ip4/127.0.0.1/tcp/0"));
		new Ping(b);
		MdnsConfig cfg;
		cfg.queryInterval = 200.msecs;
		auto bm = new Mdns(b, cfg);
		scope (exit)
			bm.close();

		auto a = Host.create();
		scope (exit)
			a.close();
		a.listen(Multiaddr.parse("/ip4/127.0.0.1/tcp/0"));
		auto am = new Mdns(a, cfg);
		scope (exit)
			am.close();
		expected = b.id;
		am.onPeerFound = (PeerId p, Multiaddr[] addrs) {
			if (p == b.id)
			{
				heard = p;
				found = true;
			}
		};

		immutable deadline = MonoTime.currTime + 5.seconds;
		while (!found && MonoTime.currTime < deadline)
			sleep(20.msecs);
		if (found)
		{
			auto s = a.newStream(b.id, pingProtocol); // through the peerstore mdns filled
			scope (exit)
				s.close();
			ping(s);
			dialed = true;
		}
	});
	found.should.equal(true);
	heard.should.equal(expected);
	dialed.should.equal(true);
}
