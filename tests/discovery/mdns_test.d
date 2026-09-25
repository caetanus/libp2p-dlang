module tests.discovery.mdns_test;

import libp2p.crypto.keys : Keypair;
import libp2p.core.peer_id : PeerId;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.discovery.mdns;
import libp2p.swarm.connection : Connection;
import fluent.asserts;

@("mDNS query round-trips through the DNS codec")
unittest
{
	DnsMessage m;
	m.questions ~= DnsQuestion(serviceName, typePtr, classIn);

	auto back = decodeMessage(encodeMessage(m));

	back.questions.length.should.equal(1);
	back.questions[0].name.should.equal(serviceName);
	back.questions[0].qtype.should.equal(typePtr);
	back.questions[0].qclass.should.equal(classIn);
	back.answers.length.should.equal(0);
}

@("mDNS response advertises and recovers a peer's addresses")
unittest
{
	auto other = PeerId.fromPublicKey(Keypair.generateEd25519().publicKey);
	auto self = PeerId.fromPublicKey(Keypair.generateEd25519().publicKey);
	auto addr = Multiaddr.parse("/ip4/192.168.1.5/udp/4001/quic-v1");

	// Build the response `other` would multicast.
	DnsMessage m;
	m.flags = 0x8400;
	immutable instance = "abcd._p2p._udp.local";
	m.answers ~= DnsRecord(serviceName, typePtr, classIn, 120, instance);
	DnsRecord txt;
	txt.name = instance;
	txt.rtype = typeTxt;
	txt.rclass = classIn;
	txt.ttl = 120;
	txt.txts = dnsaddrStrings(other, [addr]);
	m.answers ~= txt;

	auto decoded = decodeMessage(encodeMessage(m));
	auto peers = peersFromMessage(decoded, self);

	peers.length.should.equal(1);
	peers[0].id.should.equal(other);
	peers[0].addrs.length.should.equal(1);
	peers[0].addrs[0].toString().should.equal(
		(addr ~ Multiaddr.parse("/p2p/" ~ other.toBase58)).toString());
}

@("mDNS peersFromMessage skips our own advertisement")
unittest
{
	auto self = PeerId.fromPublicKey(Keypair.generateEd25519().publicKey);
	auto addr = Multiaddr.parse("/ip4/10.0.0.1/udp/4001/quic-v1");

	DnsMessage m;
	m.flags = 0x8400;
	DnsRecord txt;
	txt.name = "x._p2p._udp.local";
	txt.rtype = typeTxt;
	txt.rclass = classIn;
	txt.txts = dnsaddrStrings(self, [addr]);
	m.answers ~= txt;

	peersFromMessage(decodeMessage(encodeMessage(m)), self).length.should.equal(0);
}

@("mDNS readName follows a compression pointer")
unittest
{
	// offset 0: label "a" then terminator; offset 3: a pointer back to offset 0.
	ubyte[] msg = [0x01, 'a', 0x00, 0xc0, 0x00];
	size_t pos = 3;
	readName(msg, pos).should.equal("a");
	pos.should.equal(5); // advanced past the 2-byte pointer, not the jump target
}

// Two beacons of one service on this host, each aimed at the other's socket
// (the multicast group is a broadcast of the same exchange): the browser's
// query is answered with the announcer's TXT strings, and the browser learns
// them together with the address the answer came from.
@("mDNS beacon: a browser finds the announcer of a shared-secret service")
unittest
{
	import vibe.core.core : sleep;
	import vibe.core.net : NetworkAddress, resolveHost;
	import core.time : msecs, MonoTime, seconds, hours;
	import tests.util.loop : onLoop;

	string[] got;
	string fromHost;
	onLoop({
		immutable service = mdnsServiceFor("pw", cast(const(ubyte)[]) "the pairing token");
		MdnsBeaconConfig cfg;
		cfg.bindAddress = "127.0.0.1";
		cfg.bindPort = 0;
		cfg.group = "127.0.0.1";
		cfg.queryInterval = 1.hours;
		auto announcer = new MdnsBeacon(service, () => ["port=41521", "pk=abcd"], cfg);
		scope (exit)
			announcer.close();
		auto browser = new MdnsBeacon(service, null, cfg);
		scope (exit)
			browser.close();
		auto toA = resolveHost("127.0.0.1"); toA.port = announcer.localPort;
		auto toB = resolveHost("127.0.0.1"); toB.port = browser.localPort;
		browser.setTarget(toA);
		announcer.setTarget(toB);
		browser.onFound = (NetworkAddress from, string[] txts) nothrow {
			got = txts;
			try fromHost = from.toAddressString; catch (Exception) {}
		};
		browser.query();
		immutable deadline = MonoTime.currTime + 3.seconds;
		while (got.length == 0 && MonoTime.currTime < deadline)
			sleep(10.msecs);
	});
	got.should.equal(["port=41521", "pk=abcd"]);
	fromHost.should.equal("127.0.0.1");
	mdnsServiceFor("pw", cast(const(ubyte)[]) "x").should.not.equal(mdnsServiceFor("pw", cast(const(ubyte)[]) "y"));
}

// Two hosts that share a secret, on this box: the announcer listens on TCP, the
// browser hears the answer (id + port) and dials the address the answer came
// from — a real connection, authenticated as the announcer, no DHT anywhere.
@("mDNS rendezvous: a host reaches the announcer of its secret directly")
unittest
{
	import vibe.core.core : sleep;
	import vibe.core.net : resolveHost;
	import core.time : msecs, MonoTime, seconds, hours;
	import libp2p.host.host : Host;
	import libp2p.core.peer_id : PeerId;
	import tests.util.loop : onLoop;

	PeerId reached, expected;
	string via;
	onLoop({
		auto a = Host.create();
		scope (exit)
			a.close();
		a.listen(Multiaddr.parse("/ip4/127.0.0.1/tcp/0"));
		auto b = Host.create();
		scope (exit)
			b.close();
		expected = a.id;
		MdnsBeaconConfig bc;
		bc.bindAddress = "127.0.0.1";
		bc.bindPort = 0;
		bc.group = "127.0.0.1";
		bc.queryInterval = 1.hours;
		immutable label = mdnsServiceFor("pw", cast(const(ubyte)[]) "secret");
		auto lanA = new LanRendezvous(label, bc), lanB = new LanRendezvous(label, bc);
		scope (exit)
		{
			lanA.close();
			lanB.close();
		}
		MdnsRendezvousConfig cfg;
		auto ra = new MdnsRendezvous(a, lanA, cfg);
		cfg.announce = false;
		auto rb = new MdnsRendezvous(b, lanB, cfg);
		// the hyperswarm flavor's lines ride the same record; a libp2p browser ignores them
		lanA.addTxtSource(() => ["udx=4601", "pk=00"]);
		auto toA = resolveHost("127.0.0.1"); toA.port = lanA.underlyingBeacon.localPort;
		auto toB = resolveHost("127.0.0.1"); toB.port = lanB.underlyingBeacon.localPort;
		lanB.underlyingBeacon.setTarget(toA);
		lanA.underlyingBeacon.setTarget(toB);
		rb.onConnected = (PeerId p, Connection c) nothrow { reached = p; try via = c.remoteAddr.toString; catch (Exception) {} };
		rb.query();
		immutable deadline = MonoTime.currTime + 5.seconds;
		while (reached == PeerId.init && MonoTime.currTime < deadline)
			sleep(20.msecs);
	});
	(reached == expected).should.equal(true);
	via.should.contain("/ip4/127.0.0.1/tcp/");
	MdnsRendezvous.txtsFor(Host.create()).length.should.equal(1); // id only, no listener yet
	LanRendezvous.line(["id=x", "udx=4601"], "udx").should.equal("4601");
	LanRendezvous.line(["id=x"], "udx").should.equal(null);
}

@("mdns rendezvous: a webrtc-direct listener is announced with its certhash and dialed back from it")
unittest
{
	import libp2p.core.peer_id : PeerId;
	import libp2p.host.host : Host;
	import std.socket : InternetAddress;
	import vibe.core.net : NetworkAddress;

	auto h = Host.create();
	immutable id = h.id.toBase58;
	immutable hash = "uEiD5E0rkIhz1P9ldayh2A_zgw50UJme9JU1kNfDMyh6kRg";
	auto from = NetworkAddress(new InternetAddress("192.168.0.60", 5353));
	PeerId who;
	auto addrs = MdnsRendezvous.addrsFrom(from, ["id=" ~ id, "tcp=43169", "webrtc=43170/" ~ hash],
		PeerId.init, who);
	string[] texts;
	foreach (a; addrs)
		texts ~= a.toString;
	texts.should.contain("/ip4/192.168.0.60/udp/43170/webrtc-direct/certhash/" ~ hash ~ "/p2p/" ~ id);
	texts.should.contain("/ip4/192.168.0.60/tcp/43169/p2p/" ~ id);
	// malformed lines are skipped, never fatal
	MdnsRendezvous.addrsFrom(from, ["id=" ~ id, "webrtc=43170", "webrtc=/x"], PeerId.init, who).length.should.equal(0);
}
