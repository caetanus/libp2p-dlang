module tests.transport.dns_test;

import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.transport.dns : DnsResolver, resolve, needsResolution, maxTxtRecords,
	maxDnsLookups, dnsaddrPrefix;
import fluent.asserts;

/// Answers from a table, so the test does not depend on the world agreeing.
private final class FakeDns : DnsResolver
{
	string[][string] a, aaaa, txt;
	string[] askedTxt;

	string[] lookupA(string h)
	{
		return a.get(h, null);
	}

	string[] lookupAaaa(string h)
	{
		return aaaa.get(h, null);
	}

	string[] lookupTxt(string h)
	{
		askedTxt ~= h;
		return txt.get(h, null);
	}
}

@("dns: an address with no name is returned unchanged")
unittest
{
	auto dns = new FakeDns;
	auto addr = Multiaddr.parse("/ip4/127.0.0.1/tcp/4001");
	auto got = resolve(addr, dns);
	needsResolution(addr).should.equal(false);
	got.length.should.equal(1);
	got[0].toString().should.equal("/ip4/127.0.0.1/tcp/4001");
}

// The port and everything else around the name has to survive: resolution
// replaces one component, it does not rebuild the address from the host.
@("dns: /dns4 keeps the rest of the address around the name")
unittest
{
	auto dns = new FakeDns;
	dns.a["example.org"] = ["10.0.0.1", "10.0.0.2"];
	auto addr = Multiaddr.parse("/dns4/example.org/tcp/4001");
	needsResolution(addr).should.equal(true);

	auto got = resolve(addr, dns);
	got.length.should.equal(2);
	got[0].toString().should.equal("/ip4/10.0.0.1/tcp/4001");
	got[1].toString().should.equal("/ip4/10.0.0.2/tcp/4001");
}

// The three name forms differ in which family they accept, and a /dns4 that
// resolved to an AAAA record would produce an address nothing can dial.
@("dns: /dns4, /dns6 and /dns select different families")
unittest
{
	auto dns = new FakeDns;
	dns.a["h"] = ["10.0.0.1"];
	dns.aaaa["h"] = ["::1"];

	resolve(Multiaddr.parse("/dns4/h/tcp/1"), dns)[0].toString()
		.should.equal("/ip4/10.0.0.1/tcp/1");
	resolve(Multiaddr.parse("/dns6/h/tcp/1"), dns)[0].toString()
		.should.equal("/ip6/::1/tcp/1");
	resolve(Multiaddr.parse("/dns/h/tcp/1"), dns).length.should.equal(2);
}

@("dns: a name that does not resolve yields nothing, and does not throw")
unittest
{
	auto dns = new FakeDns;
	resolve(Multiaddr.parse("/dns4/nowhere/tcp/1"), dns).length.should.equal(0);
}

// /dnsaddr is a TXT lookup of a prefixed name, and each record is a whole
// address rather than an IP — which is how one name offers several transports.
@("dns: /dnsaddr expands TXT records into whole addresses")
unittest
{
	auto dns = new FakeDns;
	dns.txt[dnsaddrPrefix ~ "boot.example"] = [
		"dnsaddr=/ip4/1.2.3.4/tcp/4001",
		"dnsaddr=/ip4/1.2.3.4/udp/4001/quic-v1",
		"v=spf1 -all", // not ours; must be ignored rather than parsed
	];

	auto got = resolve(Multiaddr.parse("/dnsaddr/boot.example"), dns);
	dns.askedTxt.should.equal([dnsaddrPrefix ~ "boot.example"]);
	got.length.should.equal(2);
	got[0].toString().should.equal("/ip4/1.2.3.4/tcp/4001");
	got[1].toString().should.equal("/ip4/1.2.3.4/udp/4001/quic-v1");
}

// `/dnsaddr/x/p2p/Qm…` asks for the addresses of x *belonging to that peer*, so
// a record for somebody else is not an answer to the question.
@("dns: /dnsaddr records are filtered by what follows the name")
unittest
{
	enum mine = "/p2p/QmaGdzz8AKTxf3291Cm391TDhaukS3p9AoBVxF3VuifTZN";
	enum theirs = "/p2p/QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N";

	auto dns = new FakeDns;
	dns.txt[dnsaddrPrefix ~ "boot"] = [
		"dnsaddr=/ip4/1.1.1.1/tcp/4001" ~ mine,
		"dnsaddr=/ip4/2.2.2.2/tcp/4001" ~ theirs,
	];

	auto got = resolve(Multiaddr.parse("/dnsaddr/boot" ~ mine), dns);
	got.length.should.equal(1);
	got[0].toString().should.equal("/ip4/1.1.1.1/tcp/4001" ~ mine);
}

// The zone is controlled by somebody else, so the ceiling has to be ours.
@("dns: a /dnsaddr expansion is capped")
unittest
{
	auto dns = new FakeDns;
	string[] many;
	foreach (i; 0 .. maxTxtRecords + 20)
		many ~= "dnsaddr=/ip4/10.0.0.1/tcp/" ~ (cast(uint)(1000 + i)).stringOf;
	dns.txt[dnsaddrPrefix ~ "flood"] = many;

	resolve(Multiaddr.parse("/dnsaddr/flood"), dns).length.should.equal(maxTxtRecords);
}

private string stringOf(uint n)
{
	import std.conv : to;

	return n.to!string;
}

// The real bootstrap zone is two levels deep: /dnsaddr/bootstrap.libp2p.io
// returns four more /dnsaddr names, and only those carry addresses. A one-level
// expansion hands back records nothing can dial, which is what the live check
// against the actual zone found.
@("dns: a /dnsaddr naming another /dnsaddr is followed")
unittest
{
	auto dns = new FakeDns;
	dns.txt[dnsaddrPrefix ~ "boot"] = [
		"dnsaddr=/dnsaddr/eu.boot",
		"dnsaddr=/dnsaddr/us.boot",
	];
	dns.txt[dnsaddrPrefix ~ "eu.boot"] = ["dnsaddr=/ip4/1.1.1.1/tcp/4001"];
	dns.txt[dnsaddrPrefix ~ "us.boot"] = [
		"dnsaddr=/ip4/2.2.2.2/tcp/4001",
		"dnsaddr=/ip4/2.2.2.2/udp/4001/quic-v1",
	];

	auto got = resolve(Multiaddr.parse("/dnsaddr/boot"), dns);
	got.length.should.equal(3);
	got[0].toString().should.equal("/ip4/1.1.1.1/tcp/4001");
	got[1].toString().should.equal("/ip4/2.2.2.2/tcp/4001");
	got[2].toString().should.equal("/ip4/2.2.2.2/udp/4001/quic-v1");
}

// A name inside a name still ends in an IP, so /dns4 under /dnsaddr resolves.
@("dns: a /dnsaddr record containing a hostname is resolved too")
unittest
{
	auto dns = new FakeDns;
	dns.txt[dnsaddrPrefix ~ "boot"] = ["dnsaddr=/dns4/node.example/tcp/4001"];
	dns.a["node.example"] = ["9.9.9.9"];

	auto got = resolve(Multiaddr.parse("/dnsaddr/boot"), dns);
	got.length.should.equal(1);
	got[0].toString().should.equal("/ip4/9.9.9.9/tcp/4001");
}

// The zone belongs to someone else, so a name that names itself must terminate
// on our budget rather than on our stack.
@("dns: a self-referential zone terminates")
unittest
{
	auto dns = new FakeDns;
	dns.txt[dnsaddrPrefix ~ "loop"] = ["dnsaddr=/dnsaddr/loop"];

	// The assertion is that this returns at all.
	resolve(Multiaddr.parse("/dnsaddr/loop"), dns).length.should.equal(0);
	(dns.askedTxt.length <= maxDnsLookups).should.equal(true);
}

// --- transport selection ----------------------------------------------------

// The address is what picks the transport, and `/ws` differs from plain TCP by
// one component. The parser this replaced ignored components it did not know, so
// `/ip4/…/tcp/…/ws` was dialled as raw TCP: right host, right port, wrong
// protocol, and a handshake that failed for a reason the address did not show.
@("transports: tcp refuses addresses that belong to another transport")
unittest
{
	import libp2p.crypto.keys : Keypair;
	import libp2p.host : Host;
	import libp2p.transport.tcp_transport : TcpTransport;

	auto host = new Host(Keypair.generateEd25519);
	scope (exit)
		host.close();
	auto tcp = new TcpTransport(host.upgrader);

	tcp.canDial(Multiaddr.parse("/ip4/127.0.0.1/tcp/4001")).should.equal(true);
	// The canonical full form names who is there; it is still a TCP address.
	tcp.canDial(Multiaddr.parse(
			"/ip4/127.0.0.1/tcp/4001/p2p/QmaGdzz8AKTxf3291Cm391TDhaukS3p9AoBVxF3VuifTZN"))
		.should.equal(true);

	// These are somebody else's.
	tcp.canDial(Multiaddr.parse("/ip4/127.0.0.1/tcp/4001/ws")).should.equal(false);
	tcp.canDial(Multiaddr.parse("/ip4/127.0.0.1/udp/4001/quic-v1")).should.equal(false);
	tcp.canDial(Multiaddr.parse("/dns4/example.org/tcp/4001")).should.equal(false);
	tcp.canDial(Multiaddr.parse("/ip4/127.0.0.1")).should.equal(false);
}
