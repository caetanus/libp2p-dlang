/**
 * c-ares driven from a fiber, against a nameserver we run ourselves on
 * loopback, so nothing here depends on the world agreeing. The fake server
 * speaks with the same DNS codec mDNS uses.
 */
module tests.transport.dns_cares_test;

import core.time : msecs, seconds;
import std.algorithm.searching : canFind;
import std.conv : to;

import vibe.core.net;

import fluent.asserts;

import libp2p.discovery.mdns : DnsMessage, DnsRecord, decodeMessage, encodeMessage, typeTxt, typeA, classIn;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.transport.dns : resolve, dnsaddrPrefix;
import libp2p.transport.dns_cares : CaresDns;
import tests.util.loop;

/// A nameserver from a table: TXT and A records by name, NXDOMAIN otherwise.
private final class FakeServer
{
	string[][string] txt;
	string[string] a;
	string[] asked;
	private UDPConnection sock;
	private Side task;
	ushort port;

	this()
	{
		sock = listenUDP(0, "127.0.0.1");
		port = sock.localAddress.port;
		task = spawn(&serve);
	}

	void close()
	{
		task.interrupt();
		sock.close();
	}

	private void serve()
	{
		auto buf = new ubyte[4096];
		for (;;)
		{
			NetworkAddress from;
			auto pkt = sock.recv(buf, &from);
			auto q = decodeMessage(pkt);
			DnsMessage r;
			r.id = q.id;
			r.flags = 0x8180; // response, recursion available
			r.questions = q.questions;
			foreach (question; q.questions)
			{
				asked ~= question.name;
				if (question.qtype == typeTxt)
					foreach (t; txt.get(question.name, null))
					{
						DnsRecord rec;
						rec.name = question.name;
						rec.rtype = typeTxt;
						rec.rclass = classIn;
						rec.ttl = 60;
						rec.txts = [t];
						r.answers ~= rec;
					}
				else if (question.qtype == typeA)
					if (auto ip = question.name in a)
					{
						DnsRecord rec;
						rec.name = question.name;
						rec.rtype = typeA;
						rec.rclass = classIn;
						rec.ttl = 60;
						foreach (part; (*ip).split('.'))
							rec.raw ~= part.to!ubyte;
						r.answers ~= rec;
					}
			}
			if (r.answers.length == 0)
				r.flags |= 3; // NXDOMAIN
			sock.send(encodeMessage(r), &from);
		}
	}
}

import std.string : split;

@("c-ares: an A lookup against our own nameserver answers, and the loop stays free")
unittest
{
	string[] got;
	bool loopWasFree;
	onLoop({
		auto server = new FakeServer;
		scope (exit)
			server.close();
		server.a["node.test"] = "10.1.2.3";
		auto dns = new CaresDns("127.0.0.1:" ~ server.port.to!string);

		// Something else on the loop, to show the lookup did not block it.
		auto ticker = spawn({
			import vibe.core.core : sleep;

			sleep(1.msecs);
			loopWasFree = true;
		});
		got = dns.lookupA("node.test");
		ticker.join();
	});
	got.should.equal(["10.1.2.3"]);
	loopWasFree.should.equal(true);
}

@("c-ares: a name the server does not know yields nothing, and does not throw")
unittest
{
	string[] got = ["x"];
	onLoop({
		auto server = new FakeServer;
		scope (exit)
			server.close();
		auto dns = new CaresDns("127.0.0.1:" ~ server.port.to!string);
		got = dns.lookupA("nowhere.test");
	});
	got.length.should.equal(0);
}

@("c-ares: TXT records come back whole, and /dnsaddr expands through them")
unittest
{
	string[] txts;
	Multiaddr[] expanded;
	string[] asked;
	onLoop({
		auto server = new FakeServer;
		scope (exit)
			server.close();
		server.txt[dnsaddrPrefix ~ "boot.test"] = [
			"dnsaddr=/ip4/1.2.3.4/tcp/4001",
			"dnsaddr=/dns4/node.test/tcp/4001",
			"v=spf1 -all",
		];
		server.a["node.test"] = "9.9.9.9";
		auto dns = new CaresDns("127.0.0.1:" ~ server.port.to!string);
		txts = dns.lookupTxt(dnsaddrPrefix ~ "boot.test");
		expanded = resolve(Multiaddr.parse("/dnsaddr/boot.test"), dns);
		asked = server.asked;
	});
	txts.length.should.equal(3);
	txts.should.contain("dnsaddr=/ip4/1.2.3.4/tcp/4001");
	expanded.length.should.equal(2);
	expanded[0].toString.should.equal("/ip4/1.2.3.4/tcp/4001");
	expanded[1].toString.should.equal("/ip4/9.9.9.9/tcp/4001");
	asked.should.contain(dnsaddrPrefix ~ "boot.test");
	asked.should.contain("node.test");
}
