/**
 * Names in multiaddrs. `/dns4`, `/dns6` and `/dns` name a host whose A or AAAA
 * records replace the component; `/dnsaddr` names a TXT zone whose records are
 * whole addresses, possibly more names, followed on a budget we control since
 * the zone belongs to somebody else.
 *
 * The resolver is an interface so that tests answer from a table; the real one
 * asks the system for A/AAAA and the configured nameserver, over UDP, for TXT.
 */
module libp2p.transport.dns;

import core.time : seconds;
import std.algorithm.searching : startsWith, canFind, countUntil;
import std.exception : enforce;
import std.string : split, strip;

import libp2p.multiformats.multiaddr : Multiaddr, Component;

enum size_t maxTxtRecords = 16;
enum size_t maxDnsLookups = 32;
enum dnsaddrPrefix = "_dnsaddr.";

interface DnsResolver
{
	string[] lookupA(string host);
	string[] lookupAaaa(string host);
	string[] lookupTxt(string host);
}

bool needsResolution(const Multiaddr addr)
{
	foreach (c; Multiaddr(addr.bytes.dup).components)
		if (c.name == "dns" || c.name == "dns4" || c.name == "dns6" || c.name == "dnsaddr")
			return true;
	return false;
}

/// Every dialable address `addr` stands for. Unresolvable names yield nothing.
Multiaddr[] resolve(Multiaddr addr, DnsResolver dns)
{
	size_t lookups;
	return resolveInner(addr, dns, lookups);
}

private Multiaddr[] resolveInner(Multiaddr addr, DnsResolver dns, ref size_t lookups)
{
	auto comps = addr.components;
	if (comps.length == 0)
		return [addr];
	auto head = comps[0];
	auto rest = tail(comps, 1);

	switch (head.name)
	{
	case "dns4":
	case "dns6":
	case "dns":
		{
			if (lookups >= maxDnsLookups)
				return null;
			lookups++;
			Multiaddr[] out_;
			if (head.name != "dns6")
				foreach (ip; dns.lookupA(head.text))
					out_ ~= Multiaddr.parse("/ip4/" ~ ip) ~ rest;
			if (head.name != "dns4")
				foreach (ip; dns.lookupAaaa(head.text))
					out_ ~= Multiaddr.parse("/ip6/" ~ ip) ~ rest;
			return out_;
		}
	case "dnsaddr":
		{
			if (lookups >= maxDnsLookups)
				return null;
			lookups++;
			Multiaddr[] out_;
			size_t taken;
			foreach (txt; dns.lookupTxt(dnsaddrPrefix ~ head.text))
			{
				if (!txt.startsWith("dnsaddr="))
					continue;
				if (taken >= maxTxtRecords)
					break;
				Multiaddr record;
				try
					record = Multiaddr.parse(txt["dnsaddr=".length .. $].strip);
				catch (Exception)
					continue;
				// `/dnsaddr/x/p2p/Qm..` asks for x's addresses belonging to that peer.
				if (rest.bytes.length > 0 && !endsWith(record, rest))
					continue;
				taken++;
				if (needsResolution(record))
					out_ ~= resolveInner(record, dns, lookups);
				else
					out_ ~= record;
			}
			return out_;
		}
	default:
		return [addr];
	}
}

private Multiaddr tail(Component[] comps, size_t from)
{
	Multiaddr out_;
	foreach (c; comps[from .. $])
		out_ = out_ ~ Multiaddr.parse("/" ~ c.name ~ (c.protocol.size != 0 ? "/" ~ c.text : ""));
	return out_;
}

private bool endsWith(Multiaddr addr, Multiaddr suffix)
{
	return addr.bytes.length >= suffix.bytes.length && addr.bytes[$ - suffix.bytes.length .. $] == suffix.bytes;
}

/// The system's answers: getaddrinfo for A and AAAA, the first nameserver in
/// /etc/resolv.conf over UDP for TXT.
final class SystemDns : DnsResolver
{
	import vibe.core.net;
	import std.socket : AddressFamily;
	import libp2p.discovery.mdns : DnsMessage, DnsQuestion, encodeMessage, decodeMessage, typeTxt, classIn;

	private string nameserver;

	this(string nameserver = null)
	{
		this.nameserver = nameserver !is null ? nameserver : firstNameserver();
	}

	string[] lookupA(string host)
	{
		try
			return [resolveHost(host, AddressFamily.INET, true).toAddressString];
		catch (Exception)
			return null;
	}

	string[] lookupAaaa(string host)
	{
		try
			return [resolveHost(host, AddressFamily.INET6, true).toAddressString];
		catch (Exception)
			return null;
	}

	string[] lookupTxt(string host)
	{
		if (nameserver is null)
			return null;
		try
		{
			auto server = resolveHost(nameserver, AddressFamily.UNSPEC, false);
			server.port = 53;
			auto sock = listenUDP(0);
			scope (exit)
				sock.close();
			DnsMessage q;
			q.id = 0x1234;
			q.flags = 0x0100; // recursion desired
			q.questions ~= DnsQuestion(host, typeTxt, classIn);
			sock.send(encodeMessage(q), &server);
			auto buf = new ubyte[4096];
			auto reply = decodeMessage(sock.recv(3.seconds, buf));
			string[] out_;
			foreach (r; reply.answers)
				if (r.rtype == typeTxt)
					foreach (t; r.txts)
						out_ ~= t;
			return out_;
		}
		catch (Exception)
			return null;
	}

	private static string firstNameserver()
	{
		import std.file : exists, readText;

		if (!exists("/etc/resolv.conf"))
			return null;
		foreach (line; readText("/etc/resolv.conf").split('\n'))
		{
			auto parts = line.strip.split;
			if (parts.length >= 2 && parts[0] == "nameserver")
				return parts[1];
		}
		return null;
	}
}
