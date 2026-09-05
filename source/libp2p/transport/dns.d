/**
 * Names in multiaddrs. `/dns4`, `/dns6` and `/dns` name a host whose A or AAAA
 * records replace the component; `/dnsaddr` names a TXT zone whose records are
 * whole addresses, possibly more names, followed on a budget we control since
 * the zone belongs to somebody else.
 *
 * The resolver is an interface so that tests answer from a table; the real one
 * is c-ares, in `dns_cares.d`.
 */
module libp2p.transport.dns;

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
