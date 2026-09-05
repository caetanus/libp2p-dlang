/**
 * mDNS peer discovery (`_p2p._udp.local`), and the DNS message codec it needs.
 *
 * Every node listens on 224.0.0.251:5353. A query asks for PTR records of the
 * service; a response names an instance and carries one TXT record per address
 * in the form `dnsaddr=<multiaddr>/p2p/<peer>`. A node that hears a response
 * learns a peer and where to dial it; a node that hears a query answers with
 * its own addresses.
 */
module libp2p.discovery.mdns;

import core.time : Duration, seconds, minutes, msecs;
import std.algorithm.searching : canFind, startsWith;
import std.exception : enforce;
import std.random : uniform;
import std.string : split, join, toLower;

import vibe.core.core : sleep;
import vibe.core.log : logDebug;
import vibe.core.net;
import std.socket : AddressFamily;
import vibe.core.task : InterruptException;

import libp2p.core.peer_id : PeerId;
import libp2p.host.host;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.util.fibers : FiberGroup;

enum serviceName = "_p2p._udp.local";
enum mdnsGroup = "224.0.0.251";
enum ushort mdnsPort = 5353;

enum ushort typeA = 1;
enum ushort typePtr = 12;
enum ushort typeTxt = 16;
enum ushort typeAaaa = 28;
enum ushort classIn = 1;

// --- the codec ------------------------------------------------------------------------

struct DnsQuestion
{
	string name;
	ushort qtype;
	ushort qclass;
}

struct DnsRecord
{
	string name;
	ushort rtype;
	ushort rclass;
	uint ttl;
	string target; /// PTR / CNAME: the name pointed to
	string[] txts; /// TXT: the strings
	ubyte[] raw; /// anything else: the rdata as is
}

struct DnsMessage
{
	ushort id;
	ushort flags;
	DnsQuestion[] questions;
	DnsRecord[] answers; /// answer, authority and additional sections together
}

ubyte[] encodeMessage(DnsMessage m)
{
	ubyte[] out_;
	put16(out_, m.id);
	put16(out_, m.flags);
	put16(out_, cast(ushort) m.questions.length);
	put16(out_, cast(ushort) m.answers.length);
	put16(out_, 0);
	put16(out_, 0);
	foreach (q; m.questions)
	{
		putName(out_, q.name);
		put16(out_, q.qtype);
		put16(out_, q.qclass);
	}
	foreach (r; m.answers)
	{
		putName(out_, r.name);
		put16(out_, r.rtype);
		put16(out_, r.rclass);
		put32(out_, r.ttl);
		ubyte[] rdata;
		switch (r.rtype)
		{
		case typePtr:
			putName(rdata, r.target);
			break;
		case typeTxt:
			foreach (t; r.txts)
			{
				enforce(t.length < 256, "dns: TXT string too long");
				rdata ~= cast(ubyte) t.length;
				rdata ~= cast(const(ubyte)[]) t;
			}
			break;
		default:
			rdata = r.raw.dup;
		}
		put16(out_, cast(ushort) rdata.length);
		out_ ~= rdata;
	}
	return out_;
}

DnsMessage decodeMessage(const(ubyte)[] msg)
{
	enforce(msg.length >= 12, "dns: message too short");
	DnsMessage m;
	size_t pos;
	m.id = get16(msg, pos);
	m.flags = get16(msg, pos);
	immutable qd = get16(msg, pos);
	immutable an = get16(msg, pos);
	immutable ns = get16(msg, pos);
	immutable ar = get16(msg, pos);
	foreach (_; 0 .. qd)
	{
		DnsQuestion q;
		q.name = readName(msg, pos);
		q.qtype = get16(msg, pos);
		q.qclass = get16(msg, pos);
		m.questions ~= q;
	}
	foreach (_; 0 .. cast(size_t) an + ns + ar)
	{
		DnsRecord r;
		r.name = readName(msg, pos);
		r.rtype = get16(msg, pos);
		r.rclass = get16(msg, pos);
		r.ttl = get32(msg, pos);
		immutable len = get16(msg, pos);
		enforce(pos + len <= msg.length, "dns: truncated record");
		auto rdata = msg[pos .. pos + len];
		switch (r.rtype)
		{
		case typePtr:
			{
				size_t p = pos;
				r.target = readName(msg, p);
				break;
			}
		case typeTxt:
			{
				size_t p;
				while (p < rdata.length)
				{
					immutable l = rdata[p++];
					enforce(p + l <= rdata.length, "dns: truncated TXT");
					r.txts ~= (cast(const(char)[]) rdata[p .. p + l]).idup;
					p += l;
				}
				break;
			}
		default:
			r.raw = rdata.dup;
		}
		pos += len;
		m.answers ~= r;
	}
	return m;
}

/// A domain name at `pos`, following compression pointers; `pos` advances past
/// the name as written (two bytes for a pointer), not to the jump target.
string readName(const(ubyte)[] msg, ref size_t pos)
{
	string[] labels;
	size_t p = pos;
	bool jumped;
	size_t hops;
	for (;;)
	{
		enforce(p < msg.length, "dns: truncated name");
		immutable len = msg[p];
		if (len == 0)
		{
			p++;
			break;
		}
		if ((len & 0xc0) == 0xc0)
		{
			enforce(p + 1 < msg.length, "dns: truncated pointer");
			immutable target = ((len & 0x3f) << 8) | msg[p + 1];
			if (!jumped)
				pos = p + 2;
			jumped = true;
			enforce(++hops < 64, "dns: pointer loop");
			p = target;
			continue;
		}
		enforce(p + 1 + len <= msg.length, "dns: truncated label");
		labels ~= (cast(const(char)[]) msg[p + 1 .. p + 1 + len]).idup;
		p += 1 + len;
	}
	if (!jumped)
		pos = p;
	return labels.join(".");
}

private void putName(ref ubyte[] out_, string name)
{
	foreach (label; name.split('.'))
	{
		if (label.length == 0)
			continue;
		enforce(label.length < 64, "dns: label too long");
		out_ ~= cast(ubyte) label.length;
		out_ ~= cast(const(ubyte)[]) label;
	}
	out_ ~= 0;
}

private void put16(ref ubyte[] out_, ushort v)
{
	out_ ~= cast(ubyte)(v >> 8);
	out_ ~= cast(ubyte)(v & 0xff);
}

private void put32(ref ubyte[] out_, uint v)
{
	foreach (i; 0 .. 4)
		out_ ~= cast(ubyte)(v >> (8 * (3 - i)));
}

private ushort get16(const(ubyte)[] msg, ref size_t pos)
{
	enforce(pos + 2 <= msg.length, "dns: truncated");
	immutable v = cast(ushort)((msg[pos] << 8) | msg[pos + 1]);
	pos += 2;
	return v;
}

private uint get32(const(ubyte)[] msg, ref size_t pos)
{
	enforce(pos + 4 <= msg.length, "dns: truncated");
	uint v;
	foreach (i; 0 .. 4)
		v = (v << 8) | msg[pos + i];
	pos += 4;
	return v;
}

// --- what libp2p puts in the records --------------------------------------------------------

/// `dnsaddr=<addr>/p2p/<peer>` for each address.
string[] dnsaddrStrings(PeerId peer, const(Multiaddr)[] addrs)
{
	string[] out_;
	foreach (a; addrs)
	{
		auto full = Multiaddr(a.bytes.dup);
		if (!full.components.canFind!(c => c.name == "p2p"))
			full = full ~ Multiaddr.parse("/p2p/" ~ peer.toBase58);
		out_ ~= "dnsaddr=" ~ full.toString;
	}
	return out_;
}

struct DiscoveredPeer
{
	PeerId id;
	Multiaddr[] addrs;
}

/// The peers a response names, other than ourselves.
DiscoveredPeer[] peersFromMessage(DnsMessage m, PeerId self)
{
	DiscoveredPeer[] out_;
	foreach (r; m.answers)
	{
		if (r.rtype != typeTxt)
			continue;
		foreach (t; r.txts)
		{
			if (!t.startsWith("dnsaddr="))
				continue;
			Multiaddr addr;
			try
				addr = Multiaddr.parse(t["dnsaddr=".length .. $]);
			catch (Exception)
				continue;
			auto comps = addr.components;
			if (comps.length == 0 || comps[$ - 1].name != "p2p")
				continue;
			PeerId who;
			try
				who = PeerId.fromBytes(comps[$ - 1].value);
			catch (Exception)
				continue;
			if (who == self)
				continue;
			bool placed;
			foreach (ref p; out_)
				if (p.id == who)
				{
					if (!p.addrs.canFind(addr))
						p.addrs ~= addr;
					placed = true;
				}
			if (!placed)
				out_ ~= DiscoveredPeer(who, [addr]);
		}
	}
	return out_;
}

// --- the service -----------------------------------------------------------------------------

struct MdnsConfig
{
	Duration queryInterval = 5.minutes;
	uint ttl = 6 * 60; /// seconds, on our records
	string bindAddress = "0.0.0.0";
	/// Where to send. The multicast group, unless a test wants something else.
	string group = mdnsGroup;
}

final class Mdns
{
	private Host host;
	private MdnsConfig cfg;
	private UDPConnection sock;
	private NetworkAddress groupAddr;
	private string instance;
	private FiberGroup fibers;

	/// A peer heard on the network, with the addresses it advertised.
	void delegate(PeerId peer, Multiaddr[] addrs) onPeerFound;

	this(Host host, MdnsConfig cfg = MdnsConfig.init)
	{
		this.host = host;
		this.cfg = cfg;
		sock = listenUDP(mdnsPort, cfg.bindAddress, UDPListenOptions.reuseAddress | UDPListenOptions.reusePort);
		groupAddr = resolveHost(cfg.group, AddressFamily.INET, false);
		groupAddr.port = mdnsPort;
		try
			sock.addMembership(groupAddr);
		catch (Exception e)
			logDebug("libp2p: mdns could not join the multicast group: %s", e.msg);
		instance = randomLabel() ~ "." ~ serviceName;
		fibers = new FiberGroup((Exception e) nothrow { logDebug("libp2p: mdns: %s", e.msg); });
		fibers.spawn(&receiveLoop);
		fibers.spawn(&queryLoop);
	}

	void close() nothrow
	{
		fibers.stopAll();
		try
			sock.close();
		catch (Exception)
		{
		}
	}

	/// Ask now, rather than at the next interval.
	void query()
	{
		DnsMessage q;
		q.questions ~= DnsQuestion(serviceName, typePtr, classIn);
		sock.send(encodeMessage(q), &groupAddr);
	}

	private void queryLoop()
	{
		for (;;)
		{
			query();
			sleep(cfg.queryInterval);
		}
	}

	private void receiveLoop()
	{
		auto buf = new ubyte[9000];
		for (;;)
		{
			NetworkAddress from;
			auto pkt = sock.recv(buf, &from);
			DnsMessage m;
			try
				m = decodeMessage(pkt);
			catch (Exception)
				continue; // not DNS we can read; the network is full of those
			if ((m.flags & 0x8000) == 0)
				answer(m);
			else
				learn(m);
		}
	}

	private void answer(DnsMessage q)
	{
		if (!q.questions.canFind!(x => x.name.toLower == serviceName && (x.qtype == typePtr || x.qtype == 255)))
			return;
		auto addrs = host.addrs;
		if (addrs.length == 0)
			return;
		DnsMessage r;
		r.flags = 0x8400;
		r.answers ~= DnsRecord(serviceName, typePtr, classIn, cfg.ttl, instance);
		DnsRecord txt;
		txt.name = instance;
		txt.rtype = typeTxt;
		txt.rclass = classIn;
		txt.ttl = cfg.ttl;
		txt.txts = dnsaddrStrings(host.id, addrs);
		r.answers ~= txt;
		sock.send(encodeMessage(r), &groupAddr);
	}

	private void learn(DnsMessage m)
	{
		foreach (p; peersFromMessage(m, host.id))
		{
			host.peerstore.addAddrs(p.id, p.addrs);
			if (onPeerFound !is null)
				onPeerFound(p.id, p.addrs);
		}
	}

	private static string randomLabel()
	{
		enum alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
		char[] s = new char[16];
		foreach (ref c; s)
			c = alphabet[uniform(0, alphabet.length)];
		return s.idup;
	}
}
