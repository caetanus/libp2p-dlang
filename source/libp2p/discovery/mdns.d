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

import core.time : Duration, MonoTime, seconds, minutes, msecs;
import std.algorithm.searching : canFind, startsWith;
import std.exception : enforce;
import std.random : uniform;
import std.string : split, join, toLower;
import std.conv : to;

import vibe.core.core : sleep, runTask;
import vibe.core.log : logDebug, logInfo;
import vibe.core.net;
import std.socket : AddressFamily;
import vibe.core.task : InterruptException, Task;

import libp2p.core.peer_id : PeerId;
import libp2p.host.host;
import libp2p.swarm.connection : Connection;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.util.fibers : FiberGroup;

enum serviceName = "_p2p._udp.local";
enum mdnsGroup = "224.0.0.251";
enum ushort mdnsPort = 5353;

enum ushort typeA = 1;
enum ushort typePtr = 12;
enum ushort typeTxt = 16;
enum ushort typeAaaa = 28;
enum ushort typeSrv = 33;
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
		joinEverywhere(sock, groupAddr, "mdns");
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

// --- the host's interfaces -------------------------------------------------------------------

/// One IPv4 interface that is up and can multicast (loopback excluded).
struct Ipv4Interface
{
	string name;
	string ip;
	uint index;
}

/// IPv4 interfaces up, multicast-capable, not loopback. A socket bound to 0.0.0.0
/// that joins the mDNS group with INADDR_ANY joins it on the default-route
/// interface ONLY; a query arriving on any other (a VM bridge, docker, a VPN) is
/// never delivered. Multi-homed mDNS joins the group on every interface.
/// `all`: every UP IPv4 interface, multicast-capable or not (a WireGuard tun has
/// no multicast flag but its coming and going IS a network change).
Ipv4Interface[] ipv4Interfaces(bool all = false)
{
	import core.sys.linux.ifaddrs : ifaddrs, getifaddrs, freeifaddrs;
	import core.sys.posix.net.if_ : if_nametoindex;
	enum IFF_UP = 0x1, IFF_LOOPBACK = 0x8, IFF_MULTICAST = 0x1000; // <net/if.h>, Linux and bionic alike
	import core.sys.posix.netinet.in_ : sockaddr_in;
	import core.sys.posix.arpa.inet : inet_ntop, INET_ADDRSTRLEN;
	import core.sys.posix.sys.socket : AF_INET;
	import std.string : fromStringz;

	Ipv4Interface[] out_;
	ifaddrs* list;
	if (getifaddrs(&list) != 0)
		return out_;
	scope (exit)
		freeifaddrs(list);
	for (auto p = list; p !is null; p = p.ifa_next)
	{
		if (p.ifa_addr is null || p.ifa_addr.sa_family != AF_INET)
			continue;
		if (!(p.ifa_flags & IFF_UP) || (p.ifa_flags & IFF_LOOPBACK) || (!all && !(p.ifa_flags & IFF_MULTICAST)))
			continue;
		char[INET_ADDRSTRLEN] buf;
		auto sin = cast(sockaddr_in*) p.ifa_addr;
		if (inet_ntop(AF_INET, &sin.sin_addr, buf.ptr, buf.length) is null)
			continue;
		immutable name = p.ifa_name.fromStringz.idup;
		out_ ~= Ipv4Interface(name, buf.ptr.fromStringz.idup, if_nametoindex(p.ifa_name));
	}
	return out_;
}

/// What eventcore's joinMulticastGroup wants as "interface_index" for IPv4: it
/// stores the value into ip_mreq.imr_interface — the interface's IPv4 ADDRESS, in
/// host order — not an if_nametoindex() index (that would join "0.0.0.2" and fail
/// with EADDRNOTAVAIL). So the interface is named by its address here.
private uint ifaceKey(const Ipv4Interface i)
{
	import std.string : split;
	import std.conv : to;

	uint v;
	foreach (part; i.ip.split("."))
		v = (v << 8) | part.to!uint;
	return v;
}

// Join `group` on every IPv4 interface (index by index), falling back to the
// default interface when none is listed. Failures are logged, not fatal: mDNS is
// best effort, the DHT is the rendezvous.
private void joinEverywhere(ref UDPConnection sock, ref NetworkAddress group, string who)
{
	auto ifs = ipv4Interfaces();
	if (ifs.length == 0)
	{
		try
			sock.addMembership(group);
		catch (Exception e)
			logDebug("libp2p: %s could not join the multicast group: %s", who, e.msg);
		return;
	}
	foreach (i; ifs)
		try
			sock.addMembership(group, ifaceKey(i));
		catch (Exception e)
			logDebug("libp2p: %s could not join the multicast group on %s: %s", who, i.name, e.msg);
}

// --- a generic DNS-SD beacon: a service label on the LAN, no Host involved -----------------------

struct MdnsBeaconConfig
{
	uint ttl = 120; /// seconds, on our records
	string bindAddress = "0.0.0.0";
	ushort bindPort = mdnsPort; /// 0 = ephemeral (tests)
	string group = mdnsGroup; /// where queries and answers go
	ushort port = mdnsPort;
	Duration queryInterval = 30.seconds; /// steady cadence, once someone has answered
	Duration probeInterval = 2.seconds; /// cap while nobody has answered yet (a query is one tiny multicast)
}

/// Announce and browse ONE DNS-SD service on the local network, keyed by a label
/// the two sides derive from a shared secret (photo-wagon: the pairing token →
/// `_pw-<hash>._udp.local`), so a phone on the LAN finds the computer without any
/// address in the QR code and without a fixed DHCP lease. The answer carries the
/// responder's TXT strings (its listen port, its public key…); the responder's
/// IP is where the answer CAME FROM, which needs no interface enumeration and is
/// right by construction. Off the LAN nothing changes: the DHT is the rendezvous.
final class MdnsBeacon
{
	private MdnsBeaconConfig cfg;
	private UDPConnection sock;
	private NetworkAddress target;
	private UDPConnection[string] egress; // per interface (by ip): multicast leaves through it
	private Task[string] egressReader;    // the reader of each egress socket (unicast answers)
	private bool[string] joined; // "index@ip" -> group joined on the receive socket (an index reused for a new address rejoins)
	private MonoTime[string] recentlyFound; // "host|txts" -> when: one onFound per answer per 5 s
	private enum size_t maxRecentlyFound = 512; // bounded: evicted by age, then by size
	private string hostname; // our DNS-SD host name (<label>.local), for SRV/A
	private bool heard; // an answer since the last reset: steady cadence allowed
	private Duration wait; // current probe back-off
	private string ifaceSet; // the interfaces we last saw, to notice a change
	private string service, instance;
	private string[] delegate() txts; // null = browse only, never answer
	private FiberGroup fibers;
	private bool closed;

	/// A peer of this service answered: the address its answer came from (use the
	/// host, take the port from the TXT), and its TXT strings.
	void delegate(NetworkAddress from, string[] txts) nothrow onFound;

	/// `service` is the full name (`_pw-abcd1234._udp.local`); `txts` supplies what
	/// we announce (null: we only browse). Queries go out at once and every
	/// `cfg.queryInterval`, or on demand with query().
	this(string service, string[] delegate() txts, MdnsBeaconConfig cfg = MdnsBeaconConfig.init)
	{
		this.cfg = cfg;
		this.service = service.toLower;
		this.txts = txts;
		sock = listenUDP(cfg.bindPort, cfg.bindAddress, UDPListenOptions.reuseAddress | UDPListenOptions.reusePort);
		target = resolveHost(cfg.group, AddressFamily.INET, false);
		target.port = cfg.port;
		instance = randomLabel() ~ "." ~ this.service;
		hostname = instance.split(".")[0] ~ ".local"; // the SRV target; its A record is per interface
		fibers = new FiberGroup((Exception e) nothrow { logDebug("libp2p: mdns beacon: %s", e.msg); });
		if (cfg.group == mdnsGroup)
		{
			refreshInterfaces(); // spawns the per-interface readers: needs `fibers`
			fibers.spawn(&interfaceLoop);
		}
		fibers.spawn(&receiveLoop);
		fibers.spawn(&queryLoop);
	}

	/// The port this beacon listens on (ephemeral binds, tests).
	ushort localPort()
	{
		return sock.localAddress.port;
	}

	/// Where queries and answers are sent — the multicast group in production.
	void setTarget(NetworkAddress t)
	{
		target = t;
	}

	void close() nothrow
	{
		if (closed)
			return;
		closed = true;
		fibers.stopAll();
		try
		{
			sock.close();
			// by ref: a UDPConnection copy holds its own reference, so closing a foreach COPY
			// left the stored handle — and its socket — open until the GC ran (a beacon per
			// rebuilt rendezvous lingered). Close the stored handles, then drop them.
			foreach (ref e; egress)
				e.close();
			egress = null;
			egressReader = null; // stopAll above already interrupted and joined them
		}
		catch (Exception)
		{
		}
	}

	// A reader for one egress socket, in its own frame: spawned from refreshInterfaces'
	// loop, a closure there would share `e` with the next iteration.
	private Task spawnReader(UDPConnection sock)
	{
		auto e = sock; // a local: a parameter with a destructor cannot be captured by a closure
		return fibers.spawn({ receiveOn(e); });
	}

	/// Multi-homed: the receive socket joins the group on EVERY IPv4 interface, and
	/// each interface gets its own egress socket bound to its address, because a
	/// multicast datagram leaves through the interface that owns its source address
	/// — a query or announcement sent once would only ever reach the default-route
	/// network. Called at start and at every query interval, so an interface that
	/// appears later (a VM bridge, a VPN) is covered without a restart.
	private void refreshInterfaces()
	{
		bool fresh;
		// The network-change detector lives HERE, in the transport: every 2 s the
		// set of up IPv4 interfaces (a VPN tun included, multicast or not) is
		// compared with the last one. Any delta — a VPN or bridge coming or going,
		// Wi-Fi ↔ cellular, an address change — resets the probe back-off and asks
		// the LAN at once. The application never has to know about the network.
		string set;
		foreach (i; ipv4Interfaces(true))
			set ~= i.name ~ "=" ~ i.ip ~ ";";
		immutable changed = ifaceSet.length && set != ifaceSet;
		ifaceSet = set;
		auto now = ipv4Interfaces();
		// Reconcile, not just add: an interface (or an address) that went away takes
		// its egress socket and reader with it, and its membership entry — so an
		// index the kernel reuses for a new interface, or the same interface with a
		// new address, is joined afresh instead of being taken for already joined.
		bool[string] live;
		bool[string] liveKeys;
		foreach (i; now)
		{
			live[i.ip] = true;
			liveKeys[i.index.to!string ~ "@" ~ i.ip] = true;
		}
		foreach (ip; egress.keys)
			if (ip !in live)
			{
				// Stop the reader FIRST: it holds its own copy of the UDPConnection (a copy is a
				// reference), so closing the stored one alone neither wakes its recv nor frees
				// the socket — the reader and socket lingered until the whole beacon closed.
				if (auto r = ip in egressReader)
				{
					if (*r != Task.getThis())
					{
						try
							r.interrupt();
						catch (Exception)
						{
						}
						r.joinUninterruptible();
					}
					egressReader.remove(ip);
				}
				try
					egress[ip].close();
				catch (Exception)
				{
				}
				egress.remove(ip);
				logInfo("libp2p: mdns beacon: %s is gone; egress closed", ip);
			}
		foreach (k; joined.keys)
			if (k !in liveKeys)
				joined.remove(k); // the kernel dropped the membership with the interface/address
		foreach (i; now)
		{
			immutable key = i.index.to!string ~ "@" ~ i.ip;
			if (key !in joined)
			{
				try
				{
					sock.addMembership(target, ifaceKey(i));
					joined[key] = true;
					fresh = true;
					logInfo("libp2p: mdns beacon: joined %s on %s (%s)", cfg.group, i.name, i.ip);
				}
				catch (Exception e)
					logDebug("libp2p: mdns beacon could not join the group on %s: %s", i.name, e.msg);
			}
			if (i.ip !in egress)
			{
				try
				{
					// RFC 6762: multicast responses come from port 5353. Bind the egress
					// there (address + port reuse, beside the group socket and beside
					// another responder on this host); a bind refused falls back to an
					// ephemeral port, which strict receivers may discard.
					UDPConnection e;
					if (cfg.bindPort == cfg.port)
						try
							e = listenUDP(cfg.port, i.ip, UDPListenOptions.reuseAddress | UDPListenOptions.reusePort);
						catch (Exception)
							e = listenUDP(0, i.ip);
					else
						e = listenUDP(0, i.ip); // tests: unicast sockets on ephemeral ports
					egress[i.ip] = e;
					// A unicast answer to a query we sent from this socket comes back HERE,
					// not to the group socket — so this one is read too.
					egressReader[i.ip] = spawnReader(e);
				}
				catch (Exception e)
					logDebug("libp2p: mdns beacon has no egress socket on %s: %s", i.name, e.msg);
			}
		}
		if (changed)
		{
			logInfo("libp2p: mdns beacon: network changed (%s) — probing again", set);
			heard = false;
			wait = 1.seconds;
			try
				query();
			catch (Exception)
			{
			}
		}
		// A network we just joined may hold a browser that already asked and is now
		// waiting for its next probe: tell it unasked (and ask it, if we browse).
		if (fresh)
		{
			try
			{
				announce();
				if (txts is null)
					query();
			}
			catch (Exception)
			{
			}
		}
	}

	// Interfaces come and go (a VM bridge when the VM starts, a VPN, Wi-Fi): look
	// every 2 s — getifaddrs is cheap — so a new network is joined within seconds,
	// not at the next 30 s query tick (that lag was ~15 s to discover on the
	// Waydroid bridge that appears when the container starts).
	private void interfaceLoop()
	{
		for (;;)
		{
			sleep(2.seconds);
			refreshInterfaces();
		}
	}

	// The de-duplication cache stays small: entries older than the window go
	// whenever it fills, and past a hard cap the oldest go too — a LAN flooding
	// unique fake answers cannot grow it without bound.
	private void rememberFound(string key, MonoTime now)
	{
		if (recentlyFound.length >= maxRecentlyFound)
		{
			foreach (k; recentlyFound.keys)
				if (now - recentlyFound[k] >= 5.seconds)
					recentlyFound.remove(k);
			while (recentlyFound.length >= maxRecentlyFound)
			{
				string oldest;
				MonoTime oldestAt;
				foreach (k, t; recentlyFound)
					if (oldest is null || t < oldestAt)
					{
						oldest = k;
						oldestAt = t;
					}
				recentlyFound.remove(oldest);
			}
		}
		recentlyFound[key] = now;
	}

	// The IP of one of our egress sockets, or null for the group socket.
	private string egressIp(UDPConnection s)
	{
		foreach (ip, e; egress)
			if (e == s)
				return ip;
		return null;
	}

	// A source an mDNS answer can legitimately come from: link-local, loopback or
	// a private network (10/8, 172.16/12, 192.168/16, the 100.64/10 shared range
	// a carrier or a VPN hands out). A public unicast source is not on our LAN.
	static bool isLanScoped(ref NetworkAddress from)
	{
		import std.string : indexOf;
		string ip;
		try
			ip = from.toAddressString;
		catch (Exception)
			return false;
		if (ip.startsWith("::ffff:"))
			ip = ip["::ffff:".length .. $];
		if (ip.indexOf('.') < 0)
		{
			auto l = ip.toLower;
			return l.startsWith("fe8") || l.startsWith("fe9") || l.startsWith("fea") || l.startsWith("feb")
				|| l.startsWith("fd") || l.startsWith("fc") || l == "::1";
		}
		auto parts = ip.split(".");
		if (parts.length != 4)
			return false;
		int a, b;
		try
		{
			a = parts[0].to!int;
			b = parts[1].to!int;
		}
		catch (Exception)
			return false;
		return a == 10 || a == 127 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168)
			|| (a == 169 && b == 254) || (a == 100 && b >= 64 && b <= 127);
	}

	// Did this datagram come from one of our own egress sockets? A multicast we
	// send loops back through every interface we joined (a host with docker
	// bridges hears its own query half a dozen times); answering ourselves is
	// wasted work and log noise. Another process on this host has other ports.
	private bool isOurEgress(ref NetworkAddress from)
	{
		foreach (ip, e; egress)
			try
				if (from.port == e.localAddress.port && from.toAddressString == ip)
					return true;
			catch (Exception)
			{
			}
		return false;
	}

	// Send `pkt` to the group through every interface (or through the receive
	// socket alone when we have no per-interface sockets — tests, single-homed).
	private void multicast(const(ubyte)[] pkt)
	{
		if (egress.length == 0)
		{
			sock.send(pkt, &target);
			return;
		}
		foreach (e; egress)
			try
				e.send(pkt, &target);
			catch (Exception)
			{
			}
	}

	/// Ask the LAN now.
	void query()
	{
		DnsMessage q;
		q.questions ~= DnsQuestion(service, typePtr, classIn);
		multicast(encodeMessage(q));
		logInfo("libp2p: mdns beacon: query for %s sent via %s interface(s)", service,
			egress.length ? egress.length : 1);
	}

	/// Announce now, unasked (a fresh listener, a changed port).
	void announce()
	{
		if (txts is null)
			return;
		announceEach();
	}

	// One answer per interface, each carrying that interface's own A record (the
	// address a DNS-SD browser resolves the SRV target to must be the one it can
	// reach us at on THAT network); the group socket alone answers without one.
	private void announceEach()
	{
		if (egress.length == 0)
		{
			sock.send(encodeMessage(answerMessage(null)), &target);
			return;
		}
		foreach (ip, e; egress)
			try
				e.send(encodeMessage(answerMessage(ip)), &target);
			catch (Exception)
			{
			}
	}

	// The port a DNS-SD SRV record names: the first transport line of the TXT
	// (`quic=`, `tcp=`, `udx=`, `ws=`); 0 when none is announced.
	private static ushort srvPort(const(string)[] lines)
	{
		foreach (prefix; ["quic=", "tcp=", "udx=", "ws="])
			foreach (l; lines)
				if (l.startsWith(prefix))
					try
						return l[prefix.length .. $].to!ushort;
					catch (Exception)
					{
					}
		return 0;
	}

	// A full DNS-SD answer (RFC 6763): PTR → instance, the instance's SRV (host +
	// port) and TXT, and — when the answering interface is known — the host's A
	// record. Cache-flush set on the records we own (RFC 6762 §10.2).
	private DnsMessage answerMessage(string ifIp)
	{
		DnsMessage r;
		r.flags = 0x8400;
		r.answers ~= DnsRecord(service, typePtr, classIn, cfg.ttl, instance);
		auto lines = txts();
		immutable port = srvPort(lines);
		if (port != 0)
		{
			DnsRecord srv;
			srv.name = instance;
			srv.rtype = typeSrv;
			srv.rclass = classIn | 0x8000;
			srv.ttl = cfg.ttl;
			put16(srv.raw, 0); // priority
			put16(srv.raw, 0); // weight
			put16(srv.raw, port);
			putName(srv.raw, hostname);
			r.answers ~= srv;
		}
		DnsRecord txt;
		txt.name = instance;
		txt.rtype = typeTxt;
		txt.rclass = classIn | 0x8000;
		txt.ttl = cfg.ttl;
		txt.txts = lines;
		r.answers ~= txt;
		if (ifIp.length && port != 0)
		{
			auto parts = ifIp.split(".");
			if (parts.length == 4)
			{
				DnsRecord a;
				a.name = hostname;
				a.rtype = typeA;
				a.rclass = classIn | 0x8000;
				a.ttl = cfg.ttl;
				try
					foreach (p; parts)
						a.raw ~= p.to!ubyte;
				catch (Exception)
					a.raw = null;
				if (a.raw.length == 4)
					r.answers ~= a;
			}
		}
		return r;
	}

	private void queryLoop()
	{
		// mDNS probing cadence: 1 s, 2 s, … but capped at `probeInterval` for as long
		// as NOBODY has answered — a query is one tiny multicast, and the steady
		// 30 s only makes sense once the peer is found. The back-off used to grow
		// to 30 s while a VPN swallowed the multicast, so when the VPN went away the
		// peer was only discovered at the next 30 s tick (~12 s on average). It
		// resets to 1 s (and asks at once) whenever wake() is called or the set of
		// interfaces changes — a VPN or bridge coming or going.
		wait = 1.seconds;
		for (;;)
		{
			query();
			sleep(wait);
			immutable cap = heard ? cfg.queryInterval : cfg.probeInterval;
			wait = wait * 2 > cap ? cap : wait * 2;
		}
	}

	/// The network changed (an application hook — Android's connectivity, Qt's
	/// QNetworkInformation): forget the back-off and ask right now.
	void wake()
	{
		heard = false;
		wait = 1.seconds;
		try
			query();
		catch (Exception)
		{
		}
	}

	private void receiveLoop()
	{
		receiveOn(sock);
	}

	private void receiveOn(UDPConnection s)
	{
		auto buf = new ubyte[9000];
		for (;;)
		{
			NetworkAddress from;
			auto pkt = s.recv(buf, &from);
			DnsMessage m;
			try
				m = decodeMessage(pkt);
			catch (Exception)
				continue; // not DNS we can read; the network is full of those
			if ((m.flags & 0x8000) == 0)
			{
				// Do NOT drop a query just because it shares our interface IP + port
				// 5353: a conforming responder in ANOTHER process on this host looks
				// identical, and self-suppression would silence it. Answering our own
				// looped-back query is harmless — our own answer is excluded by the
				// instance-name check on the receive side.
				immutable ours = m.questions.canFind!(x => x.name.toLower == service && (x.qtype == typePtr || x.qtype == 255));
				if (ours)
					logInfo("libp2p: mdns beacon: query for %s from %s%s", service, from.toAddressString,
						txts is null ? " (we only browse; not answering)" : " — answering (group + unicast)");
				if (txts !is null && ours)
				{
					// Answer to the group (everyone on that network learns us) AND straight
					// back to the asker: the unicast reply needs no interface selection at
					// all and arrives whatever the multicast topology between us is.
					announceEach();
					try
						s.send(encodeMessage(answerMessage(egressIp(s))), &from);
					catch (Exception)
					{
					}
				}
				continue;
			}
			// An answer: ours (PTR to our service), from someone else. Only what is
			// scoped to a LAN can be one (a unicast from across the internet is not),
			// and only the TXT of the instance the PTR names counts — a record with
			// any other owner riding in the same message is not that answer.
			if (!isLanScoped(from))
				continue;
			bool[string] named;
			foreach (a; m.answers)
				if (a.rtype == typePtr && (a.rclass & 0x7fff) == classIn && a.ttl > 0
					&& a.name.toLower == service && a.target.toLower != instance)
					named[a.target.toLower] = true;
			if (named.length == 0)
				continue;
			foreach (a; m.answers)
				if (a.rtype == typeTxt && (a.rclass & 0x7fff) == classIn && a.ttl > 0
					&& (a.name.toLower in named) !is null && onFound !is null)
				{
					// The same answer reaches us once per interface path and once more by
					// unicast; a query fans out the same way. One onFound per peer per 5 s.
					immutable key = from.toAddressString ~ "|" ~ a.txts.join("\x1f");
					immutable now = MonoTime.currTime;
					if (auto t = key in recentlyFound)
						if (now - *t < 5.seconds)
							continue;
					rememberFound(key, now);
					heard = true; // steady cadence from here, until the network changes
					logInfo("libp2p: mdns beacon: %s answered from %s", service, from.toAddressString);
					onFound(from, a.txts);
				}
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

/// The service label two peers derive from a shared secret: `_<prefix>-<16 hex of
/// sha256(secret)>._udp.local`. Nothing about the secret itself is on the wire.
string mdnsServiceFor(string prefix, scope const(ubyte)[] secret)
{
	import std.digest.sha : sha256Of;
	import std.format : format;

	auto h = sha256Of(secret);
	return format("_%s-%(%02x%)._udp.local", prefix, h[0 .. 8]);
}

// --- one LAN rendezvous per sharing key, shared by every flavor in the process --------------------

/// The LAN side of a sharing key. ONE DNS-SD label per key — `mdnsServiceFor(prefix,
/// key)` — and ONE TXT record with a line per transport flavor the host runs
/// (`id=…`, `quic=…`/`tcp=…` for libp2p; `udx=…`, `pk=…` for hyperswarm): a host
/// announces everything it runs, a browser of any flavor finds the same key, reads
/// the line of ITS flavor and connects to that transport at the address the answer
/// came from — the DHT/relay/punch entrance is skipped entirely. Flavors register
/// here: a TXT source (what they announce) and a listener (what they do with an
/// answer). The application hands over the key and switches flavors on; it never
/// sees a PeerId, a public key or an address.
final class LanRendezvous
{
	private MdnsBeacon beacon;
	private string[] delegate()[] sources;
	private void delegate(NetworkAddress, string[]) nothrow[] listeners;
	private string label;
	private bool closed;
	private size_t refs; // how many flavors hold this shared rendezvous

	private static LanRendezvous[string] byLabel;

	/// The process-wide rendezvous for `key` (created on first use, shared after).
	static LanRendezvous forKey(string prefix, scope const(ubyte)[] key, MdnsBeaconConfig cfg = MdnsBeaconConfig.init)
	{
		immutable label = mdnsServiceFor(prefix, key);
		// Ownership is counted by the holders (MdnsRendezvous ctor acquire / close
		// release), NOT here — so a directly-constructed LanRendezvous and a forKey
		// one behave the same, and the shared beacon dies only at the last holder.
		if (auto p = label in byLabel)
			if (!(*p).closed)
				return *p;
		auto r = new LanRendezvous(label, cfg);
		byLabel[label] = r;
		return r;
	}

	/// A private one (tests aim two at each other; an application with one flavor
	/// may also just own it).
	this(string label, MdnsBeaconConfig cfg = MdnsBeaconConfig.init)
	{
		this.label = label;
		beacon = new MdnsBeacon(label, &txts, cfg);
		beacon.onFound = &found;
	}

	/// What this host announces: the lines of every registered flavor. With no
	/// source registered the host answers nothing (it only browses).
	void addTxtSource(string[] delegate() source)
	{
		sources ~= source;
		try
			beacon.announce();
		catch (Exception)
		{
		}
	}

	/// Someone answered: every flavor's listener sees the whole TXT and picks its
	/// own lines (`udx=` for hyperswarm, `quic=`/`tcp=` for libp2p).
	void addListener(void delegate(NetworkAddress from, string[] txts) nothrow listener)
	{
		listeners ~= listener;
	}

	/// Take a source back (the flavor that registered it is closing): the label
	/// stops carrying its lines at the next announce.
	void removeTxtSource(string[] delegate() source)
	{
		string[] delegate()[] rest;
		foreach (s; sources)
			if (s != source)
				rest ~= s;
		sources = rest;
	}

	/// Take a listener back: nothing of a closed flavor is called again.
	void removeListener(void delegate(NetworkAddress from, string[] txts) nothrow listener)
	{
		void delegate(NetworkAddress, string[]) nothrow[] rest;
		foreach (l; listeners)
			if (l != listener)
				rest ~= l;
		listeners = rest;
	}

	private string[] txts()
	{
		string[] out_;
		foreach (src; sources)
			foreach (t; src())
				if (!out_.canFind(t))
					out_ ~= t;
		return out_;
	}

	private void found(NetworkAddress from, string[] txts) nothrow
	{
		foreach (l; listeners)
			l(from, txts);
	}

	/// The `key=value` line of `txts` with this key, or null.
	static string line(const(string)[] txts, string key)
	{
		import std.string : startsWith;

		foreach (t; txts)
			if (t.startsWith(key ~ "="))
				return t[key.length + 1 .. $];
		return null;
	}

	void query()
	{
		beacon.query();
	}

	/// The network changed: reset the probing back-off and ask now.
	void wake()
	{
		beacon.wake();
	}

	void announce()
	{
		beacon.announce();
	}

	MdnsBeacon underlyingBeacon()
	{
		return beacon;
	}

	/// One holder is done with the shared rendezvous. The beacon (and its sockets
	/// and fibers) is torn down and the label unregistered only when the LAST holder
	/// releases it — so a process cycling through pairing keys does not leak a beacon
	/// per key, and a still-active flavor is never cut off.
	/// A new holder takes a reference to the shared rendezvous.
	void acquire() nothrow
	{
		refs++;
	}

	void release() nothrow
	{
		if (closed)
			return;
		if (refs > 0)
			refs--;
		if (refs == 0)
			close();
	}

	void close() nothrow
	{
		if (closed)
			return;
		closed = true;
		beacon.close();
		byLabel.remove(label);
	}
}

// --- the libp2p flavor on that rendezvous ---------------------------------------------------------

struct MdnsRendezvousConfig
{
	MdnsBeaconConfig beacon;
	bool announce = true; /// answer queries with our id + ports (the desktop); false = browse only
	size_t maxConcurrentDials = 4; /// LAN answers dialed at once; more wait for the next announce
}

/// The libp2p flavor's lines on a LanRendezvous: announces `id=<PeerId>` and one
/// `<transport>=<port>` per listen address; on an answer dials the address it
/// came from with those ports — the ordinary Noise/TLS upgrade, no DHT, no relay,
/// no punch. Runs beside the DHT discovery; the swarm's one-connection-per-peer
/// rule settles the race.
final class MdnsRendezvous
{
	private Host host;
	private LanRendezvous lan;
	private MdnsRendezvousConfig cfg;
	private bool[PeerId] dialing;
	private FiberGroup fibers; // the dials, owned: close() stops and joins them
	private string[] delegate() source; // what we registered on the rendezvous, to take back
	private bool closed;

	/// A peer of this key was reached on the LAN (also in the peerstore now).
	void delegate(PeerId peer, Connection conn) nothrow onConnected;

	/// Joins the process-wide rendezvous of (`prefix`, `key`) — the same one the
	/// hyperswarm flavor joins, so a host announces both and a browser sees both.
	this(Host host, string prefix, scope const(ubyte)[] key, MdnsRendezvousConfig cfg = MdnsRendezvousConfig.init)
	{
		this(host, LanRendezvous.forKey(prefix, key, cfg.beacon), cfg);
	}

	/// On a rendezvous the caller owns (tests).
	this(Host host, LanRendezvous lan, MdnsRendezvousConfig cfg = MdnsRendezvousConfig.init)
	{
		this.host = host;
		this.lan = lan;
		this.cfg = cfg;
		lan.acquire(); // one hold per rendezvous; close() releases it

		fibers = new FiberGroup((Exception e) nothrow { logDebug("libp2p: mdns rendezvous: %s", e.msg); });
		auto h = host;
		if (cfg.announce)
		{
			source = () => txtsFor(h);
			lan.addTxtSource(source);
		}
		lan.addListener(&found);
	}

	/// What the announcer says: `id=<peer id>` and one `<transport>=<port>` per listen
	/// address — `tcp=4001`, `quic=4001` (udp/quic-v1), `ws=4001` (tcp + ws). Ports
	/// only: the address is where the answer comes from, whatever we listen on.
	static string[] txtsFor(Host host)
	{
		import std.conv : to;

		string[] out_ = ["id=" ~ host.id.toBase58];
		foreach (a; host.addrs)
		{
			auto c = a.components;
			if (c.length < 2 || (c[0].name != "ip4" && c[0].name != "ip6"))
				continue;
			immutable port = (cast(uint) c[1].value[0] << 8) | c[1].value[1];
			string kind;
			if (c[1].name == "udp" && c.canFind!(x => x.name == "quic-v1"))
				kind = "quic";
			else if (c[1].name == "tcp" && c.canFind!(x => x.name == "ws"))
				kind = "ws";
			else if (c[1].name == "tcp")
				kind = "tcp";
			else
				continue;
			immutable t = kind ~ "=" ~ port.to!string;
			if (!out_.canFind(t))
				out_ ~= t;
		}
		return out_;
	}

	/// The dialable addresses an answer describes: the sender's address with each
	/// announced port, ending in the announced peer id. Null if the answer names
	/// ourselves, has no libp2p line, or carries no usable port.
	static Multiaddr[] addrsFrom(NetworkAddress from, const(string)[] txts, PeerId self, out PeerId who)
	{
		import std.string : startsWith;

		immutable id = LanRendezvous.line(txts, "id");
		if (id.length == 0)
			return null;
		try
			who = PeerId.fromBase58(id);
		catch (Exception)
			return null;
		if (who == self)
			return null;
		immutable ip = "/" ~ (from.family == AddressFamily.INET6 ? "ip6" : "ip4") ~ "/" ~ from.toAddressString;
		Multiaddr[] out_;
		foreach (t; txts)
		{
			string tail;
			if (t.startsWith("quic="))
				tail = "/udp/" ~ t[5 .. $] ~ "/quic-v1";
			else if (t.startsWith("tcp="))
				tail = "/tcp/" ~ t[4 .. $];
			else if (t.startsWith("ws="))
				tail = "/tcp/" ~ t[3 .. $] ~ "/ws";
			else
				continue;
			try
				out_ ~= Multiaddr.parse(ip ~ tail ~ "/p2p/" ~ id);
			catch (Exception)
			{
			}
		}
		return out_;
	}

	private void found(NetworkAddress from, string[] txts) nothrow
	{
		PeerId who;
		Multiaddr[] addrs;
		try
			addrs = addrsFrom(from, txts, host.id, who);
		catch (Exception)
		{
		}
		if (closed || addrs.length == 0 || who in dialing)
			return;
		immutable dialCap = cfg.maxConcurrentDials < 1 ? 1 : cfg.maxConcurrentDials; // 0 would block all discovery
		if (dialing.length >= dialCap)
			return; // bounded fan-out: a flood of answers is not a flood of dials; it re-offers itself
		dialing[who] = true;
		try
			fibers.spawn({
				scope (exit)
					dialing.remove(who);
				// A new path to a peer we may already talk to elsewhere (WAN): open it
				// too — the application decides which connection carries what.
				try
				{
					auto c = host.connectFresh(who, addrs);
					logInfo("libp2p: mdns rendezvous: %s reached on the LAN via %s", who.toString, c.remoteAddr.toString);
					if (onConnected !is null)
						onConnected(who, c);
				}
				catch (InterruptException e)
					throw e; // close() stopping us
				catch (Exception e)
					logInfo("libp2p: mdns rendezvous: dial of %s failed: %s", who.toString, e.msg);
			});
		catch (Exception)
			dialing.remove(who);
	}

	/// Ask the LAN now (it also asks on the beacon's own cadence).
	void query()
	{
		lan.query();
	}

	/// The network changed: probe again right away (see LanRendezvous.wake).
	void wake()
	{
		lan.wake();
	}

	/// Announce now (a listener was added).
	void announce()
	{
		lan.announce();
	}

	/// The shared rendezvous this flavor sits on.
	LanRendezvous rendezvous()
	{
		return lan;
	}

	/// Leave the rendezvous: our lines and our listener come off it (it is shared
	/// with other flavors, so it stays up — closing it is its owner's call) and
	/// the dials in flight are stopped and joined. Nothing of this instance, or of
	/// its host, is called by a later answer.
	void close() nothrow
	{
		if (closed)
			return;
		closed = true;
		try
		{
			lan.removeListener(&found);
			if (source !is null)
				lan.removeTxtSource(source);
			lan.release(); // drop our hold; the beacon dies with the last holder
		}
		catch (Exception)
		{
		}
		fibers.stopAll();
	}
}
