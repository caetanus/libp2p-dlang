/**
 * A real resolver: c-ares, driven from a fiber.
 *
 * c-ares does the protocol — retries, several nameservers, TCP when a reply is
 * truncated, search domains, any record type — and asks only to be told when
 * its sockets are readable or its timeout has passed. That is what vibe's
 * `FileDescriptorEvent` is for: a fiber parks on the descriptor and the loop
 * stays free. The descriptor handed to vibe is a `dup()` of c-ares's own,
 * because vibe closes what it adopts and c-ares must keep its socket.
 *
 * One channel per lookup: simple, and a lookup's failure cannot leak into
 * another's. The prototypes are declared here; there is no deimos binding.
 */
module libp2p.transport.dns_cares;

import core.stdc.string : strlen;
import core.sys.posix.arpa.inet : inet_ntop;
import core.sys.posix.netinet.in_ : sockaddr_in, sockaddr_in6, AF_INET, AF_INET6, INET6_ADDRSTRLEN;
import core.sys.posix.sys.socket : sockaddr, SOCK_STREAM;
import core.sys.posix.sys.time : timeval;
import core.sys.posix.unistd : dup, close;
import core.time : Duration, seconds, msecs, usecs;
import std.exception : enforce;
import std.string : toStringz;

import vibe.core.core : createFileDescriptorEvent, FileDescriptorEvent, sleep;

import libp2p.transport.dns : DnsResolver;
import libp2p.util.select : select;

// --- the parts of ares.h we use ------------------------------------------------------------

private extern (C) nothrow @nogc
{
	struct ares_channeldata;
	alias ares_channel_t = ares_channeldata;
	alias ares_socket_t = int;

	struct ares_addrinfo_hints
	{
		int ai_flags, ai_family, ai_socktype, ai_protocol;
	}

	struct ares_addrinfo_node
	{
		int ai_ttl, ai_flags, ai_family, ai_socktype, ai_protocol;
		uint ai_addrlen;
		sockaddr* ai_addr;
		ares_addrinfo_node* ai_next;
	}

	struct ares_addrinfo_cname;

	struct ares_addrinfo
	{
		ares_addrinfo_cname* cnames;
		ares_addrinfo_node* nodes;
		char* name;
	}

	struct ares_txt_reply
	{
		ares_txt_reply* next;
		ubyte* txt;
		size_t length;
	}

	int ares_library_init(int flags);
	int ares_init(ares_channel_t** channel);
	void ares_destroy(ares_channel_t* channel);
	int ares_set_servers_ports_csv(ares_channel_t* channel, const(char)* servers);
	void ares_query(ares_channel_t* channel, const(char)* name, int dnsclass, int type, ares_callback cb, void* arg);
	void ares_getaddrinfo(ares_channel_t* channel, const(char)* node, const(char)* service,
		const(ares_addrinfo_hints)* hints, ares_addrinfo_callback cb, void* arg);
	void ares_freeaddrinfo(ares_addrinfo* ai);
	int ares_parse_txt_reply(const(ubyte)* abuf, int alen, ares_txt_reply** txt);
	void ares_free_data(void* data);
	int ares_getsock(const(ares_channel_t)* channel, ares_socket_t* socks, int numsocks);
	timeval* ares_timeout(const(ares_channel_t)* channel, timeval* maxtv, timeval* tv);
	void ares_process_fd(ares_channel_t* channel, ares_socket_t readFd, ares_socket_t writeFd);
	const(char)* ares_strerror(int code);
}

// The callbacks allocate (they build D arrays), so they are not @nogc.
private extern (C) nothrow alias ares_callback = void function(void* arg, int status, int timeouts, ubyte* abuf, int alen);
private extern (C) nothrow alias ares_addrinfo_callback = void function(void* arg, int status, int timeouts,
	ares_addrinfo* res);

private enum ARES_SUCCESS = 0;
private enum ARES_ENODATA = 1; // the name exists but has no record of this type
private enum ARES_ENOTFOUND = 4; // the name does not exist
private enum ARES_SOCKET_BAD = -1;
private enum ARES_GETSOCK_MAXNUM = 16;
private enum ARES_LIB_INIT_ALL = 0;
private enum C_IN = 1;
private enum T_TXT = 16;

shared static this()
{
	ares_library_init(ARES_LIB_INIT_ALL);
}

final class CaresDns : DnsResolver
{
	private string servers; // "host:port,host:port" or null for the system's
	private Duration maxWait = 10.seconds;

	/// `servers` overrides /etc/resolv.conf, as "ip:port" entries separated by commas.
	this(string servers = null)
	{
		this.servers = servers;
	}

	string[] lookupA(string host)
	{
		return lookupAddrs(host, AF_INET);
	}

	string[] lookupAaaa(string host)
	{
		return lookupAddrs(host, AF_INET6);
	}

	string[] lookupTxt(string host)
	{
		auto ch = channel();
		scope (exit)
			ares_destroy(ch);
		TxtAnswer answer;
		ares_query(ch, host.toStringz, C_IN, T_TXT, &onTxt, &answer);
		drive(ch, &answer.done);
		enforceResolved(answer.status, host);
		return answer.txts;
	}

	// --- driving c-ares from a fiber ------------------------------------------------------------

	private ares_channel_t* channel()
	{
		ares_channel_t* ch;
		enforce(ares_init(&ch) == ARES_SUCCESS, "c-ares: could not create a channel");
		if (servers !is null && ares_set_servers_ports_csv(ch, servers.toStringz) != ARES_SUCCESS)
		{
			ares_destroy(ch);
			throw new Exception("c-ares: bad server list: " ~ servers);
		}
		return ch;
	}

	/// Wake c-ares whenever one of its sockets is readable or its timeout passes,
	/// until `*done`.
	private void drive(ares_channel_t* ch, bool* done)
	{
		while (!*done)
		{
			ares_socket_t[ARES_GETSOCK_MAXNUM] socks;
			immutable bits = ares_getsock(ch, socks.ptr, ARES_GETSOCK_MAXNUM);
			ares_socket_t[] readable;
			ares_socket_t writable = ARES_SOCKET_BAD;
			foreach (i; 0 .. ARES_GETSOCK_MAXNUM)
			{
				if (bits & (1 << i))
					readable ~= socks[i];
				if (bits & (1 << (i + ARES_GETSOCK_MAXNUM)))
					writable = socks[i];
			}

			timeval tv;
			auto tvp = ares_timeout(ch, null, &tv);
			immutable wait = tvp is null ? maxWait : (tv.tv_sec.seconds + tv.tv_usec.usecs);

			if (writable != ARES_SOCKET_BAD)
			{
				// A UDP socket is writable at once; c-ares copes if it is not.
				ares_process_fd(ch, ARES_SOCKET_BAD, writable);
				continue;
			}
			if (readable.length == 0)
			{
				sleep(wait);
				ares_process_fd(ch, ARES_SOCKET_BAD, ARES_SOCKET_BAD); // let it time out and retry
				continue;
			}

			ares_socket_t ready = ARES_SOCKET_BAD;
			if (readable.length == 1)
			{
				if (awaitReadable(readable[0], wait))
					ready = readable[0];
			}
			else
			{
				// Several sockets (a TCP fallback alongside UDP): the first to wake wins.
				void delegate()[] alts;
				bool[] got = new bool[readable.length];
				foreach (i, fd; readable)
					alts ~= { got[i] = awaitReadable(fd, wait); };
				immutable winner = select(alts);
				if (got[winner])
					ready = readable[winner];
			}
			ares_process_fd(ch, ready, ARES_SOCKET_BAD);
		}
	}

	/// True if `fd` became readable within `wait`. vibe adopts (and later
	/// closes) the descriptor it is given, so it gets a duplicate.
	private static bool awaitReadable(int fd, Duration wait)
	{
		immutable copy = dup(fd);
		enforce(copy >= 0, "c-ares: dup failed");
		auto ev = createFileDescriptorEvent(copy, FileDescriptorEvent.Trigger.read);
		return ev.wait(wait, FileDescriptorEvent.Trigger.read);
	}

	// --- answers --------------------------------------------------------------------------------

	private struct AddrAnswer
	{
		bool done;
		int status = ARES_SUCCESS;
		string[] addrs;
	}

	private struct TxtAnswer
	{
		bool done;
		int status = ARES_SUCCESS;
		string[] txts;
	}

	// A resolution that failed (SERVFAIL, timeout, refused, cancelled, ...) must be
	// distinguishable from a name that simply has no such record: the empty-but-OK
	// cases (ENODATA/ENOTFOUND) return no addresses, everything else throws.
	private static void enforceResolved(int status, string host)
	{
		if (status == ARES_SUCCESS || status == ARES_ENODATA || status == ARES_ENOTFOUND)
			return;
		import std.string : fromStringz;

		throw new Exception("dns: resolving " ~ host ~ " failed: " ~ ares_strerror(status).fromStringz.idup);
	}

	private string[] lookupAddrs(string host, int family)
	{
		auto ch = channel();
		scope (exit)
			ares_destroy(ch);
		AddrAnswer answer;
		ares_addrinfo_hints hints;
		hints.ai_family = family;
		hints.ai_socktype = SOCK_STREAM; // one entry per address, not one per socket type
		ares_getaddrinfo(ch, host.toStringz, null, &hints, &onAddrs, &answer);
		drive(ch, &answer.done);
		enforceResolved(answer.status, host);
		return answer.addrs;
	}

	private static extern (C) void onAddrs(void* arg, int status, int timeouts, ares_addrinfo* res) nothrow
	{
		auto answer = cast(AddrAnswer*) arg;
		answer.done = true;
		answer.status = status;
		if (status != ARES_SUCCESS || res is null)
			return;
		scope (exit)
			ares_freeaddrinfo(res);
		try
		{
			for (auto n = res.nodes; n !is null; n = n.ai_next)
			{
				char[INET6_ADDRSTRLEN] buf;
				const(char)* s;
				if (n.ai_family == AF_INET)
					s = inet_ntop(AF_INET, &(cast(sockaddr_in*) n.ai_addr).sin_addr, buf.ptr, buf.length);
				else if (n.ai_family == AF_INET6)
					s = inet_ntop(AF_INET6, &(cast(sockaddr_in6*) n.ai_addr).sin6_addr, buf.ptr, buf.length);
				if (s !is null)
					answer.addrs ~= s[0 .. strlen(s)].idup;
			}
		}
		catch (Exception)
		{
		}
	}

	private static extern (C) void onTxt(void* arg, int status, int timeouts, ubyte* abuf, int alen) nothrow
	{
		auto answer = cast(TxtAnswer*) arg;
		answer.done = true;
		answer.status = status;
		if (status != ARES_SUCCESS)
			return;
		ares_txt_reply* txt;
		if (ares_parse_txt_reply(abuf, alen, &txt) != ARES_SUCCESS)
			return;
		scope (exit)
			ares_free_data(txt);
		try
		{
			for (auto t = txt; t !is null; t = t.next)
				answer.txts ~= (cast(const(char)[]) t.txt[0 .. t.length]).idup;
		}
		catch (Exception)
		{
		}
	}
}
