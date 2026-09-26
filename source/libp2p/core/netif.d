/// The machine's own IP addresses, as the kernel has them now.
module libp2p.core.netif;

/// Every IPv4 and IPv6 address on an UP interface (loopback included), as text in
/// the form a multiaddr's ip4 / ip6 component carries. Empty if the kernel cannot be
/// asked — callers treat that as "unknown", never as "no network".
string[] localIps() nothrow
{
	import core.sys.linux.ifaddrs : ifaddrs, getifaddrs, freeifaddrs;
	import core.sys.posix.netinet.in_ : sockaddr_in, sockaddr_in6;
	import core.sys.posix.arpa.inet : inet_ntop, INET6_ADDRSTRLEN;
	import core.sys.posix.sys.socket : AF_INET, AF_INET6;
	import std.string : fromStringz;

	enum IFF_UP = 0x1;
	string[] out_;
	ifaddrs* list;
	if (getifaddrs(&list) != 0)
		return out_;
	scope (exit)
		freeifaddrs(list);
	for (auto p = list; p !is null; p = p.ifa_next)
	{
		if (p.ifa_addr is null || !(p.ifa_flags & IFF_UP))
			continue;
		char[INET6_ADDRSTRLEN] buf;
		const(char)* got;
		if (p.ifa_addr.sa_family == AF_INET)
			got = inet_ntop(AF_INET, &(cast(sockaddr_in*) p.ifa_addr).sin_addr, buf.ptr, buf.length);
		else if (p.ifa_addr.sa_family == AF_INET6)
			got = inet_ntop(AF_INET6, &(cast(sockaddr_in6*) p.ifa_addr).sin6_addr, buf.ptr, buf.length);
		if (got is null)
			continue;
		try
			out_ ~= buf.ptr.fromStringz.idup;
		catch (Exception)
		{
		}
	}
	return out_;
}

unittest
{
	import std.algorithm : canFind;

	auto ips = localIps();
	assert(ips.canFind("127.0.0.1"), "loopback is always there");
}
