module tests.multiformats.multiaddr_test;

import libp2p.multiformats.multiaddr;
import fluent.asserts;
import std.string : toUpper;

private ubyte[] fromHex(string h) @safe pure
{
	import std.conv : to;

	ubyte[] r;
	for (size_t i = 0; i + 1 < h.length; i += 2)
		r ~= to!ubyte(h[i .. i + 2], 16);
	return r;
}

@("text roundtrip for common addresses")
unittest
{
	foreach (s; [
		"/ip4/127.0.0.1/tcp/4001",
		"/ip4/1.2.3.4/tcp/80/ws",
		"/ip4/0.0.0.0/udp/4001/quic-v1",
		"/ip6/::1/tcp/8080",
		"/ip6/2001:db8::1/tcp/443/wss",
		"/dns4/example.com/tcp/443/wss",
		"/dnsaddr/bootstrap.libp2p.io/tcp/443/wss",
		"/ip4/127.0.0.1/tcp/4001/p2p-circuit",
	])
		Multiaddr.parse(s).toString.should.equal(s);
}

@("binary vector: /ip4/127.0.0.1/udp/1234 (rust multiaddr)")
unittest
{
	auto ma = Multiaddr.parse("/ip4/127.0.0.1/udp/1234");
	ma.encode.should.equal(fromHex("047f000001910204d2"));
	Multiaddr.decode(fromHex("047f000001910204d2")).toString
		.should.equal("/ip4/127.0.0.1/udp/1234");
}

@("binary roundtrip preserves the address")
unittest
{
	foreach (s; [
		"/ip4/8.8.8.8/tcp/53",
		"/ip6/fe80::1/udp/9999/quic-v1",
		"/dns6/ipfs.io/tcp/443/tls/ws",
		"/unix/tmp/socket",
	])
	{
		auto ma = Multiaddr.parse(s);
		Multiaddr.decode(ma.encode).should.equal(ma);
	}
}

@("p2p component roundtrips a base58 peer id")
unittest
{
	// A canonical IPFS peer id (sha2-256 multihash, base58btc).
	enum peer = "QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N";
	auto s = "/ip4/127.0.0.1/tcp/4001/p2p/" ~ peer;
	Multiaddr.parse(s).toString.should.equal(s);
}

@("ip6 zero-run compression follows RFC 5952")
unittest
{
	Multiaddr.parse("/ip6/0:0:0:0:0:0:0:1/tcp/1").toString
		.should.equal("/ip6/::1/tcp/1");
	Multiaddr.parse("/ip6/2001:db8:0:0:0:0:0:1/tcp/1").toString
		.should.equal("/ip6/2001:db8::1/tcp/1");
}

@("unknown protocol is rejected")
unittest
{
	Multiaddr.parse("/bogus/1").should.throwAnyException;
}

@("missing value is rejected")
unittest
{
	Multiaddr.parse("/ip4").should.throwAnyException;
}

// rust multiaddr errors (DataLessThanLen / EOF) when a binary buffer's value is
// truncated. The D decoder guards with `enforce(... truncated ...)`; feed it a
// chopped buffer and assert it throws rather than reading past the end.
@("multiaddr binary decode rejects a truncated buffer")
unittest
{
	auto full = Multiaddr.parse("/ip4/127.0.0.1/tcp/1234").encode;
	bool threwFixed, threwLen;
	// Chop the last byte of the tcp port (fixed-size value truncated).
	try
		Multiaddr.decode(full[0 .. $ - 1]);
	catch (Exception)
		threwFixed = true;
	threwFixed.should.equal(true);

	// A length-prefixed value (unix path) truncated after its length prefix.
	auto up = Multiaddr.parse("/unix/tmp").encode;
	try
		Multiaddr.decode(up[0 .. $ - 1]);
	catch (Exception)
		threwLen = true;
	threwLen.should.equal(true);
}
