module tests.transport.webrtc.transport_test;

import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.transport.webrtc.transport;
import libp2p.transport.webrtc.fingerprint : Fingerprint;
import fluent.asserts;

// The certhash digest all three rust parity vectors resolve to.
private enum ubyte[32] EXPECTED = [
	0xe2, 0x92, 0x9e, 0x4a, 0x55, 0x48, 0x24, 0x2e, 0xd6, 0xb5, 0x12, 0x35, 0x0d, 0xf8, 0x82, 0x9b,
	0x1e, 0x4f, 0x9d, 0x50, 0x18, 0x3c, 0x57, 0x32, 0xa0, 0x7f, 0x99, 0xd7, 0xc4, 0xb2, 0xb8, 0xeb];

@("parse valid webrtc-direct address with certhash and p2p (rust parity)")
unittest
{
	auto addr = Multiaddr.parse(
		"/ip4/127.0.0.1/udp/39901/webrtc-direct/certhash/uEiDikp5KVUgkLta1EjUN-IKbHk-dUBg8VzKgf5nXxLK46w/p2p/12D3KooWNpDk9w6WrEEcdsEH1y47W71S36yFjw4sd3j7omzgCSMS");
	auto parsed = parseWebRTCDialAddr(addr);
	parsed.isNull.should.equal(false);
	parsed.get.host.should.equal("127.0.0.1");
	parsed.get.port.should.equal(cast(ushort) 39901);
	parsed.get.fingerprint.should.equal(Fingerprint.raw(EXPECTED));
}

@("peer id is not required (rust parity)")
unittest
{
	auto addr = Multiaddr.parse(
		"/ip4/127.0.0.1/udp/39901/webrtc-direct/certhash/uEiDikp5KVUgkLta1EjUN-IKbHk-dUBg8VzKgf5nXxLK46w");
	auto parsed = parseWebRTCDialAddr(addr);
	parsed.isNull.should.equal(false);
	parsed.get.host.should.equal("127.0.0.1");
	parsed.get.port.should.equal(cast(ushort) 39901);
	parsed.get.fingerprint.should.equal(Fingerprint.raw(EXPECTED));
}

@("parse ipv6 webrtc-direct address (rust parity)")
unittest
{
	auto addr = Multiaddr.parse(
		"/ip6/::1/udp/12345/webrtc-direct/certhash/uEiDikp5KVUgkLta1EjUN-IKbHk-dUBg8VzKgf5nXxLK46w/p2p/12D3KooWNpDk9w6WrEEcdsEH1y47W71S36yFjw4sd3j7omzgCSMS");
	auto parsed = parseWebRTCDialAddr(addr);
	parsed.isNull.should.equal(false);
	parsed.get.host.should.equal("::1");
	parsed.get.port.should.equal(cast(ushort) 12345);
	parsed.get.fingerprint.should.equal(Fingerprint.raw(EXPECTED));
}

@("non-webrtc / malformed addresses do not parse")
unittest
{
	// Plain TCP address — no webrtc-direct.
	parseWebRTCDialAddr(Multiaddr.parse("/ip4/127.0.0.1/tcp/4001")).isNull.should.equal(true);
	// webrtc-direct without a certhash.
	parseWebRTCDialAddr(Multiaddr.parse("/ip4/127.0.0.1/udp/39901/webrtc-direct"))
		.isNull.should.equal(true);
	// An unexpected trailing component (not /p2p).
	parseWebRTCDialAddr(Multiaddr.parse(
		"/ip4/127.0.0.1/udp/39901/webrtc-direct/certhash/uEiDikp5KVUgkLta1EjUN-IKbHk-dUBg8VzKgf5nXxLK46w/tcp/1")).isNull.should.equal(
		true);
}

// The inbound limiter caps unauthenticated handshakes in flight: at the ceiling
// a new one is refused, and a release frees exactly one slot.
@("webrtc inbound limiter caps in-flight handshakes and frees on release")
unittest
{
	auto lim = InboundLimiter(2);
	lim.tryAcquire().should.equal(true);
	lim.tryAcquire().should.equal(true);
	lim.inFlight.should.equal(2);
	lim.tryAcquire().should.equal(false); // at the ceiling
	lim.release();
	lim.inFlight.should.equal(1);
	lim.tryAcquire().should.equal(true); // the freed slot is reusable
	lim.inFlight.should.equal(2);
}

// Releasing more than was charged must not underflow the count.
@("webrtc inbound limiter does not underflow on an extra release")
unittest
{
	auto lim = InboundLimiter(1);
	lim.release(); // nothing charged
	lim.inFlight.should.equal(0);
	lim.tryAcquire().should.equal(true);
	lim.inFlight.should.equal(1);
}

// A cap of zero means unlimited, matching the swarm limiter's convention.
@("webrtc inbound limiter of zero is unbounded")
unittest
{
	auto lim = InboundLimiter(0);
	foreach (_; 0 .. 500)
		lim.tryAcquire().should.equal(true);
	lim.inFlight.should.equal(500);
}
