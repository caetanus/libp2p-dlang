module tests.transport.webrtc.sdp_test;

import std.algorithm : canFind, all;
import std.string : startsWith, splitLines;
import libp2p.transport.webrtc.sdp;
import libp2p.transport.webrtc.fingerprint : Fingerprint;
import fluent.asserts;

private enum ubyte[32] FP = [
	0x7D, 0xE3, 0xD8, 0x3F, 0x81, 0xA6, 0x80, 0x59, 0x2A, 0x47, 0x1E, 0x6B, 0x6A, 0xBB, 0x07, 0x47,
	0xAB, 0xD3, 0x53, 0x85, 0xA8, 0x09, 0x3F, 0xDF, 0xE1, 0x12, 0xC1, 0xEE, 0xBB, 0x6C, 0xC6, 0xAC];

@("sdp answer substitutes every placeholder with the connection's values")
unittest
{
	auto sdp = answer("127.0.0.1", cast(ushort) 39901, false, Fingerprint.raw(FP), "someufrag");

	// No placeholder braces survive.
	sdp.canFind('{').should.equal(false);
	sdp.canFind('}').should.equal(false);

	// IPv4 → IP4; ip and port land in the o=/c=/m=/candidate lines.
	sdp.canFind("o=- 0 0 IN IP4 127.0.0.1").should.equal(true);
	sdp.canFind("c=IN IP4 127.0.0.1").should.equal(true);
	sdp.canFind("m=application 39901 UDP/DTLS/SCTP webrtc-datachannel").should.equal(true);
	sdp.canFind(
		"a=candidate:1467250027 1 UDP 1467250027 127.0.0.1 39901 typ host").should.equal(true);

	// ICE ufrag == pwd (spec), fixed ice-lite/passive/sctp/max-message-size lines.
	sdp.canFind("a=ice-ufrag:someufrag").should.equal(true);
	sdp.canFind("a=ice-pwd:someufrag").should.equal(true);
	sdp.canFind("a=ice-lite").should.equal(true);
	sdp.canFind("a=setup:passive").should.equal(true);
	sdp.canFind("a=sctp-port:5000").should.equal(true);
	sdp.canFind("a=max-message-size:16384").should.equal(true);

	// Fingerprint: algorithm + uppercase colon-separated hex.
	sdp.canFind(
		"a=fingerprint:sha-256 7D:E3:D8:3F:81:A6:80:59:2A:47:1E:6B:6A:BB:07:47:AB:D3:53:85:A8:09:3F:DF:E1:12:C1:EE:BB:6C:C6:AC")
		.should.equal(true);
}

@("sdp answer uses IP6 for an IPv6 target")
unittest
{
	auto sdp = answer("::1", cast(ushort) 12345, true, Fingerprint.raw(FP), "u");
	sdp.canFind("o=- 0 0 IN IP6 ::1").should.equal(true);
	sdp.canFind("c=IN IP6 ::1").should.equal(true);
}

@("random ufrag has the spec prefix plus 64 alphanumeric chars")
unittest
{
	auto u = randomUfrag();
	u.startsWith("libp2p+webrtc+v1/").should.equal(true);
	u.length.should.equal("libp2p+webrtc+v1/".length + 64);

	auto suffix = u["libp2p+webrtc+v1/".length .. $];
	suffix.all!(c => (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))
		.should.equal(true);

	// Two draws differ (probabilistically certain over 62^64).
	randomUfrag().should.not.equal(u);
}

@("punch ufrag is deterministic, order-independent, and in the ufrag charset")
unittest
{
	// Two stand-in peer ids (any bytes; punchUfrag hashes them).
	auto a = cast(const(ubyte)[])[0x00, 0x24, 0x08, 0x01, 0x12, 0x20, 0xAA, 0xBB];
	auto b = cast(const(ubyte)[])[0x00, 0x24, 0x08, 0x01, 0x12, 0x20, 0xCC, 0xDD, 0xEE];

	auto u = punchUfrag(a, b);

	// Same shape as randomUfrag: spec prefix + 32 alphanumerics (SHA-256 body).
	u.startsWith("libp2p+webrtc+v1/").should.equal(true);
	u.length.should.equal("libp2p+webrtc+v1/".length + 32);
	auto suffix = u["libp2p+webrtc+v1/".length .. $];
	suffix.all!(c => (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))
		.should.equal(true);

	// Deterministic: same inputs, same string (both peers must derive it alike).
	punchUfrag(a, b).should.equal(u);

	// Order-independent: whichever peer computes it, the pair maps to one ufrag.
	punchUfrag(b, a).should.equal(u);

	// Different peers → different ufrag.
	auto c = cast(const(ubyte)[])[0x00, 0x24, 0x08, 0x01, 0x12, 0x20, 0x11, 0x22];
	punchUfrag(a, c).should.not.equal(u);
}
