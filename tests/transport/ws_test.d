/// The WebSocket wire (RFC 6455): frame codec + the Upgrade accept-key, checked
/// against the examples in the RFC so the byte layer is provably compatible.
module tests.transport.ws_test;

import fluent.asserts;
import libp2p.transport.ws;

@("ws: Sec-WebSocket-Accept matches the RFC 6455 §1.3 example")
unittest
{
	// key "dGhlIHNhbXBsZSBub25jZQ==" -> accept "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
	wsAcceptFor("dGhlIHNhbXBsZSBub25jZQ==").should.equal("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
}

@("ws: a masked text frame matches the RFC 6455 §5.7 example bytes")
unittest
{
	ubyte[4] key = [0x37, 0xfa, 0x21, 0x3d];
	auto f = wsEncodeFrame(WsOp.text, cast(ubyte[]) "Hello".dup, true, key);
	immutable ubyte[] want = [
		0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58
	];
	(f == want).should.equal(true);
}

@("ws: binary frames round-trip, server-unmasked and client-masked")
unittest
{
	auto payload = cast(ubyte[]) "hello libp2p".dup;

	// server → client: unmasked
	auto f = wsEncodeFrame(WsOp.binary, payload, false, [0, 0, 0, 0]);
	(f[1] & 0x80).should.equal(0); // mask bit clear
	size_t used;
	auto fr = wsDecodeFrame(f, used);
	used.should.equal(f.length);
	fr.op.should.equal(WsOp.binary);
	fr.fin.should.equal(true);
	(cast(string) fr.payload).should.equal("hello libp2p");

	// client → server: masked, decodes back to the same bytes
	ubyte[4] key = [0x11, 0x22, 0x33, 0x44];
	auto fm = wsEncodeFrame(WsOp.binary, payload, true, key);
	(fm[1] & 0x80).should.equal(0x80); // mask bit set
	auto frm = wsDecodeFrame(fm, used);
	(cast(string) frm.payload).should.equal("hello libp2p");
}

@("ws: extended lengths (126 and 127 headers) round-trip")
unittest
{
	// 200 bytes uses the 16-bit length; 70000 uses the 64-bit length
	foreach (n; [size_t(200), size_t(70_000)])
	{
		auto big = new ubyte[](n);
		foreach (i; 0 .. n)
			big[i] = cast(ubyte)(i & 0xFF);
		auto f = wsEncodeFrame(WsOp.binary, big, false, [0, 0, 0, 0]);
		size_t used;
		auto fr = wsDecodeFrame(f, used);
		used.should.equal(f.length);
		fr.payload.length.should.equal(n);
		(fr.payload == big).should.equal(true);
	}
}

@("ws: a truncated frame throws WsIncomplete, not garbage")
unittest
{
	auto f = wsEncodeFrame(WsOp.binary, cast(ubyte[]) "abcdef".dup, false, [0, 0, 0, 0]);
	size_t used;
	// cut the payload short
	({ wsDecodeFrame(f[0 .. $ - 2], used); }).should.throwException!WsIncomplete;
}

@("ws: server handshake response is validated against the expected accept")
unittest
{
	immutable key = "dGhlIHNhbXBsZSBub25jZQ==";
	immutable accept = wsAcceptFor(key);
	auto resp = buildServerUpgrade(accept);
	serverHandshakeOk(resp, accept).should.equal(true);
	serverHandshakeOk(resp, "wrong").should.equal(false);
	serverHandshakeOk("HTTP/1.1 400 Bad Request\r\n\r\n", accept).should.equal(false);
}
