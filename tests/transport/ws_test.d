/// The WebSocket wire (RFC 6455): frame codec + the Upgrade accept-key, checked
/// against the examples in the RFC so the byte layer is provably compatible.
module tests.transport.ws_test;

import fluent.asserts;
import libp2p.transport.ws;
import libp2p.core.stream : Stream;
import libp2p.core.ending : EndOfStream;
import libp2p.multiformats.multiaddr : Multiaddr;
import std.algorithm.comparison : min;
import tests.util.loop;

// An in-memory duplex: `write` appends to one shared buffer, `read` drains the
// other, so two WsStreams can talk without a socket.
private final class MemStream : Stream
{
	private ubyte[]* outbuf;
	private ubyte[]* inbuf;
	this(ubyte[]* o, ubyte[]* i)
	{
		outbuf = o;
		inbuf = i;
	}

	size_t read(ubyte[] buf)
	{
		if (buf.length == 0)
			return 0;
		if ((*inbuf).length == 0)
			throw new EndOfStream("mem: empty");
		immutable n = min(buf.length, (*inbuf).length);
		buf[0 .. n] = (*inbuf)[0 .. n];
		*inbuf = (*inbuf)[n .. $];
		return n;
	}

	void write(const(ubyte)[] data)
	{
		*outbuf ~= data;
	}

	void close() nothrow {}
	void reset() nothrow {}
}

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

@("ws-stream: bytes round-trip through the framing (client masks, server doesn't)")
unittest
{
	ubyte[] ab, ba; // a→b and b→a
	auto a = new WsStream(new MemStream(&ab, &ba), true); // client
	auto b = new WsStream(new MemStream(&ba, &ab), false); // server

	a.write(cast(ubyte[]) "hello libp2p".dup);
	(ab[1] & 0x80).should.equal(0x80); // client frame is masked

	ubyte[64] buf;
	auto n = b.read(buf[]);
	(cast(string) buf[0 .. n]).should.equal("hello libp2p");

	b.write(cast(ubyte[]) "hi phone".dup);
	(ba[1] & 0x80).should.equal(0); // server frame is unmasked
	n = a.read(buf[]);
	(cast(string) buf[0 .. n]).should.equal("hi phone");
}

@("ws-stream: a ping is answered with a pong and the data still arrives")
unittest
{
	ubyte[] ab, ba;
	auto aInner = new MemStream(&ab, &ba);
	auto a = new WsStream(aInner, true);
	auto b = new WsStream(new MemStream(&ba, &ab), false);

	// client puts a ping ahead of its data (both land in the a→b buffer)
	ubyte[4] k = [1, 2, 3, 4];
	aInner.write(wsEncodeFrame(WsOp.ping, cast(ubyte[]) "ka".dup, true, k));
	a.write(cast(ubyte[]) "data".dup);

	ubyte[16] buf;
	auto n = b.read(buf[]);
	(cast(string) buf[0 .. n]).should.equal("data");

	// the server answered the ping with a pong on the b→a buffer
	(ba.length > 0).should.equal(true);
	size_t used;
	auto pong = wsDecodeFrame(ba, used);
	pong.op.should.equal(WsOp.pong);
	(cast(string) pong.payload).should.equal("ka");
}

@("ws-transport: dial and accept exchange bytes over a real /ws loopback")
unittest
{
	string gotAtServer, gotAtClient;
	Multiaddr bound;

	onLoop({
		auto t = new WsTransport; // no TLS provider → plain /ws
		auto l = t.listen(Multiaddr.parse("/ip4/127.0.0.1/tcp/0/ws"));
		scope (exit)
			l.close();
		bound = l.address;

		auto server = spawn({
			auto c = l.accept();
			scope (exit)
				c.close();
			auto buf = new ubyte[64];
			auto n = c.read(buf);
			gotAtServer = cast(string) buf[0 .. n].idup;
			c.write(cast(const(ubyte)[]) "world");
		});

		auto c = t.dial(bound);
		scope (exit)
			c.close();
		c.write(cast(const(ubyte)[]) "hello");
		auto buf = new ubyte[64];
		auto n = c.read(buf);
		gotAtClient = cast(string) buf[0 .. n].idup;
		server.join();
	});

	gotAtServer.should.equal("hello");
	gotAtClient.should.equal("world");
	bound.toString.should.not.equal("/ip4/127.0.0.1/tcp/0/ws"); // a real port
}

@("ws-transport: dials a /dns4 host, resolving the name (regression: use_dns)")
unittest
{
	import std.string : replace;

	string gotAtServer;
	onLoop({
		auto t = new WsTransport;
		auto l = t.listen(Multiaddr.parse("/ip4/127.0.0.1/tcp/0/ws"));
		scope (exit)
			l.close();
		// same listener, addressed by name: exercises ipForm's /dns resolve path
		auto viaName = l.address.toString.replace("/ip4/127.0.0.1/", "/dns4/localhost/");

		auto server = spawn({
			auto c = l.accept();
			scope (exit)
				c.close();
			auto buf = new ubyte[32];
			auto n = c.read(buf);
			gotAtServer = cast(string) buf[0 .. n].idup;
		});

		auto c = t.dial(Multiaddr.parse(viaName));
		scope (exit)
			c.close();
		c.write(cast(const(ubyte)[]) "via-name");
		server.join();
	});

	gotAtServer.should.equal("via-name");
}

// Tracks whether the underlying transport was disposed, for the R5 regression.
private final class CloseTrackMem : Stream
{
	private ubyte[]* outbuf;
	private ubyte[]* inbuf;
	bool wasClosed;
	this(ubyte[]* o, ubyte[]* i)
	{
		outbuf = o;
		inbuf = i;
	}

	size_t read(ubyte[] buf)
	{
		if (buf.length == 0)
			return 0;
		if ((*inbuf).length == 0)
			throw new EndOfStream("mem: empty");
		immutable n = min(buf.length, (*inbuf).length);
		buf[0 .. n] = (*inbuf)[0 .. n];
		*inbuf = (*inbuf)[n .. $];
		return n;
	}

	void write(const(ubyte)[] data)
	{
		*outbuf ~= data;
	}

	void close() nothrow
	{
		wasClosed = true;
	}

	void reset() nothrow {}
}

// R5: receiving a peer CLOSE sets the protocol-closed flag; a later close() must
// still tear the underlying transport down instead of early-returning on it.
@("ws-stream: close() disposes inner even after a peer CLOSE (regression: R5)")
unittest
{
	ubyte[] ab, ba;
	auto clientInner = new CloseTrackMem(&ab, &ba);
	auto serverInner = new CloseTrackMem(&ba, &ab);
	auto client = new WsStream(clientInner, true);
	auto server = new WsStream(serverInner, false);

	client.close(); // sends a CLOSE frame to the server

	// The server reads the peer CLOSE: it flips to protocol-closed and reports EOF.
	ubyte[32] buf;
	bool sawEof;
	try
		server.read(buf[]);
	catch (EndOfStream)
		sawEof = true;
	sawEof.should.equal(true);
	serverInner.wasClosed.should.equal(false); // the peer-CLOSE path did not dispose it

	// Layered cleanup (Noise/yamux) now closes the ws-stream. Before the fix this
	// early-returned on the protocol-closed flag and leaked the transport.
	server.close();
	serverInner.wasClosed.should.equal(true);
}

// S2/S2b: pre-Noise, wsDecodeFrame sees a 63-bit length from an unauthenticated
// peer. A huge length must be refused as a WsProtocolError (an Exception the
// upgrade path catches) — NOT left to exhaust the buffer, and NOT overflow
// off+len into a backwards slice (a RangeError, which is an Error the swarm's
// Exception handlers don't catch, killing the whole process).
@("ws: an oversized frame length is a WsProtocolError, not a process-killing Error (S2/S2b)")
unittest
{
	import std.bitmanip : nativeToBigEndian;

	size_t consumed;

	// S2b: len = ulong.max — the value that overflows off+len. If the fix is
	// missing this raises a RangeError (Error) that escapes this catch and fails
	// the test; with the fix it is a caught WsProtocolError.
	ubyte[] killer = [0x82, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
	bool killerRefused;
	try
		wsDecodeFrame(killer, consumed);
	catch (WsProtocolError)
		killerRefused = true;
	killerRefused.should.equal(true);

	// S2: a large-but-non-overflowing length (1 GiB) — refused before the buffer
	// is committed to accumulating it.
	ubyte[] dos = cast(ubyte[])[0x82, 0x7F] ~ nativeToBigEndian(cast(ulong)(1024UL * 1024 * 1024)).dup;
	bool dosRefused;
	try
		wsDecodeFrame(dos, consumed);
	catch (WsProtocolError)
		dosRefused = true;
	dosRefused.should.equal(true);

	// A frame at the cap is NOT a protocol error (just incomplete without payload).
	ubyte[] atCap = cast(ubyte[])[0x82, 0x7F] ~ nativeToBigEndian(cast(ulong) wsMaxFrameLen).dup;
	bool incomplete;
	try
		wsDecodeFrame(atCap, consumed);
	catch (WsIncomplete)
		incomplete = true;
	incomplete.should.equal(true);
}

// RFC 6455 §5.5: control frames (close/ping/pong) are ≤125 bytes and unfragmented.
// An oversized ping would otherwise force a large allocation + pong echo pre-Noise.
@("ws: an oversized or fragmented control frame is rejected (RFC 6455 §5.5)")
unittest
{
	size_t consumed;
	// ping (0x89) declaring 200 bytes via the 126 form: > 125 -> WsProtocolError.
	ubyte[] bigPing = [0x89, 0x7E, 0x00, 0xC8];
	bool pingRefused;
	try
		wsDecodeFrame(bigPing, consumed);
	catch (WsProtocolError)
		pingRefused = true;
	pingRefused.should.equal(true);

	// a fragmented close (FIN=0, op 0x8) -> WsProtocolError.
	ubyte[] fragClose = [0x08, 0x00];
	bool fragRefused;
	try
		wsDecodeFrame(fragClose, consumed);
	catch (WsProtocolError)
		fragRefused = true;
	fragRefused.should.equal(true);

	// a well-formed small ping (5 bytes, FIN=1) is NOT rejected here.
	ubyte[] okPing = [0x89, 0x05, 'h', 'e', 'l', 'l', 'o'];
	auto fr = wsDecodeFrame(okPing, consumed);
	fr.op.should.equal(WsOp.ping);
}
