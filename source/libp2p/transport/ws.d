/**
 * WebSocket wire (RFC 6455): the frame codec and the HTTP Upgrade handshake a
 * `/ws` (and, with a TLS layer underneath, `/tls/ws`) transport needs.
 *
 * This is the byte layer only — pure and dependency-light (Phobos SHA-1/base64,
 * no OpenSSL), so it compiles into the Android "lite" build. libp2p's own
 * security (Noise) and multiplexing run ON TOP of the stream this yields, so the
 * WebSocket carries opaque binary frames; the handshake accept-key is the only
 * hashing here. The transport/stream that drives a socket through this codec
 * (and plugs a TLS layer in for `wss`) is built on top of these helpers.
 */
module libp2p.transport.ws;

import std.base64 : Base64;
import std.bitmanip : nativeToBigEndian, bigEndianToNative;
import std.digest.sha : sha1Of;
import std.random : uniform;

/// RFC 6455 §5.2 opcodes. libp2p traffic rides `binary`; the rest are control.
enum WsOp : ubyte
{
	cont = 0x0,
	text = 0x1,
	binary = 0x2,
	close = 0x8,
	ping = 0x9,
	pong = 0xA
}

/// A decoded frame (one FIN-terminated message fragment).
struct WsFrame
{
	WsOp op;
	bool fin;
	ubyte[] payload;
}

/// Thrown by `wsDecodeFrame` when `buf` doesn't yet hold a whole frame — the
/// caller reads more bytes and retries. Not an error.
final class WsIncomplete : Exception
{
	this() @safe nothrow
	{
		super("ws: incomplete frame");
	}
}

/// The magic GUID RFC 6455 §1.3 appends to the client key before hashing.
enum WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// The `Sec-WebSocket-Accept` value for a given `Sec-WebSocket-Key`.
string wsAcceptFor(const(char)[] clientKey) @safe
{
	auto h = sha1Of(clientKey ~ WS_GUID);
	return Base64.encode(h[]);
}

/// A fresh random `Sec-WebSocket-Key` (base64 of 16 random bytes).
string wsClientKey()
{
	ubyte[16] k;
	foreach (ref b; k)
		b = cast(ubyte) uniform(0, 256);
	return Base64.encode(k[]);
}

/// The client's HTTP Upgrade request line + headers (ends with the blank line).
string buildClientUpgrade(const(char)[] host, const(char)[] path, const(char)[] key) @safe
{
	return ("GET " ~ path ~ " HTTP/1.1\r\n"
		~ "Host: " ~ host ~ "\r\n"
		~ "Upgrade: websocket\r\n"
		~ "Connection: Upgrade\r\n"
		~ "Sec-WebSocket-Key: " ~ key ~ "\r\n"
		~ "Sec-WebSocket-Version: 13\r\n"
		~ "\r\n").idup;
}

/// The server's 101 response for an accepted upgrade.
string buildServerUpgrade(const(char)[] acceptKey) @safe
{
	return ("HTTP/1.1 101 Switching Protocols\r\n"
		~ "Upgrade: websocket\r\n"
		~ "Connection: Upgrade\r\n"
		~ "Sec-WebSocket-Accept: " ~ acceptKey ~ "\r\n"
		~ "\r\n").idup;
}

/// Parse a server handshake response: true iff it is a 101 whose
/// `Sec-WebSocket-Accept` header equals `expectedAccept` (case-insensitive
/// header name, exact value).
bool serverHandshakeOk(const(char)[] response, const(char)[] expectedAccept) @safe
{
	import std.string : splitLines, strip, startsWith, indexOf, toLower;

	auto lines = response.splitLines;
	if (lines.length == 0 || lines[0].indexOf("101") < 0)
		return false;
	foreach (line; lines[1 .. $])
	{
		immutable colon = line.indexOf(':');
		if (colon < 0)
			continue;
		if (line[0 .. colon].strip.toLower == "sec-websocket-accept")
			return line[colon + 1 .. $].strip == expectedAccept;
	}
	return false;
}

/// Encode one FIN frame carrying `payload` under opcode `op`. Client→server
/// frames must be masked (RFC 6455 §5.3): pass `masked=true` with a random
/// `maskKey`; server→client frames pass `masked=false`.
ubyte[] wsEncodeFrame(WsOp op, scope const(ubyte)[] payload, bool masked, ubyte[4] maskKey) @safe
{
	ubyte[] f;
	f ~= cast(ubyte)(0x80 | cast(ubyte) op); // FIN + opcode (no RSV, single frame)

	immutable len = payload.length;
	immutable ubyte maskBit = masked ? 0x80 : 0x00;
	if (len < 126)
		f ~= cast(ubyte)(maskBit | cast(ubyte) len);
	else if (len < 0x1_0000)
	{
		f ~= cast(ubyte)(maskBit | 126);
		f ~= nativeToBigEndian(cast(ushort) len)[];
	}
	else
	{
		f ~= cast(ubyte)(maskBit | 127);
		f ~= nativeToBigEndian(cast(ulong) len)[];
	}

	if (masked)
	{
		f ~= maskKey[];
		immutable start = f.length;
		f ~= payload;
		foreach (i; 0 .. len)
			f[start + i] ^= maskKey[i % 4];
	}
	else
		f ~= payload;
	return f;
}

/// A random 4-byte masking key for a client frame.
ubyte[4] wsMaskKey()
{
	ubyte[4] k;
	foreach (ref b; k)
		b = cast(ubyte) uniform(0, 256);
	return k;
}

/// Decode one frame from the front of `buf`, setting `consumed` to its length in
/// bytes. Throws `WsIncomplete` if `buf` doesn't hold a whole frame yet.
WsFrame wsDecodeFrame(scope const(ubyte)[] buf, out size_t consumed) @safe
{
	if (buf.length < 2)
		throw new WsIncomplete;

	immutable fin = (buf[0] & 0x80) != 0;
	immutable op = cast(WsOp)(buf[0] & 0x0F);
	immutable masked = (buf[1] & 0x80) != 0;

	size_t len = buf[1] & 0x7F;
	size_t off = 2;
	if (len == 126)
	{
		if (buf.length < off + 2)
			throw new WsIncomplete;
		ubyte[2] tmp = buf[off .. off + 2];
		len = bigEndianToNative!ushort(tmp);
		off += 2;
	}
	else if (len == 127)
	{
		if (buf.length < off + 8)
			throw new WsIncomplete;
		ubyte[8] tmp = buf[off .. off + 8];
		len = cast(size_t) bigEndianToNative!ulong(tmp);
		off += 8;
	}

	ubyte[4] key;
	if (masked)
	{
		if (buf.length < off + 4)
			throw new WsIncomplete;
		key = buf[off .. off + 4];
		off += 4;
	}

	if (buf.length < off + len)
		throw new WsIncomplete;

	auto payload = buf[off .. off + len].dup;
	if (masked)
		foreach (i; 0 .. len)
			payload[i] ^= key[i % 4];

	consumed = off + len;
	return WsFrame(op, fin, payload);
}
