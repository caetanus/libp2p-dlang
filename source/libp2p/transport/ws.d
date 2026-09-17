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

import std.algorithm.comparison : min;
import std.base64 : Base64;
import std.bitmanip : nativeToBigEndian, bigEndianToNative;
import std.conv : to;
import std.digest.sha : sha1Of;
import std.exception : enforce;
import std.random : uniform;
import std.socket : AddressFamily;
import std.string : indexOf, strip, toLower, splitLines;

import vibe.core.net : resolveHost;

import libp2p.core.ending : ConnClosed, EndOfStream;
import libp2p.core.stream : Stream, readExact;
import libp2p.multiformats.multiaddr : Multiaddr, Component;
import libp2p.transport.tcp : TcpTransport;
import libp2p.transport.transport : Transport, RawConn, Listener, StreamRawConn;

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

/// The TLS layer a `wss` (`/tls/ws`) address needs, kept out of libp2p-core so
/// this transport doesn't force a TLS stack on builds that only dial `/ws`. The
/// app supplies one (e.g. backed by OpenSSL / vibe-stream:tls); `connect` must do
/// a client handshake with SNI set to `sniHost` (the cert is issued for the
/// hostname, not the resolved IP).
interface TlsProvider
{
	Stream connect(Stream inner, string sniHost);
	Stream accept(Stream inner);
}

/// A libp2p byte stream over a WebSocket: it frames every `write` as one binary
/// frame (client-masked per RFC 6455) and reassembles inbound frames into bytes,
/// answering pings and honouring close. Noise + yamux run on top of this, so the
/// frames carry opaque libp2p bytes.
final class WsStream : Stream
{
	private Stream inner;
	private bool client; // client→server frames are masked
	private ubyte[] rbuf; // bytes read from `inner`, not yet decoded
	private ubyte[] pending; // decoded payload not yet returned to the caller
	private bool closed;

	this(Stream inner, bool client) @safe nothrow
	{
		this.inner = inner;
		this.client = client;
	}

	size_t read(ubyte[] buf)
	{
		if (buf.length == 0)
			return 0;
		if (closed)
			throw new ConnClosed("ws: closed locally");
		while (pending.length == 0)
			fillPending(); // reads/handles frames until a data frame lands (or throws)
		immutable n = min(buf.length, pending.length);
		buf[0 .. n] = pending[0 .. n];
		pending = pending[n .. $];
		return n;
	}

	void write(const(ubyte)[] data)
	{
		if (closed)
			throw new ConnClosed("ws: closed locally");
		sendFrame(WsOp.binary, data);
	}

	void close() nothrow
	{
		if (closed)
			return;
		closed = true;
		try
			sendFrame(WsOp.close, null);
		catch (Exception)
		{
		}
		inner.close();
	}

	void reset() nothrow
	{
		closed = true;
		inner.reset();
	}

	private void sendFrame(WsOp op, scope const(ubyte)[] payload)
	{
		ubyte[4] key; // stays [0,0,0,0] for a server frame (unmasked)
		if (client)
			key = wsMaskKey();
		inner.write(wsEncodeFrame(op, payload, client, key));
	}

	// Decode inbound frames until a data frame's payload is buffered in `pending`.
	// Control frames are handled inline: ping → pong, pong → ignore, close → end.
	private void fillPending()
	{
		while (true)
		{
			size_t consumed;
			WsFrame fr;
			try
				fr = wsDecodeFrame(rbuf, consumed);
			catch (WsIncomplete)
			{
				readMore();
				continue;
			}
			rbuf = rbuf[consumed .. $];

			switch (fr.op)
			{
			case WsOp.binary:
			case WsOp.text:
			case WsOp.cont:
				pending ~= fr.payload;
				return;
			case WsOp.ping:
				sendFrame(WsOp.pong, fr.payload);
				break;
			case WsOp.pong:
				break;
			case WsOp.close:
				closed = true;
				try
					sendFrame(WsOp.close, null);
				catch (Exception)
				{
				}
				throw new EndOfStream("ws: peer closed the connection");
			default:
				break; // ignore unknown opcodes
			}
		}
	}

	private void readMore()
	{
		ubyte[4096] tmp;
		immutable n = inner.read(tmp[]);
		rbuf ~= tmp[0 .. n];
	}
}

// --- transport ---------------------------------------------------------------

private bool isWsHost(string name) @safe pure nothrow
{
	return name == "ip4" || name == "ip6" || name == "dns4" || name == "dns6" || name == "dns";
}

private struct WsAddr
{
	string host; // the literal IP or the DNS name (kept for SNI + Host header)
	string hostProto; // ip4 | ip6 | dns4 | dns6 | dns
	ushort port;
	bool hasTls; // /tls before /ws → wss
}

private WsAddr parseWsAddr(const Multiaddr addr) @safe
{
	auto c = addr.components;
	if (c.length >= 2 && c[$ - 1].name == "p2p")
		c = c[0 .. $ - 1]; // the canonical form names who is there; still a ws address
	enforce(c.length >= 3 && c[$ - 1].name == "ws" && c[1].name == "tcp" && isWsHost(c[0].name),
		"ws: not a websocket address: " ~ addr.toString);
	WsAddr w;
	w.host = c[0].text;
	w.hostProto = c[0].name;
	w.port = cast(ushort)((c[1].value[0] << 8) | c[1].value[1]);
	auto mid = c[2 .. $ - 1];
	if (mid.length == 1 && mid[0].name == "tls")
		w.hasTls = true;
	else
		enforce(mid.length == 0, "ws: unexpected components before /ws in " ~ addr.toString);
	return w;
}

// Read an HTTP head (request or response) up to the blank line, a byte at a time.
private string readHttpHead(Stream s)
{
	ubyte[] head;
	ubyte[1] b;
	while (head.length < 8192)
	{
		s.readExact(b[]);
		head ~= b[0];
		if (head.length >= 4 && head[$ - 4 .. $] == cast(const(ubyte)[]) "\r\n\r\n")
			return cast(string) head.idup;
	}
	throw new ConnClosed("ws: HTTP head too long");
}

private string headerValue(string head, string lowerName) @safe
{
	foreach (line; head.splitLines)
	{
		immutable c = line.indexOf(':');
		if (c < 0)
			continue;
		if (line[0 .. c].strip.toLower == lowerName)
			return line[c + 1 .. $].strip.idup;
	}
	return null;
}

/**
 * WebSocket transport. Dials/listens on `/…/tcp/<port>/ws` and, with a
 * `TlsProvider`, `/…/tcp/<port>/tls/ws` (wss). It reuses the TCP transport for
 * the socket, resolves any `/dns*` host itself (keeping the hostname for TLS SNI
 * and the WS Host header — the swarm must not pre-resolve these), runs the RFC
 * 6455 Upgrade, and hands up a `WsStream`; the swarm's own upgrade adds Noise and
 * yamux on top.
 */
final class WsTransport : Transport
{
	private TlsProvider tls;
	private TcpTransport tcp;

	this(TlsProvider tls = null)
	{
		this.tls = tls;
		this.tcp = new TcpTransport;
	}

	bool canHandle(const Multiaddr addr)
	{
		try
		{
			auto c = addr.components;
			if (c.length >= 2 && c[$ - 1].name == "p2p")
				c = c[0 .. $ - 1];
			if (c.length < 3 || c[$ - 1].name != "ws" || c[1].name != "tcp" || !isWsHost(c[0].name))
				return false;
			auto mid = c[2 .. $ - 1];
			if (mid.length == 0)
				return true; // /ws
			if (mid.length == 1 && mid[0].name == "tls")
				return tls !is null; // /tls/ws needs a TLS provider
			return false;
		}
		catch (Exception)
			return false;
	}

	RawConn dial(const Multiaddr remote)
	{
		auto w = parseWsAddr(remote);
		auto base = Multiaddr.parse("/" ~ ipForm(w) ~ "/tcp/" ~ w.port.to!string);
		auto raw = tcp.dial(base);
		Stream inner = raw;
		if (w.hasTls)
		{
			enforce(tls !is null, "ws: /tls/ws needs a TlsProvider");
			inner = tls.connect(raw, w.host); // SNI = the hostname the cert is for
		}
		immutable key = wsClientKey();
		inner.write(cast(const(ubyte)[]) buildClientUpgrade(w.host, "/", key));
		enforce(serverHandshakeOk(readHttpHead(inner), wsAcceptFor(key)),
			"ws: server rejected the upgrade");
		return new StreamRawConn(new WsStream(inner, true), raw.localAddr, Multiaddr(remote.bytes.dup));
	}

	Listener listen(const Multiaddr local)
	{
		auto w = parseWsAddr(local);
		auto base = Multiaddr.parse("/" ~ ipForm(w) ~ "/tcp/" ~ w.port.to!string);
		return new WsListener(tcp.listen(base), tls, w.hasTls);
	}

	// Resolve a /dns* host to an IP for the TCP connect; pass an IP host through.
	private string ipForm(WsAddr w)
	{
		if (w.hostProto == "ip4" || w.hostProto == "ip6")
			return w.hostProto ~ "/" ~ w.host;
		immutable fam = w.hostProto == "dns6" ? AddressFamily.INET6 : AddressFamily.INET;
		auto na = resolveHost(w.host, fam, false);
		immutable proto = na.family == AddressFamily.INET6 ? "ip6" : "ip4";
		return proto ~ "/" ~ na.toAddressString;
	}
}

final class WsListener : Listener
{
	private Listener inner;
	private TlsProvider tls;
	private bool hasTls;

	this(Listener inner, TlsProvider tls, bool hasTls) @safe nothrow
	{
		this.inner = inner;
		this.tls = tls;
		this.hasTls = hasTls;
	}

	RawConn accept()
	{
		auto raw = inner.accept();
		Stream s = raw;
		if (hasTls)
		{
			enforce(tls !is null, "ws: /tls/ws needs a TlsProvider");
			s = tls.accept(raw);
		}
		immutable key = headerValue(readHttpHead(s), "sec-websocket-key");
		enforce(key.length > 0, "ws: client upgrade missing Sec-WebSocket-Key");
		s.write(cast(const(ubyte)[]) buildServerUpgrade(wsAcceptFor(key)));
		return new StreamRawConn(new WsStream(s, false), address(), raw.remoteAddr);
	}

	Multiaddr address()
	{
		return Multiaddr.parse(inner.address.toString ~ (hasTls ? "/tls/ws" : "/ws"));
	}

	void close() nothrow
	{
		inner.close();
	}
}
