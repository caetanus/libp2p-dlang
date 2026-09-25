/**
 * multistream-select 1.0.0: agreeing on a protocol over a fresh stream.
 *
 * Every message is `varint(len) bytes '\n'`. Both sides send the header first;
 * the dialer sends its first proposal in the same write, so a successful
 * negotiation costs one round trip. The listener answers each proposal with
 * the same string (accepted) or `na` (declined). Eager negotiation only: the
 * dialer waits for the answer before using the stream.
 */
module libp2p.multistream.select;

import std.exception : enforce;
import core.time : Duration;

import libp2p.core.stream;
import libp2p.multiformats.varint;

enum multistreamHeader = "/multistream/1.0.0";
enum naToken = "na";

/// A protocol id is at most this long on the wire; a peer sending more is not
/// negotiating.
enum maxMessageLength = 1024;

/// Propose `protocols` in order; return the first the listener accepts.
string negotiateDialer(Stream s, const(string)[] protocols)
{
	enforce(protocols.length > 0, "multistream: nothing to propose");
	s.write(frame(multistreamHeader) ~ frame(protocols[0]));
	expectHeader(s);
	return propose(s, protocols, true);
}

/// Answer proposals until one is in `supported`; return it.
string negotiateListener(Stream s, const(string)[] supported)
{
	writeMessage(s, multistreamHeader);
	expectHeader(s);
	return serve(s, supported);
}

/// The simultaneous-open extension (connections/simopen.md): the id both peers
/// of a TCP hole punch propose first, since each of them dialed and neither
/// is the listener the security handshake needs.
enum simOpenProtocol = "/libp2p/simultaneous-connect";

struct SimOpenResult
{
	string protocol;
	bool initiator; /// we drive the negotiation and the handshake
}

/// Negotiate as a dialer that may be facing another dialer (a TCP simultaneous
/// open). Propose the extension first: a listener declines it with `na` and
/// we go on as the plain dialer. Another dialer echoes it; then both send a
/// random 64-bit nonce as `select:<n>` and the higher one becomes the
/// initiator (it proposes, the other serves), so a single side runs each
/// handshake role. Equal nonces fail the connection, as the spec says.
SimOpenResult negotiateSimOpen(Stream s, const(string)[] protocols)
{
	import std.conv : to;
	import std.random : uniform;
	import std.string : startsWith;

	enforce(protocols.length > 0, "multistream: nothing to propose");
	s.write(frame(multistreamHeader) ~ frame(simOpenProtocol));
	expectHeader(s);
	immutable answer = readMessage(s);
	if (answer == naToken)
		return SimOpenResult(propose(s, protocols, false), true);
	enforce(answer == simOpenProtocol, "multistream: unexpected answer '" ~ answer ~ "'");

	immutable ours = uniform!ulong();
	writeMessage(s, "select:" ~ ours.to!string);
	// The peer may have pipelined proposals before it saw ours; skip to its nonce.
	string msg;
	do
		msg = readMessage(s);
	while (!msg.startsWith("select:"));
	immutable theirs = msg["select:".length .. $].to!ulong;
	enforce(ours != theirs, "multistream: simultaneous open picked the same nonce");
	if (ours > theirs)
	{
		writeMessage(s, "initiator");
		enforce(readMessage(s) == "responder", "multistream: peer did not take the responder role");
		return SimOpenResult(propose(s, protocols, false), true);
	}
	writeMessage(s, "responder");
	enforce(readMessage(s) == "initiator", "multistream: peer did not take the initiator role");
	return SimOpenResult(serve(s, protocols), false);
}

/// Negotiate as the LISTENER of a hole punch that may not have been a
/// simultaneous open after all. DCUtR assigns us the listener role for the
/// direct connection; on a real NAT both connects cross and the peer's dialer
/// proposes to us. But with no NAT in between (one LAN, loopback) our connect
/// may simply have been ACCEPTED by the peer's ordinary listener — two listeners
/// would then wait on each other forever. A dialer pipelines its proposal right
/// behind the header, so: header exchanged and nothing behind it within `grace`
/// means the other side is a listener too, and we propose as the plain dialer.
SimOpenResult negotiateListenerOrDial(Stream s, const(string)[] protocols, Duration grace)
{
	import libp2p.util.timeout : withTimeout, Timeout;
	enforce(protocols.length > 0, "multistream: nothing to serve");
	s.write(frame(multistreamHeader));
	expectHeader(s);
	string first;
	try
		first = withTimeout(grace, "multistream: first proposal", () => readMessage(s));
	catch (Timeout)
		return SimOpenResult(propose(s, protocols, false), true); // a listener accepted us: we drive
	// A peer that is itself a punch dialer may open with the simultaneous-connect
	// extension; we are the listener it hopes for, so decline it and serve.
	if (first == simOpenProtocol)
	{
		writeMessage(s, naToken);
		return SimOpenResult(serve(s, protocols), false);
	}
	foreach (p; protocols)
		if (p == first)
		{
			writeMessage(s, p);
			return SimOpenResult(p, false);
		}
	writeMessage(s, naToken);
	return SimOpenResult(serve(s, protocols), false);
}

private void expectHeader(Stream s)
{
	immutable header = readMessage(s);
	enforce(header == multistreamHeader, "multistream: peer did not send the header, but '" ~ header ~ "'");
}

// The dialer loop: one proposal at a time, the first already on the wire or not.
private string propose(Stream s, const(string)[] protocols, bool firstSent)
{
	foreach (i, proto; protocols)
	{
		if (i > 0 || !firstSent)
			writeMessage(s, proto);
		immutable answer = readMessage(s);
		if (answer == proto)
			return proto;
		enforce(answer == naToken, "multistream: unexpected answer '" ~ answer ~ "'");
	}
	throw new Exception("multistream: no protocol in common");
}

// The listener loop: decline until a proposal is supported.
private string serve(Stream s, const(string)[] supported)
{
	while (true)
	{
		immutable proposal = readMessage(s);
		foreach (p; supported)
			if (p == proposal)
			{
				writeMessage(s, p);
				return p;
			}
		writeMessage(s, naToken);
	}
}

void writeMessage(Stream s, string msg)
{
	s.write(frame(msg));
}

string readMessage(Stream s)
{
	auto bytes = s.readLengthPrefixed(maxMessageLength);
	enforce(bytes.length > 0 && bytes[$ - 1] == '\n', "multistream: message not newline-terminated");
	return (cast(char[]) bytes[0 .. $ - 1]).idup;
}

private ubyte[] frame(string msg) @safe pure nothrow
{
	return encodeVarint(msg.length + 1) ~ cast(const(ubyte)[]) msg ~ cast(ubyte) '\n';
}
