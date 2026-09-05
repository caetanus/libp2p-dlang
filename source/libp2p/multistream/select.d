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
	immutable header = readMessage(s);
	enforce(header == multistreamHeader, "multistream: peer did not send the header, but '" ~ header ~ "'");
	foreach (i, proto; protocols)
	{
		if (i > 0)
			writeMessage(s, proto);
		immutable answer = readMessage(s);
		if (answer == proto)
			return proto;
		enforce(answer == naToken, "multistream: unexpected answer '" ~ answer ~ "'");
	}
	throw new Exception("multistream: no protocol in common");
}

/// Answer proposals until one is in `supported`; return it.
string negotiateListener(Stream s, const(string)[] supported)
{
	writeMessage(s, multistreamHeader);
	immutable header = readMessage(s);
	enforce(header == multistreamHeader, "multistream: peer did not send the header, but '" ~ header ~ "'");
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
