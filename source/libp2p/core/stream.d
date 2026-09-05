/**
 * `Stream`: the one byte-oriented surface, presented identically by a TCP
 * socket, a Noise-secured connection and a yamux substream.
 *
 * The semantics are the TCP socket API as Python exposes it: `sendall`,
 * `recv_into`, `close`. Every blocking call ends two ways — with its result,
 * or by throwing an `Ending` (or the owner's `InterruptException`). There is
 * no third outcome: `read` never returns zero for a non-empty buffer, `write`
 * never returns a count, and nothing here answers "is it closed?" as a
 * pre-condition for calling it.
 */
module libp2p.core.stream;

import std.exception : enforce;

import libp2p.core.ending;
import libp2p.multiformats.varint;

interface Stream
{
	/// Read at least one byte into `buf` (at most `buf.length`) and return how
	/// many. Blocks until something arrives. Throws `EndOfStream` when the peer
	/// has finished, `StreamReset`/`ConnClosed` when it went away. Returns 0
	/// only for an empty `buf`.
	size_t read(ubyte[] buf);

	/// Write all of `data`, blocking as needed, or throw.
	void write(const(ubyte)[] data);

	/// Graceful: "I am done, and I will not read any more." Idempotent; never
	/// throws. Data still arriving afterwards is discarded.
	void close() nothrow;

	/// Abortive: tell the peer to abandon whatever was in flight. Idempotent;
	/// never throws.
	void reset() nothrow;
}

/// Fill `buf` completely or throw.
void readExact(Stream s, ubyte[] buf)
{
	while (buf.length > 0)
	{
		immutable n = s.read(buf);
		buf = buf[n .. $];
	}
}

/// One unsigned varint, read a byte at a time (they are at most ten).
ulong readVarint(Stream s)
{
	ubyte[maxVarintLen64] scratch;
	foreach (i; 0 .. maxVarintLen64)
	{
		s.readExact(scratch[i .. i + 1]);
		if ((scratch[i] & 0x80) == 0)
			return decodeVarint(scratch[0 .. i + 1]).value;
	}
	throw new Exception("varint: longer than 10 bytes");
}

/// A varint length followed by that many bytes. `maxLength` bounds what a peer
/// can make us allocate.
ubyte[] readLengthPrefixed(Stream s, size_t maxLength)
{
	immutable len = s.readVarint;
	enforce(len <= maxLength, "length-prefixed frame exceeds the limit");
	auto out_ = new ubyte[cast(size_t) len];
	s.readExact(out_);
	return out_;
}

/// The counterpart: one write carrying the length and the payload together.
void writeLengthPrefixed(Stream s, const(ubyte)[] payload)
{
	ubyte[maxVarintLen64] scratch;
	s.write(encodeVarintInto(payload.length, scratch[]) ~ payload);
}
