/**
 * What travels on a webrtc-direct data channel: varint-length-prefixed
 * protobuf `Message`s carrying up to 16 KiB in all, each with an optional flag
 * (FIN, STOP_SENDING, RESET) and an optional payload.
 */
module libp2p.transport.webrtc.wire;

import std.typecons : Nullable, nullable;

import libp2p.core.ending : Ending, EndOfStream;
import libp2p.core.stream;
import libp2p.multiformats.varint;
import libp2p.wire.protobuf;

/// The largest frame, prefix included.
enum size_t MAX_MSG_LEN = 16 * 1024;
private enum size_t VARINT_LEN = 2;
private enum size_t PROTO_OVERHEAD = 5;
/// The most payload one frame can carry.
enum size_t MAX_DATA_LEN = MAX_MSG_LEN - VARINT_LEN - PROTO_OVERHEAD;

struct Message
{
	enum Flag : uint
	{
		FIN = 0,
		STOP_SENDING = 1,
		RESET = 2,
	}

	Flag flag;
	bool hasFlag;
	ubyte[] message;

	ubyte[] encode() const
	{
		Wire w;
		if (hasFlag)
			w.flag = cast(uint) flag;
		w.message = message.dup;
		return libp2p.wire.protobuf.encode(w);
	}

	static Message decode(const(ubyte)[] bytes)
	{
		auto w = libp2p.wire.protobuf.decode!Wire(bytes);
		Message m;
		if (!w.flag.isNull)
		{
			m.flag = cast(Flag) w.flag.get;
			m.hasFlag = true;
		}
		m.message = w.message;
		return m;
	}
}

private struct Wire
{
	@field(1) Nullable!uint flag;
	@field(2) @optional ubyte[] message;
}

/// One frame: varint length, then the protobuf.
ubyte[] encodeFrame(const ref Message m)
{
	auto body_ = m.encode;
	return encodeVarint(body_.length) ~ body_;
}

/// Frames over a byte stream (a data channel).
final class FramedDc
{
	private Stream inner;

	this(Stream inner)
	{
		this.inner = inner;
	}

	void send(const ref Message m)
	{
		inner.write(encodeFrame(m));
	}

	/// The next frame, or null once the stream ended cleanly at a boundary.
	Nullable!Message next()
	{
		ubyte[] body_;
		try
			body_ = inner.readLengthPrefixed(MAX_MSG_LEN);
		catch (EndOfStream)
			return Nullable!Message.init;
		return nullable(Message.decode(body_));
	}
}
