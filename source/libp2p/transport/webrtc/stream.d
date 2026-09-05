/**
 * A libp2p stream over one data channel: frames carrying payload and flags,
 * the state machine deciding what each half may still do. `close()` sends FIN;
 * `reset()` sends RESET. A peer's FIN ends our reads once the buffered bytes
 * are handed over; its RESET ends everything at once.
 */
module libp2p.transport.webrtc.stream;

import std.algorithm.comparison : min;

import libp2p.core.ending;
import libp2p.core.stream : Stream;
import libp2p.transport.webrtc.state;
import libp2p.transport.webrtc.wire;

public import libp2p.transport.webrtc.wire : MAX_DATA_LEN, MAX_MSG_LEN;

final class WebRtcStream : Stream
{
	private FramedDc framed;
	private Stream underlying;
	private State state;
	private ubyte[] buffer; /// payload received, not yet read
	private bool localClosed;

	this(Stream dataChannel)
	{
		underlying = dataChannel;
		framed = new FramedDc(dataChannel);
	}

	size_t read(ubyte[] buf)
	{
		if (buf.length == 0)
			return 0;
		while (buffer.length == 0)
		{
			state.readBarrier(); // throws once the read half is closed or reset
			if (state.remoteWriteClosed)
				throw new EndOfStream("webrtc: stream closed by peer");
			auto next = framed.next();
			if (next.isNull)
				throw new EndOfStream("webrtc: data channel ended");
			auto m = next.get;
			if (m.hasFlag)
			{
				state.handleInboundFlag(m.flag, buffer);
				if (m.flag == Flag.RESET)
					continue; // the barrier reports it on the next turn
			}
			buffer ~= m.message;
			if (buffer.length == 0 && state.remoteWriteClosed)
				throw new EndOfStream("webrtc: stream closed by peer");
		}
		immutable n = min(buf.length, buffer.length);
		buf[0 .. n] = buffer[0 .. n];
		buffer = buffer[n .. $];
		return n;
	}

	void write(const(ubyte)[] data)
	{
		state.writeBarrier();
		while (data.length > 0)
		{
			immutable n = min(data.length, MAX_DATA_LEN);
			Message m;
			m.message = data[0 .. n].dup;
			framed.send(m);
			data = data[n .. $];
		}
	}

	/// Send FIN: we are done writing. Idempotent.
	void close() nothrow
	{
		if (localClosed)
			return;
		localClosed = true;
		try
		{
			auto step = state.closeWriteBarrier();
			if (step.isNull)
				return;
			if (step.get == Closing.requested)
			{
				Message m;
				m.flag = Flag.FIN;
				m.hasFlag = true;
				framed.send(m);
				state.closeWriteMessageSent();
			}
			state.writeClosed();
		}
		catch (Exception)
		{
		} // already closed, or the channel is gone
	}

	void reset() nothrow
	{
		if (state.isReset)
			return;
		try
		{
			Message m;
			m.flag = Flag.RESET;
			m.hasFlag = true;
			framed.send(m);
		}
		catch (Exception)
		{
		}
		ubyte[] none;
		state.handleInboundFlag(Flag.RESET, none);
		buffer = null;
		localClosed = true;
		underlying.reset();
	}
}
