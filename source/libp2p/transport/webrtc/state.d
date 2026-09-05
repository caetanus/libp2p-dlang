/**
 * The state of one webrtc-direct stream, as the spec's flags move it: FIN
 * closes the peer's write half (our read), STOP_SENDING closes ours, RESET
 * ends everything and drops what was buffered. Closing our own halves goes
 * through a request → message sent → closed sequence so a close that is
 * interrupted can be resumed.
 *
 * A pure state machine; the checks return by throwing `StreamStateException`
 * with the kind the caller decides on.
 */
module libp2p.transport.webrtc.state;

import std.typecons : Nullable, nullable;

import libp2p.core.ending : Ending;

public import libp2p.transport.webrtc.wire : Message;

alias Flag = Message.Flag;

enum IoErrorKind
{
	brokenPipe,
	connectionReset,
	other,
}

final class StreamStateException : Ending
{
	IoErrorKind kind;

	this(IoErrorKind kind, string msg, string file = __FILE__, size_t line = __LINE__) @safe nothrow
	{
		this.kind = kind;
		super(msg, null, file, line);
	}
}

enum Closing
{
	requested,
	messageSent,
}

struct State
{
	private enum Kind
	{
		open,
		readClosed,
		writeClosed,
		closingRead,
		closingWrite,
		bothClosed,
	}

	private Kind kind;
	private bool otherClosed; /// closingRead: write already closed; closingWrite: read already closed
	private Closing inner;
	private bool reset;

	void handleInboundFlag(Flag flag, ref ubyte[] buffer) @safe pure nothrow
	{
		final switch (flag)
		{
		case Flag.FIN:
			if (kind == Kind.open)
				kind = Kind.readClosed;
			else if (kind == Kind.writeClosed)
				both(false);
			break;
		case Flag.STOP_SENDING:
			if (kind == Kind.open)
				kind = Kind.writeClosed;
			else if (kind == Kind.readClosed)
				both(false);
			break;
		case Flag.RESET:
			buffer.length = 0;
			both(true);
			break;
		}
	}

	private void both(bool byReset) @safe pure nothrow
	{
		kind = Kind.bothClosed;
		reset = byReset;
	}

	/// Flags must still be read while writing once our read half is closed.
	bool readFlagsInAsyncWrite() const @safe pure nothrow
	{
		return kind == Kind.readClosed;
	}

	void readBarrier() const @safe
	{
		final switch (kind)
		{
		case Kind.open:
		case Kind.writeClosed:
			return;
		case Kind.closingWrite:
			if (!otherClosed)
				return;
			throw new StreamStateException(IoErrorKind.brokenPipe, "webrtc: read half is closed");
		case Kind.readClosed:
		case Kind.closingRead:
			throw new StreamStateException(IoErrorKind.brokenPipe, "webrtc: read half is closed");
		case Kind.bothClosed:
			throw new StreamStateException(reset ? IoErrorKind.connectionReset : IoErrorKind.brokenPipe,
				reset ? "webrtc: stream reset" : "webrtc: stream closed");
		}
	}

	void writeBarrier() const @safe
	{
		final switch (kind)
		{
		case Kind.open:
		case Kind.readClosed:
			return;
		case Kind.closingRead:
			if (!otherClosed)
				return;
			throw new StreamStateException(IoErrorKind.brokenPipe, "webrtc: write half is closed");
		case Kind.writeClosed:
		case Kind.closingWrite:
			throw new StreamStateException(IoErrorKind.brokenPipe, "webrtc: write half is closed");
		case Kind.bothClosed:
			throw new StreamStateException(reset ? IoErrorKind.connectionReset : IoErrorKind.brokenPipe,
				reset ? "webrtc: stream reset" : "webrtc: stream closed");
		}
	}

	/// Begin (or resume) closing the write half. Null if it is already closed;
	/// otherwise how far the close has got.
	Nullable!Closing closeWriteBarrier() @safe
	{
		for (;;)
			final switch (kind)
			{
			case Kind.writeClosed:
				return Nullable!Closing.init;
			case Kind.closingWrite:
				return nullable(inner);
			case Kind.open:
				kind = Kind.closingWrite;
				otherClosed = false;
				inner = Closing.requested;
				break;
			case Kind.readClosed:
				kind = Kind.closingWrite;
				otherClosed = true;
				inner = Closing.requested;
				break;
			case Kind.closingRead:
				if (otherClosed)
					throw new StreamStateException(IoErrorKind.brokenPipe, "webrtc: write half is closed");
				throw new StreamStateException(IoErrorKind.other,
					"webrtc: cannot close the write half while closing the read half");
			case Kind.bothClosed:
				throw new StreamStateException(reset ? IoErrorKind.connectionReset : IoErrorKind.brokenPipe,
					reset ? "webrtc: stream reset" : "webrtc: stream closed");
			}
	}

	void closeWriteMessageSent() @safe pure nothrow
	{
		assert(kind == Kind.closingWrite && inner == Closing.requested);
		inner = Closing.messageSent;
	}

	void writeClosed() @safe pure nothrow
	{
		assert(kind == Kind.closingWrite && inner == Closing.messageSent);
		if (otherClosed)
			both(false);
		else
			kind = Kind.writeClosed;
	}

	Nullable!Closing closeReadBarrier() @safe
	{
		for (;;)
			final switch (kind)
			{
			case Kind.readClosed:
				return Nullable!Closing.init;
			case Kind.closingRead:
				return nullable(inner);
			case Kind.open:
				kind = Kind.closingRead;
				otherClosed = false;
				inner = Closing.requested;
				break;
			case Kind.writeClosed:
				kind = Kind.closingRead;
				otherClosed = true;
				inner = Closing.requested;
				break;
			case Kind.closingWrite:
				if (otherClosed)
					throw new StreamStateException(IoErrorKind.brokenPipe, "webrtc: read half is closed");
				throw new StreamStateException(IoErrorKind.other,
					"webrtc: cannot close the read half while closing the write half");
			case Kind.bothClosed:
				throw new StreamStateException(reset ? IoErrorKind.connectionReset : IoErrorKind.brokenPipe,
					reset ? "webrtc: stream reset" : "webrtc: stream closed");
			}
	}

	void closeReadMessageSent() @safe pure nothrow
	{
		assert(kind == Kind.closingRead && inner == Closing.requested);
		inner = Closing.messageSent;
	}

	void readClosed() @safe pure nothrow
	{
		assert(kind == Kind.closingRead && inner == Closing.messageSent);
		if (otherClosed)
			both(false);
		else
			kind = Kind.readClosed;
	}

	bool isReset() const @safe pure nothrow
	{
		return kind == Kind.bothClosed && reset;
	}

	bool remoteWriteClosed() const @safe pure nothrow
	{
		return kind == Kind.readClosed || kind == Kind.bothClosed || (kind == Kind.closingWrite && otherClosed);
	}
}
