/**
 * mplex (`/mplex/6.7.0`): the older, simpler muxer. Frames are
 * `varint((id << 3) | flag) varint(len) data`; the flag says what the frame is
 * and which side opened the stream. There is no flow control, so the two
 * ceilings rust puts around that absence are here: at most 128 substreams, and
 * a substream may buffer 32 frames before the connection stops being read —
 * the bytes wait on the wire, not in our heap, and none are lost.
 *
 * Kept for peers that still speak it; yamux is the default.
 */
module libp2p.muxer.mplex;

import std.algorithm.comparison : min;
import std.exception : enforce;

import vibe.core.core : runTask;
import core.time : Duration, seconds;
import vibe.core.sync : LocalManualEvent, createManualEvent, InterruptibleTaskMutex;
import vibe.core.task : Task, InterruptException;

import libp2p.core.ending;
import libp2p.core.stream;
import libp2p.core.upgrade : MuxerFactory;
import libp2p.multiformats.varint;
import libp2p.muxer.muxer;
import libp2p.util.timeout : withTimeout;

enum mplexProtocolId = "/mplex/6.7.0";

/// Bound on a best-effort teardown frame (close/reset), so an unresponsive peer
/// that stopped reading cannot park us on a full socket buffer during close.
private enum Duration teardownWriteTimeout = 3.seconds;
enum size_t maxFrameSize = 1024 * 1024;

enum Flag : ubyte
{
	newStream = 0,
	messageReceiver = 1,
	messageInitiator = 2,
	closeReceiver = 3,
	closeInitiator = 4,
	resetReceiver = 5,
	resetInitiator = 6,
}

struct MplexFrame
{
	ulong id;
	Flag flag;
	ubyte[] payload;
}

/// One frame off the stream. The length is checked before anything is allocated.
MplexFrame readMplexFrame(Stream s)
{
	immutable header = s.readVarint;
	MplexFrame f;
	f.id = header >> 3;
	immutable flag = header & 7;
	enforce(flag <= Flag.resetInitiator, "mplex: unknown frame flag");
	f.flag = cast(Flag) flag;
	immutable len = s.readVarint;
	enforce(len <= maxFrameSize, "mplex: frame exceeds the maximum size");
	f.payload = new ubyte[cast(size_t) len];
	s.readExact(f.payload);
	return f;
}

void writeMplexFrame(Stream s, ulong id, Flag flag, const(ubyte)[] payload)
{
	enforce(payload.length <= maxFrameSize, "mplex: frame exceeds the maximum size");
	ubyte[maxVarintLen64] a, b;
	s.write(encodeVarintInto((id << 3) | flag, a[]) ~ encodeVarintInto(payload.length, b[]) ~ payload);
}

struct MplexConfig
{
	size_t maxSubstreams = 128;
	size_t maxBufferLen = 32; /// frames per substream before the connection stops reading
}

/// A protocol error by the peer; its message is what the application sees.
final class MplexProtocolError : Exception
{
	this(string msg, string file = __FILE__, size_t line = __LINE__) @safe pure nothrow
	{
		super(msg, file, line);
	}
}

private struct Key
{
	ulong id;
	bool ours; /// we opened it
}

final class Mplex : Muxer
{
	private Stream transport;
	private immutable bool initiator;
	private MplexConfig cfg;

	private MplexStream[Key] streams;
	private ulong nextId;
	private MplexStream[] backlog;
	private LocalManualEvent arrived;
	private LocalManualEvent drained; /// a full buffer was read from

	private InterruptibleTaskMutex writeLock;
	private Task reader;
	private bool closed;
	private Exception cause;

	this(Stream transport, bool initiator, MplexConfig cfg = MplexConfig.init)
	{
		this.transport = transport;
		this.initiator = initiator;
		this.cfg = cfg;
		arrived = createManualEvent();
		drained = createManualEvent();
		writeLock = new InterruptibleTaskMutex;
		reader = runTask(&readLoop);
	}

	Stream open()
	{
		return open(null);
	}

	/// The name travels in the NewStream frame; nobody reads it.
	Stream open(string name)
	{
		if (closed)
			throw cause;
		immutable id = nextId++;
		auto s = new MplexStream(this, id, true);
		streams[Key(id, true)] = s;
		sendFrame(id, Flag.newStream, cast(const(ubyte)[]) name);
		return s;
	}

	Stream accept()
	{
		// Streams the peer opened before the session ended are still delivered;
		// the ending is reported once there is nothing left to hand over.
		auto seen = arrived.emitCount;
		while (backlog.length == 0)
		{
			if (closed)
				throw cause;
			seen = arrived.wait(seen);
		}
		auto s = backlog[0];
		backlog = backlog[1 .. $];
		return s;
	}

	void close() nothrow
	{
		if (closed)
			return;
		end(new ConnClosed("mplex: session closed"));
		if (reader != Task.getThis() && reader.running)
		{
			reader.interrupt();
			reader.joinUninterruptible();
		}
		transport.close();
	}

	bool isClosed() nothrow
	{
		return closed;
	}

	size_t openStreams() const @safe pure nothrow
	{
		return streams.length;
	}

	/// Inbound streams opened but not yet accepted. Bounded by the substream cap;
	/// a leak (a reset stream never dropped from here) shows up as unbounded growth.
	size_t backlogLength() const @safe pure nothrow
	{
		return backlog.length;
	}

	private void end(Exception why) nothrow
	{
		if (closed)
			return;
		closed = true;
		cause = why;
		try
		{
			foreach (s; streams)
				s.sessionEnded(why);
		}
		catch (Exception)
		{
		}
		streams = null;
		arrived.emit();
		drained.emit();
	}

	private void readLoop() nothrow
	{
		try
		{
			for (;;)
			{
				// Block — as rust's MaxBufferBehaviour::Block — while any substream
				// holds a full buffer: the bytes stay on the wire.
				auto seen = drained.emitCount;
				while (anyBufferFull())
					seen = drained.wait(seen);
				dispatch(readMplexFrame(transport));
			}
		}
		catch (InterruptException)
			return;
		catch (MplexProtocolError e)
			end(e);
		catch (Exception e)
			end(asConnEnding(e, "mplex"));
		transport.close();
	}

	private bool anyBufferFull()
	{
		foreach (s; streams)
			if (s.buffered.length >= cfg.maxBufferLen)
				return true;
		return false;
	}

	private void dispatch(MplexFrame f)
	{
		final switch (f.flag)
		{
		case Flag.newStream:
			{
				auto key = Key(f.id, false);
				if (key in streams)
					throw new MplexProtocolError("mplex: newStream for an already-open substream");
				// Cap on the accept BACKLOG, not just `streams`: a stream reset
				// before it is accepted stays queued (so the app can still accept it
				// and see the reset), and leaves `streams` — so a peer that
				// opens-then-resets streams a consumer never drains (at its inbound
				// ceiling) would grow the backlog without bound while streams.length
				// stays near zero. Refusing on either count bounds both.
				if (streams.length >= cfg.maxSubstreams || backlog.length >= cfg.maxSubstreams)
				{
					sendFrame(f.id, Flag.resetReceiver, null);
					return;
				}
				auto s = new MplexStream(this, f.id, false);
				streams[key] = s;
				backlog ~= s;
				arrived.emit();
				return;
			}
		case Flag.messageReceiver:
		case Flag.messageInitiator:
			if (auto s = find(f.id, f.flag == Flag.messageReceiver))
				s.onData(f.payload);
			return;
		case Flag.closeReceiver:
		case Flag.closeInitiator:
			if (auto s = find(f.id, f.flag == Flag.closeReceiver))
				s.onClose();
			return;
		case Flag.resetReceiver:
		case Flag.resetInitiator:
			if (auto s = find(f.id, f.flag == Flag.resetReceiver))
				s.onReset();
			return;
		}
	}

	/// A "Receiver" frame from the peer is about a stream we opened.
	private MplexStream find(ulong id, bool aboutOurs)
	{
		auto s = Key(id, aboutOurs) in streams;
		return s is null ? null : *s;
	}

	private void sendFrame(ulong id, Flag flag, const(ubyte)[] payload)
	{
		writeLock.lock();
		scope (exit)
			writeLock.unlock();
		writeMplexFrame(transport, id, flag, payload);
	}

	// A courtesy close/reset frame during teardown: bounded so an unresponsive
	// peer cannot hang us, and swallowed on failure. The interruptible write lock
	// lets the deadline fire even if another writer holds the lock parked in write.
	private void sendBestEffort(ulong id, Flag flag) nothrow
	{
		try
			withTimeout(teardownWriteTimeout, "mplex teardown frame", {
				sendFrame(id, flag, null);
			});
		catch (Exception)
		{
		}
	}

	private void forget(ulong id, bool ours) nothrow
	{
		streams.remove(Key(id, ours));
		drained.emit();
	}
}

private final class MplexStream : Stream
{
	private Mplex conn;
	immutable ulong id;
	immutable bool ours;

	private ubyte[][] buffered; /// frames not yet read
	private bool localClosed, remoteClosed, wasReset;
	private Exception sessionCause;
	private LocalManualEvent changed;

	private this(Mplex conn, ulong id, bool ours)
	{
		this.conn = conn;
		this.id = id;
		this.ours = ours;
		changed = createManualEvent();
	}

	size_t read(ubyte[] buf)
	{
		if (buf.length == 0)
			return 0;
		auto seen = changed.emitCount;
		while (buffered.length == 0)
		{
			if (wasReset)
				throw new StreamReset("mplex: stream reset");
			if (sessionCause !is null)
				throw sessionCause;
			if (localClosed)
				throw new ConnClosed("mplex: stream closed locally");
			if (remoteClosed)
				throw new EndOfStream("mplex: stream closed by peer");
			seen = changed.wait(seen);
		}
		auto front = buffered[0];
		immutable n = min(buf.length, front.length);
		buf[0 .. n] = front[0 .. n];
		if (n == front.length)
		{
			buffered = buffered[1 .. $];
			conn.drained.emit();
		}
		else
			buffered[0] = front[n .. $];
		return n;
	}

	void write(const(ubyte)[] data)
	{
		while (data.length > 0)
		{
			if (wasReset)
				throw new StreamReset("mplex: stream reset");
			if (sessionCause !is null)
				throw sessionCause;
			if (localClosed)
				throw new ConnClosed("mplex: stream closed locally");
			immutable n = min(data.length, maxFrameSize);
			conn.sendFrame(id, ours ? Flag.messageInitiator : Flag.messageReceiver, data[0 .. n]);
			data = data[n .. $];
		}
	}

	void close() nothrow
	{
		if (localClosed || wasReset || sessionCause !is null)
			return;
		localClosed = true;
		conn.sendBestEffort(id, ours ? Flag.closeInitiator : Flag.closeReceiver); // bounded
		buffered = null;
		// Freeing the buffer makes room the session reader may be parked waiting
		// for (it sleeps on `drained` when any substream hits maxBufferLen). forget
		// emits drained, but only runs when the remote half is already closed — so
		// wake the reader here too, or a close while the remote is still open
		// strands the whole session's reader.
		conn.drained.emit();
		if (remoteClosed)
			conn.forget(id, ours);
		changed.emit();
	}

	void reset() nothrow
	{
		if (wasReset || sessionCause !is null)
			return;
		wasReset = true;
		conn.sendBestEffort(id, ours ? Flag.resetInitiator : Flag.resetReceiver); // bounded
		conn.forget(id, ours);
		changed.emit();
	}

	private void onData(ubyte[] payload)
	{
		if (localClosed)
			return; // discarded: we said we would not read any more
		buffered ~= payload;
		changed.emit();
	}

	private void onClose()
	{
		remoteClosed = true;
		if (localClosed)
			conn.forget(id, ours);
		changed.emit();
	}

	private void onReset()
	{
		wasReset = true;
		conn.forget(id, ours);
		changed.emit();
	}

	private void sessionEnded(Exception why) nothrow
	{
		sessionCause = why;
		changed.emit();
	}
}

final class MplexFactory : MuxerFactory
{
	private MplexConfig cfg;

	this(MplexConfig cfg = MplexConfig.init)
	{
		this.cfg = cfg;
	}

	string protocolId()
	{
		return mplexProtocolId;
	}

	Muxer create(Stream secured, bool client)
	{
		return new Mplex(secured, client, cfg);
	}
}
