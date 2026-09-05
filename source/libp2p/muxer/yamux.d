/**
 * yamux: one session, many streams, one reader.
 *
 * Frame: `version(1) type(1) flags(2) streamId(4) length(4)`, big-endian.
 * Types: Data, WindowUpdate, Ping, GoAway. Flags: SYN, ACK, FIN, RST. Stream
 * ids are odd for the side that dialed, even for the side that listened; 0 is
 * the session. Every stream starts with 256 KiB of receive credit and the
 * peer may not send past it; the receiver returns credit as the application
 * reads.
 *
 * One fiber per session owns demultiplexing: it reads frames, credits stream
 * buffers, wakes readers and writers, answers pings. Its failure is the
 * session's failure: a protocol error sends GoAway and becomes the exception
 * every parked `accept`, `open`, `read` and `write` throws; the transport
 * ending becomes `ConnClosed` the same way. Writers write directly to the
 * transport under a mutex.
 *
 * Hostile input is charged before it is stored: a data frame is refused if its
 * length exceeds the credit we granted, so twelve bytes can never buy a large
 * allocation. Inbound streams past the accept backlog are reset, not queued.
 */
module libp2p.muxer.yamux;

import std.algorithm.comparison : min;

import vibe.core.core : runTask;
import vibe.core.sync : LocalManualEvent, createManualEvent, TaskMutex;
import vibe.core.task : Task, InterruptException;

import libp2p.core.ending;
import libp2p.core.stream;
import libp2p.muxer.muxer;
import libp2p.core.upgrade : MuxerFactory;

enum yamuxProtocolId = "/yamux/1.0.0";

struct YamuxConfig
{
	uint receiveWindow = 256 * 1024; /// per stream, what we let the peer have in flight
	uint maxFrame = 16 * 1024; /// the largest data frame we write
	size_t acceptBacklog = 256; /// inbound streams nobody has accepted yet
}

private enum ubyte version0 = 0;
private enum ubyte typeData = 0, typeWindowUpdate = 1, typePing = 2, typeGoAway = 3;
private enum ushort flagSyn = 0x1, flagAck = 0x2, flagFin = 0x4, flagRst = 0x8;
private enum uint goAwayNormal = 0, goAwayProtocolError = 1, goAwayInternalError = 2;
private enum headerLength = 12;

/// A peer broke the protocol. The message is what the application sees.
final class YamuxProtocolError : Exception
{
	this(string msg, string file = __FILE__, size_t line = __LINE__) @safe pure nothrow
	{
		super(msg, file, line);
	}
}

final class YamuxConn : Muxer
{
	private Stream transport;
	private immutable bool client;
	private YamuxConfig cfg;

	private YamuxStream[uint] streams;
	private uint nextId;
	private uint lastInboundId;

	private YamuxStream[] backlog; // inbound, not yet accepted
	private LocalManualEvent arrived;

	private TaskMutex writeLock;
	private Task reader;

	private bool closed;
	private Exception cause; // why the session ended; thrown to everyone parked

	this(Stream transport, bool client, YamuxConfig cfg = YamuxConfig.init)
	{
		this.transport = transport;
		this.client = client;
		this.cfg = cfg;
		nextId = client ? 1 : 2;
		arrived = createManualEvent();
		writeLock = new TaskMutex;
		reader = runTask(&readLoop);
	}

	// --- Muxer -------------------------------------------------------------------

	Stream open()
	{
		if (closed)
			throw cause;
		immutable id = nextId;
		nextId += 2;
		auto s = new YamuxStream(this, id);
		streams[id] = s;
		sendFrame(typeWindowUpdate, flagSyn, id, 0);
		return s;
	}

	Stream accept()
	{
		auto seen = arrived.emitCount;
		while (backlog.length == 0)
		{
			if (closed)
				throw cause;
			seen = arrived.wait(seen);
		}
		auto s = backlog[0];
		backlog = backlog[1 .. $];
		sendFrame(typeWindowUpdate, flagAck, s.id, 0);
		return s;
	}

	void close() nothrow
	{
		if (closed)
			return;
		end(new ConnClosed("yamux: session closed"), goAwayNormal);
		// The reader is ours: it leaves before close() returns, and it leaves by
		// being interrupted — never by having the socket closed under it. vibe's
		// close() shuts the socket down and drops a reference, but a parked read
		// holds its own, so the descriptor stays registered; cancelling the read
		// afterwards misses it (the connection's handle is already invalid) and a
		// later readable event fires an orphaned callback, which is an assertion
		// inside vibe's event loop. The swarm tests over real sockets fail when
		// this order is reversed; a minimal yamux-only reproduction does not
		// exist, because there the reader's own reference is the last one.
		// Uninterruptible because we are already finishing, and a second
		// interruption here would leave it running, which is the one thing
		// close() promises not to do.
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

	/// Streams currently in the routing table — a leak shows up here.
	size_t openStreams() const @safe pure nothrow
	{
		return streams.length;
	}

	// --- ending the session ---------------------------------------------------------

	/// Mark the session ended with `why`, tell the peer, and wake everyone.
	private void end(Exception why, uint goAwayCode) nothrow
	{
		if (closed)
			return;
		closed = true;
		cause = why;
		try
			sendFrame(typeGoAway, 0, 0, goAwayCode);
		catch (Exception)
		{
		} // the transport may already be gone; the peer will find out
		foreach (s; streams)
			s.sessionEnded(why);
		streams = null;
		backlog = null;
		arrived.emit();
		// The transport is closed by whoever owns the reader's stack at this
		// point: close() after joining it, or the reader itself on its way out.
	}

	// --- the reader ---------------------------------------------------------------

	private void readLoop() nothrow
	{
		try
		{
			ubyte[headerLength] hdr;
			for (;;)
			{
				transport.readExact(hdr[]);
				dispatch(hdr);
			}
		}
		catch (InterruptException)
		{
			// close() told us to leave; it has already ended the session and
			// closes the transport once we are gone.
			return;
		}
		catch (YamuxProtocolError e)
			end(e, goAwayProtocolError);
		catch (Exception e)
		{
			// The transport ending under a session is the connection ending.
			end(asConnEnding(e, "yamux"), goAwayInternalError);
		}
		transport.close();
	}

	private void dispatch(ref const ubyte[headerLength] h)
	{
		if (h[0] != version0)
			throw new YamuxProtocolError("yamux: unknown protocol version");
		immutable type = h[1];
		immutable ushort flags = cast(ushort)((h[2] << 8) | h[3]);
		immutable uint id = (cast(uint) h[4] << 24) | (cast(uint) h[5] << 16) | (cast(uint) h[6] << 8) | h[7];
		immutable uint length = (cast(uint) h[8] << 24) | (cast(uint) h[9] << 16) | (cast(uint) h[10] << 8) | h[11];

		switch (type)
		{
		case typeData:
		case typeWindowUpdate:
			onStreamFrame(type, flags, id, length);
			break;
		case typePing:
			if (flags & flagSyn)
				sendFrame(typePing, flagAck, 0, length);
			break;
		case typeGoAway:
			throw new ConnClosed("yamux: peer sent GoAway");
		default:
			throw new YamuxProtocolError("yamux: unknown frame type");
		}
	}

	private void onStreamFrame(ubyte type, ushort flags, uint id, uint length)
	{
		YamuxStream* s;
		if (flags & flagSyn)
		{
			// A SYN for an id we already have is a reuse; openInbound refuses it.
			s = openInbound(id);
			if (s is null) // refused: backlog full. Stay framed, then move on.
			{
				if (type == typeData)
					drain(length);
				return;
			}
		}
		else
			s = id in streams;

		if (s is null)
		{
			// A stream we no longer (or never) had. Drain to stay framed, within
			// the same bound any stream would have had.
			if (type == typeData)
			{
				if (length > cfg.receiveWindow)
					throw new YamuxProtocolError("yamux: data frame for an unknown stream exceeds the window");
				drain(length);
			}
			return;
		}

		auto stream = *s;
		if (type == typeData)
		{
			if (length > stream.recvWindow)
				throw new YamuxProtocolError("yamux: data frame exceeds the receive window");
			auto payload = new ubyte[length];
			transport.readExact(payload);
			stream.onData(payload);
		}
		else
		{
			if (cast(ulong) stream.sendWindow + length > uint.max)
				throw new YamuxProtocolError("yamux: window update overflows the send window");
			stream.onWindowUpdate(length);
		}

		if (flags & flagRst)
			stream.onReset();
		else if (flags & flagFin)
			stream.onFin();
	}

	/// Validate and register an inbound stream, or return null if it was refused.
	private YamuxStream* openInbound(uint id)
	{
		if (id == 0)
			throw new YamuxProtocolError("yamux: stream id 0 is the session, not a stream");
		immutable peerIsOdd = !client; // the peer dialed if we are the server
		if ((id & 1) != (peerIsOdd ? 1 : 0))
			throw new YamuxProtocolError("yamux: inbound stream id has the wrong parity");
		if (id <= lastInboundId)
			throw new YamuxProtocolError("yamux: inbound stream id is not increasing");
		lastInboundId = id;

		if (backlog.length >= cfg.acceptBacklog)
		{
			sendFrame(typeWindowUpdate, flagRst, id, 0);
			return null;
		}
		auto s = new YamuxStream(this, id);
		streams[id] = s;
		backlog ~= s;
		arrived.emit();
		return id in streams;
	}

	private void drain(uint length)
	{
		ubyte[4096] sink;
		while (length > 0)
		{
			immutable n = min(length, sink.length);
			transport.readExact(sink[0 .. n]);
			length -= n;
		}
	}

	// --- writing --------------------------------------------------------------------

	private void sendFrame(ubyte type, ushort flags, uint id, uint length, const(ubyte)[] payload = null)
	{
		auto buf = new ubyte[headerLength + payload.length];
		buf[0] = version0;
		buf[1] = type;
		buf[2] = cast(ubyte)(flags >> 8);
		buf[3] = cast(ubyte)(flags & 0xff);
		buf[4] = cast(ubyte)(id >> 24);
		buf[5] = cast(ubyte)(id >> 16);
		buf[6] = cast(ubyte)(id >> 8);
		buf[7] = cast(ubyte) id;
		buf[8] = cast(ubyte)(length >> 24);
		buf[9] = cast(ubyte)(length >> 16);
		buf[10] = cast(ubyte)(length >> 8);
		buf[11] = cast(ubyte) length;
		buf[headerLength .. $] = payload;
		writeLock.lock();
		scope (exit)
			writeLock.unlock();
		transport.write(buf);
	}

	private void forget(uint id) nothrow
	{
		streams.remove(id);
	}
}

private final class YamuxStream : Stream
{
	private YamuxConn conn;
	immutable uint id;

	private ubyte[] recvBuf;
	private uint recvWindow; /// credit the peer still has
	private uint consumed; /// read by the application since the last window update
	private uint sendWindow; /// credit the peer has given us

	private bool localClosed; /// we sent FIN
	private bool remoteClosed; /// we got FIN
	private bool wasReset;
	private Exception sessionCause;

	private LocalManualEvent changed;

	private this(YamuxConn conn, uint id)
	{
		this.conn = conn;
		this.id = id;
		recvWindow = conn.cfg.receiveWindow;
		sendWindow = conn.cfg.receiveWindow; // the protocol's initial window, both ways
		changed = createManualEvent();
	}

	// --- Stream --------------------------------------------------------------------

	size_t read(ubyte[] buf)
	{
		if (buf.length == 0)
			return 0;
		auto seen = changed.emitCount;
		while (recvBuf.length == 0)
		{
			if (wasReset)
				throw new StreamReset("yamux: stream reset");
			if (sessionCause !is null)
				throw sessionCause;
			if (localClosed)
				throw new ConnClosed("yamux: stream closed locally");
			if (remoteClosed)
				throw new EndOfStream("yamux: stream closed by peer");
			seen = changed.wait(seen);
		}
		immutable n = min(buf.length, recvBuf.length);
		buf[0 .. n] = recvBuf[0 .. n];
		recvBuf = recvBuf[n .. $];
		credit(cast(uint) n);
		return n;
	}

	void write(const(ubyte)[] data)
	{
		while (data.length > 0)
		{
			auto seen = changed.emitCount;
			while (sendWindow == 0)
			{
				failIfEnded();
				seen = changed.wait(seen);
			}
			failIfEnded();
			immutable n = cast(uint) min(data.length, sendWindow, conn.cfg.maxFrame);
			sendWindow -= n;
			conn.sendFrame(typeData, 0, id, n, data[0 .. n]);
			data = data[n .. $];
		}
	}

	void close() nothrow
	{
		if (localClosed || wasReset || sessionCause !is null)
			return;
		localClosed = true;
		try
			conn.sendFrame(typeWindowUpdate, flagFin, id, 0);
		catch (Exception)
		{
		} // the session is gone; nothing left to tell
		// Whatever the peer still sends is discarded (read() will not hand it
		// over), so give the credit back as if it had been read.
		if (recvBuf.length > 0)
		{
			credit(cast(uint) recvBuf.length);
			recvBuf = null;
		}
		if (remoteClosed)
			conn.forget(id);
		changed.emit();
	}

	void reset() nothrow
	{
		if (wasReset || sessionCause !is null)
			return;
		wasReset = true;
		try
			conn.sendFrame(typeWindowUpdate, flagRst, id, 0);
		catch (Exception)
		{
		}
		conn.forget(id);
		changed.emit();
	}

	// --- driven by the session's reader ------------------------------------------------

	private void onData(ubyte[] payload)
	{
		recvWindow -= cast(uint) payload.length;
		if (localClosed)
		{
			credit(cast(uint) payload.length); // discarded, but the peer paid for it
			return;
		}
		recvBuf ~= payload;
		changed.emit();
	}

	private void onWindowUpdate(uint delta)
	{
		sendWindow += delta;
		changed.emit();
	}

	private void onFin()
	{
		remoteClosed = true;
		if (localClosed)
			conn.forget(id);
		changed.emit();
	}

	private void onReset()
	{
		wasReset = true;
		conn.forget(id);
		changed.emit();
	}

	private void sessionEnded(Exception why) nothrow
	{
		sessionCause = why;
		changed.emit();
	}

	// --- helpers -----------------------------------------------------------------------

	private void failIfEnded()
	{
		if (wasReset)
			throw new StreamReset("yamux: stream reset");
		if (sessionCause !is null)
			throw sessionCause;
		if (localClosed)
			throw new ConnClosed("yamux: stream closed locally");
	}

	/// Return credit to the peer once enough has been consumed to be worth a frame.
	private void credit(uint n) nothrow
	{
		consumed += n;
		if (consumed < conn.cfg.receiveWindow / 2)
			return;
		immutable delta = consumed;
		consumed = 0;
		recvWindow += delta;
		try
			conn.sendFrame(typeWindowUpdate, 0, id, delta);
		catch (Exception)
		{
		} // if the session is gone the reader will learn it its own way
	}
}

/// yamux as the upgrade sees it.
final class YamuxFactory : MuxerFactory
{
	private YamuxConfig cfg;

	this(YamuxConfig cfg = YamuxConfig.init)
	{
		this.cfg = cfg;
	}

	string protocolId()
	{
		return yamuxProtocolId;
	}

	Muxer create(Stream secured, bool client)
	{
		return new YamuxConn(secured, client, cfg);
	}
}
