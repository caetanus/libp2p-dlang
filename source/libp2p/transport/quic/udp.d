/// Drive a QuicConnection over a vibe UDP socket — the "listen to the fd in vibe"
/// facade. A vibe `UDPConnection` is already an eventcore/epoll fd, so a persistent
/// read-loop fiber blocks in `recv` (no polling) and feeds packets to ngtcp2; a vibe
/// `Timer`, re-armed from `conn.timeout`, fires ngtcp2's loss/idle timers. QuicPump is
/// the transport-neutral engine; QuicClient owns a dedicated socket, QuicListener owns
/// one socket and routes datagrams to per-peer pumps. Opt-in behind version(Libp2pQuic).
module libp2p.transport.quic.udp;

version (Libp2pQuic):

import core.time : Duration, MonoTime, seconds;
import vibe.core.core : sleep;

private bool quicTraceOn() nothrow @trusted
{
    import core.stdc.stdlib : getenv;
    static int cached = -1;
    if (cached < 0)
        cached = getenv("LIBP2P_QUIC_TRACE") !is null ? 1 : 0;
    return cached == 1;
}

import vibe.core.net : UDPConnection, NetworkAddress, listenUDP;
import vibe.core.core : runTask, createTimer, Timer;
import vibe.core.sync : LocalManualEvent, createManualEvent, TaskMutex;

import libp2p.crypto.keys : Keypair;
import libp2p.transport.quic.connection : QuicConnection;

// The raw sockaddr bytes QuicConnection.dial/accept take, from a vibe NetworkAddress.
package ubyte[] addrBytes(NetworkAddress na) @trusted
{
    return (cast(const(ubyte)*) na.sockAddr)[0 .. na.sockAddrLen].dup;
}

/// The per-connection engine: pushes whatever the QuicConnection wants to send through
/// a `send` delegate, drives the timer, and signals handshake completion. Transport-
/// neutral (no socket) — a driver feeds it inbound packets via `deliver`.
final class QuicPump
{
    private QuicConnection _conn;
    private void delegate(scope const(ubyte)[]) _send;
    private Timer _timer;
    private LocalManualEvent _handshakeEvent;
    private bool _closed;
    private bool _flushing, _flushAgain; // one flusher at a time (see serviceOut)

    this(QuicConnection conn, void delegate(scope const(ubyte)[]) send)
    {
        _conn = conn;
        _send = send;
        _handshakeEvent = createManualEvent();
        _timer = createTimer(() @trusted nothrow { onTimer(); });
        // A stream write nudges us to flush immediately (same fiber, synchronous).
        _conn.onWantWrite = () @trusted nothrow { serviceOutNothrow(); };
        // The muxer above closes the connection (a swarm close, an error): the
        // pump follows, so its socket drops it from the demux and a handshake
        // waiter is released.
        _conn.onClosed = () @trusted nothrow { try close(); catch (Exception) {} };
        // LIBP2P_QUIC_TRACE=1: ngtcp2's congestion/RTT/loss counters for this
        // connection every 3 s on stderr — the numbers to read when a link is slow.
        if (quicTraceOn())
            runTask(() nothrow {
                try
                {
                    import core.stdc.stdio : fprintf, stderr;
                    while (!_closed)
                    {
                        sleep(3.seconds);
                        if (_closed)
                            break;
                        auto st = _conn.stats();
                        fprintf(stderr, "QUICTRACE cwnd=%llu ssthresh=%llu inflight=%llu srtt=%llums sent=%llu lost=%llu\n",
                            cast(ulong) st.cwnd, cast(ulong) st.ssthresh, cast(ulong) st.inflight,
                            cast(ulong)(st.srttUs / 1000), cast(ulong) st.pktSent, cast(ulong) st.pktLost);
                    }
                }
                catch (Exception)
                {
                }
            });
    }

    /// Send whatever is pending now (e.g. a client's opening Initial).
    void kick()
    {
        serviceOut();
    }

    /// Feed one received QUIC packet in, then flush any response.
    void deliver(scope const(ubyte)[] packet)
    {
        if (_closed)
            return;
        _conn.deliver(packet);
        serviceOut();
    }

    /// Fires once, when this pump is closed (the connection died or was closed).
    void delegate() nothrow onClosed;

    /// One send that never waits (see trySendNow), set by the socket's owner; used for
    /// the terminal CONNECTION_CLOSE. Null = no farewell packet.
    bool delegate(scope const(ubyte)[]) nothrow trySend;

    void waitForHandshake()
    {
        auto ec = _handshakeEvent.emitCount;
        while (!_conn.handshakeComplete)
        {
            if (_closed || _conn.isClosed)
                throw new Exception("quic: connection closed before the handshake completed");
            ec = _handshakeEvent.wait(ec);
        }
    }

    /// Bounded wait: throws if the handshake has not completed within `budget`. The
    /// server-accept path uses this so a stalled inbound handshake (a peer that
    /// sends an Initial and never finishes) is reclaimed, instead of leaking a pump
    /// forever — without the periodic timer ever tearing down a live handshake.
    void waitForHandshake(Duration budget)
    {
        immutable deadline = MonoTime.currTime + budget;
        auto ec = _handshakeEvent.emitCount;
        while (!_conn.handshakeComplete)
        {
            if (_closed || _conn.isClosed)
                throw new Exception("quic: connection closed before the handshake completed");
            immutable rem = deadline - MonoTime.currTime;
            if (rem <= Duration.zero)
                throw new Exception("quic: inbound handshake did not complete in time");
            ec = _handshakeEvent.wait(rem, ec);
        }
    }

    QuicConnection connection()
    {
        return _conn;
    }

    void close()
    {
        if (_closed)
            return;
        _closed = true;
        _conn.onWantWrite = null; // no re-entry into a freed conn
        _conn.onClosed = null;
        _timer.stop();
        _conn.close();
        try
            _handshakeEvent.emit(); // a waiter learns the handshake will never complete
        catch (Exception)
        {
        }
        if (onClosed !is null)
            onClosed();
    }

    // Drain outbound packets, re-arm the loss/idle timer, signal handshake done.
    // Exactly one fiber flushes at a time: a send can block on a full socket
    // buffer (a bulk stream write), and while it waits the reader or the timer
    // would re-enter here — into an ngtcp2 conn mid-write, and into a second
    // concurrent UDP send, which eventcore does not survive. A late comer just
    // asks the flusher to go round again.
    private void serviceOut()
    {
        if (_closed)
            return;
        if (_flushing)
        {
            _flushAgain = true;
            return;
        }
        _flushing = true;
        scope (exit)
            _flushing = false;
        do
        {
            _flushAgain = false;
            _conn.collectOutgoing((scope const(ubyte)[] pkt) { _send(pkt); });
        }
        while (_flushAgain && !_closed);
        if (_closed)
            return;
        if (_conn.handshakeComplete)
            _conn.tuneKeepAlive(); // before timeout(): the new keep-alive deadline must be armed on THIS pass
        immutable due = _conn.timeout();
        if (due == Duration.max)
            _timer.stop();
        else
            _timer.rearm(due < Duration.zero ? Duration.zero : due);
        if (_conn.handshakeComplete)
            _handshakeEvent.emit();
    }

    // serviceOut for nothrow contexts (the wantWrite hook, the timer).
    private void serviceOutNothrow() nothrow
    {
        try
            serviceOut();
        catch (Exception)
        {
        }
    }

    private void onTimer() nothrow
    {
        try
        {
            immutable rv = _conn.handleTimeout();
            if (rv != 0)
            {
                // Terminal (ngtcp2's contract): an idle timeout drops silently; any other
                // ending tells a still-live peer with a CONNECTION_CLOSE, so it stops
                // retransmitting now instead of at its own timeout. Sent BEFORE close()
                // (a dedicated client's socket closes with its pump) through trySend,
                // which never waits — busy lock or full buffer means skip — so the
                // cleanup below is never held up. Best effort.
                if (rv != QuicConnection.idleCloseErr && trySend !is null)
                {
                    ubyte[1500] scratch;
                    try
                    {
                        auto farewell = _conn.terminalPacket(rv, scratch[]);
                        if (farewell.length)
                            cast(void) trySend(farewell);
                    }
                    catch (Exception)
                    {
                    }
                }
                close(); // wake waiters, leave the demux
                return;
            }
            serviceOut();
        }
        catch (Exception)
        {
            // A throw from serviceOut (a send error on a live connection) is not an
            // ngtcp2 ending — those come back as handleTimeout's nonzero result above
            // and close the pump — so the connection is left to its own timers.
        }
    }
}

/// A QUIC client on its own dedicated UDP socket.
/// Send one datagram NOW or not at all: take the socket's send lock only if it is free
/// and hand the kernel the packet with IOMode.immediate (eventcore returns wouldBlock
/// instead of parking when the buffer is full). For a best-effort last packet that
/// must never hold up a close. vibe's UDPConnection has no immediate send and no typed
/// eventcore handle accessor, so the handle is read from its (only) DatagramSocketFD
/// field — checked at compile time, so a vibe-core layout change fails the build
/// instead of silently disabling the farewell.
bool trySendNow(ref UDPConnection udp, TaskMutex lock, scope const(ubyte)[] pkt, NetworkAddress to) nothrow
{
    import eventcore.core : eventDriver;
    import eventcore.driver : DatagramSocketFD, IOMode, IOStatus, RefAddress;

    enum fdFields = () { size_t n; static foreach (T; typeof(UDPConnection.tupleof)) static if (is(T == DatagramSocketFD)) n++; return n; }();
    static assert(fdFields == 1, "UDPConnection no longer has exactly one DatagramSocketFD field");
    DatagramSocketFD fd;
    static foreach (i, T; typeof(udp.tupleof))
        static if (is(T == DatagramSocketFD))
            fd = udp.tupleof[i];
    if (fd == DatagramSocketFD.invalid)
        return false;
    try
    {
        if (!lock.tryLock())
            return false; // another send is in flight: skip rather than wait
        scope (exit)
            lock.unlock();
        bool ok;
        scope addr = new RefAddress(to.sockAddr, to.sockAddrLen);
        eventDriver.sockets.send(fd, pkt, IOMode.immediate, addr,
            (DatagramSocketFD, IOStatus st, size_t n, scope RefAddress) @safe nothrow { ok = st == IOStatus.ok; });
        return ok; // immediate: the callback has already run
    }
    catch (Exception)
    {
        return false;
    }
}

final class QuicClient
{
    private UDPConnection _udp;
    private QuicConnection _conn;
    private QuicPump _pump;
    private NetworkAddress _peer;
    private TaskMutex _sendLock;

    this(Keypair identity, NetworkAddress peer, string bindHost = "127.0.0.1")
    {
        _peer = peer;
        _udp = listenUDP(0, bindHost); // ephemeral local
        // Anything below can throw (dial's TLS/ngtcp2 setup, kick's first send); close
        // the socket then so neither it nor the reader fiber is stranded on a ctor
        // that never returned (the transport's own guard cannot fire in that case).
        scope (failure)
            try
                _udp.close();
            catch (Exception)
            {
            }
        _sendLock = new TaskMutex;
        _conn = QuicConnection.dial(identity, addrBytes(_udp.localAddress), addrBytes(peer));
        _pump = new QuicPump(_conn, &send);
        _pump.trySend = (scope const(ubyte)[] pkt) nothrow => trySendNow(_udp, _sendLock, pkt, _peer);
        // When the muxer above (or an idle/handshake timeout) closes the pump, close
        // OUR udp socket too: otherwise a swarm connection close frees the muxer but
        // leaks this socket and its recv-parked reader fiber until transport shutdown.
        _pump.onClosed = () nothrow { try _udp.close(); catch (Exception) {} };
        runTask(&readLoop);
        _pump.kick(); // opening Initial
    }

    NetworkAddress localAddress()
    {
        return _udp.localAddress;
    }

    private void send(scope const(ubyte)[] pkt)
    {
        auto to = _peer;
        synchronized (_sendLock)
            _udp.send(pkt, &to);
    }

    private void readLoop() nothrow
    {
        ubyte[2048] buf;
        for (;;)
        {
            try
            {
                NetworkAddress from;
                auto pkt = _udp.recv(buf[], &from);
                _pump.deliver(pkt);
            }
            catch (Exception)
            {
                break;
            }
            catch (Error e)
            {
                import libp2p.util.fibers : reportTaskError;
                reportTaskError("quic udp read loop", e);
                break;
            }
        }
    }

    void waitForHandshake()
    {
        _pump.waitForHandshake();
    }

    QuicConnection connection()
    {
        return _conn;
    }

    bool isClosed() nothrow
    {
        return _conn is null ? true : _conn.isClosed;
    }

    void close()
    {
        _pump.close(); // its onClosed closes _udp; explicit close below is idempotent
        try
            _udp.close(); // ends the recv-parked readLoop fiber
        catch (Exception)
        {
        }
    }
}

/// A QUIC server on one UDP socket, routing datagrams to per-peer pumps by source
/// address; `onAccept` fires with each connection once its handshake completes.
final class QuicListener
{
    private UDPConnection _udp;
    private QuicPump[string] _pumps; // keyed by source address
    private Keypair _identity;
    private TaskMutex _sendLock; // one send in flight on the shared socket
    void delegate(QuicConnection, NetworkAddress) nothrow onAccept;

    this(Keypair identity, ushort port, string bindHost = "127.0.0.1")
    {
        _sendLock = new TaskMutex;
        _identity = identity;
        _udp = listenUDP(port, bindHost);
        runTask(&readLoop);
    }

    NetworkAddress localAddress()
    {
        return _udp.localAddress;
    }

    // Build a send delegate bound to one peer — `peer` BY VALUE so each pump captures
    // its own address (a loop-local would be shared across iterations).
    private bool delegate(scope const(ubyte)[]) nothrow trySender(NetworkAddress peer)
    {
        return (scope const(ubyte)[] pkt) nothrow => trySendNow(_udp, _sendLock, pkt, peer);
    }

    private void delegate(scope const(ubyte)[]) sender(NetworkAddress peer)
    {
        return (scope const(ubyte)[] pkt) {
            auto to = peer;
            synchronized (_sendLock)
                _udp.send(pkt, &to);
        };
    }

    private void readLoop() nothrow
    {
        ubyte[2048] buf;
        for (;;)
        {
            NetworkAddress from;
            const(ubyte)[] pkt;
            try
                pkt = _udp.recv(buf[], &from);
            catch (Exception)
                break; // the socket is gone: close() or a real socket error
            // A bad or unacceptable datagram must not stop the listener for every peer:
            // a late 1-RTT packet of a connection that already left the demux (idle
            // expiry) arrives here as a "new peer" and ngtcp2_accept rightly rejects it.
            QuicPump pump;
            QuicConnection conn;
            try
            {
                immutable key = from.toString();
                if (auto p = key in _pumps)
                {
                    p.deliver(pkt);
                    continue;
                }
                // New peer: build a server conn from its first Initial.
                conn = QuicConnection.accept(_identity, pkt, addrBytes(_udp.localAddress), addrBytes(from));
                pump = new QuicPump(conn, sender(from));
                pump.trySend = trySender(from);
                _pumps[key] = pump;
                untrackOnClose(key, pump);
                pump.deliver(pkt);
                spawnAccept(pump, conn, from, onAccept);
            }
            catch (Exception)
            {
                if (pump !is null)
                    try pump.close(); catch (Exception) {} // untrackOnClose drops it from the demux
                else if (conn !is null)
                    conn.close(); // accept() allocated ngtcp2/TLS state; free it
                continue;
            }
            catch (Error e)
            {
                import libp2p.util.fibers : reportTaskError;
                reportTaskError("quic udp read loop", e);
                break;
            }
        }
    }

    // Leave the demux when the pump closes (idle expiry, a swarm close), so a later
    // Initial from the same address starts a fresh connection instead of feeding a
    // dead pump. Identity-checked: a newer pump under the same key stays.
    private void untrackOnClose(string key, QuicPump pump)
    {
        pump.onClosed = () nothrow {
            if (auto p = key in _pumps)
                if (*p is pump)
                    _pumps.remove(key);
        };
    }

    // One call per new peer, so the accept task gets its OWN frame: captured straight
    // from readLoop's loop body, the task would read the NEWEST pump/conn/address after
    // waitForHandshake yields (D shares loop-body locals across iterations).
    private void spawnAccept(QuicPump pump, QuicConnection conn, NetworkAddress peerAddr,
        void delegate(QuicConnection, NetworkAddress) nothrow cb)
    {
        runTask(() nothrow {
            try
            {
                pump.waitForHandshake();
                if (cb !is null)
                    cb(conn, peerAddr);
            }
            catch (Exception)
            {
            }
        });
    }

    void close()
    {
        foreach (p; _pumps.values) // a snapshot: each close removes its own entry (untrackOnClose)
            p.close();
        _udp.close(); // ends the recv-parked readLoop fiber
    }
}

/// Connect to a QUIC server at `peer`, presenting `identity`.
QuicClient connectQuic(Keypair identity, NetworkAddress peer)
{
    return new QuicClient(identity, peer);
}
