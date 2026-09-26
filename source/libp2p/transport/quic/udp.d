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

/// And back: the NetworkAddress for raw sockaddr bytes (as ngtcp2 names a path's
/// remote). `fallback` when the bytes are not an IPv4/IPv6 sockaddr.
NetworkAddress fromAddrBytes(scope const(ubyte)[] sa, NetworkAddress fallback) @trusted nothrow
{
    import core.sys.posix.netinet.in_ : sockaddr_in, sockaddr_in6;
    import std.socket : AddressFamily;

    if (sa.length < 2)
        return fallback;
    NetworkAddress na;
    immutable fam = (cast(const(ushort)*) sa.ptr)[0];
    immutable want = fam == AddressFamily.INET ? sockaddr_in.sizeof
        : fam == AddressFamily.INET6 ? sockaddr_in6.sizeof : 0;
    if (want == 0 || sa.length < want)
        return fallback;
    (cast(ubyte*) na.sockAddr)[0 .. want] = sa[0 .. want];
    return na;
}

// The raw sockaddr bytes of `na`, without a copy (valid while `na` is).
package const(ubyte)[] sockBytes(return ref NetworkAddress na) @trusted nothrow
{
    return (cast(const(ubyte)*) na.sockAddr)[0 .. na.sockAddrLen];
}

/// Demux by source tuple, with a fallback by connection id: a socket shared by
/// several connections routes each datagram by the address it came from, but a
/// peer's NAT can rebind mid-connection (a 4G CGNAT does; the port changes, the
/// connection ids do not). A datagram from an unknown tuple whose destination
/// connection id belongs to a live connection is that connection's — delivered to
/// it with the new source so ngtcp2 validates and migrates the path — and, once
/// ngtcp2 has moved onto it, the new tuple is remembered as an alias.
package struct PumpDemux
{
    private QuicPump[string] _byTuple; // the tuple each connection started on
    private Moved[string] _moved; // tuples a connection migrated to
    private ulong _movedSeq;
    private enum size_t maxMovesPerPump = 4;

    private static struct Moved
    {
        QuicPump pump;
        ulong seq; // eviction order: the oldest move goes first
    }

    /// The connection for a datagram from tuple `key`, or null.
    ///
    /// The tuple a connection started on is its own. A tuple it later moved to is
    /// only a routing hint: the peer may have moved on again and a new peer may be
    /// using it, so a datagram from one goes to that connection only if it is a
    /// short-header packet carrying one of the connection's ids; anything else
    /// (a new peer's Initial) is left to the connection-id lookup and, failing
    /// that, to accept. And a short-header packet on a started-on tuple that does
    /// not carry the connection's id may belong to another connection whose peer
    /// rebound onto that tuple: the connection-id lookup decides.
    QuicPump find(string key, scope const(ubyte)[] pkt)
    {
        immutable shortHdr = pkt.length && (pkt[0] & 0x80) == 0;
        if (auto q = key in _byTuple)
        {
            if (shortHdr && !(*q).connection.ownsCid(shortDcid(pkt)))
                if (auto other = byConnectionId(pkt))
                    return other;
            return *q;
        }
        if (auto m = key in _moved)
            if (shortHdr && m.pump.connection.ownsCid(shortDcid(pkt)))
                return m.pump;
        return byConnectionId(pkt);
    }

    /// The connection that started on tuple `key` (a connection's own tuple; not
    /// one it moved to), or null.
    inout(QuicPump)* opBinaryRight(string op : "in")(string key) inout
    {
        return key in _byTuple;
    }

    void add(string key, QuicPump pump)
    {
        _byTuple[key] = pump;
    }

    /// Drop every tuple of `pump` (it closed). Identity-checked: a newer pump under
    /// the same tuple stays.
    void remove(QuicPump pump) nothrow
    {
        try
        {
            string[] doomed;
            foreach (k, p; _byTuple)
                if (p is pump)
                    doomed ~= k;
            foreach (k; doomed)
                _byTuple.remove(k);
            doomed = null;
            foreach (k, m; _moved)
                if (m.pump is pump)
                    doomed ~= k;
            foreach (k; doomed)
                _moved.remove(k);
        }
        catch (Exception)
        {
        }
    }

    size_t length() const nothrow @safe
    {
        return _byTuple.length;
    }

    QuicPump[] pumps()
    {
        return _byTuple.values;
    }

    private static const(ubyte)[] shortDcid(return scope const(ubyte)[] pkt)
    {
        // Short headers carry no id length: ours are always 16 bytes (randomCid,
        // and ngtcp2 asks get_new_connection_id for the same length).
        return pkt.length >= 17 ? pkt[1 .. 17] : null;
    }

    /// The live connection a datagram belongs to by its destination connection id;
    /// null if none (a stranger, or a new connection's Initial). One scan over the
    /// socket's connections — a punch socket carries a handful.
    QuicPump byConnectionId(scope const(ubyte)[] pkt)
    {
        import libp2p.transport.quic.ngtcp2 : ngtcp2_version_cid, ngtcp2_pkt_decode_version_cid;

        ngtcp2_version_cid vc;
        if (ngtcp2_pkt_decode_version_cid(&vc, pkt.ptr, pkt.length, 16) != 0 || vc.dcidlen == 0)
            return null;
        auto dcid = vc.dcid[0 .. vc.dcidlen];
        foreach (p; _byTuple.byValue)
            if (p.connection.ownsCid(dcid))
                return p;
        return null;
    }

    /// After `pump` took a datagram from `key`, a tuple it was not demuxed under:
    /// once the connection has moved onto that address, route the tuple straight
    /// to it.
    void noteMoved(string key, QuicPump pump, scope const(ubyte)[] from)
    {
        if (pump.isClosed || !pump.connection.isPeerAt(from))
            return;
        if (auto q = key in _byTuple)
            if (*q is pump)
                return; // its own starting tuple (it moved back)
        string oldest;
        ulong oldestSeq = ulong.max;
        size_t mine;
        foreach (k, m; _moved)
            if (m.pump is pump)
            {
                mine++;
                if (m.seq < oldestSeq)
                {
                    oldestSeq = m.seq;
                    oldest = k;
                }
            }
        if (mine >= maxMovesPerPump && (key in _moved) is null)
            _moved.remove(oldest);
        _moved[key] = Moved(pump, ++_movedSeq);
    }
}

/// The per-connection engine: pushes whatever the QuicConnection wants to send through
/// a `send` delegate, drives the timer, and signals handshake completion. Transport-
/// neutral (no socket) — a driver feeds it inbound packets via `deliver`.
final class QuicPump
{
    private QuicConnection _conn;
    private void delegate(scope const(ubyte)[] pkt, scope const(ubyte)[] to) _send;
    private Timer _timer;
    private LocalManualEvent _handshakeEvent;
    private bool _closed;
    private bool _flushing, _flushAgain; // one flusher at a time (see serviceOut)

    /// `send(pkt, to)`: put one datagram on the wire toward `to` (raw sockaddr bytes,
    /// the path ngtcp2 chose for it; empty = the connection's original peer).
    this(QuicConnection conn, void delegate(scope const(ubyte)[] pkt, scope const(ubyte)[] to) send)
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

    /// Feed one received QUIC packet in, then flush any response. `from` is the
    /// sender's raw sockaddr (see QuicConnection.deliver); empty = the original peer.
    void deliver(scope const(ubyte)[] packet, scope const(ubyte)[] from = null)
    {
        if (_closed)
            return;
        _conn.deliver(packet, from);
        serviceOut();
    }

    /// Fires once, when this pump is closed (the connection died or was closed).
    void delegate() nothrow onClosed;

    /// One send that never waits (see trySendNow), set by the socket's owner; used for
    /// the terminal CONNECTION_CLOSE, toward `to` (raw sockaddr; empty = the original
    /// peer). Null = no farewell packet.
    bool delegate(scope const(ubyte)[] pkt, scope const(ubyte)[] to) nothrow trySend;

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

    bool isClosed() const nothrow @safe
    {
        return _closed;
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
            _conn.collectOutgoing((scope const(ubyte)[] pkt, scope const(ubyte)[] to) { _send(pkt, to); });
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
                            cast(void) trySend(farewell, _conn.remoteAddr());
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
        _pump.trySend = (scope const(ubyte)[] pkt, scope const(ubyte)[] to) nothrow
            => trySendNow(_udp, _sendLock, pkt, fromAddrBytes(to, _peer));
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

    private void send(scope const(ubyte)[] pkt, scope const(ubyte)[] dst)
    {
        auto to = fromAddrBytes(dst, _peer);
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
                _pump.deliver(pkt, sockBytes(from));
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
    private PumpDemux _pumps; // by source address, then by connection id
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

    // Build a send delegate for one peer — `peer` BY VALUE so each pump captures its
    // own address (a loop-local would be shared across iterations). The peer is only
    // the default: each packet goes where ngtcp2's path for it says (a migration).
    private bool delegate(scope const(ubyte)[], scope const(ubyte)[]) nothrow trySender(NetworkAddress peer)
    {
        return (scope const(ubyte)[] pkt, scope const(ubyte)[] to) nothrow
            => trySendNow(_udp, _sendLock, pkt, fromAddrBytes(to, peer));
    }

    private void delegate(scope const(ubyte)[], scope const(ubyte)[]) sender(NetworkAddress peer)
    {
        return (scope const(ubyte)[] pkt, scope const(ubyte)[] dst) {
            auto to = fromAddrBytes(dst, peer);
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
                // By tuple, or — a peer whose NAT rebound — by connection id.
                if (auto p = _pumps.find(key, pkt))
                {
                    p.deliver(pkt, sockBytes(from));
                    _pumps.noteMoved(key, p, sockBytes(from));
                    continue;
                }
                // New peer: build a server conn from its first Initial.
                conn = QuicConnection.accept(_identity, pkt, addrBytes(_udp.localAddress), addrBytes(from));
                pump = new QuicPump(conn, sender(from));
                pump.trySend = trySender(from);
                _pumps.add(key, pump);
                untrackOnClose(pump);
                pump.deliver(pkt, sockBytes(from));
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
    private void untrackOnClose(QuicPump pump)
    {
        pump.onClosed = () nothrow { _pumps.remove(pump); };
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
        foreach (p; _pumps.pumps) // a snapshot: each close removes its own entries (untrackOnClose)
            p.close();
        _udp.close(); // ends the recv-parked readLoop fiber
    }
}

/// Connect to a QUIC server at `peer`, presenting `identity`.
QuicClient connectQuic(Keypair identity, NetworkAddress peer)
{
    return new QuicClient(identity, peer);
}
