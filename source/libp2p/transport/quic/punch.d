/// One UDP socket that both learns its server-reflexive address (STUN) and then
/// carries QUIC — the socket-reuse a hole punch needs. A single read loop demuxes
/// STUN replies from QUIC packets (RFC 5389 magic cookie vs QUIC's fixed bit) and
/// routes QUIC to per-peer pumps by source address, exactly like QuicListener but
/// with two extra moves punching requires: initiate a QUIC *client* on this socket
/// (`punchClient`), and open our NAT toward a peer before its Initial arrives
/// (`punchServer`). Opt-in behind version(Libp2pQuic).
module libp2p.transport.quic.punch;

version (Libp2pQuic):

import std.socket : AddressFamily;
import std.string : lastIndexOf;
import std.conv : to;
import std.typecons : Nullable, nullable;
import core.time : Duration, msecs, seconds, MonoTime;

import vibe.core.net : UDPConnection, NetworkAddress, listenUDP, resolveHost;
import vibe.core.core : runTask, sleep;
import vibe.core.sync : LocalManualEvent, createManualEvent, TaskMutex;
import vibe.core.task : InterruptException;

import webrtc.stun.message : Message, XorMappedAddress, isStunMessage, bindingRequest,
    bindingSuccess, attrXorMappedAddress, TransactionId;

import libp2p.crypto.keys : Keypair;
import libp2p.transport.quic.connection : QuicConnection;
import libp2p.transport.quic.udp : QuicPump, PumpDemux, addrBytes, fromAddrBytes, sockBytes, trySendNow;

/// A plausible-QUIC test: QUIC's long and short headers both set the fixed bit
/// (0x40); a NAT-opener pad (a zero byte) does not, so junk never reaches ngtcp2.
private bool looksLikeQuic(scope const(ubyte)[] pkt) @safe pure nothrow @nogc
{
    return pkt.length >= 1 && (pkt[0] & 0x40) != 0;
}

final class QuicPunchSocket
{
    private UDPConnection _udp;
    private Keypair _identity;
    private PumpDemux _pumps; // by source address, then by connection id (a peer that moved)
    private bool _closed;
    /// Inbound handshakes in progress at once; an Initial past this is dropped.
    /// One Initial from a fresh source tuple costs a connection, TLS state, a
    /// timer and a fiber until its handshake completes or times out — this bounds
    /// what a flood of them can pin, and every failure frees its slot.
    size_t maxPendingHandshakes = 64;
    private size_t _pendingHandshakes;

    // STUN: one binding transaction outstanding at a time.
    private LocalManualEvent _stunEvent;
    private TransactionId _pendingTxn;
    private bool _stunWaiting;
    private ubyte[] _stunResult;

    // A waiter for the inbound (server-side) conn from a specific peer.
    private LocalManualEvent _acceptEvent;
    private QuicPump[string] _accepted; // peer addr -> its pump, once accepted
    private bool[string] _expecting; // peers punchServer is actively waiting for
    private TaskMutex _sendLock; // one UDP send in flight per socket (eventcore keeps a single write callback)

    /// Fires for an inbound connection that is NOT an expected punch — i.e. this
    /// socket also serves as the plain QUIC listener when bound to the listen port.
    void delegate(QuicConnection, NetworkAddress) nothrow onInbound;

    this(Keypair identity, string bindHost = "0.0.0.0", ushort bindPort = 0)
    {
        _identity = identity;
        _udp = listenUDP(bindPort, bindHost); // bindPort 0 = ephemeral (standalone punch/STUN)
        _stunEvent = createManualEvent();
        _acceptEvent = createManualEvent();
        _sendLock = new TaskMutex;
        runTask(&readLoop);
    }

    NetworkAddress localAddress()
    {
        return _udp.localAddress;
    }

    // A send delegate for one peer (peer BY VALUE, per-pump). The peer is only the
    // default: each packet goes where ngtcp2's path for it says, so a connection
    // whose peer's NAT rebound follows it to the new port.
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

    // ---- STUN: learn our server-reflexive mapping on this socket ----------------

    /// Probe each STUN server ("host:port") in turn; return the first reflexive
    /// address learned, or null if none answered within `perServer`.
    Nullable!NetworkAddress gatherReflexive(const(string)[] servers, Duration perServer)
    {
        foreach (s; servers)
        {
            auto r = stunOnce(s, perServer);
            if (!r.isNull)
                return r;
        }
        return Nullable!NetworkAddress.init;
    }

    private Nullable!NetworkAddress stunOnce(string server, Duration budget)
    {
        NetworkAddress serverAddr;
        try
        {
            immutable colon = server.lastIndexOf(':');
            if (colon < 0)
                return Nullable!NetworkAddress.init;
            serverAddr = resolveHost(server[0 .. colon], AddressFamily.INET, true);
            serverAddr.port = server[colon + 1 .. $].to!ushort;
        }
        catch (Exception)
            return Nullable!NetworkAddress.init;

        Message m;
        m.typ = bindingRequest;
        m.transactionId = Message.randomTransactionId();
        m.addFingerprint();
        _pendingTxn = m.transactionId;
        _stunResult = null;
        _stunWaiting = true;
        scope (exit)
            _stunWaiting = false;

        immutable deadline = MonoTime.currTime + budget;
        auto encoded = m.encode;
        while (MonoTime.currTime < deadline && _stunResult is null)
        {
            auto ec = _stunEvent.emitCount;
            try
            {
                auto to = serverAddr;
                synchronized (_sendLock)
                    _udp.send(encoded, &to);
            }
            catch (Exception)
            {
                return Nullable!NetworkAddress.init;
            }
            _stunEvent.wait(300.msecs, ec); // resend if no reply this tick
        }

        if (_stunResult is null)
            return Nullable!NetworkAddress.init;
        try
        {
            auto resp = Message.decode(_stunResult);
            if (resp.typ != bindingSuccess || !resp.has(attrXorMappedAddress))
                return Nullable!NetworkAddress.init;
            auto xor = XorMappedAddress.decode(resp.get(attrXorMappedAddress), resp.transactionId);
            if (xor.ip.length != 4)
                return Nullable!NetworkAddress.init; // ipv4 srflx only for now
            auto na = resolveHost(
                xor.ip[0].to!string ~ "." ~ xor.ip[1].to!string ~ "."
                ~ xor.ip[2].to!string ~ "." ~ xor.ip[3].to!string, AddressFamily.INET, false);
            na.port = xor.port;
            return nullable(na);
        }
        catch (Exception)
            return Nullable!NetworkAddress.init;
    }

    // ---- punch: QUIC over the reused socket -------------------------------------

    /// Initiate a QUIC *client* handshake to `peer` on this socket (the dialer
    /// role). Its opening Initial goes out at once; the read loop routes replies.
    QuicPump punchClient(NetworkAddress peer)
    {
        refuseSecond(peer.toString(), false);
        // Open our NAT toward the peer NOW, before the QUIC/TLS setup below (tens
        // to hundreds of ms on a slow device): DCUtR timed this moment so that our
        // first packet leaves our NAT before the peer's first packet reaches it —
        // a NAT that books unsolicited inbound flows (nf_nat with an accept
        // policy) would otherwise map our later send to a fresh port. A 1-byte pad
        // with the fixed bit clear is ignored by the peer's read loop.
        try
        {
            ubyte[1] pad = [0];
            auto to = peer;
            synchronized (_sendLock)
                _udp.send(pad[], &to);
        }
        catch (InterruptException e)
            throw e; // a cancelled punch must unwind, not spin its whole budget
        catch (Exception)
        {
        }
        auto conn = QuicConnection.dial(_identity, addrBytes(_udp.localAddress), addrBytes(peer));
        auto pump = new QuicPump(conn, sender(peer));
        pump.trySend = trySender(peer);
        track(peer.toString(), pump);
        // kick() (the opening Initial send) can throw before the caller's own
        // scope(failure) is armed; close the pump here so it is never left demuxed.
        scope (failure)
            try
                pump.close();
            catch (Exception)
            {
            }
        pump.kick(); // opening Initial toward the peer's mapping
        return pump;
    }

    /// One connection per peer tuple on this socket. The read loop demuxes by the peer's
    /// source address, so a second connection to the same tuple — both sides running a
    /// DCUtR at once, each punching the other — replaced the first in `_pumps`: every
    /// packet of the first went to the second, and when the application closed the
    /// second as a duplicate nothing received the first any more (a live 4G link went
    /// mute both ways 0.6 s after it came up, 2026-09-25). The later punch fails at once
    /// instead; the DCUtR that asked for it finds the direct connection the first one
    /// made (awaitDirect).
    /// When each tracked pump came to be: an unfinished one only counts as an EARLIER
    /// round's leftover once it is old enough — a young one may be this round's handshake
    /// (the peer's Initial can arrive before our own punchServer starts).
    private MonoTime[string] _bornAt;
    private enum staleHandshake = 5.seconds;

    /// Returns true when an inbound handshake of this very round is already in progress
    /// on `key` (punchServer then adopts it through `_accepted` instead of starting over).
    private bool refuseSecond(string key, bool asServer)
    {
        // (a closed pump leaves _pumps by itself: see track)
        auto p = key in _pumps;
        if (p is null)
            return false;
        auto old = *p;
        bool established;
        try
            established = old.connection !is null && old.connection.handshakeComplete();
        catch (Exception)
        {
        }
        if (established)
            throw new Exception("quic punch: a connection to " ~ key ~ " already rides the punch socket");
        auto born = key in _bornAt;
        if (born is null || MonoTime.currTime - *born < staleHandshake)
        {
            // young: this round's own handshake, not a leftover
            if (asServer)
                return true;   // the peer's Initial beat us here: adopt it
            throw new Exception("quic punch: a handshake with " ~ key ~ " is already under way");
        }
        // An attempt still in its handshake long after it began belongs to an EARLIER round
        // (a punch that did not land, waiting out its budget): the new round supersedes it —
        // refusing here left a 4G retry with nothing but that stuck attempt.
        _pumps.remove(old);
        try
            old.close();
        catch (Exception)
        {
        }
        return false;
    }

    // A pump is demuxed by its peer's source tuple until it closes (a connection
    // close by the muxer above, an idle/handshake timeout): then it drops out of
    // every map here, so nothing about a dead connection is kept.
    private void track(string key, QuicPump pump)
    {
        _bornAt[key] = MonoTime.currTime;
        _pumps.add(key, pump);
        pump.onClosed = () nothrow {
            _pumps.remove(pump);
            _bornAt.remove(key);
            if (auto p = key in _accepted)
                if (*p is pump)
                    _accepted.remove(key);
        };
    }

    /// Connections currently demuxed on this socket (diagnostic / tests).
    size_t pumpCount() const nothrow @safe
    {
        return _pumps.length;
    }

    /// The server side of a punch: open our NAT toward `peer` with a few pads so
    /// the peer's Initial is let in, then wait for that Initial to arrive and the
    /// handshake to complete. Blocks up to `budget`.
    QuicPump punchServer(NetworkAddress peer, Duration budget)
    {
        immutable key = peer.toString();
        cast(void) refuseSecond(key, true);   // a young inbound handshake is adopted via _accepted below
        // Mark this peer as an EXPECTED punch so the read loop routes its inbound
        // handshake here (via _accepted) rather than firing onInbound and admitting
        // it a second time as an ordinary listener connection.
        _expecting[key] = true;
        scope (exit)
            _expecting.remove(key);
        // On interrupt/failure while waiting, an authenticated pump may already sit
        // in _accepted (the read loop published it): close and drop it so a cancelled
        // punch does not leave an unowned live connection demuxed forever.
        bool handed;
        scope (failure)
            if (!handed)
                if (auto pp = key in _accepted)
                {
                    auto dead = *pp;
                    _accepted.remove(key);
                    try
                        dead.close();
                    catch (Exception)
                    {
                    }
                }
        // Keep the NAT mapping toward the peer fresh for the WHOLE window (not just a
        // burst at the start): the dialer may fire seconds later (discovery/clock
        // skew), and its Initial only gets in while our mapping is open.
        void pad()
        {
            try
            {
                ubyte[1] p = [0]; // fixed bit clear: skipped by looksLikeQuic
                auto to = peer;
                synchronized (_sendLock)
                    _udp.send(p[], &to);
            }
            catch (InterruptException e)
                throw e; // a cancelled punch must unwind, not spin its whole budget
            catch (Exception)
            {
            }
        }

        immutable deadline = MonoTime.currTime + budget;
        auto lastPad = MonoTime.currTime - 10.seconds;
        auto ec = _acceptEvent.emitCount;
        while (MonoTime.currTime < deadline)
        {
            if (auto p = key in _accepted)
            {
                auto pump = *p;
                _accepted.remove(key); // consumed: handed to the punch, not kept here
                handed = true;
                return pump;
            }
            if (MonoTime.currTime - lastPad >= 1500.msecs)
            {
                pad();
                lastPad = MonoTime.currTime;
            }
            ec = _acceptEvent.wait(500.msecs, ec);
        }
        throw new Exception("quic punch: no inbound handshake from " ~ key);
    }

    // One call per inbound handshake, so the accept task gets its OWN frame. Spawned
    // straight from readLoop it would capture readLoop's loop-body locals, which D
    // shares across iterations: after waitForHandshake yields, the task would see the
    // NEWEST pump/conn/address — concurrent inbounds then handed one connection to
    // onInbound N times and orphaned the rest.
    private void spawnInboundAccept(QuicPump readyPump, QuicConnection readyConn, NetworkAddress peerAddr) nothrow
    {
        try
        runTask(() nothrow {
            bool slotReleased;
            void releaseSlot() nothrow
            {
                if (!slotReleased)
                {
                    slotReleased = true;
                    _pendingHandshakes--;
                }
            }
            scope (exit)
                releaseSlot();
            try
            {
                readyPump.waitForHandshake(90.seconds); // bounded: reclaim a stalled inbound
                // Authenticate BEFORE we hand it off or free the slot: a peer
                // that completes a permissive TLS handshake but whose cert does
                // not bind a libp2p peer id is dropped here, not hoarded.
                cast(void) readyConn.remotePeerId();
                immutable k = peerAddr.toString();
                if (k in _expecting)
                {
                    _accepted[k] = readyPump; // punchServer consumes + removes it
                    _acceptEvent.emit();
                }
                else if (onInbound !is null)
                    onInbound(readyConn, peerAddr); // the swarm's limiter bounds it
                else
                    readyPump.close(); // nobody asked and nobody listens: don't hoard
            }
            catch (Exception)
            {
                try
                    readyPump.close(); // dead / unauthenticated: drop it
                catch (Exception)
                {
                }
            }
        });
        catch (Exception)
        {
            // the accept task never spawned: release the slot and drop the pump
            _pendingHandshakes--;
            try
                readyPump.close();
            catch (Exception)
            {
            }
        }
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
                break; // socket closed
            if (_closed)
                break; // closing: _udp.localAddress may already be invalid below

            // A datagram whose source address has no valid family (a closing socket
            // can surface one) would throw in addrBytes(from) below and kill the
            // read loop; drop it.
            if (from.family != AddressFamily.INET && from.family != AddressFamily.INET6)
                continue;
            try
            {
                if (isStunMessage(pkt))
                {
                    if (_stunWaiting && Message.decode(pkt).transactionId == _pendingTxn)
                    {
                        _stunResult = pkt.dup;
                        _stunEvent.emit();
                    }
                    continue;
                }
                if (!looksLikeQuic(pkt))
                    continue; // NAT-opener pad or junk

                immutable key = from.toString();
                // By tuple, or by connection id: a peer whose NAT rebound (a 4G
                // CGNAT moving the phone to a new port mid-transfer) arrives from a
                // tuple no connection started on. Demuxed by tuple alone, every
                // packet after the move matched nothing and the connection went
                // mute one way; now the connection gets it and follows the peer.
                if (auto p = _pumps.find(key, pkt))
                {
                    p.deliver(pkt, sockBytes(from));
                    _pumps.noteMoved(key, p, sockBytes(from));
                    continue;
                }
                // A new peer sending QUIC: we are the server of this punch. Only so
                // many at a time: an unauthenticated Initial must not pin resources
                // without bound (see maxPendingHandshakes).
                // Charge the pending slot BEFORE constructing anything: an Initial
                // that passes ngtcp2_accept but fails read_pkt (or whose pump throws
                // on first delivery) must not leave an uncounted, timer-less pump
                // rooted in the demux. Rotating source ports otherwise grows _pumps
                // and native ngtcp2/TLS state past the cap.
                if (_pendingHandshakes >= maxPendingHandshakes)
                    continue;
                _pendingHandshakes++;
                QuicPump pump;
                QuicConnection inboundConn;
                try
                {
                    inboundConn = QuicConnection.accept(_identity, pkt,
                        addrBytes(_udp.localAddress), addrBytes(from));
                    pump = new QuicPump(inboundConn, sender(from));
                    pump.trySend = trySender(from);
                    track(key, pump);
                    pump.deliver(pkt, sockBytes(from)); // may throw on a malformed Initial
                }
                catch (Exception)
                {
                    _pendingHandshakes--;
                    if (pump !is null)
                        try
                            pump.close(); // track()'s onClosed drops it from _pumps
                        catch (Exception)
                        {
                        }
                    else if (inboundConn !is null)
                        try
                            inboundConn.close(); // accept() allocated ngtcp2/TLS; free it
                        catch (Exception)
                        {
                        }
                    continue;
                }
                spawnInboundAccept(pump, inboundConn, from);
            }
            catch (Exception)
            {
                // A bad datagram must not kill the socket; drop it and read on.
                continue;
            }
            catch (Error e)
            {
                import libp2p.util.fibers : reportTaskError;
                reportTaskError("quic punch socket read loop", e);
                continue;
            }
        }
    }

    void close()
    {
        if (_closed)
            return;
        _closed = true;
        foreach (p; _pumps.pumps) // a snapshot: each close removes its own entries
            p.close();
        _udp.close();
    }
}
