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

import webrtc.stun.message : Message, XorMappedAddress, isStunMessage, bindingRequest,
    bindingSuccess, attrXorMappedAddress, TransactionId;

import libp2p.crypto.keys : Keypair;
import libp2p.transport.quic.connection : QuicConnection;
import libp2p.transport.quic.udp : QuicPump, addrBytes;

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
    private QuicPump[string] _pumps; // by source address
    private bool _closed;

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

    // A send delegate bound to one peer (peer BY VALUE, per-pump).
    private void delegate(scope const(ubyte)[]) sender(NetworkAddress peer)
    {
        return (scope const(ubyte)[] pkt) {
            auto to = peer;
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
        catch (Exception)
        {
        }
        auto conn = QuicConnection.dial(_identity, addrBytes(_udp.localAddress), addrBytes(peer));
        auto pump = new QuicPump(conn, sender(peer));
        _pumps[peer.toString()] = pump;
        pump.kick(); // opening Initial toward the peer's mapping
        return pump;
    }

    /// The server side of a punch: open our NAT toward `peer` with a few pads so
    /// the peer's Initial is let in, then wait for that Initial to arrive and the
    /// handshake to complete. Blocks up to `budget`.
    QuicPump punchServer(NetworkAddress peer, Duration budget)
    {
        immutable key = peer.toString();
        // Mark this peer as an EXPECTED punch so the read loop routes its inbound
        // handshake here (via _accepted) rather than firing onInbound and admitting
        // it a second time as an ordinary listener connection.
        _expecting[key] = true;
        scope (exit)
            _expecting.remove(key);
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
                return *p;
            if (MonoTime.currTime - lastPad >= 1500.msecs)
            {
                pad();
                lastPad = MonoTime.currTime;
            }
            ec = _acceptEvent.wait(500.msecs, ec);
        }
        throw new Exception("quic punch: no inbound handshake from " ~ key);
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
                if (auto p = key in _pumps)
                {
                    p.deliver(pkt);
                    continue;
                }
                // A new peer sending QUIC: we are the server of this punch.
                auto conn = QuicConnection.accept(_identity, pkt,
                    addrBytes(_udp.localAddress), addrBytes(from));
                auto pump = new QuicPump(conn, sender(from));
                _pumps[key] = pump;
                pump.deliver(pkt);
                auto peerAddr = from;
                auto inboundConn = conn;
                runTask(() nothrow {
                    try
                    {
                        pump.waitForHandshake();
                        immutable k = peerAddr.toString();
                        if (k in _expecting)
                        {
                            // An expected punch: hand it to the waiting punchServer.
                            _accepted[k] = pump;
                            _acceptEvent.emit();
                        }
                        else if (onInbound !is null)
                            // A plain inbound (this socket is also the listener).
                            onInbound(inboundConn, peerAddr);
                        else
                        {
                            // No listener wired and nobody waiting: keep the old
                            // behaviour so a bare punch socket still resolves.
                            _accepted[k] = pump;
                            _acceptEvent.emit();
                        }
                    }
                    catch (Exception)
                    {
                    }
                });
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
        foreach (p; _pumps)
            p.close();
        _udp.close();
    }
}
