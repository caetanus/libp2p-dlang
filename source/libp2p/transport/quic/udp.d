/// Drive a QuicConnection over a vibe UDP socket — the "listen to the fd in vibe"
/// facade. A vibe `UDPConnection` is already an eventcore/epoll fd, so a persistent
/// read-loop fiber blocks in `recv` (no polling) and feeds packets to ngtcp2; a vibe
/// `Timer`, re-armed from `conn.timeout`, fires ngtcp2's loss/idle timers. QuicPump is
/// the transport-neutral engine; QuicClient owns a dedicated socket, QuicListener owns
/// one socket and routes datagrams to per-peer pumps. Opt-in behind version(Libp2pQuic).
module libp2p.transport.quic.udp;

version (Libp2pQuic):

import core.time : Duration;

import vibe.core.net : UDPConnection, NetworkAddress, listenUDP;
import vibe.core.core : runTask, createTimer, Timer;
import vibe.core.sync : LocalManualEvent, createManualEvent;

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

    this(QuicConnection conn, void delegate(scope const(ubyte)[]) send)
    {
        _conn = conn;
        _send = send;
        _handshakeEvent = createManualEvent();
        _timer = createTimer(() @trusted nothrow { onTimer(); });
        // A stream write nudges us to flush immediately (same fiber, synchronous).
        _conn.onWantWrite = () @trusted nothrow { serviceOutNothrow(); };
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

    void waitForHandshake()
    {
        auto ec = _handshakeEvent.emitCount;
        while (!_conn.handshakeComplete)
            ec = _handshakeEvent.wait(ec);
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
        _timer.stop();
        _conn.close();
    }

    // Drain outbound packets, re-arm the loss/idle timer, signal handshake done.
    private void serviceOut()
    {
        if (_closed)
            return;
        _conn.collectOutgoing((scope const(ubyte)[] pkt) { _send(pkt); });
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
            _conn.handleTimeout();
            serviceOut();
        }
        catch (Exception)
        {
        }
    }
}

/// A QUIC client on its own dedicated UDP socket.
final class QuicClient
{
    private UDPConnection _udp;
    private QuicConnection _conn;
    private QuicPump _pump;
    private NetworkAddress _peer;

    this(Keypair identity, NetworkAddress peer)
    {
        _peer = peer;
        _udp = listenUDP(0, "127.0.0.1"); // ephemeral local
        _conn = QuicConnection.dial(identity, addrBytes(_udp.localAddress), addrBytes(peer));
        _pump = new QuicPump(_conn, &send);
        runTask(&readLoop);
        _pump.kick(); // opening Initial
    }

    private void send(scope const(ubyte)[] pkt)
    {
        auto to = _peer;
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

    void close()
    {
        _pump.close();
        _udp.close(); // ends the recv-parked readLoop fiber
    }
}

/// A QUIC server on one UDP socket, routing datagrams to per-peer pumps by source
/// address; `onAccept` fires with each connection once its handshake completes.
final class QuicListener
{
    private UDPConnection _udp;
    private QuicPump[string] _pumps; // keyed by source address
    private Keypair _identity;
    void delegate(QuicConnection) nothrow onAccept;

    this(Keypair identity, ushort port)
    {
        _identity = identity;
        _udp = listenUDP(port, "127.0.0.1");
        runTask(&readLoop);
    }

    NetworkAddress localAddress()
    {
        return _udp.localAddress;
    }

    // Build a send delegate bound to one peer — `peer` BY VALUE so each pump captures
    // its own address (a loop-local would be shared across iterations).
    private void delegate(scope const(ubyte)[]) sender(NetworkAddress peer)
    {
        return (scope const(ubyte)[] pkt) { auto to = peer; _udp.send(pkt, &to); };
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
                immutable key = from.toString();
                if (auto p = key in _pumps)
                {
                    p.deliver(pkt);
                    continue;
                }
                // New peer: build a server conn from its first Initial.
                auto conn = QuicConnection.accept(_identity, pkt, addrBytes(_udp.localAddress), addrBytes(from));
                auto pump = new QuicPump(conn, sender(from));
                _pumps[key] = pump;
                pump.deliver(pkt);
                auto cb = onAccept;
                runTask(() nothrow {
                    try
                    {
                        pump.waitForHandshake();
                        if (cb !is null)
                            cb(conn);
                    }
                    catch (Exception)
                    {
                    }
                });
            }
            catch (Exception)
            {
                break;
            }
        }
    }

    void close()
    {
        foreach (p; _pumps)
            p.close();
        _udp.close(); // ends the recv-parked readLoop fiber
    }
}

/// Connect to a QUIC server at `peer`, presenting `identity`.
QuicClient connectQuic(Keypair identity, NetworkAddress peer)
{
    return new QuicClient(identity, peer);
}
