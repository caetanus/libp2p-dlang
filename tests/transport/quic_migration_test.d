/// A QUIC connection survives its peer's NAT rebinding: the client's packets
/// start arriving from a new source port mid-transfer (a 4G CGNAT reassigning the
/// phone's mapping), and the connection must follow — the socket matches the
/// datagrams to their connection by connection id, ngtcp2 validates the new path
/// and migrates, and replies go to the new port. Demuxed by source tuple alone the
/// connection went mute the moment the port changed (2026-09-25, a punched 4G link
/// dead after minutes of bulk transfer). Opt-in behind version(Libp2pQuic).
///
/// Assertions run AFTER runEventLoop returns — never inside a fiber body.
module tests.transport.quic_migration_test;

version (Libp2pQuic):

import fluent.asserts;
import core.time : MonoTime, msecs, seconds;
import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;
import vibe.core.net : UDPConnection, NetworkAddress, listenUDP;

import libp2p.core.ending : EndOfStream;
import libp2p.core.stream : Stream;
import libp2p.crypto.keys : Keypair;
import libp2p.transport.quic.connection : QuicConnection;
import libp2p.transport.quic.punch : QuicPunchSocket;
import libp2p.transport.quic.udp : fromAddrBytes;

/// A NAT on loopback between a client and a server. The client talks to
/// `inside`; its datagrams reach the server from `outside`. A rebind moves one
/// side to a fresh port and closes the old one — the mapping is gone, as when a
/// carrier NAT reassigns a flow:
/// - clientSide: `outside` moves, so the server sees its client at a new port;
/// - serverSide: `inside` moves, so the client sees its server at a new port.
private final class RebindingNat
{
    private UDPConnection _inside, _outside;
    private NetworkAddress _server, _client;
    private bool _haveClient, _closed, _serverSide;
    size_t rebinds;

    this(NetworkAddress server, bool serverSide)
    {
        _server = server;
        _serverSide = serverSide;
        _inside = listenUDP(0, "127.0.0.1");
        _outside = listenUDP(0, "127.0.0.1");
        startInside(_inside);
        startOutside(_outside);
    }

    /// Where the client dials.
    NetworkAddress address()
    {
        return _inside.localAddress;
    }

    /// The port that just moved.
    ushort movedPort()
    {
        return (_serverSide ? _inside : _outside).localAddress.port;
    }

    void rebind()
    {
        if (_serverSide)
        {
            auto old = _inside;
            _inside = listenUDP(0, "127.0.0.1");
            startInside(_inside);
            old.close();
        }
        else
        {
            auto old = _outside;
            _outside = listenUDP(0, "127.0.0.1");
            startOutside(_outside);
            old.close();
        }
        rebinds++;
    }

    void close()
    {
        _closed = true;
        _inside.close();
        _outside.close();
    }

    // One reader per socket, bound to it: after a rebind, the old one's reader
    // ends with it.
    private void startInside(UDPConnection sock)
    {
        runTask((UDPConnection s) nothrow {
            ubyte[2048] buf;
            try
                for (;;)
                {
                    NetworkAddress from;
                    auto pkt = s.recv(buf[], &from);
                    if (_closed)
                        return;
                    _client = from;
                    _haveClient = true;
                    auto to = _server;
                    _outside.send(pkt, &to);
                }
            catch (Exception)
            {
            }
        }, sock);
    }

    private void startOutside(UDPConnection sock)
    {
        runTask((UDPConnection s) nothrow {
            ubyte[2048] buf;
            try
                for (;;)
                {
                    auto pkt = s.recv(buf[]);
                    if (_haveClient && !_closed)
                    {
                        auto to = _client;
                        _inside.send(pkt, &to);
                    }
                }
            catch (Exception)
            {
            }
        }, sock);
    }
}

private struct Outcome
{
    string failure;
    size_t rebinds;
    ulong received;
    bool acked;
    size_t serverPumps = size_t.max;
    ushort peerSeesPort, movedPort;
}

// 12 MiB on one stream, the NAT rebinding every 3 MiB while bytes are queued and
// in the air; then FIN, and one byte back.
private Outcome transferThroughRebinds(bool serverSide)
{
    enum size_t total = 12 * 1024 * 1024;
    enum size_t rebindEvery = 3 * 1024 * 1024;
    Outcome o;

    runTask(() nothrow {
        try
        {
            auto server = new QuicPunchSocket(Keypair.generateEd25519, "127.0.0.1", 0);
            scope (exit)
                server.close();
            QuicConnection serverConn;
            server.onInbound = (QuicConnection conn, NetworkAddress) nothrow {
                serverConn = conn;
                runTask(() nothrow {
                    try
                    {
                        auto s = conn.accept();
                        auto buf = new ubyte[64 * 1024];
                        try
                            for (;;)
                                o.received += s.read(buf);
                        catch (EndOfStream)
                        {
                        }
                        s.write([cast(ubyte) 1]);
                        s.close();
                    }
                    catch (Exception e)
                        o.failure = "server: " ~ e.msg;
                });
            };

            auto nat = new RebindingNat(server.localAddress, serverSide);
            scope (exit)
                nat.close();

            auto client = new QuicPunchSocket(Keypair.generateEd25519, "127.0.0.1", 0);
            scope (exit)
                client.close();
            auto pump = client.punchClient(nat.address);
            pump.waitForHandshake();
            auto s = pump.connection.open();

            // Bounded: a connection that lost its peer would otherwise wait for
            // the idle timeout.
            bool done;
            runTask(() nothrow {
                immutable deadline = MonoTime.currTime + 60.seconds;
                while (!done && MonoTime.currTime < deadline)
                    try
                        sleep(100.msecs);
                    catch (Exception)
                        return;
                if (!done)
                {
                    o.failure = "stalled: the transfer did not finish in 60 s";
                    try
                        pump.close();
                    catch (Exception)
                    {
                    }
                }
            });
            scope (exit)
                done = true;

            auto chunk = new ubyte[64 * 1024];
            size_t sent, sinceRebind;
            while (sent < total)
            {
                s.write(chunk);
                sent += chunk.length;
                sinceRebind += chunk.length;
                if (sinceRebind >= rebindEvery && sent < total)
                {
                    sinceRebind = 0;
                    nat.rebind();
                }
            }
            s.close();
            ubyte[1] ack;
            o.acked = s.read(ack[]) == 1 && ack[0] == 1;
            o.rebinds = nat.rebinds;
            o.serverPumps = server.pumpCount;
            o.movedPort = nat.movedPort;
            // Whoever's peer moved must now be talking to the new port.
            auto watcher = serverSide ? pump.connection : serverConn;
            if (watcher !is null)
            {
                NetworkAddress none;
                auto now = fromAddrBytes(watcher.remoteAddr(), none);
                o.peerSeesPort = now.family ? now.port : 0;
            }
        }
        catch (Exception e)
        {
            if (o.failure.length == 0)
                o.failure = e.msg;
        }
        try
            exitEventLoop();
        catch (Exception)
        {
        }
    });
    runEventLoop();
    return o;
}

@("quic: a connection follows its client through NAT rebindings mid-transfer")
unittest
{
    auto o = transferThroughRebinds(false);
    o.failure.should.equal("");
    o.rebinds.should.equal(3);
    o.received.should.equal(12 * 1024 * 1024);
    o.acked.should.equal(true);
    o.serverPumps.should.equal(1); // the same connection, not a second one per port
    o.peerSeesPort.should.equal(o.movedPort); // the server migrated to the new port
}

// The server's NAT can rebind too: in a hole punch both ends sit behind NATs and
// either may be the QUIC server. QUIC gives a server no way to move; the client
// follows it once an authenticated packet arrives from the new address.
@("quic: a connection follows its server through NAT rebindings mid-transfer")
unittest
{
    auto o = transferThroughRebinds(true);
    o.failure.should.equal("");
    o.rebinds.should.equal(3);
    o.received.should.equal(12 * 1024 * 1024);
    o.acked.should.equal(true);
    o.serverPumps.should.equal(1);
    o.peerSeesPort.should.equal(o.movedPort); // the client now sends to the new port
}
