/// A REAL QUIC handshake over loopback through the full transport (QuicTransport →
/// QuicPunchSocket listener + QuicClient dialer, driven by the event loop and the
/// pump's expiry timer). The in-memory quic_check bypasses the timer; this test
/// exercises it, so a regression that makes the pump close a live handshake on a
/// timer expiry (as one did) fails HERE instead of silently in an example nobody
/// ran. Opt-in behind version(Libp2pQuic).
///
/// Assertions run AFTER runEventLoop returns — never inside a fiber body.
module tests.transport.quic_handshake_test;

version (Libp2pQuic):

import fluent.asserts;
import core.time : MonoTime, msecs, seconds;
import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;
import libp2p.core.peer_id : PeerId;
import libp2p.crypto.keys : Keypair;
import libp2p.host.host : Host, HostConfig;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.transport.transport : Transport;
import libp2p.transport.quic.transport : QuicTransport;
import libp2p.protocol.ping : Ping, PingConfig;

private __gshared bool g_connected;
private __gshared bool g_pinged;

@("quic: a real listen+dial handshake completes and carries a ping (timer-driven)")
unittest
{
    g_connected = false;
    g_pinged = false;

    runTask(() nothrow {
        try
        {
            HostConfig cfg;
            auto keyB = Keypair.generateEd25519;
            auto hostB = new Host(keyB, cast(Transport[])[], cfg);
            scope (exit)
                hostB.close();
            hostB.swarm.addCapableTransport(new QuicTransport(keyB));
            PingConfig pcB;
            pcB.interval = 200.msecs;
            pcB.timeout = 5.seconds;
            new Ping(hostB, pcB);
            hostB.listen(Multiaddr.parse("/ip4/127.0.0.1/udp/0/quic-v1"));

            auto keyA = Keypair.generateEd25519;
            auto hostA = new Host(keyA, cast(Transport[])[], cfg);
            scope (exit)
                hostA.close();
            hostA.swarm.addCapableTransport(new QuicTransport(keyA));
            PingConfig pc;
            pc.interval = 200.msecs;
            pc.timeout = 5.seconds;
            auto pingA = new Ping(hostA, pc);
            pingA.onResult = (PeerId p, typeof(MonoTime.init - MonoTime.init) rtt) nothrow {
                g_pinged = true;
            };

            hostA.connect(hostB.id, hostB.addrs);
            g_connected = true; // connect() returned: the QUIC handshake completed

            immutable deadline = MonoTime.currTime + 15.seconds;
            while (MonoTime.currTime < deadline && !g_pinged)
                sleep(20.msecs);
        }
        catch (Exception)
        {
        }
        try
            exitEventLoop();
        catch (Exception)
        {
        }
    });
    runEventLoop();

    g_connected.should.equal(true); // the listen+dial QUIC handshake completed
    g_pinged.should.equal(true); // and real libp2p streams flow over it
}
