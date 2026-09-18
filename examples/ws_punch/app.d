/// WebSocket punch dial path, D↔D: host A dials host B via swarm.dialPunch on a /ws
/// address — the swarm reuse-dials the underlying TCP socket from A's own ws listen
/// port, then WsTransport runs the identical WebSocket upgrade over it; the resulting
/// connection is upgraded (Noise+Yamux) and admitted, and ping + identify run over it.
/// PASS when the ping round-trips. Exercises the ws leg of hole-punch (TCP reuse-dial
/// + WS handshake); crossing two real NATs is the rig's job. Exit 0 = PASS.
///
///   dub run -c ws-punch-example
module app;

import core.time : Duration, MonoTime, msecs, seconds;
import std.stdio : writeln, stderr, stdout;

import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;

import libp2p.core.peer_id : PeerId;
import libp2p.crypto.keys : Keypair;
import libp2p.host.host : Host, HostConfig;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.transport.ws : WsTransport;
import libp2p.protocol.ping : Ping, PingConfig;
import libp2p.protocol.identify : IdentifyService, IdentifyInfo;

int main()
{
    int result = 1;
    runTask(() nothrow {
        try
        {
            HostConfig cfg;
            cfg.agentVersion = "libp2p-dlang/ws-punch";

            auto keyB = Keypair.generateEd25519;
            auto hostB = new Host(keyB, [new WsTransport], cfg);
            PingConfig pcB;
            pcB.interval = 200.msecs;
            pcB.timeout = 5.seconds;
            new Ping(hostB, pcB);
            new IdentifyService(hostB);
            hostB.listen(Multiaddr.parse("/ip4/127.0.0.1/tcp/0/ws"));

            auto keyA = Keypair.generateEd25519;
            auto hostA = new Host(keyA, [new WsTransport], cfg);
            bool pinged;
            PingConfig pc;
            pc.interval = 200.msecs;
            pc.timeout = 5.seconds;
            auto pingA = new Ping(hostA, pc);
            pingA.onResult = (PeerId p, Duration rtt) { pinged = true; };
            new IdentifyService(hostA);
            // A must be listening on ws so the punch has a port to reuse-dial from.
            hostA.listen(Multiaddr.parse("/ip4/127.0.0.1/tcp/0/ws"));
            writeln("A listen=", hostA.addrs[0].toString, "  B listen=", hostB.addrs[0].toString);

            auto conn = hostA.swarm.dialPunch(hostB.addrs[0], hostB.id);
            writeln("ws punch-dial established, local=", conn.localAddr.toString);

            immutable deadline = MonoTime.currTime + 15.seconds;
            while (MonoTime.currTime < deadline && !pinged)
                sleep(20.msecs);

            if (pinged)
            {
                writeln("PASS: ping over a WebSocket reuse-port punch dial D↔D");
                result = 0;
            }
            else
                writeln("FAIL: no ping");

            hostA.close();
            hostB.close();
        }
        catch (Exception e)
        {
            try
                stderr.writeln("ws-punch error: ", e.msg);
            catch (Exception)
            {
            }
        }
        try
            stdout.flush();
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
    return result;
}
