/// WebSocket (/ws) transport D↔D validation: two real libp2p hosts, the listener on
/// /ip4/127.0.0.1/tcp/0/ws, the dialer connecting over WebSocket, then ping + identify
/// over the connection. Proves the ws transport carries the full stack (multistream →
/// Noise → yamux → ping/identify) both ways. Self-standing: no rust, no external net.
/// Exit 0 = PASS, 1 = FAIL.
///
///   ws-dd
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
            cfg.agentVersion = "libp2p-dlang/ws-dd";

            PingConfig pc;
            pc.interval = 200.msecs;
            pc.timeout = 5.seconds;

            auto keyB = Keypair.generateEd25519;
            auto hostB = new Host(keyB, [new WsTransport], cfg);
            new Ping(hostB, pc); // listener must answer ping + identify
            new IdentifyService(hostB);
            hostB.listen(Multiaddr.parse("/ip4/127.0.0.1/tcp/0/ws"));
            writeln("listener (/ws): ", hostB.addrs[0].toString, " id=", hostB.id.toBase58);

            auto keyA = Keypair.generateEd25519;
            auto hostA = new Host(keyA, [new WsTransport], cfg);

            bool pinged, identified;
            auto pingA = new Ping(hostA, pc);
            pingA.onResult = (PeerId p, Duration rtt) { pinged = true; };
            auto identA = new IdentifyService(hostA);
            identA.onIdentified = (IdentifyInfo i) { identified = true; };

            hostA.connect(hostB.id, hostB.addrs);
            writeln("dialer connected over /ws");

            immutable deadline = MonoTime.currTime + 15.seconds;
            while (MonoTime.currTime < deadline && !(pinged && identified))
                sleep(20.msecs);

            if (pinged && identified)
            {
                writeln("PASS: ping + identify over WebSocket D↔D");
                result = 0;
            }
            else
                writeln("FAIL: ws D↔D (pinged=", pinged, " identified=", identified, ")");

            hostA.close();
            hostB.close();
        }
        catch (Exception e)
        {
            try
                stderr.writeln("ws-dd error: ", e.msg);
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
