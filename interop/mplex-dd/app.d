/// mplex D↔D validation: two real libp2p hosts on loopback, both offering ONLY the
/// mplex muxer (not yamux), form a connection and run ping + identify over it. Since
/// both sides advertise mplex-only, multistream-select must negotiate mplex — so a
/// green ping+identify proves the mplex muxer carries real streams both ways. Self-
/// standing: no rust, no external network. Exit 0 = PASS, 1 = FAIL.
///
///   mplex-dd
module app;

import core.time : Duration, MonoTime, msecs, seconds;
import std.stdio : writeln, stderr, stdout;

import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;

import libp2p.core.peer_id : PeerId;
import libp2p.crypto.keys : Keypair;
import libp2p.host.host : Host, HostConfig;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.transport.tcp : TcpTransport;
import libp2p.muxer.mplex : MplexFactory;
import libp2p.protocol.ping : Ping, PingConfig;
import libp2p.protocol.identify : IdentifyService, IdentifyInfo;

int main()
{
    int result = 1;
    runTask(() nothrow {
        try
        {
            HostConfig cfg;
            cfg.agentVersion = "libp2p-dlang/mplex-dd";
            cfg.swarm.muxers = [new MplexFactory]; // offer ONLY mplex on both sides

            auto keyB = Keypair.generateEd25519;
            auto hostB = new Host(keyB, [new TcpTransport], cfg);
            // The listener must run the ping + identify services so it answers the
            // dialer's streams (both register their /ipfs/... handlers on the host).
            PingConfig pcB;
            pcB.interval = 200.msecs;
            pcB.timeout = 5.seconds;
            new Ping(hostB, pcB);
            new IdentifyService(hostB);
            hostB.listen(Multiaddr.parse("/ip4/127.0.0.1/tcp/0"));
            writeln("listener (mplex-only): ", hostB.addrs[0].toString, " id=", hostB.id.toBase58);

            auto keyA = Keypair.generateEd25519;
            auto hostA = new Host(keyA, [new TcpTransport], cfg);

            bool pinged, identified;
            PingConfig pc;
            pc.interval = 200.msecs;
            pc.timeout = 5.seconds;
            auto pingA = new Ping(hostA, pc);
            pingA.onResult = (PeerId p, Duration rtt) { pinged = true; };
            pingA.onFailure = (PeerId p, Exception e) {
                try
                    writeln("DIALER ping failed: ", e.msg);
                catch (Exception)
                {
                }
            };
            auto identA = new IdentifyService(hostA);
            identA.onIdentified = (IdentifyInfo i) { identified = true; };

            hostA.connect(hostB.id, hostB.addrs);
            writeln("dialer connected (negotiated mplex)");

            immutable deadline = MonoTime.currTime + 15.seconds;
            while (MonoTime.currTime < deadline && !(pinged && identified))
                sleep(20.msecs);

            if (pinged && identified)
            {
                writeln("PASS: ping + identify over mplex D↔D");
                result = 0;
            }
            else
                writeln("FAIL: mplex D↔D (pinged=", pinged, " identified=", identified, ")");

            hostA.close();
            hostB.close();
        }
        catch (Exception e)
        {
            try
                stderr.writeln("mplex-dd error: ", e.msg);
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
