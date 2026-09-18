/// QUIC D↔D validation: two real libp2p hosts on loopback whose ONLY transport is
/// QUIC (/quic-v1) form a connection and run ping + identify over it. QUIC secures
/// and multiplexes itself, so there is no Noise/Yamux here — a green ping+identify
/// proves the QuicConnection carries real libp2p streams both ways, with the peer
/// identity verified from the certificate. Self-standing: no rust, no external
/// network. Exit 0 = PASS, 1 = FAIL.
///
///   dub run -c quic-host-example
module app;

import core.time : Duration, MonoTime, msecs, seconds;
import std.stdio : writeln, stderr, stdout;

import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;

import libp2p.core.peer_id : PeerId;
import libp2p.crypto.keys : Keypair;
import libp2p.host.host : Host, HostConfig;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.transport.transport : Transport;
import libp2p.transport.quic.transport : QuicTransport;
import libp2p.protocol.ping : Ping, PingConfig;
import libp2p.protocol.identify : IdentifyService, IdentifyInfo;

int main()
{
    int result = 1;
    runTask(() nothrow {
        try
        {
            HostConfig cfg;
            cfg.agentVersion = "libp2p-dlang/quic-host";

            // Listener: QUIC-only. Register ping + identify so it answers the dialer.
            auto keyB = Keypair.generateEd25519;
            auto hostB = new Host(keyB, cast(Transport[]) [], cfg);
            hostB.swarm.addCapableTransport(new QuicTransport(keyB));
            PingConfig pcB;
            pcB.interval = 200.msecs;
            pcB.timeout = 5.seconds;
            new Ping(hostB, pcB);
            new IdentifyService(hostB);
            hostB.listen(Multiaddr.parse("/ip4/127.0.0.1/udp/0/quic-v1"));
            writeln("listener (quic-only): ", hostB.addrs[0].toString, " id=", hostB.id.toBase58);

            auto keyA = Keypair.generateEd25519;
            auto hostA = new Host(keyA, cast(Transport[]) [], cfg);
            hostA.swarm.addCapableTransport(new QuicTransport(keyA));

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
            writeln("dialer connected over QUIC");

            immutable deadline = MonoTime.currTime + 15.seconds;
            while (MonoTime.currTime < deadline && !(pinged && identified))
                sleep(20.msecs);

            if (pinged && identified)
            {
                writeln("PASS: ping + identify over QUIC D↔D");
                result = 0;
            }
            else
                writeln("FAIL: quic D↔D (pinged=", pinged, " identified=", identified, ")");

            hostA.close();
            hostB.close();
        }
        catch (Exception e)
        {
            try
                stderr.writeln("quic-host error: ", e.msg);
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
