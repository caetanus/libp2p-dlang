/// Plaintext security D↔D validation: two hosts whose security transport is
/// /plaintext/2.0.0 (not Noise), running ping + identify over it. Proves the
/// plaintext SecureConn carries the full stack (multistream → plaintext → yamux →
/// ping/identify) both ways. Self-standing: no rust, no external net. 0=PASS, 1=FAIL.
///
///   plaintext-dd
module app;

import core.time : Duration, MonoTime, msecs, seconds;
import std.stdio : writeln, stderr, stdout;

import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;

import libp2p.core.peer_id : PeerId;
import libp2p.crypto.keys : Keypair;
import libp2p.host.host : Host, HostConfig;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.transport.tcp : TcpTransport;
import libp2p.security.plaintext : PlaintextTransport;
import libp2p.security.security : SecureTransport;
import libp2p.protocol.ping : Ping, PingConfig;
import libp2p.protocol.identify : IdentifyService, IdentifyInfo;

int main()
{
    int result = 1;
    runTask(() nothrow {
        try
        {
            HostConfig cfg;
            cfg.agentVersion = "libp2p-dlang/plaintext-dd";
            // Offer ONLY plaintext security on both sides, built from each host's key.
            cfg.swarm.securityFactory = (Keypair k) => [cast(SecureTransport) new PlaintextTransport(k)];

            PingConfig pc;
            pc.interval = 200.msecs;
            pc.timeout = 5.seconds;

            auto keyB = Keypair.generateEd25519;
            auto hostB = new Host(keyB, [new TcpTransport], cfg);
            new Ping(hostB, pc);
            new IdentifyService(hostB);
            hostB.listen(Multiaddr.parse("/ip4/127.0.0.1/tcp/0"));
            writeln("listener (plaintext): ", hostB.addrs[0].toString, " id=", hostB.id.toBase58);

            auto keyA = Keypair.generateEd25519;
            auto hostA = new Host(keyA, [new TcpTransport], cfg);

            bool pinged, identified;
            auto pingA = new Ping(hostA, pc);
            pingA.onResult = (PeerId p, Duration rtt) { pinged = true; };
            auto identA = new IdentifyService(hostA);
            identA.onIdentified = (IdentifyInfo i) { identified = true; };

            hostA.connect(hostB.id, hostB.addrs);
            writeln("dialer connected (plaintext)");

            immutable deadline = MonoTime.currTime + 15.seconds;
            while (MonoTime.currTime < deadline && !(pinged && identified))
                sleep(20.msecs);

            if (pinged && identified)
            {
                writeln("PASS: ping + identify over plaintext D↔D");
                result = 0;
            }
            else
                writeln("FAIL: plaintext D↔D (pinged=", pinged, " identified=", identified, ")");

            hostA.close();
            hostB.close();
        }
        catch (Exception e)
        {
            try
                stderr.writeln("plaintext-dd error: ", e.msg);
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
