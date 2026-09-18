/// mDNS discovery D↔D validation: two libp2p hosts on the same machine, each running
/// the mDNS service, discover each other over real multicast (224.0.0.251:5353) — no
/// bootstrap, no dialing by hand. PASS when at least one host discovers the other by
/// peer id via onPeerFound. Self-standing: no rust; uses the real LAN multicast stack.
/// Exit 0 = PASS, 1 = FAIL.
///
///   mdns-dd
module app;

import core.time : Duration, MonoTime, msecs, seconds;
import std.stdio : writeln, stderr, stdout;

import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;

import libp2p.core.peer_id : PeerId;
import libp2p.crypto.keys : Keypair;
import libp2p.host.host : Host, HostConfig;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.transport.tcp : TcpTransport;
import libp2p.discovery.mdns : Mdns;

int main()
{
    int result = 1;
    runTask(() nothrow {
        try
        {
            auto keyA = Keypair.generateEd25519;
            auto hostA = new Host(keyA, [new TcpTransport]);
            hostA.listen(Multiaddr.parse("/ip4/0.0.0.0/tcp/0")); // routable addr to advertise

            auto keyB = Keypair.generateEd25519;
            auto hostB = new Host(keyB, [new TcpTransport]);
            hostB.listen(Multiaddr.parse("/ip4/0.0.0.0/tcp/0"));

            bool aFoundB, bFoundA;
            auto mdnsA = new Mdns(hostA);
            mdnsA.onPeerFound = (PeerId peer, Multiaddr[] addrs) {
                if (peer == hostB.id)
                    aFoundB = true;
            };
            auto mdnsB = new Mdns(hostB);
            mdnsB.onPeerFound = (PeerId peer, Multiaddr[] addrs) {
                if (peer == hostA.id)
                    bFoundA = true;
            };
            writeln("A=", hostA.id.toBase58, " B=", hostB.id.toBase58, " — waiting for mDNS...");

            immutable deadline = MonoTime.currTime + 20.seconds;
            while (MonoTime.currTime < deadline && !(aFoundB || bFoundA))
                sleep(100.msecs);

            if (aFoundB || bFoundA)
            {
                writeln("PASS: mDNS discovered a peer (A→B=", aFoundB, " B→A=", bFoundA, ")");
                result = 0;
            }
            else
                writeln("FAIL: neither host discovered the other over mDNS in 20s");

            hostA.close();
            hostB.close();
        }
        catch (Exception e)
        {
            try
                stderr.writeln("mdns-dd error: ", e.msg);
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
