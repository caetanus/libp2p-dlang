/// Gossipsub D↔D burn-in: two real libp2p hosts on loopback form a meshsub and a
/// message published on one reaches the other. Exercises the whole path — TCP,
/// multistream, Noise-XX, yamux, then gossipsub's subscribe/graft/publish — with
/// no node and no external network. Single-shot: exit 0 = PASS, 1 = FAIL, and it
/// prints each stage so a failure says where it stopped.
///
///   gossipsub-harness [--topic <name>] [--payload <text>]
module app;

import core.time : Duration, MonoTime, msecs, seconds;
import std.getopt : getopt;
import std.stdio : writeln, stderr, stdout;

import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;

import libp2p.core.peer_id : PeerId;
import libp2p.crypto.keys : Keypair;
import libp2p.host.host : Host, HostConfig;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.protocol.gossipsub.service : Gossipsub;
import libp2p.transport.tcp : TcpTransport;

private bool waitUntil(bool delegate() nothrow cond, Duration limit)
{
    immutable deadline = MonoTime.currTime + limit;
    while (MonoTime.currTime < deadline)
    {
        if (cond())
            return true;
        sleep(5.msecs);
    }
    return false;
}

int main(string[] args)
{
    string topic = "burn-in", payload = "the quick brown fox";
    auto help = getopt(args, "topic", &topic, "payload", &payload);
    if (help.helpWanted)
    {
        writeln("gossipsub-harness [--topic <name>] [--payload <text>]");
        return 0;
    }

    int result = 1;
    runTask(() nothrow {
        try
        {
            string[] received;

            auto keyB = Keypair.generateEd25519;
            auto hostB = new Host(keyB, [new TcpTransport]);
            hostB.listen(Multiaddr.parse("/ip4/127.0.0.1/tcp/0"));
            auto gsB = new Gossipsub(hostB, keyB);
            gsB.subscribe(topic);
            gsB.onMessage = (PeerId from, string t, const(ubyte)[] data) {
                received ~= cast(string) data.idup;
            };
            writeln("subscriber listening: ", hostB.addrs[0].toString, " id=", hostB.id.toBase58);

            auto keyA = Keypair.generateEd25519;
            auto hostA = new Host(keyA, [new TcpTransport]);
            auto gsA = new Gossipsub(hostA, keyA);
            gsA.subscribe(topic);

            hostA.connect(hostB.id, hostB.addrs);
            writeln("publisher connected to subscriber");

            // Graft: both sides must have the other in the topic mesh before a
            // publish will actually flow (state(topic)[1] = mesh peer count).
            immutable meshed = waitUntil(() nothrow {
                try
                    return gsA.state(topic)[1] > 0 && gsB.state(topic)[1] > 0;
                catch (Exception)
                    return false;
            }, 10.seconds);
            writeln("meshed: ", meshed);
            if (!meshed)
            {
                writeln("FAIL: mesh never formed (no graft) — subscribe/connect path stalled");
                throw new Exception("no mesh");
            }

            gsA.publish(topic, cast(const(ubyte)[]) payload);
            writeln("published on topic '", topic, "'");

            immutable got = waitUntil(() nothrow => received.length > 0, 10.seconds);
            if (got && received[0] == payload)
            {
                writeln("PASS: subscriber received the published message intact");
                result = 0;
            }
            else if (got)
                writeln("FAIL: received but corrupted: '", received[0], "' != '", payload, "'");
            else
                writeln("FAIL: mesh formed but the message never arrived");

            gsA.close();
            gsB.close();
            hostA.close();
            hostB.close();
        }
        catch (Exception e)
        {
            try
                stderr.writeln("gossipsub-harness error: ", e.msg);
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
