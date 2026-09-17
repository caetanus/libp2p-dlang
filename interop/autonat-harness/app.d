/// AutoNAT D↔D burn-in: a client asks a server "can you reach me?", the server
/// dials the client's advertised address back, and the client learns its
/// reachability from whether the dial-back landed. Two real hosts on loopback, so
/// the client IS reachable and must be told publicNat, at the address it gave.
/// Exercises the /libp2p/autonat path over TCP/Noise-XX/yamux. No node.
///
/// PASS (exit 0) = the probe returns publicNat at the client's listen address.
///
///   autonat-harness
module app;

import std.algorithm.searching : canFind;
import std.getopt : getopt;
import std.stdio : writeln, stderr, stdout;

import vibe.core.core : runTask, runEventLoop, exitEventLoop;

import libp2p.host.host : Host;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.protocol.autonat : AutoNat, NatKind;

int main(string[] args)
{
    auto help = getopt(args);
    if (help.helpWanted)
    {
        writeln("autonat-harness");
        return 0;
    }

    int result = 1;
    runTask(() nothrow {
        try
        {
            auto server = Host.create();
            server.listen(Multiaddr.parse("/ip4/127.0.0.1/tcp/0"));
            auto serverNat = new AutoNat(server);
            writeln("server listening: ", server.addrs[0].toString);

            auto client = Host.create();
            client.listen(Multiaddr.parse("/ip4/127.0.0.1/tcp/0")); // listening, so the dial-back can land
            auto clientNat = new AutoNat(client);
            auto listening = client.addrs[0];
            writeln("client listening: ", listening.toString);

            auto st = clientNat.probe(server.addrs[0], client.addrs);
            writeln("probe result: kind=", st.kind, " seenAt=", st.addr.toString);

            if (st.kind == NatKind.publicNat && st.addr.toString.canFind(listening.toString))
            {
                writeln("PASS: the client was told publicNat at the address it advertised");
                result = 0;
            }
            else if (st.kind == NatKind.publicNat)
                writeln("FAIL: publicNat but at an unexpected address");
            else
                writeln("FAIL: expected publicNat for a reachable client, got ", st.kind);

            clientNat.close();
            serverNat.close();
            client.close();
            server.close();
        }
        catch (Exception e)
        {
            try
                stderr.writeln("autonat-harness error: ", e.msg);
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
