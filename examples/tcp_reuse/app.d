/// TCP port-reuse dial primitive: prove we can bind an outbound connector to the
/// SAME local port a listener already holds (SO_REUSEADDR|SO_REUSEPORT), connect it,
/// and drive it as a live vibe TCPConnection — the mechanic a TCP hole punch needs
/// (egress from the listen port so the peer's NAT mapping matches). Peer A holds a
/// reuse-port listener on portA and then dials peer B *from portA*; PASS when the
/// echo round-trips AND the connection's local port is portA. This is the primitive;
/// crossing two real NATs is the rig's job. Exit 0 = PASS.
///
///   dub run -c tcp-reuse-example
module app;

import core.time : seconds, MonoTime, msecs;
import std.stdio : writeln, stderr, stdout;

import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;
import vibe.core.net : listenTCP, TCPConnection, TCPListenOptions, NetworkAddress, resolveHost;
import vibe.core.stream : IOMode;

import libp2p.transport.tcp_reuse : connectReusingPort;

int main()
{
    int result = 1;
    runTask(() nothrow {
        try
        {
            // B: a plain echo listener.
            auto lB = listenTCP(0, (TCPConnection c) nothrow {
                try
                {
                    ubyte[5] buf;
                    c.read(buf[], IOMode.all);
                    c.write(buf[]);
                    c.flush();
                }
                catch (Exception)
                {
                }
            }, "127.0.0.1");
            immutable portB = lB.bindAddress.port;

            // A: hold a reuse-port listener on portA, then dial B *from* portA.
            auto lA = listenTCP(0, (TCPConnection c) nothrow {}, "127.0.0.1",
                TCPListenOptions.reuseAddress | TCPListenOptions.reusePort);
            immutable portA = lA.bindAddress.port;
            writeln("A listen port=", portA, "  B listen port=", portB);

            auto peer = resolveHost("127.0.0.1");
            peer.port = portB;
            auto conn = connectReusingPort(portA, peer, 5.seconds);
            immutable localPort = conn.localAddress.port;

            conn.write(cast(const(ubyte)[]) "hello");
            conn.flush();
            ubyte[5] got;
            conn.read(got[], IOMode.all);
            conn.close();

            immutable echoed = cast(string) got.idup;
            if (echoed == "hello" && localPort == portA)
            {
                writeln("PASS: dialed from reused listen port ", portA, ", echo='", echoed, "'");
                result = 0;
            }
            else
                writeln("FAIL: echo='", echoed, "' localPort=", localPort, " (want ", portA, ")");

            lA.stopListening();
            lB.stopListening();
        }
        catch (Exception e)
        {
            try
                stderr.writeln("tcp-reuse error: ", e.msg);
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
