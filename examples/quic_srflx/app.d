/// QUIC reflexive-address smoke: QuicTransport.reflexiveAddr() sends a STUN binding
/// request over its own UDP socket (the standalone webrtc.stun.message client, no
/// ICE agent) and turns the XOR-MAPPED-ADDRESS into a /ip4/<srflx>/udp/<port>/quic-v1
/// multiaddr — the address a NAT'd peer would punch to. Informational (needs a
/// reachable STUN server): prints the gathered address, or notes none answered.
///
///   dub run -c quic-srflx-example
module app;

import std.stdio : writeln, stderr, stdout;

import vibe.core.core : runTask, runEventLoop, exitEventLoop;

import libp2p.crypto.keys : Keypair;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.transport.quic.transport : QuicTransport;

int main()
{
    runTask(() nothrow {
        try
        {
            auto t = new QuicTransport(Keypair.generateEd25519);
            auto srflx = t.reflexiveAddr();
            if (srflx.bytes.length)
                writeln("OK quic reflexiveAddr: ", srflx.toString);
            else
                writeln("no STUN server answered (offline?) — reflexiveAddr is empty");
            t.close();
        }
        catch (Exception e)
        {
            try
                stderr.writeln("quic-srflx error: ", e.msg);
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
    return 0;
}
