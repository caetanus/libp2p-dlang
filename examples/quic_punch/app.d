/// QUIC hole-punch mechanics over loopback: two QuicPunchSockets, each on its own
/// UDP socket, punch to each other at once — one runs the QUIC client role
/// (punchClient), the other the server role (punchServer, which first fires NAT-
/// opener pads then waits for the Initial). PASS when both complete the handshake
/// and each recovers the other's verified PeerId. This exercises the socket reuse,
/// the STUN/QUIC demux, the opener-pad filtering and the asymmetric client/server
/// split — everything a real punch needs EXCEPT crossing two real NATs (that needs
/// the two-NAT rig; loopback cannot punch). Exit 0 = PASS.
///
///   dub run -c quic-punch-example
module app;

import core.time : MonoTime, msecs, seconds;
import std.stdio : writeln, stderr, stdout;

import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;
import vibe.core.net : NetworkAddress;

import libp2p.core.peer_id : PeerId;
import libp2p.crypto.keys : Keypair;
import libp2p.transport.quic.punch : QuicPunchSocket;

int main()
{
    int result = 1;
    runTask(() nothrow {
        try
        {
            auto keyA = Keypair.generateEd25519;
            auto keyB = Keypair.generateEd25519;
            auto a = new QuicPunchSocket(keyA, "127.0.0.1");
            auto b = new QuicPunchSocket(keyB, "127.0.0.1");
            auto addrA = a.localAddress;
            auto addrB = b.localAddress;
            writeln("A on ", addrA.toString, "  B on ", addrB.toString);

            // Both punch at once: A dials (client), B serves.
            PeerId aSawB, bSawA;
            bool aDone, bDone;
            runTask(() nothrow {
                try
                {
                    auto pump = a.punchClient(addrB);
                    pump.waitForHandshake();
                    aSawB = pump.connection.remotePeerId();
                    aDone = true;
                }
                catch (Exception e)
                {
                    try
                        writeln("A punch failed: ", e.msg);
                    catch (Exception)
                    {
                    }
                }
            });
            auto pumpB = b.punchServer(addrA, 10.seconds);
            pumpB.waitForHandshake();
            bSawA = pumpB.connection.remotePeerId();
            bDone = true;

            immutable deadline = MonoTime.currTime + 5.seconds;
            while (!aDone && MonoTime.currTime < deadline)
                sleep(20.msecs);

            auto wantA = PeerId.fromPublicKey(keyA.publicKey);
            auto wantB = PeerId.fromPublicKey(keyB.publicKey);
            if (aDone && bDone && aSawB == wantB && bSawA == wantA)
            {
                writeln("PASS: QUIC punch mechanics D↔D (A saw ", aSawB.toBase58,
                    ", B saw ", bSawA.toBase58, ")");
                result = 0;
            }
            else
                writeln("FAIL: aDone=", aDone, " bDone=", bDone);

            a.close();
            b.close();
        }
        catch (Exception e)
        {
            try
                stderr.writeln("quic-punch error: ", e.msg);
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
