/// QUIC handshake over a real loopback UDP socket: a QuicListener and a QuicClient
/// (connectQuic) complete a TLS 1.3 handshake driven by vibe's event loop (the UDP
/// socket is an eventcore fd — a read-loop fiber blocks in recv, a Timer fires ngtcp2's
/// timers). PASS when both the client and the server report a completed handshake.
///
///   dub run -c quic-udp-example
module app;

import std.stdio : writeln, stderr, stdout;
import core.time : msecs, seconds, MonoTime;

import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;
import vibe.core.net : NetworkAddress, resolveHost;

import libp2p.transport.quic.udp : QuicListener, QuicClient, connectQuic;
import libp2p.crypto.keys : Keypair;
import libp2p.transport.quic.connection : QuicConnection;

int main()
{
    int result = 1;
    runTask(() nothrow {
        try
        {
            bool serverDone;
            auto serverId = Keypair.generateEd25519();
            auto listener = new QuicListener(serverId, 0);
            listener.onAccept = (QuicConnection conn, NetworkAddress from) nothrow { serverDone = true; };
            immutable port = listener.localAddress.port;
            writeln("QUIC listener on 127.0.0.1:", port);

            auto peer = resolveHost("127.0.0.1");
            peer.port = port;
            auto clientId = Keypair.generateEd25519();
            auto client = connectQuic(clientId, peer);
            client.waitForHandshake();

            immutable deadline = MonoTime.currTime + 5.seconds;
            while (!serverDone && MonoTime.currTime < deadline)
                sleep(20.msecs);

            if (client.connection.handshakeComplete && serverDone)
            {
                writeln("PASS: QUIC handshake over loopback UDP (client + server)");
                result = 0;
            }
            else
                writeln("FAIL: client=", client.connection.handshakeComplete, " server=", serverDone);

            client.close();
            listener.close();
        }
        catch (Exception e)
        {
            try
                stderr.writeln("quic-udp error: ", e.msg);
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
