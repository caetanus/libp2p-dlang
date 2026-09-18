/// QUIC-native streams over loopback UDP: a client opens a bidirectional stream on
/// a QuicConnection (used as a Muxer), writes a message and FINs; the server accepts
/// the stream, reads it to end, echoes it back and FINs; the client reads the echo to
/// end and compares. PASS when the echo matches — exercising open/accept/read/write/
/// close plus ngtcp2 stream flow control, all driven by vibe's event loop.
///
///   dub run -c quic-stream-example
module app;

import std.stdio : writeln, stderr, stdout;
import core.time : msecs, seconds, MonoTime;

import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;
import vibe.core.net : NetworkAddress, resolveHost;

import libp2p.core.stream : Stream;
import libp2p.core.ending : EndOfStream;
import libp2p.transport.quic.udp : QuicListener, QuicClient, connectQuic;
import libp2p.crypto.keys : Keypair;
import libp2p.transport.quic.connection : QuicConnection;

// Read a stream until the peer FINs, returning everything received.
private ubyte[] readToEnd(Stream s)
{
    ubyte[512] buf;
    ubyte[] acc;
    try
        for (;;)
        {
            immutable n = s.read(buf[]);
            acc ~= buf[0 .. n];
        }
    catch (EndOfStream)
    {
    }
    return acc;
}

int main()
{
    enum message = "hello quic-native streams";
    int result = 1;
    runTask(() nothrow {
        try
        {
            auto serverId = Keypair.generateEd25519();
            auto listener = new QuicListener(serverId, 0);
            listener.onAccept = (QuicConnection conn) nothrow {
                runTask(() nothrow {
                    try
                    {
                        auto s = conn.accept();
                        auto got = readToEnd(s);
                        s.write(got); // echo
                        s.close(); // FIN
                    }
                    catch (Exception)
                    {
                    }
                });
            };
            immutable port = listener.localAddress.port;
            writeln("QUIC listener on 127.0.0.1:", port);

            auto peer = resolveHost("127.0.0.1");
            peer.port = port;
            auto clientId = Keypair.generateEd25519();
            auto client = connectQuic(clientId, peer);
            client.waitForHandshake();

            auto s = client.connection.open();
            s.write(cast(const(ubyte)[]) message);
            s.close(); // FIN our write side
            auto echoed = cast(string) readToEnd(s);

            if (echoed == message)
            {
                writeln("PASS: QUIC stream echo over UDP (", echoed, ")");
                result = 0;
            }
            else
                writeln("FAIL: echo mismatch: got '", echoed, "' want '", message, "'");

            client.close();
            listener.close();
        }
        catch (Exception e)
        {
            try
                stderr.writeln("quic-stream error: ", e.msg);
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
