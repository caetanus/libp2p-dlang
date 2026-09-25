/// The QUIC stack's throughput ceiling, no relay, no punch: a direct QUIC dial and
/// one stream carrying N MiB (64 KiB writes, like an app pushing a file), acked by
/// one byte from the server once the FIN arrives. Run the server on one box (or
/// netem container) and the client on the other; loopback gives the CPU ceiling.
///
///   quic-burn --role server [--port P]
///   quic-burn --role client --peer ip:port --mib N
module app;

import core.time : MonoTime, msecs, seconds;
import std.conv : to;
import std.getopt : getopt;
import std.stdio : writeln, stdout, stderr;
import std.string : indexOf;

import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;
import vibe.core.net : NetworkAddress, resolveHost;

import libp2p.core.ending : EndOfStream;
import libp2p.core.stream : Stream;
import libp2p.crypto.keys : Keypair;
import libp2p.transport.quic.udp : QuicListener, QuicClient;
import libp2p.transport.quic.punch : QuicPunchSocket;
import libp2p.transport.quic.connection : QuicConnection;

// Control stream: echo every 4-byte frame until the peer FINs. A separate function
// so the task owns its stream — a closure declared inside the accept loop would
// see `s` re-assigned by the next accept (D closures share loop-body variables).
private void serveControl(Stream s)
{
    runTask(() nothrow {
        try
        {
            ubyte[4] f;
            for (;;)
            {
                size_t n;
                while (n < 4) n += s.read(f[n .. 4]);
                s.write(f[]);
            }
        }
        catch (Exception) {}
    });
}

int main(string[] args)
{
    string role = "server", peerStr; ushort port = 4700; uint mib = 64; uint streams = 1; bool stats, ctrl, prod;
    auto help = getopt(args, "role", &role, "port", &port, "peer", &peerStr, "mib", &mib, "streams", &streams, "stats", &stats, "ctrl", &ctrl, "prod", &prod);
    if (help.helpWanted || (role == "client" && peerStr.indexOf(':') <= 0))
    {
        writeln("quic-burn --role server [--port P] | --role client --peer ip:port [--mib N]");
        return 2;
    }
    int result = 1;
    runTask(() nothrow {
        try
        {
            auto id = Keypair.generateEd25519();
            if (role == "server")
            {
                // --prod: serve on QuicPunchSocket, the socket the production QuicTransport uses.
                QuicListener listener;
                QuicPunchSocket psock;
                if (prod) psock = new QuicPunchSocket(id, "0.0.0.0", port);
                else listener = new QuicListener(id, port, "0.0.0.0");
                writeln("quic-burn server on :", prod ? psock.localAddress.port : listener.localAddress.port, prod ? " (QuicPunchSocket)" : ""); stdout.flush();
                void delegate(QuicConnection, NetworkAddress) nothrow onConn = delegate(QuicConnection conn, NetworkAddress from) nothrow {
                    try { writeln("inbound conn from ", from.toString()); stdout.flush(); } catch (Exception) {}
                    runTask(() nothrow {
                        try
                        for (;;)
                        {
                            auto s = conn.accept();
                            writeln("accepted a stream"); stdout.flush();
                            immutable t0 = MonoTime.currTime;
                            ubyte[64 * 1024] buf;
                            ulong got, mark;
                            immutable first = s.read(buf[0 .. 1]);
                            if (first == 1 && buf[0] == 0xC0)
                            {
                                serveControl(s); // its own frame: a closure here would share `s` with the next accept
                                continue;
                            }
                            got += first;
                            try
                                for (;;)
                                {
                                    got += s.read(buf[]);
                                    if (got - mark >= 4 * 1024 * 1024) { mark = got; writeln("  got ", got); stdout.flush(); }
                                }
                            catch (EndOfStream) {}
                            immutable ms = (MonoTime.currTime - t0).total!"msecs";
                            writeln("received ", got, " bytes in ", ms, " ms = ", ms ? got / 1024.0 / ms : 0, " MB/s"); stdout.flush();
                            s.write([cast(ubyte) 1]);
                            s.close();
                        }
                        catch (Exception e) { try writeln("server stream error: ", e.msg); catch (Exception) {} }
                    });
                };
                if (prod) psock.onInbound = onConn; else listener.onAccept = onConn;
                foreach (_; 0 .. 3600) sleep(1.seconds);
            }
            else
            {
                immutable c = peerStr.indexOf(':');
                auto peer = resolveHost(peerStr[0 .. c]);
                peer.port = peerStr[c + 1 .. $].to!ushort;
                auto client = new QuicClient(id, peer, "0.0.0.0");
                client.waitForHandshake();
                auto conn = client.connection;
                bool running = true;
                if (stats)
                    runTask(() nothrow {
                        try
                            while (running)
                            {
                                sleep(1.seconds);
                                auto st = conn.stats();
                                writeln("  stats: cwnd=", st.cwnd, " ssthresh=", st.ssthresh, " inflight=", st.inflight, " srtt=", st.srttUs / 1000.0, "ms sent=", st.pktSent, " lost=", st.pktLost);
                                stdout.flush();
                            }
                        catch (Exception) {}
                    });
                result = 0;
                Stream cs;
                bool ctrlRun = ctrl;
                ulong ctrlPings, ctrlMaxMs, ctrlSumMs;
                if (ctrl)
                {
                    cs = conn.open();
                    cs.write([cast(ubyte) 0xC0]);
                    runTask(() nothrow {
                        try
                            while (ctrlRun)
                            {
                                sleep(500.msecs);
                                immutable tp = MonoTime.currTime;
                                ubyte[4] f = [1, 2, 3, 4];
                                cs.write(f[]);
                                size_t n;
                                while (n < 4) n += cs.read(f[n .. 4]);
                                immutable ms = (MonoTime.currTime - tp).total!"msecs";
                                ctrlPings++; ctrlSumMs += ms; if (ms > ctrlMaxMs) ctrlMaxMs = ms;
                            }
                        catch (Exception) {}
                    });
                }
                foreach (i; 0 .. streams)
                {
                    auto s = conn.open();
                    immutable total = cast(ulong)(mib + 8 * i) * 1024 * 1024; // each stream a bit bigger
                    ubyte[64 * 1024] chunk = 0x42;
                    immutable t0 = MonoTime.currTime;
                    ulong sent;
                    ulong mark;
                    while (sent < total)
                    {
                        immutable n = total - sent < chunk.length ? cast(size_t)(total - sent) : chunk.length;
                        s.write(chunk[0 .. n]);
                        sent += n;
                        if (sent - mark >= 4 * 1024 * 1024) { mark = sent; writeln("  stream ", i + 1, " queued ", sent); stdout.flush(); }
                    }
                    writeln("  stream ", i + 1, " all queued, closing"); stdout.flush();
                    immutable tw = (MonoTime.currTime - t0).total!"msecs";
                    s.close(); // FIN after the buffered bytes drain
                    ubyte[1] ack;
                    immutable r = s.read(ack[]);
                    immutable ms = (MonoTime.currTime - t0).total!"msecs";
                    if (r == 1 && ack[0] == 1)
                        writeln("BURN PASS stream ", i + 1, ": ", total, " bytes acked in ", ms, " ms = ", total / 1024.0 / ms, " MB/s (writes returned after ", tw, " ms)");
                    else
                    {
                        writeln("BURN FAIL stream ", i + 1, ": no ack");
                        result = 1;
                    }
                    stdout.flush();
                }
                running = false;
                ctrlRun = false;
                if (ctrl)
                    writeln("CTRL: ", ctrlPings, " pings on the control stream during the burn, mean ", ctrlPings ? ctrlSumMs / ctrlPings : 0, " ms, max ", ctrlMaxMs, " ms");
                stdout.flush();
                client.close();
            }
        }
        catch (Exception e)
        {
            try stderr.writeln("quic-burn error: ", e.msg); catch (Exception) {}
        }
        try exitEventLoop(); catch (Exception) {}
    });
    runEventLoop();
    return result;
}
