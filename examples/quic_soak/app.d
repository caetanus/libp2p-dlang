/// A sustained multi-stream push over QUIC, the shape photo sync puts on a punched
/// connection: N bulk streams each writing 1 MiB pieces back-to-back with at most
/// `window` unanswered, the server answering every piece with one byte, plus a
/// control stream pinging every 3 s. Both ends ride QuicPunchSocket (the production
/// socket). Runs for --secs; exits 1 the moment nothing is answered for --stall s.
///
///   quic-soak --role server [--port P]
///   quic-soak --role client --peer ip:port [--secs 300] [--streams 3]
module app;

import core.time : Duration, MonoTime, msecs, seconds;
import std.conv : to;
import std.getopt : getopt;
import std.stdio : writeln, writefln, stdout, stderr;
import std.string : indexOf;

import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;
import vibe.core.net : NetworkAddress, resolveHost;

import libp2p.core.stream : Stream;
import libp2p.crypto.keys : Keypair;
import libp2p.transport.quic.punch : QuicPunchSocket;
import libp2p.transport.quic.connection : QuicConnection;

enum size_t piece = 1024 * 1024;

private void serveStream(Stream s)
{
    runTask(() nothrow {
        try
        {
            ubyte[1] kind;
            s.read(kind[]);
            auto buf = new ubyte[64 * 1024];
            if (kind[0] == 0xC0)
                for (;;)
                {
                    ubyte[4] f;
                    size_t n;
                    while (n < 4)
                        n += s.read(f[n .. 4]);
                    s.write(f[]);
                }
            size_t inPiece;
            for (;;)
            {
                inPiece += s.read(buf[0 .. (piece - inPiece < buf.length ? piece - inPiece : buf.length)]);
                if (inPiece == piece)
                {
                    inPiece = 0;
                    s.write([cast(ubyte) 1]);
                }
            }
        }
        catch (Exception e)
        {
            try { writeln("server stream ended: ", e.msg); stdout.flush(); } catch (Exception) {}
        }
    });
}

int main(string[] args)
{
    string role = "server", peerStr;
    ushort port = 4710;
    uint secs = 300, streams = 3, window = 16, stall = 20;
    getopt(args, "role", &role, "port", &port, "peer", &peerStr, "secs", &secs,
        "streams", &streams, "window", &window, "stall", &stall);
    int result = 1;
    runTask(() nothrow {
        try
        {
            auto id = Keypair.generateEd25519();
            if (role == "server")
            {
                auto psock = new QuicPunchSocket(id, "0.0.0.0", port);
                writeln("quic-soak server on :", psock.localAddress.port); stdout.flush();
                psock.onInbound = delegate(QuicConnection conn, NetworkAddress from) nothrow {
                    try { writeln("inbound conn from ", from.toString()); stdout.flush(); } catch (Exception) {}
                    runTask(() nothrow {
                        try
                            for (;;)
                                serveStream(conn.accept());
                        catch (Exception e)
                        {
                            try { writeln("conn ended: ", e.msg); stdout.flush(); } catch (Exception) {}
                        }
                    });
                };
                sleep((secs + 600).seconds);
                result = 0;
            }
            else
            {
                immutable c = peerStr.indexOf(':');
                auto peer = resolveHost(peerStr[0 .. c]);
                peer.port = peerStr[c + 1 .. $].to!ushort;
                auto psock = new QuicPunchSocket(id, "0.0.0.0", 0);
                auto pump = psock.punchClient(peer);
                pump.waitForHandshake();
                auto conn = pump.connection;
                writeln("connected from :", psock.localAddress.port); stdout.flush();

                immutable start = MonoTime.currTime;
                auto lastProgress = MonoTime.currTime;
                ulong answered, pings;
                bool done, failed;
                string why;

                // control: a ping every 3 s, answered by the server
                auto cs = conn.open();
                cs.write([cast(ubyte) 0xC0]);
                runTask(() nothrow {
                    try
                        while (!done)
                        {
                            sleep(3.seconds);
                            ubyte[4] f = [1, 2, 3, 4];
                            cs.write(f[]);
                            size_t n;
                            while (n < 4)
                                n += cs.read(f[n .. 4]);
                            pings++;
                        }
                    catch (Exception e)
                    {
                        if (!done) { failed = true; why = "control: " ~ e.msg; }
                    }
                });

                void pusher(uint k)
                {
                    runTask(() nothrow {
                        try
                        {
                            auto s = conn.open();
                            s.write([cast(ubyte) 0xB0]);
                            ulong sent, acked;
                            runTask(() nothrow {
                                try
                                {
                                    ubyte[1] a;
                                    while (!done)
                                    {
                                        s.read(a[]);
                                        acked++;
                                        answered++;
                                        lastProgress = MonoTime.currTime;
                                    }
                                }
                                catch (Exception e)
                                {
                                    if (!done) { failed = true; why = "answers: " ~ e.msg; }
                                }
                            });
                            auto p = new ubyte[piece];
                            foreach (i, ref b; p)
                                b = cast(ubyte)(i + k);
                            while (!done)
                            {
                                if (sent - acked >= window)
                                {
                                    sleep(20.msecs);
                                    continue;
                                }
                                s.write(p);
                                sent++;
                            }
                        }
                        catch (Exception e)
                        {
                            if (!done) { failed = true; why = "push: " ~ e.msg; }
                        }
                    });
                }

                foreach (k; 0 .. streams)
                    pusher(k);

                ulong lastAnswered;
                auto lastReport = MonoTime.currTime;
                while (!failed)
                {
                    sleep(1.seconds);
                    immutable now = MonoTime.currTime;
                    if (now - lastReport >= 10.seconds)
                    {
                        lastReport = now;
                        auto st = conn.stats();
                        writefln("t=%ss answered=%s MiB (+%s) pings=%s cwnd=%s inflight=%s srtt=%sms sent=%s lost=%s",
                            (now - start).total!"seconds", answered, answered - lastAnswered, pings,
                            st.cwnd, st.inflight, st.srttUs / 1000, st.pktSent, st.pktLost);
                        stdout.flush();
                        lastAnswered = answered;
                    }
                    if (now - lastProgress >= stall.seconds)
                    {
                        failed = true;
                        why = "STALL: no piece answered for " ~ stall.to!string ~ " s";
                        break;
                    }
                    if (now - start >= secs.seconds)
                        break;
                }
                done = true;
                auto st = conn.stats();
                writefln("%s after %ss: %s MiB answered, %s pings; cwnd=%s inflight=%s srtt=%sms sent=%s lost=%s closed=%s%s",
                    failed ? "SOAK FAIL" : "SOAK PASS", (MonoTime.currTime - start).total!"seconds",
                    answered, pings, st.cwnd, st.inflight, st.srttUs / 1000, st.pktSent, st.pktLost,
                    conn.isClosed, failed ? " — " ~ why : "");
                stdout.flush();
                result = failed ? 1 : 0;
                psock.close();
            }
        }
        catch (Exception e)
        {
            result = 1;
            try stderr.writeln("quic-soak error: ", e.msg); catch (Exception) {}
        }
        try exitEventLoop(); catch (Exception) {}
    });
    runEventLoop();
    return result;
}
