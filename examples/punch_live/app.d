/// Live TCP hole-punch tester (real NATs, not loopback). Both peers listen on a
/// reuse-port TCP socket AND, at a shared wall-clock instant, connect() from that same
/// port to the peer's observed address (SO_REUSEADDR|SO_REUSEPORT). Whichever lands
/// first — our outbound connect (TCP simultaneous-open) or our listener accepting the
/// peer's SYN — is the punched connection; we then exchange a byte to confirm it is
/// bidirectional. Prints "TCP PUNCH ok" with the path that won. Meant to run one peer
/// behind each of two real NATs.
///
///   punch-live --local-port P --peer <ip:port> --at <unix_ms> --role dialer|listener
module app;

import std.stdio : writeln, stderr, stdout;
import std.getopt : getopt;
import std.conv : to;
import std.string : split, strip;
import std.file : exists, readText, write;
import core.time : msecs, MonoTime, seconds;
import std.datetime.systime : Clock;

import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;
import vibe.core.net : listenTCP, connectTCP, TCPConnection, TCPListener,
    TCPListenOptions, NetworkAddress, resolveHost;
import vibe.core.stream : IOMode;
import vibe.core.sync : LocalManualEvent, createManualEvent;

import libp2p.transport.tcp_reuse : connectReusingPort;
import libp2p.transport.ws : wsClientKey, buildClientUpgrade, serverHandshakeOk, wsAcceptFor,
    buildServerUpgrade, wsEncodeFrame, wsDecodeFrame, wsMaskKey, WsOp, WsFrame;

__gshared ushort g_localPort = 51830;
__gshared string g_peer;      // ip:port (the peer's observed/srflx TCP address)
__gshared long g_atMs = 0;    // shared wall-clock fire instant
__gshared string g_role = "dialer";
__gshared string g_proto = "tcp"; // tcp | ws
__gshared string g_reflector; // ip:port of a TCP srflx reflector (learn our external addr)
__gshared string g_outFile;   // write our learned srflx here
__gshared string g_peerFile;  // poll here for the peer's srflx

// Read an HTTP head (to the blank line) off a punched TCP connection.
private string readHttpHead(ref TCPConnection c)
{
    ubyte[1] b;
    string s;
    while (s.length < 8192)
    {
        c.read(b[], IOMode.all);
        s ~= cast(char) b[0];
        if (s.length >= 4 && s[$ - 4 .. $] == "\r\n\r\n")
            break;
    }
    return s;
}

// Run the WebSocket upgrade + one framed PING/PONG over the punched TCP conn.
private bool doWs(ref TCPConnection c, string role)
{
    import std.string : splitLines, toLower, startsWith, strip;

    if (role == "dialer") // WS client
    {
        immutable key = wsClientKey();
        c.write(cast(const(ubyte)[]) buildClientUpgrade(g_peer, "/", key));
        c.flush();
        if (!serverHandshakeOk(readHttpHead(c), wsAcceptFor(key)))
            return false;
        c.write(wsEncodeFrame(WsOp.binary, cast(const(ubyte)[]) "PING", true, wsMaskKey()));
        c.flush();
        ubyte[64] buf;
        immutable n = c.read(buf[], IOMode.once);
        size_t used;
        auto f = wsDecodeFrame(buf[0 .. n], used);
        writeln("WS PUNCH ok: upgrade accepted, frame='", cast(string) f.payload.idup, "'");
        return cast(string) f.payload.idup == "PONG";
    }
    else // WS server
    {
        auto req = readHttpHead(c);
        string key;
        foreach (line; req.splitLines)
            if (line.toLower.startsWith("sec-websocket-key:"))
                key = line["sec-websocket-key:".length .. $].strip;
        c.write(cast(const(ubyte)[]) buildServerUpgrade(wsAcceptFor(key)));
        c.flush();
        ubyte[64] buf;
        immutable n = c.read(buf[], IOMode.once);
        size_t used;
        auto f = wsDecodeFrame(buf[0 .. n], used);
        c.write(wsEncodeFrame(WsOp.binary, cast(const(ubyte)[]) "PONG", false, wsMaskKey()));
        c.flush();
        writeln("WS PUNCH ok: upgrade served, frame='", cast(string) f.payload.idup, "'");
        return cast(string) f.payload.idup == "PING";
    }
}

private long nowMs()
{
    auto t = Clock.currTime;
    return t.toUnixTime!long * 1000 + t.fracSecs.total!"msecs";
}

int main(string[] args)
{
    getopt(args, "local-port", &g_localPort, "peer", &g_peer, "at", &g_atMs, "role", &g_role,
        "proto", &g_proto, "reflector", &g_reflector, "out-file", &g_outFile, "peer-file", &g_peerFile);
    int rc = 1;
    runTask(() nothrow {
        try
        {
            auto ev = createManualEvent();
            __gshared TCPConnection winner;
            __gshared bool have;
            __gshared string via;

            // Listener on the reuse port: accept the peer's inbound SYN.
            auto lst = listenTCP(g_localPort, (TCPConnection c) nothrow {
                try
                {
                    if (!have) { have = true; winner = c; via = "inbound(accept)"; ev.emit(); }
                    else c.close();
                }
                catch (Exception) {}
            }, "0.0.0.0", TCPListenOptions.reuseAddress | TCPListenOptions.reusePort);

            // Bind an OS-assigned (free) port to avoid a fixed-port conflict that
            // would make the NAT remap us; Linux nf_nat then preserves it, so our
            // srflx port == this local port. Print it for the orchestrator to relay.
            if (g_localPort == 0)
                g_localPort = lst.bindAddress.port;
            writeln("LOCALPORT ", g_localPort);
            stdout.flush();
            // learn the peer's srflx from the rendezvous file (the orchestrator relays it)
            if (g_peer.length == 0 && g_peerFile.length)
                while (g_peer.length == 0)
                {
                    if (exists(g_peerFile)) g_peer = readText(g_peerFile).strip;
                    if (g_peer.length == 0) sleep(300.msecs);
                }

            auto pp = g_peer.split(":");
            auto peer = resolveHost(pp[0]);
            peer.port = pp[1].to!ushort;

            writeln("listening reuse-port ", g_localPort, "; peer ", g_peer, "; firing at ", g_atMs);
            stdout.flush();
            if (g_atMs > 0)
            {
                immutable wait = g_atMs - nowMs();
                if (wait > 0) sleep(wait.msecs);
            }
            writeln("FIRE (simultaneous connect from ", g_localPort, ")");
            stdout.flush();

            // Outbound: connect from the same reuse port to the peer (retry the window).
            runTask(() nothrow {
                foreach (attempt; 0 .. 40)
                {
                    if (have) return;
                    try
                    {
                        auto c = connectReusingPort(g_localPort, peer, 900.msecs);
                        if (!have) { have = true; winner = c; via = "outbound(connect)"; ev.emit(); }
                        return;
                    }
                    catch (Exception) { try sleep(250.msecs); catch (Exception) {} }
                }
            });

            // Wait for the first connection (either direction), up to ~15s.
            immutable deadline = MonoTime.currTime + 15.seconds;
            auto ec = ev.emitCount;
            while (!have && MonoTime.currTime < deadline)
                ec = ev.wait(500.msecs, ec);

            if (!have)
            {
                writeln("FAIL: no TCP connection punched");
            }
            else
            {
                writeln(g_proto, " connection via ", via);
                if (g_proto == "ws")
                {
                    if (doWs(winner, g_role)) rc = 0;
                }
                else if (g_role == "dialer")
                {
                    winner.write(cast(const(ubyte)[]) "PING");
                    winner.flush();
                    ubyte[4] b; winner.read(b[], IOMode.all);
                    writeln("TCP PUNCH ok: got '", cast(string) b.idup, "' via ", via);
                    if (cast(string) b.idup == "PONG") rc = 0;
                }
                else
                {
                    ubyte[4] b; winner.read(b[], IOMode.all);
                    if (cast(string) b.idup == "PING") { winner.write(cast(const(ubyte)[]) "PONG"); winner.flush(); }
                    writeln("TCP PUNCH ok: got '", cast(string) b.idup, "' via ", via);
                    rc = 0;
                }
                try winner.close(); catch (Exception) {}
            }
            lst.stopListening();
        }
        catch (Exception e)
        {
            try stderr.writeln("punch-live error: ", e.msg); catch (Exception) {}
        }
        try stdout.flush(); catch (Exception) {}
        try exitEventLoop(); catch (Exception) {}
    });
    runEventLoop();
    return rc;
}
