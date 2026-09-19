/// WireGuard-over-libp2p, serverless: two peers behind NAT establish a DIRECT QUIC
/// connection by hole-punching (no relay in the data path) and tunnel WireGuard over
/// it. Each side gathers its server-reflexive /quic-v1 address via public STUN, the
/// two exchange srflx+PeerId out of band (a file rendezvous the orchestrator fills),
/// then at a shared wall-clock `--fire-at` both punch at once (the d-hyperswarm
/// simultaneity lesson). The resulting QUIC connection carries one stream; a local
/// UDP proxy bridges that stream to WireGuard: WG's Endpoint is 127.0.0.1:<proxy>,
/// so WG's datagrams ride the punched P2P link. Opt-in behind version(Libp2pQuic).
///
///   modes: --mode punch (real 2-NAT) | direct-listen | direct-dial (loopback test)
module app;

import std.stdio : writeln, stderr, stdout;
import std.getopt : getopt;
import std.conv : to;
import std.string : strip, split;
import std.exception : enforce;
import std.typecons : Nullable, nullable;
import std.file : exists, readText, write;
import std.datetime.systime : Clock;
import core.time : msecs, seconds, MonoTime, Duration;

import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;
import vibe.core.net : UDPConnection, NetworkAddress, listenUDP, resolveHost,
    TCPConnection, TCPListener, listenTCP, connectTCP;
import vibe.core.stream : IOMode;

import libp2p.crypto.keys : Keypair;
import libp2p.core.peer_id : PeerId;
import libp2p.core.stream : Stream, readExact;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.muxer.muxer : Muxer;
import libp2p.swarm.swarm : UpgradedConn;
import libp2p.transport.quic.transport : QuicTransport;

__gshared string g_mode = "punch";
__gshared string g_role = "dialer"; // dialer punches as QUIC client; listener as server
__gshared string g_outFile; // write our "srflx peerId" here
__gshared string g_peerFile; // poll for the peer's "srflx peerId" here
__gshared string g_peerArg; // or pass the peer's "srflx peerId" directly
__gshared string g_listen = "/ip4/0.0.0.0/udp/0/quic-v1"; // direct-listen addr
__gshared long g_fireAtMs = 0; // wall-clock (unix ms) to punch; 0 = as soon as ready
__gshared ushort g_proxyPort = 51821; // local UDP that WG's Endpoint targets
__gshared ushort g_wgPort = 51820; // WG's own ListenPort (reply target); 0 = learn it
__gshared string g_service = "udp"; // "udp" (WireGuard tunnel) | "tcpfwd" (TCP over the punch)
__gshared ushort g_fwdListen = 8080; // tcpfwd client: local TCP port to listen on
__gshared string g_fwdConnect = "127.0.0.1:8080"; // tcpfwd server: where to forward each stream

private long nowUnixMs()
{
    auto t = Clock.currTime;
    return t.toUnixTime!long * 1000 + t.fracSecs.total!"msecs";
}

int main(string[] args)
{
    getopt(args, "mode", &g_mode, "role", &g_role, "out-file", &g_outFile,
        "peer-file", &g_peerFile, "peer", &g_peerArg, "listen", &g_listen,
        "fire-at", &g_fireAtMs, "proxy-port", &g_proxyPort, "wg-port", &g_wgPort,
        "service", &g_service, "fwd-listen", &g_fwdListen, "fwd-connect", &g_fwdConnect);

    int rc = 1;
    runTask(() nothrow {
        try
        {
            auto key = Keypair.generateEd25519;
            auto myId = PeerId.fromPublicKey(key.publicKey);
            auto t = new QuicTransport(key);

            Muxer mux;
            switch (g_mode)
            {
            case "punch":
                mux = doPunch(t, myId);
                break;
            case "direct-listen":
                mux = doDirectListen(t, myId);
                break;
            case "direct-dial":
                mux = doDirectDial(t, myId);
                break;
            default:
                throw new Exception("unknown --mode " ~ g_mode);
            }

            if (g_service == "tcpfwd")
            {
                // TCP over the punch: many streams, no WireGuard, no root.
                writeln("TCPFWD up: role=", g_role);
                stdout.flush();
                if (g_role == "dialer")
                    tcpForwardClient(mux); // listen locally, one stream per TCP conn
                else
                    tcpForwardServer(mux); // one inbound stream -> TCP to the service
            }
            else
            {
                // One stream carries the WireGuard tunnel: dialer opens, listener accepts.
                auto stream = (g_role == "dialer") ? mux.open() : mux.accept();
                writeln("TUNNEL up: role=", g_role, " proxy=127.0.0.1:", g_proxyPort,
                    " wg=127.0.0.1:", g_wgPort);
                stdout.flush();
                bridge(stream);
            }
            rc = 0;
        }
        catch (Exception e)
        {
            try
                stderr.writeln("wg-punch error: ", e.msg);
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
    return rc;
}

// --- connection setup ---------------------------------------------------------

private Muxer doPunch(QuicTransport t, PeerId myId)
{
    auto srflx = t.reflexiveAddr();
    enforce(srflx.bytes.length != 0, "no STUN reflexive address (no public STUN reachable?)");
    immutable line = srflx.toString ~ " " ~ myId.toBase58;
    writeln("MYADDR ", line);
    stdout.flush();
    if (g_outFile.length)
        write(g_outFile, line ~ "\n");

    // Learn the peer: an arg wins, else poll the rendezvous file.
    string peerLine = g_peerArg.strip;
    if (peerLine.length == 0)
    {
        writeln("waiting for peer address...");
        stdout.flush();
        while (peerLine.length == 0)
        {
            if (g_peerFile.length && exists(g_peerFile))
                peerLine = readText(g_peerFile).strip;
            if (peerLine.length == 0)
                sleep(200.msecs);
        }
    }
    auto parts = peerLine.split;
    enforce(parts.length >= 2, "peer line must be '<srflx multiaddr> <peerId> [fireAtMs]'");
    auto peerAddr = Multiaddr.parse(parts[0]);
    auto peerId = PeerId.fromBase58(parts[1]);
    if (parts.length >= 3) // a shared wall-clock fire instant, carried in the ticket
        g_fireAtMs = parts[2].to!long;
    writeln("peer: ", parts[0], " ", parts[1]);
    stdout.flush();

    // Fire simultaneously: sleep until the shared wall-clock instant.
    if (g_fireAtMs > 0)
    {
        immutable wait = g_fireAtMs - nowUnixMs();
        writeln("firing in ", wait, " ms");
        stdout.flush();
        if (wait > 0)
            sleep(wait.msecs);
    }
    writeln("PUNCH now (asDialer=", g_role == "dialer", ")");
    stdout.flush();
    auto up = t.punch(peerAddr, peerId, g_role == "dialer", nullable(peerId));
    writeln("PUNCH ok: direct QUIC to ", up.remotePeer.toBase58, " at ", up.remoteAddr.toString);
    stdout.flush();
    return up.muxer;
}

private Muxer doDirectListen(QuicTransport t, PeerId myId)
{
    UpgradedConn got;
    bool have;
    t.listen(Multiaddr.parse(g_listen), (UpgradedConn up) {
        if (!have)
        {
            got = up;
            have = true;
        }
    });
    writeln("MYADDR (direct-listen) ", myId.toBase58);
    stdout.flush();
    while (!have)
        sleep(50.msecs);
    return got.muxer;
}

private Muxer doDirectDial(QuicTransport t, PeerId myId)
{
    auto parts = g_peerArg.strip.split;
    enforce(parts.length >= 2, "--peer '<multiaddr> <peerId>' required for direct-dial");
    auto up = t.dial(Multiaddr.parse(parts[0]), nullable(PeerId.fromBase58(parts[1])));
    return up.muxer;
}

// --- TCP over the punch (no WireGuard, no root) -------------------------------

// Copy bytes both ways between a TCP connection and a libp2p stream until either
// end closes, then tear both down.
private void copyBidir(TCPConnection tc, Stream s)
{
    // tc is a scoped-destruction struct, so it can't be captured in a closure;
    // pass a pointer as a task argument instead. tc's frame stays alive because
    // this fiber blocks on the stream->tcp loop and then joins the pump.
    static void tcpToStream(TCPConnection* p, Stream st) nothrow
    {
        try
        {
            ubyte[8192] b;
            for (;;)
            {
                immutable n = p.read(b[], IOMode.once);
                if (n == 0)
                    break;
                st.write(b[0 .. n]);
            }
        }
        catch (Exception)
        {
        }
        try
            st.close();
        catch (Exception)
        {
        }
    }

    auto pump = runTask(&tcpToStream, &tc, s);
    try
    {
        ubyte[8192] b;
        for (;;)
        {
            immutable n = s.read(b[]);
            tc.write(b[0 .. n]);
            tc.flush();
        }
    }
    catch (Exception)
    {
    }
    try
        tc.close();
    catch (Exception)
    {
    }
    pump.join();
}

// Client (dialer): listen on a local TCP port; each accepted connection gets its
// own libp2p stream over the punched connection.
private void tcpForwardClient(Muxer mux)
{
    listenTCP(g_fwdListen, (TCPConnection tc) nothrow {
        try
        {
            auto s = mux.open();
            copyBidir(tc, s);
        }
        catch (Exception)
        {
        }
    }, "127.0.0.1");
    writeln("tcpfwd: forwarding 127.0.0.1:", g_fwdListen, " over the punch");
    stdout.flush();
    // Keep the process (and the punched connection) alive.
    for (;;)
        sleep(1.seconds);
}

// Server (listener): each inbound stream is bridged to a fresh TCP connection to
// the local service (the httpd).
private void tcpForwardServer(Muxer mux)
{
    import std.string : split, strip;
    import std.conv : to;

    auto hp = g_fwdConnect.strip.split(":");
    auto host = hp[0];
    immutable port = hp[1].to!ushort;
    for (;;)
    {
        auto s = mux.accept();
        runTask(() nothrow {
            try
            {
                auto tc = connectTCP(host, port);
                copyBidir(tc, s);
            }
            catch (Exception)
            {
            }
        });
    }
}

// --- the WireGuard tunnel: local UDP  <->  libp2p stream ----------------------

private void bridge(Stream stream)
{
    auto udp = listenUDP(g_proxyPort, "127.0.0.1");
    NetworkAddress wgAddr;
    bool haveWg;

    // Pre-seed the WG reply target if its port was given.
    if (g_wgPort != 0)
    {
        wgAddr = resolveHost("127.0.0.1");
        wgAddr.port = g_wgPort;
        haveWg = true;
    }

    // stream -> UDP (deliver peer's WG datagrams to local WG)
    runTask(() nothrow {
        try
        {
            for (;;)
            {
                ubyte[2] hdr;
                stream.readExact(hdr[]);
                immutable n = (hdr[0] << 8) | hdr[1];
                auto payload = new ubyte[n];
                stream.readExact(payload);
                if (haveWg)
                {
                    auto to = wgAddr;
                    udp.send(payload, &to);
                }
            }
        }
        catch (Exception)
        {
        }
    });

    // UDP -> stream (ship local WG's outbound datagrams to the peer)
    ubyte[2048] buf;
    for (;;)
    {
        NetworkAddress from;
        auto pkt = udp.recv(buf[], &from);
        wgAddr = from; // learn/refresh WG's socket address
        haveWg = true;
        ubyte[2] hdr = [cast(ubyte)(pkt.length >> 8), cast(ubyte)(pkt.length & 0xff)];
        stream.write(hdr[]);
        stream.write(pkt);
    }
}
