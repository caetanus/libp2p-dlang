/// One end of the two-NAT webrtc hole-punch validation (2e).
///
/// Each punch-peer is a Host with the WebRTC transport added as a CapableTransport
/// (so it gathers a server-reflexive webrtc-direct address, advertises it in the
/// DCUtR exchange, and routes a webrtc-direct address through the punch instead of
/// a fresh dial), the relay client, and ping.
///
///   responder:  reserves a slot on the relay and waits. When the initiator opens
///               DCUtR, its serveDcutr handler answers and punches back by role.
///   initiator:  reaches the responder through the relay, then calls holePunch —
///               the DCUtR exchange runs, both sides punch to each other's srflx,
///               and the direct connection is adopted into the pool. PASS iff a
///               non-relayed /webrtc-direct/ connection forms and ping runs on it.
///
/// By default the punch is DRIVEN here (explicit holePunch), so the harness can
/// measure it. With --auto the initiator instead relies on auto-DCUtR: it only
/// dials through the relay and the Relay service upgrades the link on its own
/// (Relay.autoHolePunch, default on) — same PASS condition, no explicit punch.
///
///   punch-peer --relay /ip4/<pub>/tcp/<port>/p2p/<relayId> --role responder
///   punch-peer --relay /ip4/<pub>/tcp/<port>/p2p/<relayId> --role initiator --peer <responderId>
module app;

import core.time : msecs, seconds, MonoTime;
import std.algorithm.searching : canFind;
import std.getopt : getopt;
import std.stdio : writeln, stderr, stdout;

import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;
import vibe.core.log : setLogLevel, LogLevel;

import libp2p.core.peer_id : PeerId;
import libp2p.core.stream : Stream;
import libp2p.crypto.keys : Keypair;
import libp2p.host.host : Host, Connection;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.protocol.ping : Ping, ping, pingProtocol;
import libp2p.protocol.relay.service : Relay;
import libp2p.transport.tcp : TcpTransport;
import libp2p.transport.webrtc.transport : WebRtcTransport;
version (Libp2pQuic) import libp2p.transport.quic.transport : QuicTransport;

// The direct (non-relayed) connection to `peer`, if the punch upgraded us off the
// relay: a /webrtc-direct/ one when punching webrtc, a plain /tcp/ one for TCP.
__gshared string g_proto = "webrtc"; // webrtc | tcp

// A data burn: the initiator streams `size` bytes to the responder on this protocol
// and waits for a one-byte ack. Over a relay circuit that dies at its byte budget
// (128 KiB on a public relay) — the photo-wagon "connects, then drops in seconds".
enum burnProtocol = "/punch/burn/1.0.0";

private void serveBurn(Stream s)
{
    ubyte[8] hdr;
    size_t got;
    while (got < 8)
        got += s.read(hdr[got .. $]);
    ulong size;
    foreach (b; hdr)
        size = (size << 8) | b;
    ubyte[64 * 1024] buf;
    ulong left = size;
    while (left > 0)
    {
        immutable n = s.read(buf[0 .. left < buf.length ? cast(size_t) left : buf.length]);
        if (n == 0)
            break;
        left -= n;
    }
    if (left == 0)
        s.write([cast(ubyte) 1]);
}

// ngtcp2 congestion/RTT snapshot of the direct connection to `peer` (QUIC only).
private string quicStats(Host host, PeerId peer)
{
    version (Libp2pQuic)
    {
        import libp2p.transport.quic.connection : QuicConnection;
        import std.conv : to;
        try
        {
            foreach (c; host.swarm.connectionsTo(peer))
                if (auto q = cast(QuicConnection) c.underlyingMuxer)
                {
                    auto st = q.stats();
                    return " [cwnd=" ~ st.cwnd.to!string ~ " inflight=" ~ st.inflight.to!string ~ " srtt=" ~ (st.srttUs / 1000).to!string
                        ~ "ms sent=" ~ st.pktSent.to!string ~ " lost=" ~ st.pktLost.to!string ~ "]";
                }
        }
        catch (Exception) {}
    }
    return "";
}

// Returns true when every byte was acked; prints where it died otherwise.
private bool burn(Host host, PeerId peer, ulong size)
{
    immutable t0 = MonoTime.currTime;
    auto via = host.swarm.connection(peer).remoteAddr.toString;
    writeln("BURN: ", size, " bytes to the peer; new streams go via ", via);
    stdout.flush();
    ulong sent;
    try
    {
        auto s = host.newStream(peer, burnProtocol);
        scope (exit)
            s.close();
        ubyte[8] hdr;
        foreach (i; 0 .. 8)
            hdr[i] = cast(ubyte)(size >> (56 - 8 * i));
        s.write(hdr[]);
        ubyte[64 * 1024] buf = 0x42;
        auto tp = MonoTime.currTime;
        while (sent < size)
        {
            immutable n = size - sent < buf.length ? cast(size_t)(size - sent) : buf.length;
            s.write(buf[0 .. n]);
            sent += n;
            if (MonoTime.currTime - tp >= 3.seconds)
            {
                tp = MonoTime.currTime;
                writeln("  [t+", (tp - t0).total!"msecs" / 1000.0, "s] queued ", sent, " bytes", quicStats(host, peer));
                stdout.flush();
            }
        }
        writeln("  [t+", (MonoTime.currTime - t0).total!"msecs" / 1000.0, "s] all queued; waiting for the ack", quicStats(host, peer)); stdout.flush();
        ubyte[1] ack;
        size_t r;
        auto ackWait = runTask(() nothrow {
            try
                for (;;)
                {
                    sleep(5.seconds);
                    writeln("  [t+", (MonoTime.currTime - t0).total!"msecs" / 1000.0, "s] still waiting for the ack", quicStats(host, peer));
                    stdout.flush();
                }
            catch (Exception) {}
        });
        try
            r = s.read(ack[]);
        finally
            ackWait.interrupt();
        if (r != 1 || ack[0] != 1)
            throw new Exception("no ack from the peer");
        writeln("BURN PASS: ", size, " bytes acked in ", (MonoTime.currTime - t0).total!"msecs", " ms via ", via);
        stdout.flush();
        return true;
    }
    catch (Exception e)
    {
        writeln("BURN FAIL after ", sent, " bytes sent (", (MonoTime.currTime - t0).total!"msecs", " ms) via ", via, ": ", e.msg);
        for (Throwable t = e.next; t !is null; t = t.next)
            writeln("  because: ", t.msg);
        stdout.flush();
        return false;
    }
}
private Connection directTo(Host host, PeerId peer)
{
    immutable want = g_proto == "tcp" ? "/tcp/" : g_proto == "quic" ? "/quic-v1/" : "/webrtc-direct/";
    foreach (c; host.swarm.connectionsTo(peer))
        if (c.remoteAddr.toString.canFind(want) && !c.remoteAddr.toString.canFind("/p2p-circuit"))
            return c;
    return null;
}

// The soak: keep the punched connection for `secs`, pinging over a fresh stream
// every `every` seconds (or not at all until the end, to see whether an idle
// link survives the NAT mapping timers). Reports every change in the connection
// set with a timestamp, and the first ping that fails — with why.
private bool hold(Host host, PeerId peer, Connection direct, uint secs, uint every)
{
    immutable t0 = MonoTime.currTime;
    auto stamp() { return (MonoTime.currTime - t0).total!"msecs" / 1000.0; }
    writeln("HOLD: watching the direct link for ", secs, "s, ping every ", every ? every : secs, "s");
    string lastState;
    auto nextPing = MonoTime.currTime + (every ? every.seconds : secs.seconds);
    immutable end = MonoTime.currTime + secs.seconds;
    bool ok = true;
    while (true)
    {
        string state;
        foreach (c; host.swarm.connectionsTo(peer))
            state ~= (state.length ? " | " : "") ~ c.remoteAddr.toString;
        if (state != lastState)
        {
            writeln("[t+", stamp(), "s] connections to peer: ", state.length ? state : "(none)");
            stdout.flush();
            lastState = state;
        }
        immutable now = MonoTime.currTime;
        if (now >= nextPing || now >= end)
        {
            try
            {
                auto s = direct.newStream(pingProtocol);
                scope (exit)
                    s.close();
                auto rtt = ping(s);
                writeln("[t+", stamp(), "s] ping ok, rtt ", rtt.total!"usecs" / 1000.0, " ms");
            }
            catch (Exception e)
            {
                writeln("[t+", stamp(), "s] PING FAILED: ", e.msg);
                for (Throwable t = e.next; t !is null; t = t.next)
                    writeln("  because: ", t.msg);
                ok = false;
            }
            stdout.flush();
            if (!ok || now >= end)
                break;
            nextPing = now + every.seconds;
        }
        sleep(200.msecs);
    }
    writeln(ok ? "HOLD PASS: the direct link stayed usable for the whole hold" : "HOLD FAIL");
    stdout.flush();
    return ok;
}

int main(string[] args)
{
    string relayStr, role = "responder", peerStr;
    bool autoMode, debugLog;
    ulong burnBytes; // --burn: after connecting, stream this many bytes to the peer and wait for the ack
    bool connectDirectMode; // --connect-direct: the rendezvous API — Relay.connectDirect, then everything on the result
    bool noPunch; // --no-punch: stay on the relay (what a phone whose NAT cannot be punched sees)
    uint holdSecs; // --hold: after the punch, keep the direct link and watch it for this long
    uint pingEvery = 15; // --ping-every: seconds between pings while holding (0 = stay idle, ping once at the end)
    string observed; // --proto tcp: our external IP (port-preserving NAT: srflx port == listen port)
    ushort listenPort; // --proto tcp: fixed TCP listen port, the port the punch dials out from
    auto help = getopt(args, "relay", &relayStr, "role", &role, "peer", &peerStr, "auto", &autoMode,
        "proto", &g_proto, "listen-port", &listenPort, "observed", &observed, "debug", &debugLog, "hold", &holdSecs, "ping-every", &pingEvery, "burn", &burnBytes, "no-punch", &noPunch, "connect-direct", &connectDirectMode);
    if (debugLog)
        setLogLevel(LogLevel.debug_);
    if (help.helpWanted || relayStr.length == 0)
    {
        writeln("punch-peer --relay <multiaddr/p2p/relayId> --role responder|initiator [--peer <id>]");
        stdout.flush();
        return help.helpWanted ? 0 : 2;
    }

    int result = 1;
    runTask(() nothrow {
        try
        {
            // Split the relay multiaddr into its dial address and its peer id.
            auto relayMa = Multiaddr.parse(relayStr);
            PeerId relayId;
            {
                bool found;
                foreach (c; relayMa.components)
                    if (c.name == "p2p")
                    {
                        relayId = PeerId.fromBytes(c.value);
                        found = true;
                    }
                if (!found)
                    throw new Exception("--relay must end in /p2p/<relayId>");
            }

            auto key = Keypair.generateEd25519;
            auto host = new Host(key, [new TcpTransport]);
            auto relay = new Relay(host);
            if (g_proto == "tcp")
            {
                // TCP punch = simultaneous-open from our listen port; the DCUtR exchange
                // advertises the observed address the peer must dial (no STUN for TCP).
                import std.conv : to;
                if (observed.length == 0 || listenPort == 0)
                    throw new Exception("--proto tcp needs --observed <ip> and --listen-port <port>");
                host.listen(Multiaddr.parse("/ip4/0.0.0.0/tcp/" ~ listenPort.to!string));
                auto obs = Multiaddr.parse("/ip4/" ~ observed ~ "/tcp/" ~ listenPort.to!string);
                relay.setObservedAddrs([obs.encode]);
                writeln("tcp punch: listening on :", listenPort, ", advertising ", obs.toString);
            }
            else if (g_proto == "quic")
            {
                // QUIC punch: srflx via STUN on a socket the punch then reuses; TLS 1.3
                // carries the peer identity, streams are native — no Noise, no yamux.
                version (Libp2pQuic)
                    host.swarm.addCapableTransport(new QuicTransport(key));
                else
                    throw new Exception("this build has no QUIC (Libp2pQuic)");
            }
            else
                host.swarm.addCapableTransport(new WebRtcTransport(key)); // srflx + punch
            relay.autoHolePunch = autoMode; // --auto: the service upgrades the link itself; else we punch explicitly
            new Ping(host);
            host.setStreamHandler(burnProtocol, (Stream s, Connection, string) {
                scope (exit)
                    s.close();
                serveBurn(s);
            });
            host.peerstore.addAddrs(relayId, [relayMa]);

            writeln("my peer id: ", host.id.toBase58);
            // Gather + show our reflexive webrtc-direct address up front: an empty
            // list means STUN was unreachable from here (e.g. no route/DNS out of
            // the netns) — the punch cannot work without it, so this is the first
            // thing to check when a run fails.
            auto myReflexive = host.reflexiveAddrs();
            if (myReflexive.length == 0)
                writeln("WARNING: no reflexive address gathered — STUN unreachable from here.");
            foreach (a; myReflexive)
                writeln("my reflexive addr: ", a.toString);
            stdout.flush();

            if (role == "responder")
            {
                relay.reserve(relayId);
                writeln("reserved on relay — waiting to be punched. Pass this id to the initiator.");
                stdout.flush();
                // serveDcutr punches back on its own when the initiator opens
                // DCUtR; we just stay alive and note when the direct link forms.
                // (A long-lived responder would re-reserve before the ~1h expiry.)
                immutable hasPeer = peerStr.length > 0;
                auto other = hasPeer ? PeerId.fromBase58(peerStr) : PeerId.init;
                bool announced;
                immutable t0 = MonoTime.currTime;
                string lastState;
                foreach (_; 0 .. 36_000) // ~1h at 100ms
                {
                    if (hasPeer && !announced && directTo(host, other) !is null)
                    {
                        writeln("DIRECT connection to the initiator formed — punched from this side too.");
                        stdout.flush();
                        announced = true;
                    }
                    // Every change in the connection set, with a timestamp: this is how a
                    // soak run shows WHEN the relayed and the direct links go away.
                    string state;
                    foreach (c; host.swarm.connections())
                        state ~= (state.length ? " | " : "") ~ c.remoteAddr.toString;
                    if (state != lastState)
                    {
                        writeln("[t+", (MonoTime.currTime - t0).total!"msecs" / 1000.0, "s] connections: ", state.length ? state : "(none)");
                        stdout.flush();
                        lastState = state;
                    }
                    sleep(100.msecs);
                }
                result = 0;
            }
            else
            {
                auto peer = PeerId.fromBase58(peerStr);
                writeln("reaching ", peer.toBase58, " through the relay...");
                stdout.flush();
                Connection direct;
                if (connectDirectMode)
                {
                    writeln("connectDirect: meeting through the relay, punching, dropping the circuit...");
                    stdout.flush();
                    direct = relay.connectDirect(relayId, peer);
                    writeln("DIRECT connection: ", direct.remoteAddr.toString);
                    foreach (c; host.swarm.connectionsTo(peer))
                        writeln("  in pool: ", c.remoteAddr.toString);
                    stdout.flush();
                }
                else
                    relay.connectVia(relayId, peer); // relayed connection first
                if (connectDirectMode)
                {
                }
                else if (noPunch)
                {
                    writeln("relayed — NOT punching (--no-punch); everything rides the circuit.");
                    stdout.flush();
                    result = burnBytes ? (burn(host, peer, burnBytes) ? 0 : 1) : 0;
                    if (holdSecs)
                        result = hold(host, peer, host.swarm.connection(peer), holdSecs, pingEvery) ? 0 : 1;
                }
                else if (autoMode)
                {
                    writeln("relayed — waiting for auto-DCUtR to upgrade the link...");
                    stdout.flush();
                    // No explicit punch: Relay.connected() saw the relayed dial and
                    // is running the DCUtR exchange + punch on its own.
                }
                else
                {
                    writeln("relayed — triggering hole punch (DCUtR)...");
                    stdout.flush();
                    // A punch that opens no path throws ("no direct address answered");
                    // don't bail on it — fall through so the FAIL branch below can dump
                    // the connection state, which is what tells us why it didn't punch.
                    try
                    {
                        auto got = relay.holePunch(peer);
                        writeln("DCUtR done; authenticated ", got.toBase58);
                    }
                    catch (Exception e)
                    {
                        writeln("DCUtR punch did not complete: ", e.msg);
                        for (Throwable t = e.next; t !is null; t = t.next)
                            writeln("  because: ", t.msg);
                    }
                    stdout.flush();
                }

                // auto-DCUtR has to run the exchange itself, so give it a bit longer.
                immutable deadline = MonoTime.currTime + (noPunch || connectDirectMode ? 0.seconds : autoMode ? 20.seconds : 10.seconds);
                while (direct is null && MonoTime.currTime < deadline)
                {
                    direct = directTo(host, peer);
                    if (direct !is null)
                        break;
                    sleep(100.msecs);
                }
                if (direct is null && noPunch)
                {
                }
                else if (direct is null)
                {
                    writeln("FAIL: no direct ", g_proto, " connection formed (still relayed).");
                    writeln("connections to the peer right now:");
                    foreach (c; host.swarm.connectionsTo(peer))
                        writeln("  ", c.remoteAddr.toString);
                    stdout.flush();
                }
                else
                {
                    writeln("DIRECT connection: ", direct.remoteAddr.toString);
                    stdout.flush();
                    auto s = direct.newStream(pingProtocol);
                    scope (exit)
                        s.close();
                    auto rtt = ping(s);
                    writeln("PASS: ping over the punched connection, rtt ", rtt.total!"usecs" / 1000.0, " ms");
                    stdout.flush();
                    result = 0;
                    if (burnBytes && !burn(host, peer, burnBytes))
                        result = 1;
                    if (holdSecs && !hold(host, peer, direct, holdSecs, pingEvery))
                        result = 1;
                }
            }
        }
        catch (Exception e)
        {
            try
                stderr.writeln("punch-peer failed: ", e.msg);
            catch (Exception)
            {
            }
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
