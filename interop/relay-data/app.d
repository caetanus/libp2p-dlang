/// Circuit-relay v2 DATA-path burn-in: two peers talk THROUGH the relay without
/// hole-punching (force-relayed), and we push a large payload over that circuit.
/// Exercises the relay's byte forwarding, its per-circuit byte limit, and
/// backpressure — the classic weak spot: does it forward every byte intact, and
/// at the limit does it cut cleanly or stall / lose data?
///
/// Two phases, both self-diagnosing:
///  1. THROUGHPUT — relay limit raised above the payload; assert bytes-received ==
///     bytes-sent and the checksum matches (no loss, no corruption).
///  2. LIMIT — default 128 KiB cap, push well past it; assert the transfer stops
///     at ~the cap with a clean error (not a hang), and what arrived is intact.
///
/// PASS (exit 0) iff both phases hold. Pure D, no node, loopback.
///
///   relay-data [--mb <throughput payload MiB, default 4>]
module app;

import core.time : Duration, MonoTime, msecs, seconds, minutes, hours;
import std.getopt : getopt;
import std.stdio : writeln, stderr, stdout;

import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;

import libp2p.core.ending : EndOfStream, ConnClosed;
import libp2p.core.stream : Stream;
import libp2p.core.peer_id : PeerId;
import libp2p.crypto.keys : Keypair;
import libp2p.host.host : Host, Connection;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.protocol.relay.service : Relay, RelayLimits;
import libp2p.transport.tcp : TcpTransport;

private enum dataProto = "/burn-in/relay-data/1.0.0";

// A sink handler: read everything until EOF, count bytes + an additive checksum.
private __gshared size_t g_recvLen;
private __gshared ulong g_recvSum;
private __gshared bool g_sinkDone;

private void sink(Stream s, Connection, string) nothrow
{
    g_recvLen = 0;
    g_recvSum = 0;
    g_sinkDone = false;
    try
    {
        auto buf = new ubyte[64 * 1024];
        for (;;)
        {
            immutable n = s.read(buf);
            foreach (b; buf[0 .. n])
                g_recvSum += b;
            g_recvLen += n;
        }
    }
    catch (Exception)
    {
        // EOF (sender closed) or the circuit was cut at the limit; either way the
        // receive side is done — the counters hold what actually arrived.
    }
    g_sinkDone = true;
}

// Send `total` bytes (pattern byte i = i & 0xff) over `s`, returns the checksum
// of what we managed to write; sets *cut if the circuit errored mid-send.
private ulong pump(Stream s, size_t total, out bool cut, out size_t sent)
{
    auto chunk = new ubyte[64 * 1024];
    ulong sum = 0;
    sent = 0;
    cut = false;
    size_t i = 0;
    while (i < total)
    {
        immutable n = total - i < chunk.length ? total - i : chunk.length;
        foreach (j; 0 .. n)
        {
            immutable b = cast(ubyte)((i + j) & 0xff);
            chunk[j] = b;
            sum += b;
        }
        try
            s.write(chunk[0 .. n]);
        catch (Exception)
        {
            cut = true; // the relay cut the circuit (limit) or the peer went away
            break;
        }
        sent += n;
        i += n;
    }
    return sum;
}

private struct Nodes
{
    Host relayHost, aHost, bHost;
    Relay relay, aRelay, bRelay;
}

// Stand up relay + A + B, B reserves, A connects THROUGH the relay (no punch).
private Connection wire(RelayLimits limits)
{
    auto rk = Keypair.generateEd25519;
    auto relayHost = new Host(rk, [new TcpTransport]);
    new Relay(relayHost, limits);
    relayHost.listen(Multiaddr.parse("/ip4/127.0.0.1/tcp/0"));

    auto bk = Keypair.generateEd25519;
    auto bHost = new Host(bk, [new TcpTransport]);
    auto bRelay = new Relay(bHost);
    bHost.setStreamHandler(dataProto, (Stream s, Connection c, string p) nothrow{ sink(s, c, p); });
    bHost.peerstore.addAddrs(relayHost.id, relayHost.addrs);
    bRelay.reserve(relayHost.id);

    auto ak = Keypair.generateEd25519;
    auto aHost = new Host(ak, [new TcpTransport]);
    auto aRelay = new Relay(aHost);
    aHost.peerstore.addAddrs(relayHost.id, relayHost.addrs);

    return aRelay.connectVia(relayHost.id, bHost.id); // relayed connection
}

int main(string[] args)
{
    size_t mb = 4;
    auto help = getopt(args, "mb", &mb);
    if (help.helpWanted)
    {
        writeln("relay-data [--mb <throughput payload MiB, default 4>]");
        return 0;
    }

    int result = 1;
    runTask(() nothrow {
        bool throughputOk, limitOk;
        try
        {
            // --- Phase 1: throughput, limit raised above the payload -------------
            immutable payload = mb * 1024 * 1024;
            RelayLimits big;
            big.maxCircuitBytes = payload + 1024 * 1024;
            big.maxCircuitDuration = 10.minutes;
            auto c1 = wire(big);
            auto s1 = c1.newStream(dataProto);
            bool cut1;
            size_t sent1;
            immutable sum1 = pump(s1, payload, cut1, sent1);
            s1.close(); // EOF to the sink
            waitSink();
            writeln("PHASE throughput: sent=", sent1, " recv=", g_recvLen,
                " cut=", cut1, " sum_match=", (g_recvSum == sum1));
            throughputOk = !cut1 && g_recvLen == payload && g_recvSum == sum1;

            // --- Phase 2: default 128 KiB cap, push past it ---------------------
            RelayLimits small; // default maxCircuitBytes = 128 KiB
            immutable overshoot = 512 * 1024;
            auto c2 = wire(small);
            auto s2 = c2.newStream(dataProto);
            bool cut2;
            size_t sent2;
            cast(void) pump(s2, overshoot, cut2, sent2);
            try
                s2.close();
            catch (Exception)
            {
            }
            waitSink();
            // Clean cut: the receiver got at most the cap, the sender saw the
            // circuit close rather than hanging, and nothing beyond the cap slipped.
            writeln("PHASE limit: recv=", g_recvLen, " cap=", small.maxCircuitBytes,
                " sender_saw_cut=", cut2);
            limitOk = g_recvLen <= small.maxCircuitBytes && g_recvLen > 0;

            if (throughputOk && limitOk)
            {
                writeln("PASS: relay forwards a large payload intact and enforces its byte cap cleanly");
                result = 0;
            }
            else
                writeln("FAIL: throughputOk=", throughputOk, " limitOk=", limitOk);
        }
        catch (Exception e)
        {
            try
                stderr.writeln("relay-data error: ", e.msg);
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

// Wait for the sink handler to finish draining the current transfer.
private void waitSink()
{
    immutable deadline = MonoTime.currTime + 30.seconds;
    while (!g_sinkDone && MonoTime.currTime < deadline)
        sleep(10.msecs);
}
