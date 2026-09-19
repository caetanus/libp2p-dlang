/// Live webrtc-direct hole-punch tester. Gathers our server-reflexive
/// /webrtc-direct address via STUN/ICE, exchanges it with the peer out of band
/// (file rendezvous the orchestrator fills), then both punch at a shared instant.
/// Prints "PUNCH ok" with the verified remote PeerId. Meant to run one peer behind
/// each NAT (works through double NAT — it is STUN-based like QUIC).
///
///   webrtc-punch --role dialer|listener --out-file F --peer-file F --fire-at MS
module app;

import std.stdio : writeln, stderr, stdout;
import std.getopt : getopt;
import std.conv : to;
import std.string : strip, split;
import std.typecons : Nullable, nullable;
import std.file : exists, readText, write;
import std.datetime.systime : Clock;
import core.time : msecs, MonoTime, seconds;

import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;

import libp2p.crypto.keys : Keypair;
import libp2p.core.peer_id : PeerId;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.swarm.swarm : UpgradedConn;
import libp2p.transport.webrtc.transport : WebRtcTransport, WebRtcConfig;

__gshared string g_role = "dialer";
__gshared string g_outFile;
__gshared string g_peerFile;
__gshared string g_peerArg;
__gshared long g_fireAtMs = 0;

private long nowMs()
{
    auto t = Clock.currTime;
    return t.toUnixTime!long * 1000 + t.fracSecs.total!"msecs";
}

int main(string[] args)
{
    getopt(args, "role", &g_role, "out-file", &g_outFile, "peer-file", &g_peerFile,
        "peer", &g_peerArg, "fire-at", &g_fireAtMs);
    int rc = 1;
    runTask(() nothrow {
        try
        {
            auto key = Keypair.generateEd25519;
            auto myId = PeerId.fromPublicKey(key.publicKey);
            auto t = new WebRtcTransport(key);

            auto srflx = t.reflexiveAddr();
            if (srflx.bytes.length == 0)
                throw new Exception("no webrtc reflexive address (STUN unreachable?)");
            immutable line = srflx.toString ~ " " ~ myId.toBase58;
            writeln("MYADDR ", line);
            stdout.flush();
            if (g_outFile.length)
                write(g_outFile, line ~ "\n");

            string peerLine = g_peerArg.strip;
            while (peerLine.length == 0)
            {
                if (g_peerFile.length && exists(g_peerFile))
                    peerLine = readText(g_peerFile).strip;
                if (peerLine.length == 0)
                    sleep(300.msecs);
            }
            auto parts = peerLine.split;
            auto peerAddr = Multiaddr.parse(parts[0]);
            auto peerId = PeerId.fromBase58(parts[1]);
            if (parts.length >= 3)
                g_fireAtMs = parts[2].to!long;
            writeln("peer: ", parts[0], " ", parts[1], " role=", g_role);
            stdout.flush();

            if (g_fireAtMs > 0)
            {
                immutable wait = g_fireAtMs - nowMs();
                if (wait > 0)
                    sleep(wait.msecs);
            }
            writeln("PUNCH now (asDialer=", g_role == "dialer", ")");
            stdout.flush();
            auto up = t.punch(peerAddr, peerId, g_role == "dialer", nullable(peerId));
            writeln("PUNCH ok: direct webrtc to ", up.remotePeer.toBase58, " at ", up.remoteAddr.toString);
            stdout.flush();
            rc = 0;
            // keep it briefly so both sides settle
            sleep(2.seconds);
            up.muxer.close();
        }
        catch (Exception e)
        {
            try
                stderr.writeln("webrtc-punch error: ", e.msg);
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
