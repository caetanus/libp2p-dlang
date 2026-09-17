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
/// The punch is DRIVEN here on purpose (explicit holePunch) — auto-DCUtR on a
/// relayed connection is the thin-consumer piece (item 3), out of scope for 2e.
///
///   punch-peer --relay /ip4/<pub>/tcp/<port>/p2p/<relayId> --role responder
///   punch-peer --relay /ip4/<pub>/tcp/<port>/p2p/<relayId> --role initiator --peer <responderId>
module app;

import core.time : msecs, seconds, MonoTime;
import std.algorithm.searching : canFind;
import std.getopt : getopt;
import std.stdio : writeln, stderr, stdout;

import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;

import libp2p.core.peer_id : PeerId;
import libp2p.crypto.keys : Keypair;
import libp2p.host.host : Host, Connection;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.protocol.ping : Ping, ping, pingProtocol;
import libp2p.protocol.relay.service : Relay;
import libp2p.transport.tcp : TcpTransport;
import libp2p.transport.webrtc.transport : WebRtcTransport;

// The webrtc-direct connection to `peer`, if the punch upgraded us off the relay.
private Connection directTo(Host host, PeerId peer)
{
    foreach (c; host.swarm.connectionsTo(peer))
        if (c.remoteAddr.toString.canFind("/webrtc-direct/") && !c.remoteAddr.toString.canFind("/p2p-circuit"))
            return c;
    return null;
}

int main(string[] args)
{
    string relayStr, role = "responder", peerStr;
    auto help = getopt(args, "relay", &relayStr, "role", &role, "peer", &peerStr);
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
            host.swarm.addCapableTransport(new WebRtcTransport(key)); // srflx + punch
            auto relay = new Relay(host);
            new Ping(host);
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
                foreach (_; 0 .. 36_000) // ~1h at 100ms
                {
                    if (hasPeer && !announced && directTo(host, other) !is null)
                    {
                        writeln("DIRECT connection to the initiator formed — punched from this side too.");
                        stdout.flush();
                        announced = true;
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
                relay.connectVia(relayId, peer); // relayed connection first
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
                    writeln("DCUtR punch did not complete: ", e.msg);
                stdout.flush();

                Connection direct;
                immutable deadline = MonoTime.currTime + 10.seconds;
                while (MonoTime.currTime < deadline)
                {
                    direct = directTo(host, peer);
                    if (direct !is null)
                        break;
                    sleep(100.msecs);
                }
                if (direct is null)
                {
                    writeln("FAIL: no direct /webrtc-direct/ connection formed (still relayed).");
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
