/// A public relay + DCUtR rendezvous for the two-NAT hole-punch validation (2e).
///
/// Runs a plain TCP Host with the relay service on it: reservers get a slot, a
/// dialer reaches a reserved peer through the circuit, and the /libp2p/dcutr
/// stream both punch-peers use to swap their reflexive webrtc-direct addresses
/// rides over the same connection. The relay itself needs no NAT and no webrtc —
/// the punch is peer-to-peer; the relay only carries the signaling and the
/// initial relayed connection.
///
/// Run on the public server:
///   relay-node --listen /ip4/0.0.0.0/tcp/4001 --public <server-public-ip>
/// It prints the dialable multiaddr the punch-peers pass as --relay.
module app;

import std.getopt : getopt;
import std.stdio : writeln, stderr, stdout;

import vibe.core.core : runTask, runEventLoop;

import libp2p.crypto.keys : Keypair;
import libp2p.host.host : Host;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.protocol.relay.service : Relay;
import libp2p.transport.tcp : TcpTransport;

int main(string[] args)
{
    string listen = "/ip4/0.0.0.0/tcp/4001";
    string publicIp = "";
    ushort port = 4001;
    auto help = getopt(args, "listen", &listen, "public", &publicIp, "port", &port);
    if (help.helpWanted)
    {
        writeln("relay-node --listen /ip4/0.0.0.0/tcp/<port> --public <public-ip> [--port <port>]");
        return 0;
    }

    runTask(() nothrow {
        try
        {
            auto key = Keypair.generateEd25519;
            auto host = new Host(key, [new TcpTransport]);
            new Relay(host); // installs hop/stop/dcutr handlers on the host
            host.listen(Multiaddr.parse(listen));

            writeln("relay peer id: ", host.id.toBase58);
            foreach (a; host.addrs)
                writeln("relay listening: ", a.toString);
            if (publicIp.length)
                writeln("relay dial addr (pass as --relay): /ip4/", publicIp, "/tcp/", port,
                    "/p2p/", host.id.toBase58);
            writeln("relay ready — reservations + DCUtR signaling open.");
            stdout.flush(); // stdout is block-buffered off a TTY; flush so the operator sees the id now
        }
        catch (Exception e)
        {
            try
                stderr.writeln("relay-node failed: ", e.msg);
            catch (Exception)
            {
            }
        }
    });
    runEventLoop();
    return 0;
}
