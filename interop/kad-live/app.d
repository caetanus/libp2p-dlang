/// Kademlia against the real public IPFS DHT (live network, no node): seed the
/// libp2p bootstrap nodes, then ask for the peers closest to a random key. If the
/// (seeding the table with them), self-bootstrap to fill it, then ask the network
/// table grows past the seeds and find_node converges, our kad stack — /ipfs/kad/1.0.0
/// over TCP/Noise-XX/yamux/identify — genuinely interoperates with the live DHT.
///
/// PASS (exit 0) = at least one bootstrap reachable, the table learned peers
/// beyond the seeds, and getClosestPeers returned peers. Self-diagnosing per stage.
///
///   kad-live [--bootstrap <multiaddr/p2p/id>]...   (repeatable; sensible defaults)
module app;

import std.getopt : getopt;
import std.random : uniform;
import std.stdio : writeln, stderr, stdout;

import vibe.core.core : runTask, runEventLoop, exitEventLoop;

import libp2p.core.peer_id : PeerId;
import libp2p.crypto.keys : Keypair;
import libp2p.host.host : Host;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.protocol.kad.kad : Kademlia;
import libp2p.protocol.identify : IdentifyService;
import libp2p.transport.tcp : TcpTransport;

private enum string[] defaultBootstrap = [
    "/dnsaddr/bootstrap.libp2p.io/p2p/QmNnooDu7bfjPFoTZYxMNLWUQJyrVwtbZg5gBMjTezGAJN",
    "/dnsaddr/va1.bootstrap.libp2p.io/p2p/12D3KooWKnDdG3iXw9eTFijk3EWSunZcFdmad7GqDsQ9Jr9AH2ka",
    "/ip4/104.131.131.82/tcp/4001/p2p/QmaCpDMGvV2BGHeYERUEnRQAwe3N8SzbUtfsmvsqQLuvuJ",
];

int main(string[] args)
{
    string[] bootstrap;
    auto help = getopt(args, "bootstrap", &bootstrap);
    if (help.helpWanted)
    {
        writeln("kad-live [--bootstrap <multiaddr/p2p/id>]... (repeatable)");
        return 0;
    }
    if (bootstrap.length == 0)
        bootstrap = defaultBootstrap.dup;

    int result = 1;
    runTask(() nothrow {
        try
        {
            auto key = Keypair.generateEd25519;
            auto host = new Host(key, [new TcpTransport]);
            new IdentifyService(host);
            auto kad = new Kademlia(host);
            writeln("our id: ", host.id.toBase58);

            // Seed the routing table with the bootstrap peers. addAddress (not
            // host.connect) is what puts a peer in the kad table — connecting only
            // updates the status of a peer already there; the lookup dials the
            // seeds itself. Without seeding, bootstrap()'s query has no one to ask.
            size_t seeded;
            foreach (b; bootstrap)
            {
                try
                {
                    auto ma = Multiaddr.parse(b);
                    PeerId peer;
                    bool found;
                    foreach (c; ma.components)
                        if (c.name == "p2p")
                        {
                            peer = PeerId.fromBytes(c.value);
                            found = true;
                        }
                    if (!found)
                    {
                        writeln("skip (no /p2p/id): ", b);
                        continue;
                    }
                    kad.addAddress(peer, ma);
                    seeded++;
                    writeln("seeded bootstrap: ", peer.toBase58);
                }
                catch (Exception e)
                    writeln("bad bootstrap (", b, "): ", e.msg);
                stdout.flush();
            }

            if (seeded == 0)
            {
                writeln("FAIL: no usable bootstrap address — supply --bootstrap <multiaddr/p2p/id>");
                throw new Exception("no bootstrap");
            }

            immutable tableSize = kad.bootstrap(); // dials the seeds, self-lookup fills the table
            writeln("routing table after bootstrap: ", tableSize, " peers (seeds: ", seeded, ")");

            ubyte[32] target;
            foreach (ref x; target)
                x = cast(ubyte) uniform(0, 256);
            auto closest = kad.getClosestPeers(target[]);
            writeln("getClosestPeers(random) returned ", closest.length, " peers");

            if (tableSize > seeded && closest.length > 0)
            {
                writeln("PASS: kad converged on the live IPFS DHT");
                result = 0;
            }
            else
                writeln("FAIL: connected but the query did not converge (table ", tableSize,
                    ", closest ", closest.length, ")");

            host.close();
        }
        catch (Exception e)
        {
            try
                stderr.writeln("kad-live error: ", e.msg);
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
