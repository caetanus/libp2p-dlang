/// QUIC handshake, in memory: a client QuicConnection and a server QuicConnection
/// drive a full TLS 1.3 handshake over ngtcp2 by handing each other packets (no
/// sockets). PASS when both report handshakeComplete. Validates the whole
/// QuicConnection wrapper (dial/accept/wireTls/deliver/writeOne) end to end.
///
///   dub run -c quic-check
module app;

import std.stdio : writeln;
import core.sys.posix.sys.socket : AF_INET;
import core.sys.posix.netinet.in_ : sockaddr_in;
import core.sys.posix.arpa.inet : htons, htonl;

import libp2p.crypto.keys : Keypair;
import libp2p.transport.quic.connection : QuicConnection;

// sockaddr_in(127.0.0.1:port) as raw bytes.
private ubyte[] loopback(ushort port)
{
    sockaddr_in sa;
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(0x7f00_0001);
    return (cast(ubyte*)&sa)[0 .. sockaddr_in.sizeof].dup;
}

// Drain every packet `from` wants to send and feed each to `to`.
private void pump(QuicConnection from, QuicConnection to)
{
    ubyte[2048] scratch;
    for (;;)
    {
        auto pkt = from.writeOne(scratch[]);
        if (pkt.length == 0)
            break;
        to.deliver(pkt);
    }
}

int main()
{
    auto clientAddr = loopback(1234);
    auto serverAddr = loopback(5678);

    auto clientId = Keypair.generateEd25519();
    auto serverId = Keypair.generateEd25519();

    // client: local=clientAddr, remote=serverAddr. server mirrors.
    auto client = QuicConnection.dial(clientId, clientAddr, serverAddr);
    scope (exit)
        client.close();

    // The client's first Initial (ClientHello) bootstraps the server.
    ubyte[2048] scratch;
    auto initial = client.writeOne(scratch[]).dup;
    writeln("client Initial: ", initial.length, " bytes, first=0x",
        initial.length ? initial[0] : 0);

    auto server = QuicConnection.accept(serverId, initial, serverAddr, clientAddr);
    scope (exit)
        server.close();
    server.deliver(initial);

    foreach (round; 0 .. 20)
    {
        if (client.handshakeComplete && server.handshakeComplete)
            break;
        pump(server, client);
        pump(client, server);
    }

    writeln("client handshake: ", client.handshakeComplete,
        "  server handshake: ", server.handshakeComplete);
    if (!client.handshakeComplete || !server.handshakeComplete)
    {
        writeln("FAIL: handshake did not complete");
        return 1;
    }

    // Each side reads the other's PeerId from its certificate's libp2p extension
    // and it must match the identity that side actually holds.
    import libp2p.core.peer_id : PeerId;

    auto wantServer = PeerId.fromPublicKey(serverId.publicKey);
    auto wantClient = PeerId.fromPublicKey(clientId.publicKey);
    auto gotServer = client.remotePeerId();
    auto gotClient = server.remotePeerId();
    writeln("client sees server as ", gotServer.toBase58);
    writeln("server sees client as ", gotClient.toBase58);
    if (gotServer != wantServer || gotClient != wantClient)
    {
        writeln("FAIL: peer id mismatch");
        return 1;
    }

    writeln("PASS: QUIC libp2p-TLS handshake + verified peer identities (in memory)");
    return 0;
}
