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

    // client: local=clientAddr, remote=serverAddr. server mirrors.
    auto client = QuicConnection.dial(clientAddr, serverAddr);
    scope (exit)
        client.close();

    // The client's first Initial (ClientHello) bootstraps the server.
    ubyte[2048] scratch;
    auto initial = client.writeOne(scratch[]).dup;
    writeln("client Initial: ", initial.length, " bytes, first=0x",
        initial.length ? initial[0] : 0);

    auto server = QuicConnection.accept(initial, serverAddr, clientAddr);
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
    if (client.handshakeComplete && server.handshakeComplete)
    {
        writeln("PASS: QUIC TLS 1.3 handshake completed both ways (in memory)");
        return 0;
    }
    writeln("FAIL: handshake did not complete");
    return 1;
}
