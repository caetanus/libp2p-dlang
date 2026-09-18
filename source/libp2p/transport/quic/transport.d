/// QUIC as a first-class libp2p transport (/quic-v1).
///
/// QUIC is special: a `QuicConnection` is already a secured, multiplexed session
/// with a verified peer identity (TLS 1.3 + the libp2p cert extension + native
/// streams). So it does NOT take the raw dial → upgrade(Noise, Yamux) path; it
/// implements `CapableTransport`, handing the swarm a finished `UpgradedConn`.
/// The swarm still owns admission (limits, gater, pool). Opt-in behind
/// version(Libp2pQuic).
module libp2p.transport.quic.transport;

version (Libp2pQuic):

import std.algorithm.searching : canFind, find;
import std.exception : enforce;
import std.format : format;
import std.range : empty, front;
import std.socket : AddressFamily;
import std.typecons : Nullable;

import vibe.core.net : NetworkAddress, resolveHost;

import libp2p.crypto.keys : Keypair;
import libp2p.core.peer_id : PeerId;
import libp2p.multiformats.multiaddr : Multiaddr, Component;
import libp2p.swarm.swarm : CapableTransport, UpgradedConn;
import libp2p.transport.quic.connection : QuicConnection;
import libp2p.transport.quic.udp : QuicClient, QuicListener;

final class QuicTransport : CapableTransport
{
    private Keypair _identity;
    private QuicListener[] _listeners;
    private QuicClient[] _clients;

    this(Keypair identity)
    {
        _identity = identity;
    }

    bool canHandle(const Multiaddr addr)
    {
        try
        {
            auto c = Multiaddr(addr.bytes.dup).components;
            return c.canFind!(x => x.name == "quic-v1")
                && c.canFind!(x => x.name == "udp")
                && c.canFind!(x => x.name == "ip4" || x.name == "ip6");
        }
        catch (Exception)
            return false;
    }

    UpgradedConn dial(const Multiaddr remote, Nullable!PeerId expected)
    {
        enforce(canHandle(remote), "quic: cannot dial " ~ remote.toString);
        auto ma = Multiaddr(remote.bytes.dup);
        auto c = ma.components;

        // A trailing /p2p/<id> names who we expect on the far side.
        if (!c.empty && c[$ - 1].name == "p2p")
        {
            auto named = PeerId.fromBytes(c[$ - 1].value);
            enforce(expected.isNull || expected.get == named, "quic: address names another peer");
            expected = named;
        }

        immutable ipv6 = c.canFind!(x => x.name == "ip6");
        auto peer = toUdpAddress(c);
        auto client = new QuicClient(_identity, peer, ipv6 ? "::" : "0.0.0.0");
        _clients ~= client;
        scope (failure)
            client.close();

        client.waitForHandshake();
        auto conn = client.connection;
        auto rp = conn.remotePeerId(); // verified from the cert's libp2p extension
        enforce(expected.isNull || expected.get == rp,
            "quic: the peer is " ~ rp.toString ~ ", not " ~ expected.get.toString);

        UpgradedConn up;
        up.muxer = conn;
        up.remotePeer = rp;
        rp.tryPublicKey(up.remoteKey);
        up.localAddr = toQuicMultiaddr(client.localAddress);
        up.remoteAddr = ma;
        return up;
    }

    Multiaddr listen(const Multiaddr local, void delegate(UpgradedConn) onInbound)
    {
        enforce(canHandle(local), "quic: cannot listen on " ~ local.toString);
        auto c = Multiaddr(local.bytes.dup).components;
        auto bind = toUdpAddress(c);
        auto ipText = c.find!(x => x.name == "ip4" || x.name == "ip6").front.text;

        auto listener = new QuicListener(_identity, bind.port, ipText);
        _listeners ~= listener;
        listener.onAccept = (QuicConnection conn, NetworkAddress from) nothrow {
            try
            {
                UpgradedConn up;
                up.muxer = conn;
                up.remotePeer = conn.remotePeerId(); // onAccept fires post-handshake
                up.remotePeer.tryPublicKey(up.remoteKey);
                up.localAddr = toQuicMultiaddr(listener.localAddress);
                up.remoteAddr = toQuicMultiaddr(from);
                onInbound(up);
            }
            catch (Exception)
            {
            }
        };
        return toQuicMultiaddr(listener.localAddress);
    }

    /// QUIC is not (yet) in the DCUtR hole-punch path.
    Multiaddr reflexiveAddr()
    {
        return Multiaddr.init;
    }

    UpgradedConn punch(const Multiaddr peerSrflx, PeerId remote, bool asDialer, Nullable!PeerId expected)
    {
        throw new Exception("quic: hole punch not implemented yet");
    }

    void close() nothrow
    {
        foreach (l; _listeners)
            try
                l.close();
            catch (Exception)
            {
            }
        foreach (cl; _clients)
            try
                cl.close();
            catch (Exception)
            {
            }
    }
}

// The ip/udp of a /ip4|ip6/.../udp/<port>/quic-v1 address as a NetworkAddress.
private NetworkAddress toUdpAddress(scope Component[] c)
{
    auto ip = c.find!(x => x.name == "ip4" || x.name == "ip6");
    enforce(!ip.empty, "quic: address has no ip4/ip6");
    auto udp = c.find!(x => x.name == "udp");
    enforce(!udp.empty, "quic: address has no udp");
    auto na = resolveHost(ip.front.text,
        ip.front.name == "ip4" ? AddressFamily.INET : AddressFamily.INET6, false);
    na.port = cast(ushort)((udp.front.value[0] << 8) | udp.front.value[1]);
    return na;
}

// A /ip4|ip6/<ip>/udp/<port>/quic-v1 multiaddr for `na`.
private Multiaddr toQuicMultiaddr(NetworkAddress na)
{
    immutable ip = na.toAddressString;
    immutable proto = na.family == AddressFamily.INET6 ? "ip6" : "ip4";
    return Multiaddr.parse(format("/%s/%s/udp/%d/quic-v1", proto, ip, na.port));
}
