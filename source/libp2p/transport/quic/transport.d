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
import core.time : MonoTime, msecs, seconds;
import vibe.core.core : runTask, sleep;

import vibe.core.net : NetworkAddress, resolveHost;

import libp2p.crypto.keys : Keypair;
import libp2p.core.peer_id : PeerId;
import libp2p.multiformats.multiaddr : Multiaddr, Component;
import libp2p.swarm.swarm : CapableTransport, UpgradedConn;
import libp2p.transport.quic.connection : QuicConnection;
import libp2p.transport.quic.udp : QuicClient, QuicListener, QuicPump;
import libp2p.transport.quic.punch : QuicPunchSocket;

/// QUIC transport configuration.
struct QuicConfig
{
    /// STUN servers ("host:port") probed for our server-reflexive address, on the
    /// socket a later hole punch reuses. Mirrors WebRtcConfig's default list.
    string[] stunServers = ["stun.l.google.com:19302", "stun.cloudflare.com:3478"];
}

final class QuicTransport : CapableTransport
{
    private Keypair _identity;
    private QuicConfig _cfg;
    private QuicListener[] _listeners;
    private QuicClient[] _clients;
    private QuicPunchSocket _punchSock; // shared srflx-gathering + punch socket
    private Multiaddr _reflexive;
    private bool _gathered;

    this(Keypair identity, QuicConfig cfg = QuicConfig.init)
    {
        _identity = identity;
        _cfg = cfg;
    }

    bool canHandle(const Multiaddr addr)
    {
        try
        {
            auto c = Multiaddr(addr.bytes.dup).components;
            // A /webtransport address rides QUIC but speaks HTTP/3 + certhashes — not
            // ours to dial as plain quic-v1.
            return c.canFind!(x => x.name == "quic-v1")
                && c.canFind!(x => x.name == "udp")
                && c.canFind!(x => x.name == "ip4" || x.name == "ip6")
                && !c.canFind!(x => x.name == "webtransport");
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

        // ONE UDP socket does listen + hole-punch + STUN (the go-libp2p / quic-go
        // single-PacketConn model): every path shares one NAT mapping, so the address
        // we advertise (observed IP paired with THIS listen port) is exactly the
        // mapping our punch egresses from. A separate ephemeral punch socket would
        // fire from a different source port than the one the peer was told to aim at,
        // and the two simultaneous-open packets would never meet. `listen()` runs at
        // startup before any dial/punch, so it is the one that binds the shared socket.
        if (_punchSock is null)
            _punchSock = new QuicPunchSocket(_identity, ipText, bind.port);
        auto sock = _punchSock;
        sock.onInbound = (QuicConnection conn, NetworkAddress from) nothrow {
            try
            {
                UpgradedConn up;
                up.muxer = conn;
                up.remotePeer = conn.remotePeerId(); // fires post-handshake
                up.remotePeer.tryPublicKey(up.remoteKey);
                up.localAddr = toQuicMultiaddr(sock.localAddress);
                up.remoteAddr = toQuicMultiaddr(from);
                onInbound(up);
            }
            catch (Exception)
            {
            }
        };
        startReflexive(); // warm our srflx on THIS socket from node start
        return toQuicMultiaddr(sock.localAddress);
    }

    /// Our server-reflexive /quic-v1 address, gathered once via STUN on a socket
    /// kept open so a later hole punch reuses the same NAT mapping. Multiaddr.init
    /// if no STUN server answered.
    Multiaddr reflexiveAddr()
    {
        // The gather is fully async (startReflexive's background task); we never run
        // STUN inline here. Once warmed — the common case, since listen() starts the
        // gather at boot — _gathered is set and we return the cache at once. A cold
        // or direct caller (a diagnostic, the first punch before warming lands) gets
        // a brief COOPERATIVE wait for the first round; it is bounded, so unreachable
        // STUN (VPN down, no internet) returns empty instead of hanging, and it yields
        // to the event loop rather than blocking the thread.
        startReflexive();
        for (int i = 0; i < 30 && !_gathered; i++)
            try
                sleep(100.msecs);
            catch (Exception)
                break; // no event loop to yield to: hand back whatever we have
        return _reflexive;
    }

    /// Begin gathering our server-reflexive address in the BACKGROUND, refreshing
    /// it on a keepalive cadence — so a DCUtR offer reads a warm cache instead of
    /// blocking on STUN, and so the address exists BEFORE the first punch, not only
    /// during one (the punch socket is otherwise created lazily by a punch itself).
    /// Idempotent, non-blocking and nothrow: called eagerly on listen() and again
    /// when a relayed connection forms (a punch is imminent), it must never abort or
    /// stall those paths. A failed/unreachable STUN round (e.g. VPN down, no
    /// internet on Android) is swallowed and simply retried. A NAT forgets an idle
    /// UDP mapping in 30-120 s (a CGNAT sooner), so the same-socket STUN round every
    /// 20 s both refreshes the mapping and keeps the cached address current.
    void startReflexive() nothrow
    {
        if (_keepalive)
            return;
        _keepalive = true;
        try
            runTask(() nothrow {
                try
                    for (;;)
                    {
                        if (!_gathered || MonoTime.currTime - _gatheredAt >= srflxMaxAge)
                            gather();
                        sleep(20.seconds);
                    }
                catch (Exception)
                {
                }
            });
        catch (Exception)
            _keepalive = false; // spawning failed; let a later call try again
    }

    private enum srflxMaxAge = 25.seconds;
    private MonoTime _gatheredAt;
    private bool _keepalive;
    private bool _gathering;

    // One STUN round on the punch socket; a failed round keeps the last answer.
    private void gather() nothrow
    {
        if (_gathering)
            return; // one STUN transaction on the shared punch socket at a time
        _gathering = true;
        scope (exit)
            _gathering = false;
        try
        {
            if (_punchSock is null)
                _punchSock = new QuicPunchSocket(_identity);
            auto srflx = _punchSock.gatherReflexive(_cfg.stunServers, 2.seconds);
            if (!srflx.isNull)
            {
                _reflexive = toQuicMultiaddr(srflx.get);
                _gathered = true;
                _gatheredAt = MonoTime.currTime;
            }
        }
        catch (Exception)
        {
        }
    }

    /// Punch a direct QUIC connection to `remote` at its reflexive address, reusing
    /// the socket reflexiveAddr() gathered on. Both peers call this at once (DCUtR);
    /// `asDialer` splits the one asymmetric role QUIC needs — the dialer runs the
    /// QUIC client handshake, the other side the server. TLS identity replaces any
    /// certhash pin.
    UpgradedConn punch(const Multiaddr peerSrflx, PeerId remote, bool asDialer, Nullable!PeerId expected)
    {
        if (_punchSock is null)
            _punchSock = new QuicPunchSocket(_identity);
        auto ma = Multiaddr(peerSrflx.bytes.dup);
        auto peer = toUdpAddress(ma.components);

        auto pump = asDialer ? _punchSock.punchClient(peer) : _punchSock.punchServer(peer, 60.seconds);
        pump.waitForHandshake();
        auto conn = pump.connection;
        auto rp = conn.remotePeerId();
        enforce(expected.isNull || expected.get == rp,
            "quic punch: the peer is " ~ rp.toString ~ ", not " ~ expected.get.toString);

        UpgradedConn up;
        up.muxer = conn;
        up.remotePeer = rp;
        rp.tryPublicKey(up.remoteKey);
        up.localAddr = toQuicMultiaddr(_punchSock.localAddress);
        up.remoteAddr = ma;
        return up;
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
        if (_punchSock !is null)
            try
                _punchSock.close();
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
