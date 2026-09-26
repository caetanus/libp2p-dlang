/// A single QUIC connection: an ngtcp2 conn plus its OpenSSL TLS session, behind a
/// small D face. Network endpoints come in as raw sockaddr bytes (a driver adapts
/// vibe's NetworkAddress); the sockaddr storage lives in the object so ngtcp2's path
/// pointers stay valid. `deliver` feeds an inbound datagram to ngtcp2; `writeOne`
/// drains one outbound packet; `handshakeComplete`/`timeout`/`handleTimeout` drive the
/// loop. TLS + stream muxing are QUIC-native, so this is the whole connection (no
/// Noise/yamux). Opt-in behind version(Libp2pQuic).
module libp2p.transport.quic.connection;

version (Libp2pQuic):

import std.algorithm : min;
import std.exception : enforce;
import core.time : Duration, nsecs;
import core.sys.posix.sys.socket : socklen_t;

import deimos.openssl.ssl;

import vibe.core.sync : LocalManualEvent, createManualEvent;

import libp2p.core.stream : Stream;
import libp2p.core.ending : EndOfStream, StreamReset, ConnClosed;
import libp2p.core.peer_id : PeerId;
import libp2p.crypto.keys : Keypair;
import libp2p.muxer.muxer : Muxer;
import libp2p.transport.quic.ngtcp2;
import libp2p.transport.quic.ngtcp2_crypto;
import libp2p.transport.quic.tls;
import libp2p.transport.quic.identity : verifyRemotePeer = remotePeerId;
import libp2p.transport.quic.engine;

enum QuicRole
{
    client,
    server
}

// ngtcp2_crypto_ossl recovers the conn from the SSL's ex_data slot 0 (an
// ngtcp2_crypto_conn_ref) via this get_conn — a module-level extern(C) fn (a lambda
// would be a linkage mismatch).
extern (C) private ngtcp2_conn* getConn(ngtcp2_crypto_conn_ref* r)
{
    return cast(ngtcp2_conn*) r.user_data;
}

private string ngtcpErr(int rv)
{
    import std.string : fromStringz;

    return cast(string) ngtcp2_strerror(rv).fromStringz;
}

// One-time init of libngtcp2_crypto_ossl (idempotent guard).
private __gshared bool g_cryptoInit;
package void ensureCryptoInit()
{
    if (!g_cryptoInit)
    {
        enforce(ngtcp2_crypto_ossl_init() == 0, "ngtcp2_crypto_ossl_init failed");
        g_cryptoInit = true;
    }
}

private __gshared bool quicTrace = false;
shared static this()
{
    import core.stdc.stdlib : getenv;
    quicTrace = getenv("LIBP2P_QUIC_TRACE") !is null;
}

// The raw sockaddr bytes of a path half.
private const(ubyte)[] addrOf(ref const ngtcp2_addr a) @trusted pure nothrow @nogc
{
    return a.addr is null ? null : (cast(const(ubyte)*) a.addr)[0 .. a.addrlen];
}

/// Whether two raw sockaddrs name the same endpoint: family, port and address —
/// not the padding (sin_zero) or IPv6 flow label a byte comparison would also see.
bool sameEndpoint(scope const(ubyte)[] a, scope const(ubyte)[] b) @trusted pure nothrow @nogc
{
    import std.socket : AddressFamily;

    // sa_family (host order) then the port, at the same place for v4 and v6
    if (a.length < 4 || b.length < 4 || a[0 .. 4] != b[0 .. 4])
        return false;
    immutable fam = *cast(const(ushort)*) a.ptr;
    if (fam == AddressFamily.INET)
        return a.length >= 8 && b.length >= 8 && a[4 .. 8] == b[4 .. 8];
    if (fam == AddressFamily.INET6) // address, then scope id; not the flow label
        return a.length >= 28 && b.length >= 28 && a[8 .. 24] == b[8 .. 24] && a[24 .. 28] == b[24 .. 28];
    return a == b;
}

final class QuicConnection : Muxer
{
    private
    {
        ngtcp2_conn* _conn;
        SSL_CTX* _sslCtx;
        SSL* _ssl;
        ngtcp2_crypto_ossl_ctx* _ossl;
        ngtcp2_crypto_conn_ref _connRef; // stable back-ref, lives with the object
        QuicRole _role;
        ngtcp2_path _path;
        ubyte[128] _localSa; // sockaddr storage — ngtcp2 keeps the path pointers
    private ubyte[] _retryToken; // Retry token storage (ngtcp2 keeps a pointer into settings)
        ubyte[128] _remoteSa;
        ngtcp2_callbacks _cb;
        ngtcp2_settings _settings;
        size_t _rrNext; // round-robin cursor over the streams with data
        ngtcp2_transport_params _params;
        QuicStream[long] _streams; // by stream id
        QuicStream[] _acceptQueue; // inbound streams awaiting acceptStream
        LocalManualEvent _acceptEvent;
        bool _closed;
        Keypair _identity; // this node's stable identity
        PeerId _remotePeer; // verified once, after the handshake
        bool _remotePeerKnown;
    }

    /// The driver (QuicPump) sets this so a stream's write can flush immediately.
    void delegate() nothrow onWantWrite;
    /// Fires once, at close(), so the driver above can drop its references.
    void delegate() nothrow onClosed;

    private this(QuicRole role, Keypair identity)
    {
        _role = role;
        _identity = identity;
        _acceptEvent = createManualEvent();
    }

    // Add the stream callbacks to a callbacks table (they route back via user_data).
    private static void wireStreamCallbacks(ref ngtcp2_callbacks cb)
    {
        cb.stream_open = &streamOpenCb;
        cb.recv_stream_data = &recvStreamDataCb;
        cb.stream_close = &streamCloseCb;
        cb.acked_stream_data_offset = &ackedStreamDataCb;
        cb.path_validation = &pathValidationCb;
    }

    private void setPath(scope const(ubyte)[] local, scope const(ubyte)[] remote)
    {
        _localSa[0 .. local.length] = local[];
        _remoteSa[0 .. remote.length] = remote[];
        _path.local.addr = cast(ngtcp2_sockaddr*) _localSa.ptr;
        _path.local.addrlen = cast(ngtcp2_socklen) local.length;
        _path.remote.addr = cast(ngtcp2_sockaddr*) _remoteSa.ptr;
        _path.remote.addrlen = cast(ngtcp2_socklen) remote.length;
    }

    /// A fresh client connection to `remote` from `local` (raw sockaddr bytes). Its
    /// first Initial (ClientHello) comes out of the first `writeOne`.
    static QuicConnection dial(Keypair identity, scope const(ubyte)[] local,
        scope const(ubyte)[] remote)
    {
        ensureCryptoInit();
        auto self = new QuicConnection(QuicRole.client, identity);
        scope (failure)
            self.close(); // free any ngtcp2/OpenSSL state if construction throws
        self.setPath(local, remote);
        self._sslCtx = newClientContext(identity);
        self._ssl = SSL_new(self._sslCtx);
        enforce(self._ssl !is null, "SSL_new (client) failed");
        SSL_set_connect_state(self._ssl);
        enforce(SSL_set_alpn_protos(self._ssl, libp2pAlpn.ptr, cast(uint) libp2pAlpn.length) == 0,
            "SSL_set_alpn_protos failed");
        enforce(ngtcp2_crypto_ossl_configure_client_session(self._ssl) == 0,
            "configure_client_session failed");
        self._cb = clientCallbacks();
        wireStreamCallbacks(self._cb);
        ngtcp2_settings_default(&self._settings);
        self._settings.handshake_timeout = 90_000_000_000; // 90s: keep retransmitting Initials across punch skew
        // Flow-control windows auto-tune up to these (ngtcp2 grows them with the
        // measured bandwidth-delay product); without them the 1 MiB / 256 KiB
        // initial windows cap a long-RTT link at a few MB/s.
        self._settings.max_window = 8 * 1024 * 1024;
        self._settings.max_stream_window = 6 * 1024 * 1024;
        // BBR, not cubic: a cellular uplink has a deep queue and no loss, so cubic
        // fills it and sits at seconds of RTT (bufferbloat) — a keepalive on another
        // stream then dies behind the bulk. BBR keeps bytes in flight near the
        // bandwidth-delay product and the queue, and the RTT, stay small.
        self._settings.cc_algo = NGTCP2_CC_ALGO_BBR;
        // Same clock as every later timestamp (nowNanos): left at 0, ngtcp2 measures the
        // idle timeout from the epoch and closes the connection mid-handshake.
        self._settings.initial_ts = nowNanos();
        ngtcp2_transport_params_default(&self._params);
        setStreamLimits(self._params);
        auto dcid = randomCid();
        auto scid = randomCid();
        enforce(ngtcp2_conn_client_new(&self._conn, &dcid, &scid, &self._path,
                NGTCP2_PROTO_VER_V1, &self._cb, &self._settings, &self._params, null,
                cast(void*) self) == 0, "ngtcp2_conn_client_new failed");
        ngtcp2_conn_set_keep_alive_timeout(self._conn, quicKeepAliveNs);
        self.wireTls();
        return self;
    }

    /// A server connection built from the client's first Initial `packet`.
    static QuicConnection accept(Keypair identity, scope const(ubyte)[] packet,
        scope const(ubyte)[] local, scope const(ubyte)[] remote,
        scope const(ubyte)[] retryToken = null, const(ngtcp2_cid)* retryOdcid = null,
        const(ngtcp2_cid)* retryScid = null)
    {
        ngtcp2_pkt_hd hd;
        enforce(ngtcp2_accept(&hd, packet.ptr, packet.length) == 0, "ngtcp2_accept failed");
        ensureCryptoInit();
        auto self = new QuicConnection(QuicRole.server, identity);
        scope (failure)
            self.close(); // free any ngtcp2/OpenSSL state if construction throws
        self.setPath(local, remote);
        self._sslCtx = newServerContext(identity);
        self._ssl = SSL_new(self._sslCtx);
        enforce(self._ssl !is null, "SSL_new (server) failed");
        SSL_set_accept_state(self._ssl);
        enforce(ngtcp2_crypto_ossl_configure_server_session(self._ssl) == 0,
            "configure_server_session failed");
        self._cb = serverCallbacks();
        wireStreamCallbacks(self._cb);
        ngtcp2_settings_default(&self._settings);
        self._settings.handshake_timeout = 90_000_000_000; // 90s: keep retransmitting Initials across punch skew
        // Flow-control windows auto-tune up to these (ngtcp2 grows them with the
        // measured bandwidth-delay product); without them the 1 MiB / 256 KiB
        // initial windows cap a long-RTT link at a few MB/s.
        self._settings.max_window = 8 * 1024 * 1024;
        self._settings.max_stream_window = 6 * 1024 * 1024;
        // BBR, not cubic: a cellular uplink has a deep queue and no loss, so cubic
        // fills it and sits at seconds of RTT (bufferbloat) — a keepalive on another
        // stream then dies behind the bulk. BBR keeps bytes in flight near the
        // bandwidth-delay product and the queue, and the RTT, stay small.
        self._settings.cc_algo = NGTCP2_CC_ALGO_BBR;
        // Same clock as every later timestamp (nowNanos): left at 0, ngtcp2 measures the
        // idle timeout from the epoch and closes the connection mid-handshake.
        self._settings.initial_ts = nowNanos();
        ngtcp2_transport_params_default(&self._params);
        setStreamLimits(self._params);
        if (retryToken.length && retryOdcid !is null && retryScid !is null)
        {
            // The client's address was validated by a Retry: original_dcid is the
            // DCID from BEFORE the retry (recovered from the token), retry_scid is
            // the SCID we put in the Retry, and the token is fed back so ngtcp2
            // checks the client echoed both — the RFC 9000 §8.1.2 validation.
            self._params.original_dcid = *retryOdcid;
            self._params.original_dcid_present = 1;
            self._params.retry_scid = *retryScid;
            self._params.retry_scid_present = 1;
            self._retryToken = retryToken.dup; // storage outlives ngtcp2_conn_server_new
            self._settings.token = self._retryToken.ptr;
            self._settings.tokenlen = self._retryToken.length;
        }
        else
        {
            self._params.original_dcid = hd.dcid; // no retry: DCID as sent
            self._params.original_dcid_present = 1;
        }
        auto scid = randomCid();
        enforce(ngtcp2_conn_server_new(&self._conn, &hd.scid, &scid, &self._path,
                hd.version_, &self._cb, &self._settings, &self._params, null,
                cast(void*) self) == 0, "ngtcp2_conn_server_new failed");
        ngtcp2_conn_set_keep_alive_timeout(self._conn, quicKeepAliveNs);
        self.wireTls();
        return self;
    }

    // Wire the TLS session into the conn and give the SSL a back-ref (ex_data 0).
    private void wireTls()
    {
        enforce(ngtcp2_crypto_ossl_ctx_new(&_ossl, _ssl) == 0, "ngtcp2_crypto_ossl_ctx_new failed");
        ngtcp2_conn_set_tls_native_handle(_conn, _ossl);
        _connRef.get_conn = &getConn;
        _connRef.user_data = cast(void*) _conn;
        SSL_set_ex_data(_ssl, 0, &_connRef);
    }

    /// Feed one inbound datagram to ngtcp2. `from` is the sockaddr it came from;
    /// empty = the connection's original path.
    ///
    /// A source other than the peer's known address is a peer that moved — a NAT
    /// rebinding, a 4G CGNAT handing the phone a new port mid-transfer:
    /// - on the server side ngtcp2 validates the new path and migrates the
    ///   connection onto it (RFC 9000 §9), which it can only do when told the
    ///   address the packet really came from;
    /// - on the client side QUIC has no such move (a server is meant to stay put)
    ///   and ngtcp2 ignores a packet from an unknown path. In a hole punch both ends
    ///   sit behind NATs and either may rebind, so the client follows its peer (see
    ///   followPeer): an authenticated packet from a new address starts ngtcp2's own
    ///   path validation toward it, and only a PATH_RESPONSE from there moves the
    ///   connection.
    void deliver(scope const(ubyte)[] packet, scope const(ubyte)[] from = null)
    {
        if (_conn is null)
            return;
        if (_role == QuicRole.client)
            return deliverAsClient(packet, from);
        ngtcp2_pkt_info pi;
        ngtcp2_path path = _path;
        ubyte[128] fromSa = void;
        if (from.length && from.length <= fromSa.length)
        {
            fromSa[0 .. from.length] = from[];
            path.remote.addr = cast(ngtcp2_sockaddr*) fromSa.ptr;
            path.remote.addrlen = cast(ngtcp2_socklen) from.length;
        }
        readPkt(path, packet);
    }

    private void readPkt(ref ngtcp2_path path, scope const(ubyte)[] packet)
    {
        ngtcp2_pkt_info pi;
        immutable rv = ngtcp2_conn_read_pkt(_conn, &path, &pi, packet.ptr, packet.length, nowNanos());
        enforce(rv == 0, "ngtcp2_conn_read_pkt failed");
    }

    // ---- client side: following a server that moved ------------------------------
    //
    // ngtcp2 migrates a client only onto a path with a different LOCAL address (the
    // client's own interface change). Ours stays the same socket; the peer's
    // address is what changed. The local half of a path is only a name to ngtcp2 —
    // nothing goes on the wire from it — so each move gets a fresh name: our real
    // local address with a synthetic port (a "label"), and ngtcp2 sees an ordinary
    // client migration it validates with PATH_CHALLENGE / PATH_RESPONSE on the new
    // path. Validation is what makes the move safe: a replayed or reordered packet
    // from some other address only starts a validation that address cannot answer
    // (a victim, a dead mapping), and the connection stays where it is.

    private ushort _labelGen; // local-name generation for the next move
    private ubyte[128] _pvLocal; // the label of the move being validated
    private ubyte[128] _pvRemote; // ... and where to
    private ngtcp2_path _pvPath;
    private bool _pvPending;

    private void deliverAsClient(scope const(ubyte)[] packet, scope const(ubyte)[] from)
    {
        settleMove();
        auto cur = ngtcp2_conn_get_path2(_conn);
        ngtcp2_path_storage ps; // a copy: read_pkt may move the connection's path
        if (cur is null)
        {
            ngtcp2_path_storage_init(&ps, _path.local.addr, _path.local.addrlen,
                _path.remote.addr, _path.remote.addrlen, null);
            return readPkt(ps.path, packet);
        }
        ngtcp2_path_storage_init(&ps, cur.local.addr, cur.local.addrlen, cur.remote.addr, cur.remote.addrlen, null);
        if (from.length == 0 || sameEndpoint(from, addrOf(cur.remote)))
            return readPkt(ps.path, packet); // the peer where ngtcp2 knows it
        if (_pvPending && sameEndpoint(from, addrOf(_pvPath.remote)))
        {
            // on the path being validated: this may be its PATH_RESPONSE
            ngtcp2_path_storage pv;
            ngtcp2_path_storage_init(&pv, _pvPath.local.addr, _pvPath.local.addrlen,
                _pvPath.remote.addr, _pvPath.remote.addrlen, null);
            readPkt(pv.path, packet);
            settleMove();
            return;
        }
        // An unknown address. Read the packet as if it came on the current path —
        // ngtcp2 would drop it unread otherwise — and if it authenticates (ngtcp2
        // took it: decrypted and not a duplicate), the peer may live there now.
        ngtcp2_conn_info before, after;
        ngtcp2_conn_get_conn_info(_conn, &before);
        readPkt(ps.path, packet);
        if (_conn is null)
            return;
        ngtcp2_conn_get_conn_info(_conn, &after);
        if (after.pkt_recv > before.pkt_recv && (packet[0] & 0x80) == 0)
            followPeer(from);
    }

    // Start validating a move to `to`. One at a time: a move already being
    // validated is left to finish (a late packet from an older address must not
    // abort the validation of the current one).
    private void followPeer(scope const(ubyte)[] to)
    {
        settleMove();
        if (_pvPending || to.length > _pvRemote.length || _path.local.addrlen > _pvLocal.length)
            return;
        immutable llen = _path.local.addrlen;
        _pvLocal[0 .. llen] = _localSa[0 .. llen];
        // a synthetic port for the label (sin_port / sin6_port sit at bytes 2..3)
        immutable realPort = cast(ushort)((_localSa[2] << 8) | _localSa[3]);
        // (the generation only advances when a validation really starts, so labels
        // are not burnt by refused attempts and do not come round to one still in
        // ngtcp2's path history, which would skip the validation)
        ushort gen = _labelGen;
        ushort label;
        do
            label = cast(ushort)(realPort + ++gen);
        while (label == realPort || label == 0);
        _pvLocal[2] = cast(ubyte)(label >> 8);
        _pvLocal[3] = cast(ubyte) label;
        _pvRemote[0 .. to.length] = to[];
        _pvPath.local.addr = cast(ngtcp2_sockaddr*) _pvLocal.ptr;
        _pvPath.local.addrlen = llen;
        _pvPath.remote.addr = cast(ngtcp2_sockaddr*) _pvRemote.ptr;
        _pvPath.remote.addrlen = cast(ngtcp2_socklen) to.length;
        immutable rv = ngtcp2_conn_initiate_migration(_conn, &_pvPath, nowNanos());
        if (rv == 0)
        {
            _labelGen = gen;
            _pvPending = true;
            if (quicTrace)
            {
                import core.stdc.stdio : fprintf, stderr;
                fprintf(stderr, "QUICTRACE client: the peer answered from a new address; validating the path\n");
            }
        }
        // else: no spare connection id yet (NGTCP2_ERR_CONN_ID_BLOCKED) or not
        // allowed now — the next authenticated packet from there tries again
    }

    // The validation ended when ngtcp2 says so — its path_validation callback, on
    // success, failure or abort — or when the validated path is already current.
    private void settleMove()
    {
        if (!_pvPending || _conn is null)
            return;
        auto cur = ngtcp2_conn_get_path2(_conn);
        if (cur !is null && sameEndpoint(addrOf(cur.local), _pvLocal[0 .. _pvPath.local.addrlen])
            && sameEndpoint(addrOf(cur.remote), _pvRemote[0 .. _pvPath.remote.addrlen]))
            _pvPending = false; // moved: the validated path is current
    }

    // ngtcp2's verdict on a path validation (either role; only the client's own
    // moves are tracked).
    private void onPathValidation()
    {
        _pvPending = false;
    }

    /// The peer's address now (raw sockaddr bytes): the current path's remote.
    /// Empty once closed.
    ubyte[] remoteAddr()
    {
        if (_conn is null)
            return null;
        auto p = ngtcp2_conn_get_path2(_conn);
        if (p is null || p.remote.addr is null)
            return null;
        return addrOf(p.remote).dup;
    }

    /// Whether the peer, as this connection knows it now, is at `addr`.
    bool isPeerAt(scope const(ubyte)[] addr)
    {
        if (_conn is null)
            return false;
        auto p = ngtcp2_conn_get_path2(_conn);
        return p !is null && sameEndpoint(addrOf(p.remote), addr);
    }

    /// Whether `dcid` is one of the connection ids this end issued — how a packet
    /// arriving from an unknown address (a peer whose NAT rebound) is matched to its
    /// connection.
    bool ownsCid(scope const(ubyte)[] dcid)
    {
        if (_conn is null || dcid.length == 0 || dcid.length > NGTCP2_MAX_CIDLEN)
            return false;
        immutable n = ngtcp2_conn_get_scid2(_conn, null);
        if (n == 0)
            return false;
        ngtcp2_cid[16] fixed;
        auto ids = n <= fixed.length ? fixed[0 .. n] : new ngtcp2_cid[n];
        immutable got = ngtcp2_conn_get_scid2(_conn, ids.ptr);
        foreach (ref c; ids[0 .. got])
            if (c.datalen == dcid.length && c.data[0 .. c.datalen] == dcid)
                return true;
        return false;
    }

    /// Drain one outbound packet into `scratch`; the returned slice is empty when
    /// there is nothing more to send for now.
    ubyte[] writeOne(return ubyte[] scratch)
    {
        if (_conn is null)
            return scratch[0 .. 0];
        ngtcp2_pkt_info pi;
        // path is an OUTPUT (which path the packet is for) — null = don't care.
        immutable n = ngtcp2_conn_write_pkt(_conn, null, &pi, scratch.ptr, scratch.length, nowNanos());
        enforce(n >= 0, "ngtcp2_conn_write_pkt failed: " ~ ngtcpErr(cast(int) n));
        return scratch[0 .. cast(size_t) n];
    }

    bool handshakeComplete()
    {
        if (_conn is null)
            return false;
        return ngtcp2_conn_get_handshake_completed(_conn) != 0;
    }

    /// The peer's verified libp2p PeerId, read from its certificate's libp2p
    /// extension. Valid only once the handshake has completed; verified once and
    /// cached. Throws if the certificate is missing or the binding is invalid.
    PeerId remotePeerId()
    {
        if (!_remotePeerKnown)
        {
            enforce(handshakeComplete(), "quic: handshake not complete");
            _remotePeer = verifyRemotePeer(_ssl);
            _remotePeerKnown = true;
        }
        return _remotePeer;
    }

    /// Time until ngtcp2's next timer; Duration.zero if already due.
    Duration timeout()
    {
        if (_conn is null)
            return Duration.max;
        immutable expiry = ngtcp2_conn_get_expiry(_conn);
        if (expiry == ulong.max)
            return Duration.max; // no timer armed
        immutable now = nowNanos();
        return expiry <= now ? Duration.zero : nsecs(cast(long)(expiry - now));
    }

    /// Run ngtcp2's timer work. Returns 0 while the connection lives; any other value
    /// is terminal (ngtcp2's contract for handle_expiry): NGTCP2_ERR_IDLE_CLOSE means
    /// drop silently, anything else (NGTCP2_ERR_HANDSHAKE_TIMEOUT — which
    /// ngtcp2_err_is_fatal does NOT flag — and the fatal ones) means send the peer a
    /// CONNECTION_CLOSE (terminalPacket) and then drop. Either way the caller closes.
    /// NGTCP2_ERR_IDLE_CLOSE, for callers that do not import the binding.
    enum int idleCloseErr = NGTCP2_ERR_IDLE_CLOSE;

    int handleTimeout()
    {
        if (_conn is null)
            return NGTCP2_ERR_IDLE_CLOSE;
        return ngtcp2_conn_handle_expiry(_conn, nowNanos());
    }

    /// The CONNECTION_CLOSE carrying library error `liberr`, written into `scratch`;
    /// empty if ngtcp2 cannot produce one (the connection is already closing/draining).
    ubyte[] terminalPacket(int liberr, return ubyte[] scratch)
    {
        if (_conn is null)
            return scratch[0 .. 0];
        ngtcp2_ccerr ccerr;
        ngtcp2_ccerr_default(&ccerr);
        ngtcp2_ccerr_set_liberr(&ccerr, liberr, null, 0);
        ngtcp2_pkt_info pi;
        immutable n = ngtcp2_conn_write_connection_close(_conn, null, &pi, scratch.ptr, scratch.length,
            &ccerr, nowNanos());
        return n > 0 ? scratch[0 .. cast(size_t) n] : scratch[0 .. 0];
    }

    private bool _keepAliveTuned;

    /// Once the handshake is done, fit the keep-alive to the NEGOTIATED idle timeout:
    /// the effective one is the smaller of ours and the peer's, and a peer with a
    /// shorter timeout that sends no PINGs itself would otherwise expire a healthy
    /// idle link before our fixed interval fires. PING at a third of it (max
    /// quicKeepAliveNs), so two may be lost before the link is declared dead.
    void tuneKeepAlive()
    {
        if (_keepAliveTuned || _conn is null || !ngtcp2_conn_get_handshake_completed(_conn))
            return;
        _keepAliveTuned = true;
        ulong idle = _params.max_idle_timeout;
        auto rp = ngtcp2_conn_get_remote_transport_params(_conn);
        if (rp !is null && rp.max_idle_timeout != 0 && (idle == 0 || rp.max_idle_timeout < idle))
            idle = rp.max_idle_timeout;
        ulong ka = quicKeepAliveNs;
        if (idle != 0 && idle / 3 < ka)
            ka = idle / 3;
        ngtcp2_conn_set_keep_alive_timeout(_conn, ka);
    }

    // ---- Muxer: streams over the one QUIC connection --------------------------

    /// Open a new outbound bidirectional stream. QUIC assigns its id; the first
    /// bytes go out on the next `collectOutgoing`.
    Stream open()
    {
        if (_closed || _conn is null)
            throw new ConnClosed("quic: connection closed");
        long id;
        enforce(ngtcp2_conn_open_bidi_stream(_conn, &id, null) == 0, "open_bidi_stream failed");
        auto s = new QuicStream(this, id);
        _streams[id] = s;
        return s;
    }

    /// The next stream the peer opened. Blocks until one arrives, or throws
    /// `ConnClosed` once the connection is gone.
    Stream accept()
    {
        auto ec = _acceptEvent.emitCount;
        for (;;)
        {
            if (_acceptQueue.length)
            {
                auto s = _acceptQueue[0];
                _acceptQueue = _acceptQueue[1 .. $];
                return s;
            }
            if (_closed)
                throw new ConnClosed("quic: connection closed");
            ec = _acceptEvent.wait(ec);
        }
    }

    /// Congestion/RTT snapshot from ngtcp2 (cwnd, ssthresh, bytes in flight, srtt in µs).
    struct Stats { ulong cwnd, ssthresh, inflight; ulong srttUs; ulong pktSent, pktLost; }
    Stats stats() nothrow
    {
        Stats st;
        if (_conn is null)
            return st;
        ngtcp2_conn_info ci;
        try
            ngtcp2_conn_get_conn_info(_conn, &ci);
        catch (Exception)
            return st;
        st.cwnd = ci.cwnd;
        st.ssthresh = ci.ssthresh;
        st.inflight = ci.bytes_in_flight;
        st.srttUs = ci.smoothed_rtt / 1000;
        st.pktSent = ci.pkt_sent;
        st.pktLost = ci.pkt_lost;
        return st;
    }

    bool isClosed() nothrow
    {
        return _closed;
    }

    /// Ask the driver to flush outbound packets (a stream wrote or wants to FIN).
    void wantWrite() nothrow
    {
        if (onWantWrite !is null)
            onWantWrite();
    }

    /// Drain outbound QUIC packets — handshake/ACK frames and stream data alike —
    /// into `sink`. This is the writing side of the whole connection: with no
    /// stream to offer it behaves exactly like `writeOne` (stream id -1). The
    /// driver calls it whenever it wants to service output.
    void collectOutgoing(scope void delegate(scope const(ubyte)[] pkt, scope const(ubyte)[] to) sink)
    {
        if (_conn is null)
            return;
        ubyte[2048] buf;
        ngtcp2_pkt_info pi;
        // Where each packet goes is ngtcp2's to say: after a peer migrates, the
        // current path is the new address, and a path validation also probes the
        // old one. A fixed destination would keep talking to a port the peer's NAT
        // has already given up.
        ngtcp2_path_storage ps;
        ngtcp2_path_storage_zero(&ps);
        // Pacing: ngtcp2 tells us how many bytes may leave in one burst (the send
        // quantum, sized from cwnd and the pacing rate); past it we stop, stamp
        // the transmit time, and let the expiry timer bring us back. Without this
        // a whole cwnd went out in one burst and the receiver's 212 KB socket
        // buffer dropped the tail — every drop a cubic collapse, 1 MB/s at 220 ms.
        size_t budget = ngtcp2_conn_get_send_quantum(_conn);
        if (budget == 0)
            budget = 1200; // never starve a pending ACK/handshake packet
        size_t burst;
        // Streams take turns, one packet each: a bulk stream must not starve a
        // control stream's 100-byte frame behind megabytes of its own backlog.
        QuicStream[] ready;
        foreach (s; _streams)
            if (s._outbuf.length || s._finPending)
                ready ~= s;
        size_t turn;
        foreach (_; 0 .. 256)
        {
            QuicStream chosen;
            foreach (k; 0 .. ready.length)
            {
                auto s = ready[(_rrNext + turn + k) % ready.length];
                if (s._blocked || (s._outbuf.length == 0 && !s._finPending))
                    continue;
                chosen = s;
                turn += k + 1;
                break;
            }

            long streamId = -1;
            uint flags = NGTCP2_WRITE_STREAM_FLAG_NONE;
            ngtcp2_vec vec;
            ngtcp2_vec* datav = null;
            size_t datavcnt = 0;
            if (chosen !is null)
            {
                streamId = chosen._id;
                if (chosen._finPending)
                    flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
                if (chosen._outbuf.length)
                {
                    vec.base = cast(ubyte*) chosen._outbuf.ptr;
                    vec.len = chosen._outbuf.length;
                    datav = &vec;
                    datavcnt = 1;
                }
            }

            long written = -1;
            immutable n = ngtcp2_conn_writev_stream(_conn, &ps.path, &pi, buf.ptr, buf.length,
                &written, flags, streamId, datav, datavcnt, nowNanos());

            if (n == NGTCP2_ERR_STREAM_DATA_BLOCKED)
            {
                if (chosen !is null)
                    chosen._blocked = true; // flow-controlled this round; skip it
                continue;
            }
            if (n == NGTCP2_ERR_STREAM_SHUT_WR && chosen !is null)
            {
                // Our write side is shut (the peer sent STOP_SENDING, or our FIN
                // already went) while we still held bytes or a FIN for it. Only the
                // write side: the peer may well still be sending (a response after
                // a STOP_SENDING of the request body) and the read side stays open
                // until ngtcp2's stream_close says the whole stream is gone.
                if (quicTrace)
                {
                    import core.stdc.stdio : fprintf, stderr;
                    fprintf(stderr, "QUICTRACE stream %lld write side shut\n", cast(long) chosen._id);
                }
                chosen._outbuf = null;
                chosen._finPending = false;
                chosen._writeShut = true;
                chosen._writeEvent.emit();
                continue;
            }
            if (n == NGTCP2_ERR_STREAM_NOT_FOUND && chosen !is null)
            {
                // This stream is gone as far as ngtcp2 is concerned (the peer reset
                // it, or its FIN already went) while we still held bytes or a FIN
                // for it. Throwing here aborted the WHOLE round — and every later
                // round, since the stream stayed first in line: the connection's
                // output froze with the other streams' data behind it. Retire the
                // stream and carry on with the rest.
                if (quicTrace)
                {
                    import core.stdc.stdio : fprintf, stderr;
                    fprintf(stderr, "QUICTRACE stream %lld retired on write: %s\n",
                        cast(long) chosen._id, ngtcpErr(cast(int) n).ptr);
                }
                chosen._outbuf = null;
                chosen._finPending = false;
                chosen._closed = true;
                chosen._writeEvent.emit();
                chosen._dataEvent.emit();
                _streams.remove(chosen._id);
                continue;
            }
            enforce(n >= 0, "writev_stream failed: " ~ ngtcpErr(cast(int) n));

            // written >= 0 means ngtcp2 consumed that many of the offered bytes
            // (including an empty-FIN, where written == 0).
            if (chosen !is null && written >= 0)
            {
                if (written > 0)
                    chosen._retain ~= chosen._outbuf[0 .. cast(size_t) written]; // alive until acked
                chosen._outbuf = chosen._outbuf[cast(size_t) written .. $];
                if (chosen._outbuf.length == 0 && chosen._finPending)
                    chosen._finPending = false; // FIN went with the last bytes
                if (written > 0 || chosen._outbuf.length == 0)
                    chosen._writeEvent.emit(); // a writer parked above the watermark may go on
            }

            if (n == 0)
                break; // nothing more to send right now
            sink(buf[0 .. cast(size_t) n], addrOf(ps.path.remote));
            burst += cast(size_t) n;
            if (_conn is null)
                return; // the send yielded and the connection was closed meanwhile (idle
                        // expiry, a swarm close): nothing native may be touched now
            if (burst >= budget)
                break; // the quantum is spent; the pacing timer resumes us
        }
        if (burst && _conn !is null)
            ngtcp2_conn_update_pkt_tx_time(_conn, nowNanos());
        if (ready.length)
            _rrNext = (_rrNext + turn) % ready.length; // next round starts after the last served
        foreach (s; _streams)
            s._blocked = false;
    }

    // Called from the ngtcp2 callbacks (pump fiber). ---------------------------

    private void onStreamOpen(long id)
    {
        if (id in _streams)
            return; // locally opened; ngtcp2 shouldn't call us, but be safe
        auto s = new QuicStream(this, id);
        _streams[id] = s;
        _acceptQueue ~= s;
        _acceptEvent.emit();
    }

    private void onRecvStreamData(long id, scope const(ubyte)[] data, bool fin)
    {
        auto p = id in _streams;
        if (p is null)
            return;
        auto s = *p;
        if (data.length)
            s._inbuf ~= data.dup;
        if (fin)
            s._remoteFin = true;
        s._dataEvent.emit();
    }

    // ngtcp2 keeps POINTERS into the stream data we hand writev_stream — it does not
    // copy — and reads them again to retransmit a lost packet. So every chunk we
    // hand it stays referenced here until this callback says the peer has it;
    // slicing it off _outbuf alone let the GC free it under ngtcp2 (SIGSEGV in
    // memcpy inside writev_stream, only on lossy links: retransmission).
    private void onAckedStreamData(long id, ulong offset, ulong datalen)
    {
        auto p = id in _streams;
        if (p is null)
            return;
        auto s = *p;
        immutable acked = offset + datalen;
        while (s._retain.length && s._retainBase + s._retain[0].length <= acked)
        {
            s._retainBase += s._retain[0].length;
            s._retain = s._retain[1 .. $];
        }
    }

    private void onStreamClose(long id)
    {
        auto p = id in _streams;
        if (p is null)
            return;
        auto s = *p;
        if (!s._remoteFin)
            s._remoteReset = true; // closed without a clean FIN
        s._closed = true;
        s._dataEvent.emit();
        s._writeEvent.emit();
        _streams.remove(id);
    }

    /// End the session: wake everyone parked here and free the C resources.
    /// Idempotent, never throws (Muxer contract).
    void close() nothrow
    {
        if (_closed)
            return;
        _closed = true;
        scope (exit)
            if (onClosed !is null)
                onClosed(); // the driver drops its references (demux entry, timer)
        try
        {
            _acceptEvent.emit();
            foreach (s; _streams)
            {
                s._closed = true;
                s._dataEvent.emit();
                s._writeEvent.emit();
            }
            if (_conn !is null)
            {
                ngtcp2_conn_del(_conn);
                _conn = null;
            }
            if (_ossl !is null)
            {
                ngtcp2_crypto_ossl_ctx_del(_ossl);
                _ossl = null;
            }
            if (_ssl !is null)
            {
                SSL_free(_ssl);
                _ssl = null;
            }
            if (_sslCtx !is null)
            {
                SSL_CTX_free(_sslCtx);
                _sslCtx = null;
            }
        }
        catch (Exception)
        {
        }
    }
}

// The three ngtcp2 stream callbacks route back to the QuicConnection via user_data
// (the conn we handed conn_client_new/server_new). They run in the pump fiber; an
// exception must not cross into C, so each is wrapped.
extern (C) private int streamOpenCb(ngtcp2_conn* conn, long streamId, void* userData)
{
    auto self = cast(QuicConnection) userData;
    try
        self.onStreamOpen(streamId);
    catch (Exception)
        return NGTCP2_ERR_CALLBACK_FAILURE;
    return 0;
}

extern (C) private int recvStreamDataCb(ngtcp2_conn* conn, uint flags, long streamId,
    ulong offset, const(ubyte)* data, size_t datalen, void* userData, void* streamUserData)
{
    auto self = cast(QuicConnection) userData;
    try
    {
        immutable fin = (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0;
        self.onRecvStreamData(streamId, data[0 .. datalen], fin);
        // We consumed the bytes into _inbuf; hand the credit back so the peer can
        // keep sending (both stream- and connection-level flow control).
        if (datalen)
        {
            ngtcp2_conn_extend_max_stream_offset(conn, streamId, datalen);
            ngtcp2_conn_extend_max_offset(conn, datalen);
        }
    }
    catch (Exception)
        return NGTCP2_ERR_CALLBACK_FAILURE;
    return 0;
}

extern (C) private int ackedStreamDataCb(ngtcp2_conn* conn, long streamId, ulong offset,
    ulong datalen, void* userData, void* streamUserData)
{
    auto self = cast(QuicConnection) userData;
    try
        self.onAckedStreamData(streamId, offset, datalen);
    catch (Exception)
        return NGTCP2_ERR_CALLBACK_FAILURE;
    return 0;
}

extern (C) private int pathValidationCb(ngtcp2_conn* conn, uint flags, const(ngtcp2_path)* path,
    const(ngtcp2_path)* fallbackPath, ngtcp2_path_validation_result res, void* userData)
{
    auto self = cast(QuicConnection) userData;
    try
        self.onPathValidation();
    catch (Exception)
        return NGTCP2_ERR_CALLBACK_FAILURE;
    return 0;
}

extern (C) private int streamCloseCb(ngtcp2_conn* conn, uint flags, long streamId,
    ulong appErrorCode, void* userData, void* streamUserData)
{
    auto self = cast(QuicConnection) userData;
    try
        self.onStreamClose(streamId);
    catch (Exception)
        return NGTCP2_ERR_CALLBACK_FAILURE;
    return 0;
}

/// One QUIC stream as a libp2p `Stream`. Reads block on inbound data pushed by the
/// recv callback; writes buffer into `_outbuf` and nudge the connection to flush,
/// blocking until the bytes are handed to ngtcp2. Lives in the same module as
/// QuicConnection, so it reaches the conn's internals directly.
final class QuicStream : Stream
{
    private
    {
        QuicConnection _conn;
        long _id;
        ubyte[] _inbuf; // received, not yet read
        ubyte[] _outbuf; // to send, not yet handed to ngtcp2
        bool _finPending; // we want to send FIN once _outbuf drains
        bool _remoteFin; // peer sent FIN (read side finished)
        bool _remoteReset; // peer reset the stream
        bool _localReset; // we reset it
        bool _closed; // stream fully closed (or conn gone)
        bool _writeShut; // our write side is shut (STOP_SENDING / FIN sent); reads go on
        bool _blocked; // flow-controlled this collectOutgoing round
        ubyte[][] _retain; // handed to ngtcp2, not yet acked by the peer (see onAckedStreamData)
        ulong _retainBase; // stream offset where _retain[0] starts
        enum size_t highWater = 2 * 1024 * 1024; // write() blocks above this much queued
        LocalManualEvent _dataEvent; // inbound data / read-side state change
        LocalManualEvent _writeEvent; // outbound drained / write-side state change
    }

    private this(QuicConnection conn, long id)
    {
        _conn = conn;
        _id = id;
        _dataEvent = createManualEvent();
        _writeEvent = createManualEvent();
    }

    size_t read(ubyte[] buf)
    {
        if (buf.length == 0)
            return 0;
        auto ec = _dataEvent.emitCount;
        for (;;)
        {
            if (_inbuf.length)
            {
                immutable n = min(buf.length, _inbuf.length);
                buf[0 .. n] = _inbuf[0 .. n];
                _inbuf = _inbuf[n .. $];
                return n;
            }
            if (_remoteFin)
                throw new EndOfStream("quic: stream finished");
            if (_remoteReset)
                throw new StreamReset("quic: stream reset by peer");
            if (_closed || _conn._closed)
                throw new ConnClosed("quic: connection closed");
            ec = _dataEvent.wait(ec);
        }
    }

    void write(const(ubyte)[] data)
    {
        if (_localReset)
            throw new StreamReset("quic: stream reset");
        if (_closed || _conn._closed)
            throw new ConnClosed("quic: connection closed");
        if (_writeShut)
            throw new StreamReset("quic: the peer stopped reading this stream");
        if (data.length == 0)
            return;
        _outbuf ~= data.dup; // outlives caller's buffer across fiber yields
        _conn.wantWrite();
        // Return as soon as the queue is below the high watermark, NOT when it is
        // empty: waiting for the drain made every write a stop-and-wait of one
        // chunk per RTT (64 KiB writes at 220 ms = 0.7 MB/s, whatever the link).
        // With a deep enough queue ngtcp2 keeps the congestion window full and the
        // sender is bound by flow control and cwnd, as it should be. close() still
        // sends the FIN only after the whole queue has gone out.
        while (_outbuf.length > highWater)
        {
            if (_localReset)
                throw new StreamReset("quic: stream reset");
            if (_writeShut)
                throw new StreamReset("quic: the peer stopped reading this stream");
            if (_closed || _conn._closed)
                throw new ConnClosed("quic: connection closed");
            auto ec = _writeEvent.emitCount;
            if (_outbuf.length <= highWater)
                break;
            _writeEvent.wait(ec);
        }
    }

    /// Graceful: send FIN after the buffered bytes drain. Idempotent, never throws.
    void close() nothrow
    {
        if (_finPending || _remoteReset || _localReset)
            return;
        _finPending = true;
        _conn.wantWrite();
    }

    /// Abortive: tell the peer to abandon the stream. Idempotent, never throws.
    void reset() nothrow
    {
        if (_localReset || _closed)
            return;
        _localReset = true;
        try
        {
            if (_conn._conn !is null)
                ngtcp2_conn_shutdown_stream(_conn._conn, 0, _id, 0);
            _conn.wantWrite();
            _writeEvent.emit();
        }
        catch (Exception)
        {
        }
    }
}
