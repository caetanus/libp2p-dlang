/// A single QUIC connection: an ngtcp2 conn plus its OpenSSL TLS session, behind a
/// small D face. Network endpoints come in as raw sockaddr bytes (a driver adapts
/// vibe's NetworkAddress); the sockaddr storage lives in the object so ngtcp2's path
/// pointers stay valid. `deliver` feeds an inbound datagram to ngtcp2; `writeOne`
/// drains one outbound packet; `handshakeComplete`/`timeout`/`handleTimeout` drive the
/// loop. TLS + stream muxing are QUIC-native, so this is the whole connection (no
/// Noise/yamux). Opt-in behind version(Libp2pQuic).
module libp2p.transport.quic.connection;

version (Libp2pQuic):

import std.exception : enforce;
import core.time : Duration, nsecs;
import core.sys.posix.sys.socket : socklen_t;

import deimos.openssl.ssl;

import libp2p.transport.quic.ngtcp2;
import libp2p.transport.quic.ngtcp2_crypto;
import libp2p.transport.quic.tls;
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
private void ensureCryptoInit()
{
    if (!g_cryptoInit)
    {
        enforce(ngtcp2_crypto_ossl_init() == 0, "ngtcp2_crypto_ossl_init failed");
        g_cryptoInit = true;
    }
}

final class QuicConnection
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
        ubyte[128] _remoteSa;
        ngtcp2_callbacks _cb;
        ngtcp2_settings _settings;
        ngtcp2_transport_params _params;
    }

    private this(QuicRole role)
    {
        _role = role;
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
    static QuicConnection dial(scope const(ubyte)[] local, scope const(ubyte)[] remote)
    {
        ensureCryptoInit();
        auto self = new QuicConnection(QuicRole.client);
        self.setPath(local, remote);
        self._sslCtx = newClientContext();
        self._ssl = SSL_new(self._sslCtx);
        enforce(self._ssl !is null, "SSL_new (client) failed");
        SSL_set_connect_state(self._ssl);
        enforce(SSL_set_alpn_protos(self._ssl, libp2pAlpn.ptr, cast(uint) libp2pAlpn.length) == 0,
            "SSL_set_alpn_protos failed");
        enforce(ngtcp2_crypto_ossl_configure_client_session(self._ssl) == 0,
            "configure_client_session failed");
        self._cb = clientCallbacks();
        ngtcp2_settings_default(&self._settings);
        ngtcp2_transport_params_default(&self._params);
        setStreamLimits(self._params);
        auto dcid = randomCid();
        auto scid = randomCid();
        enforce(ngtcp2_conn_client_new(&self._conn, &dcid, &scid, &self._path,
                NGTCP2_PROTO_VER_V1, &self._cb, &self._settings, &self._params, null,
                cast(void*) self) == 0, "ngtcp2_conn_client_new failed");
        self.wireTls();
        return self;
    }

    /// A server connection built from the client's first Initial `packet`.
    static QuicConnection accept(scope const(ubyte)[] packet, scope const(ubyte)[] local,
        scope const(ubyte)[] remote)
    {
        ngtcp2_pkt_hd hd;
        enforce(ngtcp2_accept(&hd, packet.ptr, packet.length) == 0, "ngtcp2_accept failed");
        ensureCryptoInit();
        auto self = new QuicConnection(QuicRole.server);
        self.setPath(local, remote);
        self._sslCtx = newServerContext();
        self._ssl = SSL_new(self._sslCtx);
        enforce(self._ssl !is null, "SSL_new (server) failed");
        SSL_set_accept_state(self._ssl);
        enforce(ngtcp2_crypto_ossl_configure_server_session(self._ssl) == 0,
            "configure_server_session failed");
        self._cb = serverCallbacks();
        ngtcp2_settings_default(&self._settings);
        ngtcp2_transport_params_default(&self._params);
        setStreamLimits(self._params);
        self._params.original_dcid = hd.dcid; // MANDATORY, else the TP check fails
        self._params.original_dcid_present = 1;
        auto scid = randomCid();
        enforce(ngtcp2_conn_server_new(&self._conn, &hd.scid, &scid, &self._path,
                hd.version_, &self._cb, &self._settings, &self._params, null,
                cast(void*) self) == 0, "ngtcp2_conn_server_new failed");
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

    /// Feed one inbound datagram to ngtcp2.
    void deliver(scope const(ubyte)[] packet)
    {
        ngtcp2_pkt_info pi;
        immutable rv = ngtcp2_conn_read_pkt(_conn, &_path, &pi, packet.ptr, packet.length, nowNanos());
        enforce(rv == 0, "ngtcp2_conn_read_pkt failed");
    }

    /// Drain one outbound packet into `scratch`; the returned slice is empty when
    /// there is nothing more to send for now.
    ubyte[] writeOne(return ubyte[] scratch)
    {
        ngtcp2_pkt_info pi;
        // path is an OUTPUT (which path the packet is for) — null = don't care.
        immutable n = ngtcp2_conn_write_pkt(_conn, null, &pi, scratch.ptr, scratch.length, nowNanos());
        enforce(n >= 0, "ngtcp2_conn_write_pkt failed: " ~ ngtcpErr(cast(int) n));
        return scratch[0 .. cast(size_t) n];
    }

    bool handshakeComplete()
    {
        return ngtcp2_conn_get_handshake_completed(_conn) != 0;
    }

    /// Time until ngtcp2's next timer; Duration.zero if already due.
    Duration timeout()
    {
        immutable expiry = ngtcp2_conn_get_expiry(_conn);
        immutable now = nowNanos();
        return expiry <= now ? Duration.zero : nsecs(cast(long)(expiry - now));
    }

    void handleTimeout()
    {
        enforce(ngtcp2_conn_handle_expiry(_conn, nowNanos()) == 0, "ngtcp2_conn_handle_expiry failed");
    }

    void close()
    {
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
}
