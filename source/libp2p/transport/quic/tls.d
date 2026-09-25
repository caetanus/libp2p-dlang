/// QUIC TLS 1.3 contexts (OpenSSL) for the ngtcp2_crypto_ossl handshake: build a
/// client/server SSL_CTX, offer/require the "libp2p" ALPN, and install the node's
/// libp2p-TLS identity certificate. The self-signed chain is accepted at the TLS
/// layer; the real peer-identity check happens after the handshake, from the cert's
/// libp2p extension (see identity.d, `remotePeerId`). Opt-in behind
/// version(Libp2pQuic).
module libp2p.transport.quic.tls;

version (Libp2pQuic):

import std.exception : enforce;

import deimos.openssl.ssl;
import deimos.openssl.x509_vfy : X509_STORE_CTX;

import libp2p.crypto.keys : Keypair;
import libp2p.transport.quic.identity : installIdentityCert;

// ALPN wire form: one length-prefixed protocol, "libp2p".
package static immutable ubyte[7] libp2pAlpn = [6, 'l', 'i', 'b', 'p', '2', 'p'];

SSL_CTX* newClientContext(Keypair identity)
{
    auto ctx = SSL_CTX_new(TLS_method());
    enforce(ctx !is null, "SSL_CTX_new (client) failed");
    scope (failure)
        SSL_CTX_free(ctx); // installIdentityCert throws before we return ctx
    installIdentityCert(ctx, identity);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, &acceptAnyCert);
    return ctx;
}

SSL_CTX* newServerContext(Keypair identity)
{
    auto ctx = SSL_CTX_new(TLS_method());
    enforce(ctx !is null, "SSL_CTX_new (server) failed");
    scope (failure)
        SSL_CTX_free(ctx); // installIdentityCert throws before we return ctx
    installIdentityCert(ctx, identity);
    SSL_CTX_set_alpn_select_cb(ctx, &selectLibp2pAlpn, null);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, &acceptAnyCert);
    return ctx;
}

// The TLS chain is a self-signed cert, so accept it here; the peer's real identity is
// verified after the handshake from the cert's libp2p extension (identity.d).
extern (C) int acceptAnyCert(int preverifyOk, X509_STORE_CTX* ctx) @nogc nothrow
{
    return 1;
}

// Server ALPN callback: pick "libp2p" or fail the handshake (no_application_protocol).
extern (C) private int selectLibp2pAlpn(SSL* ssl, const(ubyte)** out_, ubyte* outlen,
    const(ubyte)* in_, uint inlen, void* arg)
{
    // in_ is a sequence of length-prefixed protocols; look for our "libp2p".
    uint i = 0;
    while (i < inlen)
    {
        immutable l = in_[i];
        if (l == 6 && in_[i + 1 .. i + 7] == libp2pAlpn[1 .. 7])
        {
            *out_ = in_ + i + 1;
            *outlen = 6;
            return 0; // SSL_TLSEXT_ERR_OK
        }
        i += 1 + l;
    }
    return 3; // SSL_TLSEXT_ERR_NOACK / no match
}
