/// QUIC TLS 1.3 contexts (OpenSSL) for the ngtcp2_crypto_ossl handshake: build a
/// client/server SSL_CTX, offer/require the "libp2p" ALPN, and accept the peer's
/// self-signed cert at the TLS layer (the real peer-identity check happens after the
/// handshake, on the cert's libp2p extension — that's a later stage; for now the cert
/// is a throwaway ephemeral Ed25519, enough to bring the handshake up). Opt-in behind
/// version(Libp2pQuic).
module libp2p.transport.quic.tls;

version (Libp2pQuic):

import std.exception : enforce;

import deimos.openssl.ssl;
import deimos.openssl.x509;
import deimos.openssl.x509_vfy : X509_STORE_CTX;
import deimos.openssl.evp;
import deimos.openssl.asn1;

// NID_ED25519 (== EVP_PKEY_ED25519); not surfaced by the deimos binding.
private enum EVP_PKEY_ED25519 = 1087;

// ALPN wire form: one length-prefixed protocol, "libp2p".
package static immutable ubyte[7] libp2pAlpn = [6, 'l', 'i', 'b', 'p', '2', 'p'];

SSL_CTX* newClientContext()
{
    auto ctx = SSL_CTX_new(TLS_method());
    enforce(ctx !is null, "SSL_CTX_new (client) failed");
    installThrowawayCert(ctx);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, &acceptAnyCert);
    return ctx;
}

SSL_CTX* newServerContext()
{
    auto ctx = SSL_CTX_new(TLS_method());
    enforce(ctx !is null, "SSL_CTX_new (server) failed");
    installThrowawayCert(ctx);
    SSL_CTX_set_alpn_select_cb(ctx, &selectLibp2pAlpn, null);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, &acceptAnyCert);
    return ctx;
}

// The TLS chain is a self-signed cert, so accept it here; the peer's real identity is
// verified after the handshake from the cert's libp2p extension (later stage).
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

private EVP_PKEY* generateEd25519Key()
{
    auto kctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, null);
    enforce(kctx !is null, "EVP_PKEY_CTX_new_id failed");
    scope (exit)
        EVP_PKEY_CTX_free(kctx);
    enforce(EVP_PKEY_keygen_init(kctx) == 1, "EVP_PKEY_keygen_init failed");
    EVP_PKEY* key;
    enforce(EVP_PKEY_keygen(kctx, &key) == 1, "EVP_PKEY_keygen failed");
    return key;
}

// A throwaway self-signed Ed25519 cert wired into the ctx. The identity-bearing cert
// (libp2p Public Key Extension) replaces this in a later stage.
private void installThrowawayCert(SSL_CTX* ctx)
{
    auto key = generateEd25519Key();
    scope (exit)
        EVP_PKEY_free(key);

    auto cert = X509_new();
    enforce(cert !is null, "X509_new failed");
    scope (exit)
        X509_free(cert);

    X509_set_version(cert, 2); // v3
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), 60 * 60 * 24 * 365);
    X509_set_pubkey(cert, key);
    auto name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", 0x1000 | 1 /* MBSTRING_ASC */,
        cast(const(ubyte)*) "libp2p".ptr, 6, -1, 0);
    X509_set_issuer_name(cert, name); // self-signed
    enforce(X509_sign(cert, key, null) != 0, "X509_sign failed"); // md=null: Ed25519 one-shot

    enforce(SSL_CTX_use_certificate(ctx, cert) == 1, "SSL_CTX_use_certificate failed");
    enforce(SSL_CTX_use_PrivateKey(ctx, key) == 1, "SSL_CTX_use_PrivateKey failed");
}
