/// libp2p-TLS identity: bind a QUIC/TLS certificate to a libp2p PeerId.
///
/// The TLS handshake runs on a throwaway *certificate key* (ephemeral Ed25519);
/// the node's stable identity key never touches TLS. Instead the certificate
/// carries a custom X.509 extension (OID 1.3.6.1.4.1.53594.1.1) holding the
/// identity public key and a signature by it over `"libp2p-tls-handshake:"` ++
/// the certificate's SubjectPublicKeyInfo (DER). After the handshake each side
/// reads the peer's certificate, checks that signature, and derives the peer's
/// PeerId from the identity key — that, not the self-signed chain, is the real
/// authentication. Matches the rust-libp2p / go-libp2p spec. Opt-in behind
/// version(Libp2pQuic).
module libp2p.transport.quic.identity;

version (Libp2pQuic):

import std.exception : enforce;
import std.string : toStringz, fromStringz;

import deimos.openssl.ssl;
import deimos.openssl.x509;
import deimos.openssl.objects;
import deimos.openssl.asn1;
import deimos.openssl.evp;

import libp2p.crypto.keys : Keypair, PublicKey;
import libp2p.core.peer_id : PeerId;

// The libp2p Public Key Extension OID and the signed-payload prefix, both fixed
// by the libp2p-TLS spec.
enum libp2pTlsOid = "1.3.6.1.4.1.53594.1.1";
private static immutable ubyte[] signingPrefix = cast(immutable ubyte[]) "libp2p-tls-handshake:";

// NID_ED25519 (== EVP_PKEY_ED25519); not surfaced by the deimos binding.
private enum EVP_PKEY_ED25519 = 1087;

// ---- minimal DER --------------------------------------------------------------

// DER definite length: short form under 0x80, else long form (big-endian bytes).
private ubyte[] derLength(size_t n)
{
    if (n < 0x80)
        return [cast(ubyte) n];
    ubyte[] tmp;
    while (n > 0)
    {
        tmp = cast(ubyte)(n & 0xff) ~ tmp;
        n >>= 8;
    }
    return cast(ubyte)(0x80 | tmp.length) ~ tmp;
}

private ubyte[] derTlv(ubyte tag, const(ubyte)[] content)
{
    return tag ~ derLength(content.length) ~ content;
}

private ubyte[] derOctetString(const(ubyte)[] v)
{
    return derTlv(0x04, v);
}

private ubyte[] derSequence(const(ubyte)[] v)
{
    return derTlv(0x30, v);
}

// Read one DER TLV of the expected tag from the front of `b`, advancing `b` past
// it and returning the content. Rejects anything malformed.
private const(ubyte)[] derRead(ref const(ubyte)[] b, ubyte expectedTag)
{
    enforce(b.length >= 2, "der: truncated");
    enforce(b[0] == expectedTag, "der: unexpected tag");
    size_t p = 1;
    size_t len;
    immutable l0 = b[p++];
    if (l0 < 0x80)
        len = l0;
    else
    {
        immutable n = l0 & 0x7f;
        enforce(n >= 1 && n <= size_t.sizeof && p + n <= b.length, "der: bad length");
        foreach (_; 0 .. n)
            len = (len << 8) | b[p++];
    }
    enforce(p + len <= b.length, "der: content overruns");
    auto content = b[p .. p + len];
    b = b[p + len .. $];
    return content;
}

// ---- keys & SPKI --------------------------------------------------------------

// A fresh ephemeral Ed25519 key that backs the certificate itself (never the
// node's identity key).
private EVP_PKEY* generateCertKey()
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

// The DER SubjectPublicKeyInfo of `key`. Uses the self-allocating i2d idiom
// (length probe, then write into our own buffer) so there is nothing to free.
private ubyte[] publicKeyDer(EVP_PKEY* key)
{
    immutable n = i2d_PUBKEY(key, null);
    enforce(n > 0, "i2d_PUBKEY failed");
    auto der = new ubyte[n];
    auto p = der.ptr;
    enforce(i2d_PUBKEY(key, &p) == n, "i2d_PUBKEY (write) failed");
    return der;
}

// ---- certificate build --------------------------------------------------------

/// Build the libp2p-TLS certificate for `identity` and install it (with its
/// ephemeral key) into `ctx`.
void installIdentityCert(SSL_CTX* ctx, Keypair identity)
{
    auto certKey = generateCertKey();
    scope (exit)
        EVP_PKEY_free(certKey);

    auto cert = X509_new();
    enforce(cert !is null, "X509_new failed");
    scope (exit)
        X509_free(cert);

    X509_set_version(cert, 2); // v3
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), 60 * 60 * 24 * 365);
    X509_set_pubkey(cert, certKey);
    auto name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", 0x1000 | 1 /* MBSTRING_ASC */,
        cast(const(ubyte)*) "libp2p".ptr, 6, -1, 0);
    X509_set_issuer_name(cert, name); // self-signed

    // The binding: identity key signs prefix || cert-SPKI. SignedKey ::=
    // SEQUENCE { publicKey OCTET STRING, signature OCTET STRING }.
    auto spki = publicKeyDer(certKey);
    auto sig = identity.sign(signingPrefix ~ spki);
    auto pubProto = identity.publicKey.toProtobuf;
    auto signedKey = derSequence(derOctetString(pubProto) ~ derOctetString(sig));

    addExtension(cert, signedKey);

    enforce(X509_sign(cert, certKey, null) != 0, "X509_sign failed"); // md=null: Ed25519
    enforce(SSL_CTX_use_certificate(ctx, cert) == 1, "SSL_CTX_use_certificate failed");
    enforce(SSL_CTX_use_PrivateKey(ctx, certKey) == 1, "SSL_CTX_use_PrivateKey failed");
}

// Attach `der` under the libp2p OID as a non-critical extension.
private void addExtension(X509* cert, const(ubyte)[] der)
{
    auto obj = OBJ_txt2obj(libp2pTlsOid.toStringz, 1 /* numeric only */);
    enforce(obj !is null, "OBJ_txt2obj failed");
    scope (exit)
        ASN1_OBJECT_free(obj);

    auto os = M_ASN1_OCTET_STRING_new();
    enforce(os !is null, "ASN1_OCTET_STRING_new failed");
    scope (exit)
        M_ASN1_OCTET_STRING_free(os);
    enforce(ASN1_OCTET_STRING_set(os, der.ptr, cast(int) der.length) == 1,
        "ASN1_OCTET_STRING_set failed");

    auto ext = X509_EXTENSION_create_by_OBJ(null, obj, 0 /* non-critical */, os);
    enforce(ext !is null, "X509_EXTENSION_create_by_OBJ failed");
    scope (exit)
        X509_EXTENSION_free(ext);
    enforce(X509_add_ext(cert, ext, -1) != 0, "X509_add_ext failed");
}

// ---- peer verification --------------------------------------------------------

/// Read the peer's certificate off a completed handshake, verify the libp2p
/// identity binding, and return the peer's PeerId. Throws if the certificate is
/// missing, lacks the extension, or the signature does not check out.
PeerId remotePeerId(SSL* ssl)
{
    auto cert = SSL_get_peer_certificate(ssl); // +1 ref
    enforce(cert !is null, "libp2p-tls: peer presented no certificate");
    scope (exit)
        X509_free(cert);

    auto certKey = X509_get_pubkey(cert); // +1 ref
    enforce(certKey !is null, "libp2p-tls: peer certificate has no public key");
    scope (exit)
        EVP_PKEY_free(certKey);
    auto spki = publicKeyDer(certKey);

    auto extBytes = findExtension(cert);
    enforce(extBytes.length > 0, "libp2p-tls: certificate lacks the libp2p extension");

    // Parse SignedKey ::= SEQUENCE { publicKey OCTET STRING, signature OCTET STRING }.
    auto seq = derRead(extBytes, 0x30);
    auto pubProto = derRead(seq, 0x04);
    auto signature = derRead(seq, 0x04);

    auto remoteKey = PublicKey.fromProtobuf(pubProto);
    enforce(remoteKey.verify(signingPrefix ~ spki, signature),
        "libp2p-tls: identity signature does not verify");
    return PeerId.fromPublicKey(remoteKey);
}

// The bytes of the libp2p-OID extension, or empty if absent.
private const(ubyte)[] findExtension(X509* cert)
{
    immutable count = X509_get_ext_count(cert);
    foreach (i; 0 .. count)
    {
        auto ext = X509_get_ext(cert, i);
        if (ext is null)
            continue;
        auto obj = X509_EXTENSION_get_object(ext);
        char[128] buf;
        immutable n = OBJ_obj2txt(buf.ptr, cast(int) buf.length, obj, 1 /* numeric */);
        if (n <= 0)
            continue;
        if (cast(string) buf[0 .. n] != libp2pTlsOid)
            continue;
        auto data = X509_EXTENSION_get_data(ext);
        enforce(data !is null, "libp2p-tls: extension has no data");
        auto p = ASN1_STRING_data(data);
        immutable len = ASN1_STRING_length(data);
        return p[0 .. len].dup;
    }
    return null;
}
