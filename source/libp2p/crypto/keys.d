/**
 * libp2p identity keys.
 *
 * This node signs with Ed25519 (libsodium). It must *verify* whatever a peer
 * chose — RSA, ECDSA P-256, secp256k1 — because identify records, signed peer
 * records and the Noise handshake all rest on that check. Those three go
 * through OpenSSL's EVP, which is the one place OpenSSL is used.
 *
 * `PublicKey` is the protobuf `keys.proto` defines: a type tag and the key
 * material in the encoding libp2p specifies for that type (raw 32 bytes for
 * Ed25519, DER SubjectPublicKeyInfo for RSA and ECDSA, compressed SEC1 point
 * for secp256k1). Its protobuf bytes are what a peer id is derived from.
 */
module libp2p.crypto.keys;

import std.exception : enforce;

import libp2p.wire.protobuf;

enum KeyType : uint
{
	rsa = 0,
	ed25519 = 1,
	secp256k1 = 2,
	ecdsa = 3,
}

private struct PublicKeyMsg
{
	@field(1) uint type;
	@field(2) ubyte[] data;
}

struct PublicKey
{
	KeyType type;
	ubyte[] data;

	ubyte[] toProtobuf() const
	{
		return encode(PublicKeyMsg(type, data.dup));
	}

	static PublicKey fromProtobuf(const(ubyte)[] bytes)
	{
		auto m = decode!PublicKeyMsg(bytes);
		enforce(m.type <= KeyType.max, "public key: unknown key type");
		return PublicKey(cast(KeyType) m.type, m.data);
	}

	/// True only if `sig` is a valid signature over `msg` by this key. Malformed
	/// keys, malformed signatures and mismatched types all answer false.
	bool verify(const(ubyte)[] msg, const(ubyte)[] sig) const nothrow @trusted
	{
		try
		{
			final switch (type)
			{
			case KeyType.ed25519:
				return verifyEd25519(data, msg, sig);
			// LibP2P_Lite (the phone): no OpenSSL, so only Ed25519 peers verify
			version (LibP2P_Lite)
			{
			case KeyType.rsa:
			case KeyType.ecdsa:
			case KeyType.secp256k1:
				return false;
			}
			else
			{
			case KeyType.rsa:
				return openssl.verifyDer(data, msg, sig, openssl.EVP_PKEY_RSA);
			case KeyType.ecdsa:
				return openssl.verifyDer(data, msg, sig, openssl.EVP_PKEY_EC);
			case KeyType.secp256k1:
				return openssl.verifySecp256k1(data, msg, sig);
			}
			}
		}
		catch (Exception)
			return false;
	}

	bool opEquals(const PublicKey o) const @safe pure nothrow
	{
		return type == o.type && data == o.data;
	}

	size_t toHash() const @safe pure nothrow
	{
		return hashOf(data, hashOf(type));
	}
}

/// An Ed25519 signing keypair: this node's identity.
struct Keypair
{
	private ubyte[64] secret;
	private ubyte[32] public_;

	static Keypair generateEd25519() @trusted
	{
		Keypair kp;
		sodium.crypto_sign_ed25519_keypair(kp.public_.ptr, kp.secret.ptr);
		return kp;
	}

	static Keypair fromSeed(const(ubyte)[] seed) @trusted
	{
		enforce(seed.length == 32, "ed25519: seed must be 32 bytes");
		Keypair kp;
		sodium.crypto_sign_ed25519_seed_keypair(kp.public_.ptr, kp.secret.ptr, seed.ptr);
		return kp;
	}

	/// The raw 32-byte public key.
	ubyte[] pub() const @safe pure nothrow
	{
		return public_.dup;
	}

	PublicKey publicKey() const @safe pure nothrow
	{
		return PublicKey(KeyType.ed25519, public_.dup);
	}

	/// A 64-byte detached signature.
	ubyte[] sign(const(ubyte)[] msg) const @trusted nothrow
	{
		auto sig = new ubyte[64];
		sodium.crypto_sign_ed25519_detached(sig.ptr, null, msg.ptr, msg.length, secret.ptr);
		return sig;
	}
}

private bool verifyEd25519(const(ubyte)[] key, const(ubyte)[] msg, const(ubyte)[] sig) nothrow @trusted
{
	if (key.length != 32 || sig.length != 64)
		return false;
	return sodium.crypto_sign_ed25519_verify_detached(sig.ptr, msg.ptr, msg.length, key.ptr) == 0;
}

// --- libsodium ------------------------------------------------------------

private struct sodium
{
	static import libsodium;

	alias crypto_sign_ed25519_keypair = libsodium.crypto_sign_ed25519_keypair;
	alias crypto_sign_ed25519_seed_keypair = libsodium.crypto_sign_ed25519_seed_keypair;
	alias crypto_sign_ed25519_detached = libsodium.crypto_sign_ed25519_detached;
	alias crypto_sign_ed25519_verify_detached = libsodium.crypto_sign_ed25519_verify_detached;
}

shared static this()
{
	static import libsodium;

	enforce(libsodium.sodium_init() >= 0, "libsodium failed to initialise");
}

// --- OpenSSL --------------------------------------------------------------

version (LibP2P_Lite) {} else
private struct openssl
{
	import deimos.openssl.evp;
	import deimos.openssl.x509 : d2i_PUBKEY;
	import deimos.openssl.ec : EC_KEY, EC_KEY_new_by_curve_name, EC_KEY_free, o2i_ECPublicKey;
	import deimos.openssl.obj_mac : NID_secp256k1;
	import core.stdc.config : c_long;

	enum EVP_PKEY_RSA = 6;
	enum EVP_PKEY_EC = 408;

	/// SHA-256 digest verification with a DER SubjectPublicKeyInfo of `expectedKind`.
	static bool verifyDer(const(ubyte)[] der, const(ubyte)[] msg, const(ubyte)[] sig, int expectedKind) @trusted
	{
		if (der.length == 0 || sig.length == 0)
			return false;
		const(ubyte)* p = der.ptr;
		auto pkey = d2i_PUBKEY(null, &p, cast(c_long) der.length);
		if (pkey is null)
			return false;
		scope (exit)
			EVP_PKEY_free(pkey);
		if (EVP_PKEY_base_id(pkey) != expectedKind)
			return false;
		return digestVerify(pkey, msg, sig);
	}

	/// A compressed SEC1 point on secp256k1 and a DER ECDSA signature over SHA-256.
	static bool verifySecp256k1(const(ubyte)[] point, const(ubyte)[] msg, const(ubyte)[] sig) @trusted
	{
		if (point.length == 0 || sig.length == 0)
			return false;
		auto ec = EC_KEY_new_by_curve_name(NID_secp256k1);
		if (ec is null)
			return false;
		scope (exit)
			EC_KEY_free(ec);
		const(ubyte)* p = point.ptr;
		if (o2i_ECPublicKey(&ec, &p, cast(c_long) point.length) is null)
			return false;
		auto pkey = EVP_PKEY_new();
		if (pkey is null)
			return false;
		scope (exit)
			EVP_PKEY_free(pkey);
		if (EVP_PKEY_set1_EC_KEY(pkey, ec) != 1)
			return false;
		return digestVerify(pkey, msg, sig);
	}

	private static bool digestVerify(EVP_PKEY* pkey, const(ubyte)[] msg, const(ubyte)[] sig) @trusted
	{
		auto ctx = EVP_MD_CTX_new();
		if (ctx is null)
			return false;
		scope (exit)
			EVP_MD_CTX_free(ctx);
		if (EVP_DigestVerifyInit(ctx, null, EVP_sha256(), null, pkey) != 1)
			return false;
		return EVP_DigestVerify(ctx, sig.ptr, sig.length, msg.ptr, msg.length) == 1;
	}
}
