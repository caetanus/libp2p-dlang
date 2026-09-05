/**
 * A DTLS certificate fingerprint: the SHA-256 of the certificate, which travels
 * in the multiaddr as `/certhash/<multibase multihash>` and in SDP as
 * uppercase colon-separated hex.
 */
module libp2p.transport.webrtc.fingerprint;

import std.digest.sha : sha256Of;
import std.format : format;
import std.typecons : Nullable, nullable;

import libp2p.multiformats.multihash : Multihash, HashCode;

struct Fingerprint
{
	ubyte[32] digest;

	enum algorithm = "sha-256";

	/// All ones: the placeholder a client puts in its own offer.
	static Fingerprint FF()
	{
		Fingerprint f;
		f.digest[] = 0xff;
		return f;
	}

	static Fingerprint raw(ubyte[32] digest)
	{
		return Fingerprint(digest);
	}

	static Fingerprint fromCertificate(const(ubyte)[] der)
	{
		return Fingerprint(sha256Of(der));
	}

	Multihash toMultihash() const
	{
		return Multihash(HashCode.sha2_256, digest.dup);
	}

	/// Null unless the multihash is a 32-byte sha2-256.
	static Nullable!Fingerprint tryFromMultihash(Multihash mh)
	{
		if (mh.code != HashCode.sha2_256 || mh.digest.length != 32)
			return Nullable!Fingerprint.init;
		Fingerprint f;
		f.digest[] = mh.digest[0 .. 32];
		return nullable(f);
	}

	/// `7D:E3:...`, as SDP wants it.
	string toSdpFormat() const
	{
		string s;
		foreach (i, b; digest)
			s ~= (i > 0 ? ":" : "") ~ format("%02X", b);
		return s;
	}

	bool opEquals(const Fingerprint o) const @safe pure nothrow @nogc
	{
		return digest == o.digest;
	}

	size_t toHash() const @safe pure nothrow @nogc
	{
		return hashOf(digest[]);
	}
}
