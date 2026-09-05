/**
 * PeerId: a multihash of the peer's `PublicKey` protobuf. Keys whose protobuf
 * is 42 bytes or shorter (Ed25519, secp256k1) are inlined under the identity
 * hash, so the key can be read back out of the id; longer ones (RSA, ECDSA)
 * are hashed with sha2-256. The text form is base58btc of the multihash.
 */
module libp2p.core.peer_id;

import std.exception : enforce;

import libp2p.crypto.keys : PublicKey;
import libp2p.multiformats.multihash;
import libp2p.multiformats.base58;

struct PeerId
{
	ubyte[] bytes;

	private enum maxInlineKeyLength = 42;

	static PeerId fromPublicKey(const PublicKey key)
	{
		auto pb = key.toProtobuf;
		auto mh = pb.length <= maxInlineKeyLength ? multihashIdentity(pb) : multihashSha256(pb);
		return PeerId(mh.encode);
	}

	/// Accepts a multihash and nothing else.
	static PeerId fromBytes(const(ubyte)[] bytes)
	{
		auto mh = Multihash.decode(bytes);
		enforce(mh.encode.length == bytes.length, "peer id: trailing bytes after the multihash");
		return PeerId(bytes.dup);
	}

	static PeerId fromBase58(const(char)[] text)
	{
		return fromBytes(base58Decode(text));
	}

	string toBase58() const
	{
		return base58Encode(bytes);
	}

	string toString() const
	{
		return toBase58;
	}

	/// The public key, if the id inlines one.
	bool tryPublicKey(out PublicKey key) const
	{
		auto mh = Multihash.decode(bytes);
		if (mh.code != HashCode.identity)
			return false;
		key = PublicKey.fromProtobuf(mh.digest);
		return true;
	}

	/// True if `key` is the key this id was derived from.
	bool matches(const PublicKey key) const
	{
		return this == fromPublicKey(key);
	}

	bool opEquals(const PeerId o) const @safe pure nothrow
	{
		return bytes == o.bytes;
	}

	size_t toHash() const @safe pure nothrow
	{
		return hashOf(bytes);
	}
}
