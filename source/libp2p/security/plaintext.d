/**
 * `/plaintext/2.0.0`: no encryption, but identity. Each side sends one message
 * naming the peer id it claims and the public key it must derive from; the one
 * check the protocol makes is that the two agree. For tests and trusted
 * networks only.
 */
module libp2p.security.plaintext;

import std.exception : enforce;
import std.typecons : Nullable;

import libp2p.core.peer_id : PeerId;
import libp2p.core.stream;
import libp2p.crypto.keys : Keypair, PublicKey;
import libp2p.security.security;
import libp2p.wire.protobuf;

enum plaintextProtocol = "/plaintext/2.0.0";
enum maxExchange = 4 * 1024;

struct Exchange
{
	@field(1) @optional ubyte[] id;
	@field(2) @optional ubyte[] pubkey;

	ubyte[] encode() const
	{
		return libp2p.wire.protobuf.encode(this);
	}

	static Exchange decode(const(ubyte)[] bytes)
	{
		return libp2p.wire.protobuf.decode!Exchange(bytes);
	}
}

/// The stream, unchanged, plus who is on the other end.
final class PlaintextStream : SecureConn
{
	private Stream inner;
	private PublicKey key;
	private PeerId peer;

	private this(Stream inner, PublicKey key)
	{
		this.inner = inner;
		this.key = key;
		this.peer = PeerId.fromPublicKey(key);
	}

	size_t read(ubyte[] buf)
	{
		return inner.read(buf);
	}

	void write(const(ubyte)[] data)
	{
		inner.write(data);
	}

	void close() nothrow
	{
		inner.close();
	}

	void reset() nothrow
	{
		inner.reset();
	}

	PeerId remotePeer()
	{
		return PeerId(peer.bytes.dup);
	}

	PublicKey remoteKey()
	{
		return PublicKey(key.type, key.data.dup);
	}
}

/// Both sides run the same exchange; there is no initiator.
SecureConn plaintextUpgrade(Stream raw, Keypair local)
{
	Exchange ours;
	ours.id = PeerId.fromPublicKey(local.publicKey).bytes;
	ours.pubkey = local.publicKey.toProtobuf;
	raw.writeLengthPrefixed(ours.encode);

	auto theirs = Exchange.decode(raw.readLengthPrefixed(maxExchange));
	enforce(theirs.pubkey.length > 0, "plaintext: peer sent no public key");
	auto key = PublicKey.fromProtobuf(theirs.pubkey);
	enforce(theirs.id.length > 0 && PeerId.fromBytes(theirs.id).matches(key),
		"plaintext: the peer id does not match the public key");
	return new PlaintextStream(raw, key);
}

final class PlaintextTransport : SecureTransport
{
	private Keypair identity;

	this(Keypair identity)
	{
		this.identity = identity;
	}

	string protocolId()
	{
		return plaintextProtocol;
	}

	SecureConn secureOutbound(Stream raw, Nullable!PeerId expected)
	{
		auto s = plaintextUpgrade(raw, identity);
		enforce(expected.isNull || expected.get == s.remotePeer,
			"plaintext: the peer is " ~ s.remotePeer.toString ~ ", not " ~ expected.get.toString);
		return s;
	}

	SecureConn secureInbound(Stream raw)
	{
		return plaintextUpgrade(raw, identity);
	}
}
