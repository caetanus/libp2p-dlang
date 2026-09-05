/**
 * The gossipsub RPC (`gossipsub.proto`): subscriptions, published messages and
 * control (IHAVE, IWANT, GRAFT, PRUNE, IDONTWANT), one varint length-prefixed
 * frame per RPC. Also the message id, and signing under the
 * `libp2p-pubsub:` prefix.
 */
module libp2p.protocol.gossipsub.wire;

import std.conv : to;
import std.typecons : Nullable;

import libp2p.core.peer_id : PeerId;
import libp2p.crypto.keys : Keypair, PublicKey;
import libp2p.wire.protobuf;

enum meshsubProtocolIds = ["/meshsub/1.2.0", "/meshsub/1.1.0", "/meshsub/1.0.0"];

struct SubOpts
{
	@field(1) @optional bool subscribe;
	@field(2) @optional string topic;
}

struct Message
{
	@field(1) @optional ubyte[] from;
	@field(2) @optional ubyte[] data;
	@field(3) @optional ubyte[] seqno;
	@field(4) @optional string topic;
	@field(5) @optional ubyte[] signature;
	@field(6) @optional ubyte[] key;

	/// The default message id: `base58(from) ~ decimal(seqno as u64)`, with
	/// `PeerId([0,1,0])` standing in for a missing source and 0 for a missing seqno.
	ubyte[] id() const
	{
		auto source = from.length > 0 ? PeerId(from.dup) : PeerId([0, 1, 0]);
		ulong n;
		foreach (b; seqno)
			n = (n << 8) | b;
		return cast(ubyte[])(source.toBase58 ~ n.to!string);
	}
}

struct IHave
{
	@field(1) @optional string topic;
	@field(2) ubyte[][] messageIds;
}

struct IWant
{
	@field(1) ubyte[][] messageIds;
}

struct Graft
{
	@field(1) @optional string topic;
}

struct PeerInfo
{
	@field(1) @optional ubyte[] peerId;
	@field(2) @optional ubyte[] signedPeerRecord;
}

struct Prune
{
	@field(1) @optional string topic;
	@field(2) PeerInfo[] peers;
	@field(3) @optional ulong backoff; /// seconds
}

struct IDontWant
{
	@field(1) ubyte[][] messageIds;
}

struct Control
{
	@field(1) IHave[] ihave;
	@field(2) IWant[] iwant;
	@field(3) Graft[] graft;
	@field(4) Prune[] prune;
	@field(5) IDontWant[] idontwant;

	bool empty() const @safe pure nothrow
	{
		return ihave.length == 0 && iwant.length == 0 && graft.length == 0 && prune.length == 0
			&& idontwant.length == 0;
	}
}

struct Rpc
{
	@field(1) SubOpts[] subscriptions;
	@field(2) Message[] messages;
	@field(3) @optional Control control;

	bool empty() const @safe pure nothrow
	{
		return subscriptions.length == 0 && messages.length == 0 && control.empty;
	}
}

ubyte[] encodeRpc(const ref Rpc rpc)
{
	return encode(rpc);
}

Rpc decodeRpc(const(ubyte)[] frame)
{
	return decode!Rpc(frame);
}

/**
 * The limits a peer may not make us exceed, checked before an RPC is acted on.
 * Returns null when the frame is acceptable, otherwise the reason.
 */
string validateRpcLimits(const(ubyte)[] frame, size_t maxTransmitSize, size_t maxPublishMessages,
	size_t maxControlSize)
{
	if (frame.length > maxTransmitSize)
		return "message exceeds max transmit size";
	Rpc rpc;
	try
		rpc = decodeRpc(frame);
	catch (Exception e)
		return "rpc does not decode: " ~ e.msg;
	if (rpc.messages.length > maxPublishMessages)
		return "too many publish messages";
	if (encode(rpc.control).length > maxControlSize)
		return "rpc control size exceeds max control message size";
	return null;
}

// --- signing -------------------------------------------------------------------------

enum signingPrefix = "libp2p-pubsub:";

/// The bytes a signature covers: the prefix, then the message without its
/// signature and key.
private ubyte[] signable(const ref Message m)
{
	Message bare;
	bare.from = m.from.dup;
	bare.data = m.data.dup;
	bare.seqno = m.seqno.dup;
	bare.topic = m.topic;
	return cast(ubyte[]) signingPrefix ~ encode(bare);
}

/// A message from `kp` on `topic`, signed. The key is inlined in the peer id
/// (Ed25519), so the `key` field stays empty.
Message buildSignedMessage(Keypair kp, string topic, const(ubyte)[] data, ulong seqno)
{
	Message m;
	m.from = PeerId.fromPublicKey(kp.publicKey).bytes;
	m.data = data.dup;
	m.seqno = new ubyte[8];
	foreach (i; 0 .. 8)
		m.seqno[i] = cast(ubyte)(seqno >> (8 * (7 - i)));
	m.topic = topic;
	m.signature = kp.sign(signable(m));
	return m;
}

/// True only if the message carries a signature by the key its source names.
bool verifySignature(const ref Message m)
{
	if (m.signature.length == 0 || m.from.length == 0)
		return false;
	PeerId source;
	PublicKey key;
	try
	{
		source = PeerId.fromBytes(m.from);
		if (m.key.length > 0)
		{
			key = PublicKey.fromProtobuf(m.key);
			if (!source.matches(key))
				return false;
		}
		else if (!source.tryPublicKey(key))
			return false;
	}
	catch (Exception)
		return false;
	return key.verify(signable(m), m.signature);
}
