/**
 * The upgrade: raw connection → secured → multiplexed. A function, not a
 * service. It takes no host, no swarm and no callback; it negotiates a security
 * protocol with multistream-select, runs its handshake, negotiates a muxer over
 * the secured stream, and hands back the muxer and the peer's identity.
 */
module libp2p.core.upgrade;

import std.exception : enforce;
import std.typecons : Nullable;

import libp2p.core.peer_id : PeerId;
import libp2p.core.stream : Stream;
import libp2p.crypto.keys : PublicKey;
import libp2p.multistream.select;
import libp2p.muxer.muxer : Muxer;
import libp2p.security.security : SecureTransport, SecureConn;

/// Which side of the connection we are. Security and muxer roles follow it.
enum Endpoint
{
	dialer,
	listener,
}

interface MuxerFactory
{
	string protocolId();
	Muxer create(Stream secured, bool client);
}

struct UpgradeConfig
{
	SecureTransport[] security;
	MuxerFactory[] muxers;
}

struct Upgraded
{
	Muxer muxer;
	PeerId remotePeer;
	PublicKey remoteKey;
	string securityProtocol;
	string muxerProtocol;
}

Upgraded upgrade(Stream raw, Endpoint role, UpgradeConfig cfg,
	Nullable!PeerId expected = Nullable!PeerId.init)
{
	enforce(cfg.security.length > 0, "upgrade: no security transport configured");
	enforce(cfg.muxers.length > 0, "upgrade: no muxer configured");

	Upgraded up;

	// Security.
	SecureConn sec;
	if (role == Endpoint.dialer)
	{
		up.securityProtocol = negotiateDialer(raw, ids(cfg.security));
		sec = pick(cfg.security, up.securityProtocol).secureOutbound(raw, expected);
	}
	else
	{
		up.securityProtocol = negotiateListener(raw, ids(cfg.security));
		sec = pick(cfg.security, up.securityProtocol).secureInbound(raw);
	}
	up.remotePeer = sec.remotePeer;
	up.remoteKey = sec.remoteKey;

	// Muxer, over the secured stream.
	if (role == Endpoint.dialer)
		up.muxerProtocol = negotiateDialer(sec, ids(cfg.muxers));
	else
		up.muxerProtocol = negotiateListener(sec, ids(cfg.muxers));
	up.muxer = pick(cfg.muxers, up.muxerProtocol).create(sec, role == Endpoint.dialer);
	return up;
}

private string[] ids(T)(T[] items)
{
	string[] out_;
	foreach (i; items)
		out_ ~= i.protocolId;
	return out_;
}

private T pick(T)(T[] items, string id)
{
	foreach (i; items)
		if (i.protocolId == id)
			return i;
	assert(false, "negotiated a protocol we did not offer");
}
