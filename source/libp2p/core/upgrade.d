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

import core.time : Duration, msecs;

struct UpgradeConfig
{
	SecureTransport[] security;
	MuxerFactory[] muxers;
	/// The listener role of a hole punch waits this long for the peer's first
	/// proposal after the header before concluding the peer is a listener too
	/// (our connect was accepted, no NAT in between) and driving instead. A dialer
	/// pipelines its proposal behind the header, so the wait is only ever paid in
	/// that accepted case.
	Duration punchListenerGrace = 750.msecs;
}

struct Upgraded
{
	Muxer muxer;
	PeerId remotePeer;
	PublicKey remoteKey;
	string securityProtocol;
	string muxerProtocol;
}

/// `simultaneousOpen`: this dial may have met the peer's dial head-on (a TCP
/// hole punch), leaving no listener; the multistream simultaneous-open
/// extension then decides which side takes the initiator role for the
/// handshakes. The endpoint `role` stays what the caller did (dial), only
/// the handshake roles follow the tie-break.
Upgraded upgrade(Stream raw, Endpoint role, UpgradeConfig cfg,
	Nullable!PeerId expected = Nullable!PeerId.init, bool simultaneousOpen = false)
{
	enforce(cfg.security.length > 0, "upgrade: no security transport configured");
	enforce(cfg.muxers.length > 0, "upgrade: no muxer configured");

	Upgraded up;

	// Security.
	SecureConn sec;
	bool initiator = role == Endpoint.dialer;
	if (role == Endpoint.dialer && simultaneousOpen)
	{
		auto r = negotiateSimOpen(raw, ids(cfg.security));
		up.securityProtocol = r.protocol;
		initiator = r.initiator;
	}
	else if (role == Endpoint.listener && simultaneousOpen)
	{
		// The listener role of a punch: serve the peer's proposal — or, when the
		// connect was plainly accepted by its listener (no NAT between us), drive.
		auto r = negotiateListenerOrDial(raw, ids(cfg.security), cfg.punchListenerGrace);
		up.securityProtocol = r.protocol;
		initiator = r.initiator;
	}
	else if (role == Endpoint.dialer)
		up.securityProtocol = negotiateDialer(raw, ids(cfg.security));
	else
		up.securityProtocol = negotiateListener(raw, ids(cfg.security));
	if (initiator)
		sec = pick(cfg.security, up.securityProtocol).secureOutbound(raw, expected);
	else
	{
		sec = pick(cfg.security, up.securityProtocol).secureInbound(raw);
		// Lost the tie-break: the inbound handshake could not pin the peer, so check now.
		enforce(expected.isNull || sec.remotePeer == expected.get,
			"upgrade: peer authenticated as " ~ sec.remotePeer.toString ~ ", not the one dialed");
	}
	up.remotePeer = sec.remotePeer;
	up.remoteKey = sec.remoteKey;

	// Muxer, over the secured stream.
	if (initiator)
		up.muxerProtocol = negotiateDialer(sec, ids(cfg.muxers));
	else
		up.muxerProtocol = negotiateListener(sec, ids(cfg.muxers));
	up.muxer = pick(cfg.muxers, up.muxerProtocol).create(sec, initiator);
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
