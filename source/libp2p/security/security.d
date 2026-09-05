/**
 * A security transport turns a raw `Stream` into one that is encrypted and
 * authenticated, and tells you who is on the other end.
 */
module libp2p.security.security;

import std.typecons : Nullable;

import libp2p.core.peer_id : PeerId;
import libp2p.core.stream : Stream;
import libp2p.crypto.keys : PublicKey;

interface SecureConn : Stream
{
	PeerId remotePeer();
	PublicKey remoteKey();
}

interface SecureTransport
{
	/// The multistream id this transport negotiates under ("/noise").
	string protocolId();

	/// Handshake as the initiator. If `expected` is set, a peer that turns out
	/// to be someone else is refused before the connection goes anywhere.
	SecureConn secureOutbound(Stream raw, Nullable!PeerId expected);

	/// Handshake as the responder.
	SecureConn secureInbound(Stream raw);
}
