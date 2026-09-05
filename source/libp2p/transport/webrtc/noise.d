/**
 * Noise in webrtc-direct: not for encryption — DTLS did that — but to prove
 * each side's libp2p identity and to bind the handshake to the two DTLS
 * certificates, whose fingerprints go into the prologue. Roles are reversed
 * from the connection's: the WebRTC server (listener) is the Noise initiator.
 */
module libp2p.transport.webrtc.noise;

import libp2p.core.peer_id : PeerId;
import libp2p.core.stream : Stream;
import libp2p.crypto.keys : Keypair;
import libp2p.security.noise : noiseAuthenticate;
import libp2p.transport.webrtc.fingerprint : Fingerprint;

/// `"libp2p-webrtc-noise:" || multihash(client) || multihash(server)`.
ubyte[] noisePrologue(Fingerprint client, Fingerprint server)
{
	return cast(ubyte[]) "libp2p-webrtc-noise:" ~ client.toMultihash.encode ~ server.toMultihash.encode;
}

/// The listener's half: Noise initiator. Returns the client's identity.
PeerId inbound(Keypair identity, Stream s, Fingerprint clientFp, Fingerprint serverFp)
{
	return PeerId.fromPublicKey(noiseAuthenticate(s, identity, true, noisePrologue(clientFp, serverFp)));
}

/// The dialer's half: Noise responder. Returns the server's identity.
PeerId outbound(Keypair identity, Stream s, Fingerprint serverFp, Fingerprint clientFp)
{
	return PeerId.fromPublicKey(noiseAuthenticate(s, identity, false, noisePrologue(clientFp, serverFp)));
}
