module tests.transport.webrtc.noise_test;

import std.conv : to;
import std.string : toLower;
import std.digest : toHexString;

import libp2p.transport.webrtc.noise;
import libp2p.transport.webrtc.fingerprint : Fingerprint;
import libp2p.core.stream : ByteStream;
import libp2p.core.peer_id : PeerId;
import libp2p.crypto.keys : Keypair;
import fluent.asserts;
import tests.util.fiberpipe : runPair;

private ubyte[32] fromHex(string h)
{
	ubyte[32] o;
	foreach (i; 0 .. 32)
		o[i] = h[2 * i .. 2 * i + 2].to!ubyte(16);
	return o;
}

@("noise prologue binds both fingerprints (rust parity vectors)")
unittest
{
	auto a = Fingerprint.raw(fromHex("3e79af40d6059617a0d83b83a52ce73b0c1f37a72c6043ad2969e2351bdca870"));
	auto b = Fingerprint.raw(fromHex("30fc9f469c207419dfdd0aab5f27a86c973c94e40548db9375cca2e915973b99"));

	noisePrologue(a, b).toHexString.toLower.should.equal(
		"6c69627032702d7765627274632d6e6f6973653a12203e79af40d6059617a0d83b83a52ce73b0c1f37a72c6043ad2969e2351bdca870122030fc9f469c207419dfdd0aab5f27a86c973c94e40548db9375cca2e915973b99");
	noisePrologue(b, a).toHexString.toLower.should.equal(
		"6c69627032702d7765627274632d6e6f6973653a122030fc9f469c207419dfdd0aab5f27a86c973c94e40548db9375cca2e915973b9912203e79af40d6059617a0d83b83a52ce73b0c1f37a72c6043ad2969e2351bdca870");
}

@("webrtc noise handshake authenticates both peers with reversed roles")
unittest
{
	auto serverKp = Keypair.generateEd25519;
	auto clientKp = Keypair.generateEd25519;
	// Arbitrary but distinct fingerprints — both sides must agree on them.
	auto clientFp = Fingerprint.raw(fromHex("1111111111111111111111111111111111111111111111111111111111111111"));
	auto serverFp = Fingerprint.raw(fromHex("2222222222222222222222222222222222222222222222222222222222222222"));

	PeerId serverSawClient, clientSawServer;

	runPair((ByteStream a) {
		// WebRTC server = Noise initiator.
		serverSawClient = inbound(serverKp, a, clientFp, serverFp);
	}, (ByteStream b) {
		// WebRTC client = Noise responder.
		clientSawServer = outbound(clientKp, b, serverFp, clientFp);
	});

	serverSawClient.should.equal(PeerId.fromPublicKey(clientKp.publicKey));
	clientSawServer.should.equal(PeerId.fromPublicKey(serverKp.publicKey));
}
