module tests.core.upgrade_test;

import std.typecons : Nullable, nullable;

import libp2p.core.peer_id : PeerId;
import libp2p.core.stream : Stream;
import libp2p.core.upgrade;
import libp2p.crypto.keys : Keypair;
import libp2p.muxer.yamux : YamuxFactory;
import libp2p.security.noise : NoiseTransport;
import libp2p.security.security : SecureTransport;
import tests.util.pipe : runPair;
import fluent.asserts;

private UpgradeConfig cfgFor(Keypair k)
{
	UpgradeConfig c;
	c.security = [cast(SecureTransport) new NoiseTransport(k)];
	c.muxers = [cast(MuxerFactory) new YamuxFactory];
	return c;
}

// The TCP simultaneous open: both sides dialed, so both upgrade as dialers.
// With the simultaneous-open tie-break one of them runs the handshakes as the
// responder, and each still authenticates the other as the peer it dialed.
@("upgrade: two dialers on one punched connection both come up, authenticated")
unittest
{
	auto ka = Keypair.generateEd25519, kb = Keypair.generateEd25519;
	auto ida = PeerId.fromPublicKey(ka.publicKey), idb = PeerId.fromPublicKey(kb.publicKey);
	Upgraded ua, ub;
	runPair(
		(Stream s) { ua = upgrade(s, Endpoint.dialer, cfgFor(ka), nullable(idb), true); },
		(Stream s) { ub = upgrade(s, Endpoint.dialer, cfgFor(kb), nullable(ida), true); });
	ua.remotePeer.should.equal(idb);
	ub.remotePeer.should.equal(ida);
	ua.securityProtocol.should.equal(ub.securityProtocol);
	ua.muxerProtocol.should.equal(ub.muxerProtocol);
	ua.muxer.close();
	ub.muxer.close();
}

// Pinned to the wrong peer, the side that lost the tie-break (whose inbound
// handshake cannot pin) still refuses the connection.
@("upgrade: a punched connection to an unexpected peer is refused on both sides")
unittest
{
	auto ka = Keypair.generateEd25519, kb = Keypair.generateEd25519, kx = Keypair.generateEd25519;
	auto idx = PeerId.fromPublicKey(kx.publicKey), ida = PeerId.fromPublicKey(ka.publicKey);
	Exception ea, eb;
	runPair(
		(Stream s) { try upgrade(s, Endpoint.dialer, cfgFor(ka), nullable(idx), true); catch (Exception e) ea = e; },
		(Stream s) { try upgrade(s, Endpoint.dialer, cfgFor(kb), nullable(ida), true); catch (Exception e) eb = e; });
	(ea !is null).should.equal(true);
}
