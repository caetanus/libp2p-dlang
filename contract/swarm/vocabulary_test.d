module tests.swarm.vocabulary_test;

import fluent.asserts;

import libp2p.swarm.id : ConnectionId, ListenerId, IdAllocator;
import libp2p.swarm.endpoint : Endpoint, ConnectedPoint, opposite, isDialer, isListener;
import libp2p.swarm.dial_opts : DialOpts, ListenOpts, PeerCondition;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.core.peer_id : PeerId;
import libp2p.crypto.keys : Keypair;

// rust is explicit that the Swarm "enforces that ConnectionIds are unique and
// not reused" — a behaviour holds an id across events, so a recycled id would
// silently address a different connection.
@("swarm ids: the allocator never repeats an id")
unittest
{
	IdAllocator alloc;
	bool[ulong] seen;
	foreach (i; 0 .. 1000)
	{
		auto c = alloc.nextConnectionId();
		(c.value in seen).should.equal(null);
		seen[c.value] = true;
	}
	// Listener ids come from the same counter, so they never collide with
	// connection ids either.
	foreach (i; 0 .. 100)
	{
		auto l = alloc.nextListenerId();
		(l.value in seen).should.equal(null);
		seen[l.value] = true;
	}
}

// D default-constructs structs, so a field left unset must not look like a valid
// handle to the first connection: ids start at 1 and 0 stays "none".
@("swarm ids: a default-constructed id is never a real one")
unittest
{
	ConnectionId none;
	none.value.should.equal(0);

	IdAllocator alloc;
	alloc.nextConnectionId().value.should.be.greaterThan(0);
}

@("endpoint: opposite/isDialer/isListener")
unittest
{
	Endpoint.dialer.opposite.should.equal(Endpoint.listener);
	Endpoint.listener.opposite.should.equal(Endpoint.dialer);
	Endpoint.dialer.isDialer.should.equal(true);
	Endpoint.dialer.isListener.should.equal(false);
	Endpoint.listener.isListener.should.equal(true);
}

@("connected point: a dialed connection carries the address we dialed")
unittest
{
	auto addr = Multiaddr.parse("/ip4/1.2.3.4/tcp/4001");
	auto p = ConnectedPoint.dialer(addr);

	p.isDialer.should.equal(true);
	p.isListener.should.equal(false);
	p.address.toString.should.equal(addr.toString);
	// For a dialer the remote is whoever we dialed.
	p.remoteAddress.toString.should.equal(addr.toString);
	p.roleOverride.should.equal(Endpoint.dialer);
	p.effectiveEndpoint.should.equal(Endpoint.dialer);
}

@("connected point: an accepted connection carries local and send-back addresses")
unittest
{
	auto local = Multiaddr.parse("/ip4/0.0.0.0/tcp/4001");
	auto back = Multiaddr.parse("/ip4/5.6.7.8/tcp/55555");
	auto p = ConnectedPoint.listener(local, back);

	p.isListener.should.equal(true);
	p.localAddr.toString.should.equal(local.toString);
	p.sendBackAddr.toString.should.equal(back.toString);
	// For a listener the remote is the address it can be dialed back on.
	p.remoteAddress.toString.should.equal(back.toString);
	// A listener is never role-overridden.
	p.roleOverride.should.equal(Endpoint.dialer);
	p.effectiveEndpoint.should.equal(Endpoint.listener);
}

// The DCUtR simultaneous-open case: we dial, but both sides agreed we act as the
// listener, so the upgrade must run with listener roles.
@("connected point: a role-overridden dial presents as the listener")
unittest
{
	auto addr = Multiaddr.parse("/ip4/1.2.3.4/tcp/4001");
	auto p = ConnectedPoint.dialer(addr, Endpoint.listener);

	p.isDialer.should.equal(true); // we still dialed
	p.roleOverride.should.equal(Endpoint.listener);
	p.effectiveEndpoint.should.equal(Endpoint.listener); // but we act as listener
}

@("dial opts: targeting a peer defaults to disconnected-and-not-dialing")
unittest
{
	auto id = PeerId.fromPublicKey(Keypair.generateEd25519.publicKey);
	auto o = DialOpts.peer(id);

	o.hasPeer.should.equal(true);
	o.peerId.should.equal(id);
	o.condition.should.equal(PeerCondition.disconnectedAndNotDialing);
	o.extendAddressesThroughBehaviour.should.equal(true);
}

// A bare address has no peer to be "already connected" to, so rust lets it
// through unconditionally and does not ask behaviours for more addresses.
@("dial opts: a bare address always dials and is not extended")
unittest
{
	auto o = DialOpts.address(Multiaddr.parse("/ip4/1.2.3.4/tcp/4001"));

	o.hasPeer.should.equal(false);
	o.condition.should.equal(PeerCondition.always);
	o.extendAddressesThroughBehaviour.should.equal(false);
	o.addresses.length.should.equal(1);
	o.allowedGiven(true, true).should.equal(true);
}

// The matrix that stops dial storms (connected/dialing -> dial or not).
@("dial opts: the peer-condition matrix")
unittest
{
	auto id = PeerId.fromPublicKey(Keypair.generateEd25519.publicKey);
	auto opts(PeerCondition c) => DialOpts.peer(id).withCondition(c);

	// disconnected: only when not connected (dialing is irrelevant)
	opts(PeerCondition.disconnected).allowedGiven(false, false).should.equal(true);
	opts(PeerCondition.disconnected).allowedGiven(false, true).should.equal(true);
	opts(PeerCondition.disconnected).allowedGiven(true, false).should.equal(false);

	// notDialing: only when not already dialing (connectedness is irrelevant)
	opts(PeerCondition.notDialing).allowedGiven(false, false).should.equal(true);
	opts(PeerCondition.notDialing).allowedGiven(true, false).should.equal(true);
	opts(PeerCondition.notDialing).allowedGiven(false, true).should.equal(false);

	// the default: both must hold
	auto both = PeerCondition.disconnectedAndNotDialing;
	opts(both).allowedGiven(false, false).should.equal(true);
	opts(both).allowedGiven(true, false).should.equal(false);
	opts(both).allowedGiven(false, true).should.equal(false);
	opts(both).allowedGiven(true, true).should.equal(false);

	// always: no gate at all
	opts(PeerCondition.always).allowedGiven(true, true).should.equal(true);
}

@("dial opts: addresses accumulate and the role override is carried")
unittest
{
	auto id = PeerId.fromPublicKey(Keypair.generateEd25519.publicKey);
	auto a1 = Multiaddr.parse("/ip4/1.2.3.4/tcp/4001");
	auto a2 = Multiaddr.parse("/ip4/5.6.7.8/tcp/4002");

	auto o = DialOpts.peer(id);
	o.withAddresses([a1]).withAddresses([a2]).withRoleOverride(Endpoint.listener);

	o.addresses.length.should.equal(2);
	o.addresses[0].toString.should.equal(a1.toString);
	o.addresses[1].toString.should.equal(a2.toString);
	o.roleOverride.should.equal(Endpoint.listener);
}

@("listen opts: carries the address")
unittest
{
	auto a = Multiaddr.parse("/ip4/0.0.0.0/tcp/4001");
	ListenOpts.address(a).addr.toString.should.equal(a.toString);
}
