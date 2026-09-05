/**
 * Two hosts with ping and identify as services, over loopback TCP. What the
 * old behaviour tests pinned, asserted in the new shape: a host pings its peer
 * and reports the round trip; the dialer learns the listener's identity,
 * protocols and agent; the observed address comes back as an external
 * candidate; the listener reports having sent its identity; and a connection
 * used only by ping still goes idle and closes.
 */
module tests.host.host_test;

import core.time : Duration, msecs, seconds, MonoTime;
import vibe.core.core : sleep;

import fluent.asserts;

import libp2p.core.peer_id : PeerId;
import libp2p.host.host;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.protocol.identify;
import libp2p.protocol.ping;
import tests.util.loop;

private enum loopback = "/ip4/127.0.0.1/tcp/0";

private Host listeningHost(HostConfig cfg = HostConfig.init)
{
	auto h = Host.create(cfg);
	h.listen(Multiaddr.parse(loopback));
	return h;
}

@("host: a host pings its peer and reports the round-trip time")
unittest
{
	Duration rtt = Duration.min;
	PeerId from, expected;
	onLoop({
		auto listener = listeningHost();
		scope (exit)
			listener.close();
		auto lp = new Ping(listener);

		auto dialer = Host.create();
		scope (exit)
			dialer.close();
		PingConfig pc;
		pc.interval = 50.msecs;
		auto dp = new Ping(dialer, pc);
		dp.onResult = (PeerId p, Duration d) { from = p; rtt = d; };

		expected = listener.id;
		dialer.connect(listener.id, listener.addrs);
		immutable deadline = MonoTime.currTime + 3.seconds;
		while (rtt == Duration.min && MonoTime.currTime < deadline)
			sleep(10.msecs);
	});
	(rtt >= Duration.zero).should.equal(true);
	from.should.equal(expected);
}

@("host: the dialer learns the listener's identity, protocols and agent")
unittest
{
	IdentifyInfo info;
	bool got;
	PeerId listenerId;
	string[] listenerProtocols;
	Multiaddr[] listenerAddrs;
	string agentInStore;
	onLoop({
		HostConfig cfg;
		cfg.agentVersion = "test-agent/9.9";
		auto listener = listeningHost(cfg);
		scope (exit)
			listener.close();
		new IdentifyService(listener);
		new Ping(listener);
		listenerId = listener.id;
		listenerProtocols = listener.protocols;
		listenerAddrs = listener.addrs;

		auto dialer = Host.create();
		scope (exit)
			dialer.close();
		auto ids = new IdentifyService(dialer);
		ids.onIdentified = (IdentifyInfo i) { info = i; got = true; };

		dialer.connect(listener.id, listener.addrs);
		immutable deadline = MonoTime.currTime + 3.seconds;
		while (!got && MonoTime.currTime < deadline)
			sleep(10.msecs);
		agentInStore = dialer.peerstore.agent(listener.id);
	});
	got.should.equal(true);
	info.peer.should.equal(listenerId);
	info.agentVersion.should.equal("test-agent/9.9");
	info.protocols.should.equal(listenerProtocols);
	info.protocols.should.contain(identifyProtocol);
	info.protocols.should.contain(pingProtocol);
	info.listenAddrs.should.equal(listenerAddrs);
	agentInStore.should.equal("test-agent/9.9");
}

@("host: the observed address comes back as an external candidate")
unittest
{
	Multiaddr[] candidates;
	onLoop({
		auto listener = listeningHost();
		scope (exit)
			listener.close();
		new IdentifyService(listener);

		auto dialer = Host.create();
		scope (exit)
			dialer.close();
		auto ids = new IdentifyService(dialer);

		dialer.connect(listener.id, listener.addrs);
		immutable deadline = MonoTime.currTime + 3.seconds;
		while (ids.observedAddrs.length == 0 && MonoTime.currTime < deadline)
			sleep(10.msecs);
		candidates = ids.observedAddrs;
	});
	candidates.length.should.be.greaterThan(0);
	// The address the listener saw us dial FROM: loopback with our ephemeral
	// source port, not a port we (never) listened on.
	candidates[0].toString.should.contain("/ip4/127.0.0.1/tcp/");
}

@("host: the listener reports having sent its identity")
unittest
{
	PeerId sentTo, dialerId;
	bool sent;
	onLoop({
		auto listener = listeningHost();
		scope (exit)
			listener.close();
		auto lid = new IdentifyService(listener);
		lid.onSent = (PeerId p) { sentTo = p; sent = true; };

		auto dialer = Host.create();
		scope (exit)
			dialer.close();
		new IdentifyService(dialer);
		dialerId = dialer.id;

		dialer.connect(listener.id, listener.addrs);
		immutable deadline = MonoTime.currTime + 3.seconds;
		while (!sent && MonoTime.currTime < deadline)
			sleep(10.msecs);
	});
	sent.should.equal(true);
	sentTo.should.equal(dialerId);
}

@("host: a ping-only connection still goes idle and closes")
unittest
{
	bool pinged, closedItself;
	onLoop({
		auto listener = listeningHost();
		scope (exit)
			listener.close();
		new Ping(listener);

		HostConfig cfg;
		cfg.swarm.idleTimeout = 100.msecs;
		auto dialer = Host.create(cfg);
		scope (exit)
			dialer.close();
		PingConfig pc;
		pc.interval = 20.msecs;
		auto dp = new Ping(dialer, pc);
		dp.onResult = (PeerId, Duration) { pinged = true; };

		dialer.connect(listener.id, listener.addrs);
		immutable deadline = MonoTime.currTime + 3.seconds;
		while (dialer.swarm.isConnected(listener.id) && MonoTime.currTime < deadline)
			sleep(10.msecs);
		closedItself = !dialer.swarm.isConnected(listener.id);
	});
	pinged.should.equal(true);
	closedItself.should.equal(true);
}

@("host: a stream to a peer we are not connected to dials through the peerstore")
unittest
{
	string echoed;
	onLoop({
		auto listener = listeningHost();
		scope (exit)
			listener.close();
		new Ping(listener);

		auto dialer = Host.create();
		scope (exit)
			dialer.close();
		dialer.peerstore.addAddrs(listener.id, listener.addrs);

		auto s = dialer.newStream(listener.id, pingProtocol); // no connect() first
		scope (exit)
			s.close();
		auto rtt = ping(s);
		echoed = rtt >= Duration.zero ? "ok" : "bad";
	});
	echoed.should.equal("ok");
}
