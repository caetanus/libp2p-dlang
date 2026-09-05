/**
 * Two swarms over loopback TCP, through the whole stack: tcp → noise → yamux,
 * a protocol handler, notifiees, limits, the idle timer, and closing. The leak
 * gate proves that when a swarm is closed nothing of it is left running.
 */
module tests.swarm.swarm_test;

import core.time : msecs, seconds, MonoTime;
import vibe.core.core : sleep;

import fluent.asserts;

import libp2p.core.ending;
import libp2p.core.peer_id : PeerId;
import libp2p.core.stream;
import libp2p.core.upgrade : Endpoint;
import libp2p.crypto.keys : Keypair;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.swarm.swarm;
import libp2p.transport.tcp : TcpTransport;
import tests.util.loop;
import std.functional : toDelegate;

private enum echoProtocol = "/test/echo/1.0.0";
private enum loopback = "/ip4/127.0.0.1/tcp/0";

private Swarm makeSwarm(SwarmConfig cfg = SwarmConfig.init, ConnectionGater gater = null)
{
	return new Swarm(Keypair.generateEd25519, [new TcpTransport], cfg, gater);
}

/// Echo: read one message, write it back, close.
private void echoHandler(Stream s, Connection, string)
{
	scope (exit)
		s.close();
	auto buf = new ubyte[64];
	immutable n = s.read(buf);
	s.write(buf[0 .. n]);
}

private string echoOnce(Connection c, string word)
{
	auto s = c.newStream(echoProtocol);
	scope (exit)
		s.close();
	s.write(cast(const(ubyte)[]) word);
	auto buf = new ubyte[64];
	immutable n = s.read(buf);
	return cast(string) buf[0 .. n].idup;
}

private final class Recorder : Notifiee
{
	PeerId[] connected_, disconnected_;

	void connected(Connection c)
	{
		connected_ ~= c.remotePeer;
	}

	void disconnected(Connection c)
	{
		disconnected_ ~= c.remotePeer;
	}
}

@("swarm: two swarms connect and a protocol completes end to end")
unittest
{
	string echoed;
	bool listenerKnowsDialer, dialerKnowsListener;
	size_t listenerPeers;
	auto lr = new Recorder, dr = new Recorder;

	onLoop({
		auto listener = makeSwarm();
		scope (exit)
			listener.close();
		listener.setStreamHandler(echoProtocol, toDelegate(&echoHandler));
		listener.addNotifiee(lr);
		listener.listen(Multiaddr.parse(loopback));

		auto dialer = makeSwarm();
		scope (exit)
			dialer.close();
		dialer.addNotifiee(dr);

		auto c = dialer.connect(listener.localPeer, listener.listenAddrs);
		echoed = echoOnce(c, "ping");

		sleep(20.msecs); // let the listener finish its bookkeeping
		listenerKnowsDialer = listener.isConnected(dialer.localPeer);
		dialerKnowsListener = dialer.isConnected(listener.localPeer);
		listenerPeers = listener.connectedPeers.length;
	});

	echoed.should.equal("ping");
	listenerKnowsDialer.should.equal(true);
	dialerKnowsListener.should.equal(true);
	listenerPeers.should.equal(1);
	lr.connected_.length.should.equal(1);
	dr.connected_.length.should.equal(1);
	// Closing the swarms told both sides.
	lr.disconnected_.length.should.equal(1);
	dr.disconnected_.length.should.equal(1);
}

@("swarm: connecting to a peer we already have returns the same connection")
unittest
{
	bool same;
	onLoop({
		auto listener = makeSwarm();
		scope (exit)
			listener.close();
		listener.listen(Multiaddr.parse(loopback));
		auto dialer = makeSwarm();
		scope (exit)
			dialer.close();

		auto a = dialer.connect(listener.localPeer, listener.listenAddrs);
		auto b = dialer.connect(listener.localPeer, listener.listenAddrs);
		same = a is b;
	});
	same.should.equal(true);
}

private final class DenyAll : ConnectionGater
{
	bool allowInbound(Multiaddr)
	{
		return false;
	}

	bool allowPeer(PeerId, Endpoint)
	{
		return true;
	}
}

@("swarm: a gater refuses an inbound connection before the handshake runs")
unittest
{
	bool dialFailed;
	size_t listenerPeers = size_t.max;
	onLoop({
		auto listener = makeSwarm(SwarmConfig.init, new DenyAll);
		scope (exit)
			listener.close();
		listener.listen(Multiaddr.parse(loopback));
		auto dialer = makeSwarm();
		scope (exit)
			dialer.close();

		try
			dialer.connect(listener.localPeer, listener.listenAddrs);
		catch (DialFailure)
			dialFailed = true;
		listenerPeers = listener.connectedPeers.length;
	});
	dialFailed.should.equal(true);
	listenerPeers.should.equal(0);
}

@("swarm: closing a connection empties the pool, reports it, and allows a redial")
unittest
{
	bool connectedBefore, connectedAfter = true, redialled;
	auto dr = new Recorder;
	onLoop({
		auto listener = makeSwarm();
		scope (exit)
			listener.close();
		listener.listen(Multiaddr.parse(loopback));
		auto dialer = makeSwarm();
		scope (exit)
			dialer.close();
		dialer.addNotifiee(dr);

		auto c = dialer.connect(listener.localPeer, listener.listenAddrs);
		connectedBefore = dialer.isConnected(listener.localPeer);

		c.close();
		connectedAfter = dialer.isConnected(listener.localPeer);

		auto again = dialer.connect(listener.localPeer, listener.listenAddrs);
		redialled = again !is c && !again.isClosed;
	});
	connectedBefore.should.equal(true);
	connectedAfter.should.equal(false);
	dr.disconnected_.length.should.be.greaterThan(0);
	redialled.should.equal(true);
}

@("swarm: a peer closing its connection is noticed on our side")
unittest
{
	bool gone;
	onLoop({
		auto listener = makeSwarm();
		scope (exit)
			listener.close();
		listener.listen(Multiaddr.parse(loopback));
		auto dialer = makeSwarm();
		scope (exit)
			dialer.close();

		auto c = dialer.connect(listener.localPeer, listener.listenAddrs);
		sleep(20.msecs);
		listener.connection(dialer.localPeer).close(); // the far side hangs up

		immutable deadline = MonoTime.currTime + 3.seconds;
		while (dialer.isConnected(listener.localPeer) && MonoTime.currTime < deadline)
			sleep(5.msecs);
		gone = !dialer.isConnected(listener.localPeer) && c.isClosed;
	});
	gone.should.equal(true);
}

@("swarm: a busy connection does not accumulate fibers")
unittest
{
	size_t idle = size_t.max, afterChurn = size_t.max;
	onLoop({
		auto listener = makeSwarm();
		scope (exit)
			listener.close();
		listener.setStreamHandler(echoProtocol, toDelegate(&echoHandler));
		listener.listen(Multiaddr.parse(loopback));
		auto dialer = makeSwarm();
		scope (exit)
			dialer.close();

		auto c = dialer.connect(listener.localPeer, listener.listenAddrs);
		sleep(20.msecs);
		idle = listener.liveTasks;

		foreach (_; 0 .. 200)
			echoOnce(c, "x");

		immutable deadline = MonoTime.currTime + 5.seconds;
		while (listener.liveTasks > idle && MonoTime.currTime < deadline)
			sleep(5.msecs);
		afterChurn = listener.liveTasks;
	});
	idle.should.equal(0);
	afterChurn.should.equal(0);
}

@("swarm: an inbound connection limit admits exactly N")
unittest
{
	size_t listenerPeers = size_t.max;
	bool secondFailed;
	onLoop({
		SwarmConfig cfg;
		cfg.limits.establishedInbound = 1;
		auto listener = makeSwarm(cfg);
		scope (exit)
			listener.close();
		listener.listen(Multiaddr.parse(loopback));

		auto a = makeSwarm();
		scope (exit)
			a.close();
		auto b = makeSwarm();
		scope (exit)
			b.close();

		a.connect(listener.localPeer, listener.listenAddrs);
		sleep(20.msecs);
		// The listener admits the second through the handshake and then refuses
		// it: from here the dialer sees its fresh connection die.
		try
		{
			auto c = b.connect(listener.localPeer, listener.listenAddrs);
			immutable deadline = MonoTime.currTime + 3.seconds;
			while (!c.isClosed && MonoTime.currTime < deadline)
				sleep(5.msecs);
			secondFailed = c.isClosed;
		}
		catch (DialFailure)
			secondFailed = true;
		listenerPeers = listener.connectedPeers.length;
	});
	listenerPeers.should.equal(1);
	secondFailed.should.equal(true);
}

@("swarm: a failed dial gives its pending slot back")
unittest
{
	bool firstFailed, secondWorked;
	onLoop({
		auto listener = makeSwarm();
		scope (exit)
			listener.close();
		listener.listen(Multiaddr.parse(loopback));

		// Learn a port nobody listens on any more.
		auto dead = makeSwarm();
		dead.listen(Multiaddr.parse(loopback));
		auto deadAddr = dead.listenAddrs[0];
		dead.close();

		SwarmConfig cfg;
		cfg.limits.pendingOutbound = 1;
		auto dialer = makeSwarm(cfg);
		scope (exit)
			dialer.close();

		try
			dialer.dial(deadAddr);
		catch (DialFailure)
			firstFailed = true;
		dialer.connect(listener.localPeer, listener.listenAddrs); // the slot is back
		secondWorked = dialer.isConnected(listener.localPeer);
	});
	firstFailed.should.equal(true);
	secondWorked.should.equal(true);
}

@("swarm: a hold disarms the idle timer, and releasing it arms a fresh one")
unittest
{
	bool heldOpen, closedItself;
	onLoop({
		auto listener = makeSwarm();
		scope (exit)
			listener.close();
		listener.listen(Multiaddr.parse(loopback));

		SwarmConfig cfg;
		cfg.idleTimeout = 100.msecs;
		auto dialer = makeSwarm(cfg);
		scope (exit)
			dialer.close();

		auto c = dialer.connect(listener.localPeer, listener.listenAddrs);
		{
			auto h = c.hold();
			sleep(300.msecs); // three idle timeouts, and still claimed
			heldOpen = dialer.isConnected(listener.localPeer);
		} // released here: the timer is armed afresh

		immutable deadline = MonoTime.currTime + 3.seconds;
		while (dialer.isConnected(listener.localPeer) && MonoTime.currTime < deadline)
			sleep(20.msecs);
		closedItself = !dialer.isConnected(listener.localPeer);
	});
	heldOpen.should.equal(true);
	closedItself.should.equal(true);
}

@("swarm: a handler that throws resets its stream and the connection lives")
unittest
{
	bool streamEnded, stillConnected;
	onLoop({
		auto listener = makeSwarm();
		scope (exit)
			listener.close();
		listener.setStreamHandler("/test/fail/1.0.0", (Stream s, Connection, string) {
			throw new Exception("handler blew up");
		});
		listener.listen(Multiaddr.parse(loopback));
		auto dialer = makeSwarm();
		scope (exit)
			dialer.close();

		auto c = dialer.connect(listener.localPeer, listener.listenAddrs);
		auto s = c.newStream("/test/fail/1.0.0");
		try
		{
			auto buf = new ubyte[4];
			s.read(buf);
		}
		catch (Ending)
			streamEnded = true;
		s.close();
		stillConnected = dialer.isConnected(listener.localPeer) && !c.isClosed;
	});
	streamEnded.should.equal(true);
	stillConnected.should.equal(true);
}
