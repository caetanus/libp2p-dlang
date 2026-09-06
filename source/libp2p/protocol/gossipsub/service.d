/**
 * gossipsub on a host.
 *
 * Each side opens one meshsub stream to the other and writes on it; it reads
 * the stream the peer opened. So a connection gives the router exactly one
 * peer. The router decides; this service owns the streams and the fibers: a
 * reader per inbound stream, a writer per peer draining a queue, and the
 * heartbeat. While a peer is in the router its connection is held, so the
 * idle timer leaves it alone; when its stream ends the hold goes with it.
 */
module libp2p.protocol.gossipsub.service;

import core.time : Duration, seconds;
import std.algorithm.mutation : move;
import std.algorithm.searching : canFind;

import vibe.core.core : sleep;
import vibe.core.log : logDebug;
import vibe.core.sync : LocalManualEvent, createManualEvent;
import vibe.core.task : InterruptException;

import libp2p.core.ending : Ending;
import libp2p.core.peer_id : PeerId;
import libp2p.core.stream;
import libp2p.core.upgrade : Endpoint;
import libp2p.crypto.keys : Keypair;
import libp2p.host.host;
import libp2p.protocol.gossipsub.router;
import libp2p.protocol.gossipsub.score : PeerScoreParams, PeerScoreThresholds;
import libp2p.protocol.gossipsub.wire;
import libp2p.util.fibers : FiberGroup;

struct GossipsubConfig
{
	Duration heartbeatInitialDelay = 5.seconds;
	Duration heartbeatInterval = 1.seconds;
	/// Sign what we publish and drop what is unsigned (the rust default).
	bool strictSigning = true;
}

private final class PeerLink
{
	Connection conn;
	Hold hold;
	Stream out_; // our stream to them
	Rpc[] queue;
	LocalManualEvent wake;
	bool gone;

	this(Connection conn)
	{
		this.conn = conn;
		wake = createManualEvent();
	}
}

final class Gossipsub : Notifiee
{
	private Host host;
	private GossipsubConfig cfg;
	GossipSub router;
	private PeerLink[PeerId] links;
	private FiberGroup fibers;
	private bool closed;

	/// A message on a topic we subscribe to.
	void delegate(PeerId from, string topic, const(ubyte)[] data) onMessage;
	/// A peer's meshsub stream ended: it left the router.
	void delegate(PeerId peer) onPeerGone;

	this(Host host, Keypair identity, GossipsubConfig cfg = GossipsubConfig.init)
	{
		this.host = host;
		this.cfg = cfg;
		router = cfg.strictSigning ? new GossipSub(identity) : new GossipSub(PeerId.fromPublicKey(identity.publicKey));
		router.onMessageFull = (PeerId from, Message m) {
			if (onMessage !is null)
				onMessage(from, m.topic, m.data);
		};
		fibers = new FiberGroup((Exception e) nothrow {
			logDebug("libp2p: gossipsub fiber failed: %s", e.msg);
		});
		foreach (id; meshsubProtocolIds)
			host.setStreamHandler(id, &serve);
		host.addNotifiee(this);
		fibers.spawn(&heartbeatLoop);
	}

	void withPeerScore(PeerScoreParams params, PeerScoreThresholds thresholds)
	{
		router.withPeerScore(params, thresholds);
	}

	void close() nothrow
	{
		if (closed)
			return;
		// Fence first: a connection-owned serve() (not in our fiber group, so
		// stopAll cannot interrupt it) must not attach a new peer — with a fresh
		// hold and writer — after we have dropped everything.
		closed = true;
		try
		{
			host.removeNotifiee(this);
			foreach (id; meshsubProtocolIds)
				host.removeStreamHandler(id);
		}
		catch (Exception)
		{
		}
		fibers.stopAll();
		foreach (p, link; links)
			drop(link);
		links = null;
	}

	// --- the application -----------------------------------------------------------------------

	void subscribe(string topic)
	{
		send(router.subscribe(topic));
	}

	void unsubscribe(string topic)
	{
		send(router.unsubscribe(topic));
	}

	void publish(string topic, const(ubyte)[] data)
	{
		send(router.publish(topic, data));
	}

	/// [peers subscribed to the topic, mesh size].
	size_t[2] state(string topic)
	{
		return router.state(topic);
	}

	// --- peers --------------------------------------------------------------------------------

	void connected(Connection c)
	{
		if (closed)
			return;
		fibers.spawn({ attach(c); });
	}

	void disconnected(Connection c)
	{
		if (auto link = c.remotePeer in links)
			if (link.conn is c)
				lost(c.remotePeer);
	}

	/// Open our stream to the peer and introduce it to the router.
	private void attach(Connection c)
	{
		if (closed)
			return;
		auto peer = c.remotePeer;
		if (peer in links)
			return;
		auto link = new PeerLink(c);
		link.hold = c.hold();
		string chosen;
		try
			link.out_ = c.newStream(meshsubProtocolIds, chosen);
		catch (InterruptException e)
		{
			link.hold.release(); // release the hold, then let the stop unwind
			throw e;
		}
		catch (Exception)
		{
			link.hold.release();
			return; // not a gossipsub peer; nothing to do
		}
		// close() may have run while newStream blocked; drop the stream and hold we
		// just opened rather than keep an unowned stream and a spawned writer.
		if (closed)
		{
			drop(link);
			return;
		}
		links[peer] = link;
		router.addPeer(peer, c.role == Endpoint.dialer);
		link.queue ~= router.helloRpc;
		link.wake.emit();
		fibers.spawn({ writer(peer, link); });
	}

	/// Their stream to us: read RPCs for as long as it lasts.
	private void serve(Stream s, Connection c, string)
	{
		scope (exit)
			s.close();
		auto peer = c.remotePeer;
		// A peer that writes before we attached still counts.
		if (peer !in links)
			attach(c);
		try
		{
			for (;;)
			{
				auto frame = s.readLengthPrefixed(maxTransmitSize);
				if (auto why = validateRpcLimits(frame, maxTransmitSize, maxPublishMessages, maxControlSize))
				{
					logDebug("libp2p: gossipsub rpc from %s refused: %s", peer.toString, why);
					continue;
				}
				send(router.onReceive(peer, decodeRpc(frame)));
			}
		}
		catch (Ending)
		{
		}
		lost(peer);
	}

	private void writer(PeerId peer, PeerLink link)
	{
		auto seen = link.wake.emitCount;
		try
		{
			for (;;)
			{
				while (link.queue.length == 0 && !link.gone)
					seen = link.wake.wait(seen);
				if (link.gone)
					return;
				auto rpc = link.queue[0];
				link.queue = link.queue[1 .. $];
				link.out_.writeLengthPrefixed(encodeRpc(rpc));
			}
		}
		catch (Ending)
		{
			lost(peer);
		}
	}

	private void send(Out[] outs)
	{
		foreach (o; outs)
		{
			auto link = o.peer in links;
			if (link is null || link.gone)
				continue;
			link.queue ~= o.rpc;
			link.wake.emit();
		}
	}

	private void lost(PeerId peer)
	{
		auto link = peer in links;
		if (link is null)
			return;
		auto l = *link;
		links.remove(peer);
		drop(l);
		router.removePeer(peer);
		if (onPeerGone !is null)
			onPeerGone(peer);
	}

	private void drop(PeerLink link) nothrow
	{
		if (link.gone)
			return;
		link.gone = true;
		link.wake.emit();
		if (link.out_ !is null)
			link.out_.close();
		link.hold.release();
	}

	private void heartbeatLoop()
	{
		sleep(cfg.heartbeatInitialDelay);
		for (;;)
		{
			send(router.heartbeat());
			sleep(cfg.heartbeatInterval);
		}
	}
}
