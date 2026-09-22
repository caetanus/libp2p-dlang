/**
 * Kademlia as a service on a host.
 *
 * The routing table learns from every peer that speaks the protocol to us and
 * every peer that answers us. Lookups are iterative: α fibers contact the
 * closest known peers, learn closer ones, and converge on the k closest to the
 * target. Writes (records, provider announcements) go to the k closest peers a
 * lookup returned. Reads stop at the first answer. Every request is one
 * substream: negotiate, one message out, one message back (none for
 * ADD_PROVIDER), close.
 *
 * The background jobs re-replicate what we hold and re-announce what we
 * provide, on one fiber owned by the service.
 */
module libp2p.protocol.kad.kad;

import core.time : Duration, MonoTime, seconds, hours, minutes, msecs;
import std.algorithm.searching : canFind;
import std.algorithm.iteration : filter;
import std.array : array;
import std.exception : enforce;
import std.typecons : Nullable, nullable;

import vibe.core.core : sleep;
import vibe.core.log : logDebug;
import vibe.core.task : InterruptException;

import libp2p.core.ending : Ending;
import libp2p.core.peer_id : PeerId;
import libp2p.core.stream;
import libp2p.host.host;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.util.fibers : FiberGroup;
import libp2p.util.timeout : withTimeout;

public import libp2p.protocol.kad.bucket : kValue, NodeStatus;
public import libp2p.protocol.kad.key : Key;
public import libp2p.protocol.kad.message : kadProtocolId;
public import libp2p.protocol.kad.store;
import libp2p.protocol.kad.jobs;
import libp2p.protocol.kad.message : KadMessage, KadPeer, MessageType, ConnectionType;
private alias WireRecord = imported!"libp2p.protocol.kad.message".Record;
import libp2p.protocol.kad.key : Key, Distance;
import libp2p.protocol.kad.query;
import libp2p.protocol.kad.table;

/// Reachable from another network: not unspecified, loopback, link-local or
/// RFC 1918 / ULA private. A /dns* or /p2p-circuit address is taken as public.
bool isPubliclyRoutable(const Multiaddr a)
{
	import std.string : startsWith, split;
	import std.conv : to;

	auto c = a.components;
	if (c.length == 0)
		return false;
	if (c[0].name == "ip4")
	{
		immutable ip = c[0].text;
		if (ip == "0.0.0.0" || ip.startsWith("127.") || ip.startsWith("169.254.") || ip.startsWith("10."))
			return false;
		if (ip.startsWith("192.168."))
			return false;
		if (ip.startsWith("172."))
		{
			auto parts = ip.split(".");
			if (parts.length > 1)
				try
				{
					immutable second = parts[1].to!int;
					if (second >= 16 && second <= 31)
						return false;
				}
				catch (Exception)
				{
				}
		}
		if (ip.startsWith("100."))
		{
			auto parts = ip.split(".");
			if (parts.length > 1)
				try
				{
					immutable second = parts[1].to!int;
					if (second >= 64 && second <= 127)
						return false; // CGNAT shared space (RFC 6598): not ours to advertise
				}
				catch (Exception)
				{
				}
		}
		return true;
	}
	if (c[0].name == "ip6")
	{
		import std.string : toLower;
		immutable ip = c[0].text.toLower;
		return !(ip == "::" || ip == "::1" || ip.startsWith("fe80:") || ip.startsWith("fc") || ip.startsWith("fd"));
	}
	return true;
}

/// A peer and where to reach it.
struct PeerInfo
{
	PeerId peerId;
	Multiaddr[] addrs;
}

struct KademliaConfig
{
	size_t parallelism = 10; /// α — go-libp2p's default; 3 made a public lookup crawl
	size_t replicationFactor = kValue; /// k
	Duration queryTimeout = 60.seconds;
	Duration requestTimeout = 10.seconds;
	size_t maxPacket = 16 * 1024; /// the largest message we accept
	Duration recordTtl = 36.hours;
	Duration providerTtl = 48.hours;
	MemoryStoreConfig store;
	/// Client mode: query the DHT (lookups, providers, records) but never serve it —
	/// no stream handler, so peers cannot put us in their tables or store on us. For
	/// a phone or any node behind a NAT that only needs to find others.
	bool clientMode = false;
}

final class Kademlia
{
	private Host host;
	private KademliaConfig cfg;
	KBucketsTable!(Multiaddr[]) table;
	MemoryStore store;
	private FiberGroup fibers;
	private Notifier notifier;

	this(Host host, KademliaConfig cfg = KademliaConfig.init)
	{
		this.host = host;
		this.cfg = cfg;
		table = KBucketsTable!(Multiaddr[])(Key.fromPeer(host.id));
		store = new MemoryStore(host.id, cfg.store);
		fibers = new FiberGroup((Exception e) nothrow {
			logDebug("libp2p: kad background work failed: %s", e.msg);
		});
		if (!cfg.clientMode)
			host.setStreamHandler(kadProtocolId, &serve);
		notifier = new Notifier(this);
		host.addNotifiee(notifier);
	}

	void close() nothrow
	{
		try
		{
			host.removeNotifiee(notifier);
			host.removeStreamHandler(kadProtocolId);
		}
		catch (Exception)
		{
		}
		fibers.stopAll();
	}

	// --- the routing table -------------------------------------------------------------

	/// Teach the node about a peer; it is dialed when a lookup reaches for it.
	void addAddress(PeerId peer, Multiaddr addr)
	{
		host.peerstore.addAddrs(peer, [addr]);
		auto key = Key.fromPeer(peer);
		auto have = table.get(key);
		Multiaddr[] addrs = have ? *have : null;
		if (!addrs.canFind(addr))
			addrs ~= addr;
		table.insert(key, addrs, host.swarm.isConnected(peer) ? NodeStatus.connected : NodeStatus.disconnected);
	}

	private void learned(PeerId peer, Multiaddr[] addrs, NodeStatus status)
	{
		if (peer == host.id)
			return;
		if (addrs.length > 0)
			host.peerstore.addAddrs(peer, addrs);
		auto key = Key.fromPeer(peer);
		auto have = table.get(key);
		Multiaddr[] all = have ? *have : null;
		foreach (a; addrs)
			if (!all.canFind(a))
				all ~= a;
		if (all.length == 0)
			all = host.peerstore.addrs(peer);
		table.insert(key, all, status);
	}

	private PeerInfo[] closestKnown(Key target, size_t n, PeerId exclude)
	{
		PeerInfo[] out_;
		foreach (node; table.closest(target, n + 1))
		{
			if (node.key.peer == exclude)
				continue;
			out_ ~= PeerInfo(node.key.peer, node.value);
			if (out_.length >= n)
				break;
		}
		return out_;
	}

	// --- lookups ---------------------------------------------------------------------------

	/// The k closest peers to `key` the network knows.
	PeerInfo[] getClosestPeers(const(ubyte)[] key)
	{
		auto target = Key.fromBytes(key);
		auto found = lookup(target, (PeerId p) => findNode(p, key));
		return infos(found);
	}

	/// Store a record locally and on the k closest peers; returns how many took it.
	size_t putRecord(Record rec)
	{
		if (!rec.hasPublisher)
		{
			rec.hasPublisher = true;
			rec.publisher = host.id;
		}
		if (!rec.hasExpires)
		{
			rec.hasExpires = true;
			rec.expires = MonoTime.currTime + cfg.recordTtl;
		}
		enforce(store.put(rec) == StoreError.none, "kad: the local store refused the record");
		auto closest = lookup(Key.fromBytes(rec.key.bytes), (PeerId p) => findNode(p, rec.key.bytes));
		return writeTo(closest, (PeerId p) { sendPutValue(p, rec); });
	}

	/// Look a record up: our own copy, or the first peer's that has it. Null if none.
	Record* getRecord(const(ubyte)[] key)
	{
		auto rk = RecordKey.from(key);
		if (auto local = store.get(rk))
			return local;
		Record found;
		bool have;
		auto target = Key.fromBytes(key);
		cast(void) lookup(target, (PeerId p) {
			auto reply = request(p, message(MessageType.getValue, key));
			if (reply.hasRecord && !have)
			{
				found = fromWire(reply.record, MonoTime.currTime);
				have = true;
			}
			return remember(p, reply);
		}, () => have);
		if (!have)
			return null;
		return new Record(found.key, found.value).fill(found);
	}

	/// Announce that we provide `key`; returns how many peers took the announcement.
	/// `addrs` is what the announcement tells others to dial — a node behind a NAT
	/// passes its relay circuit addresses here (host.addrs, the default, are the
	/// listen addresses: fine for a public node, useless for one nobody can reach).
	/// A rendezvous is exactly this: provide a key both peers derive, the other side
	/// asks getProviders for it and gets our id and these addresses back.
	size_t startProviding(const(ubyte)[] key, Multiaddr[] addrs = null, bool allowPrivate = false)
	{
		auto ours = addrs.length ? addrs : host.addrs;
		// A provider record lives on the public DHT: a LAN, loopback or unspecified
		// address in it is noise to everyone else and a leak of our inside network.
		// Circuits (relay's public address) and public addresses stay.
		if (!allowPrivate)
			ours = ours.filter!(a => isPubliclyRoutable(a)).array;
		enforce(ours.length > 0, "kad: no publicly routable address to provide (pass allowPrivate for a LAN-only DHT)");
		auto rk = RecordKey.from(key);
		auto rec = ProviderRecord(rk, host.id, ours);
		rec.hasExpires = true;
		rec.expires = MonoTime.currTime + cfg.providerTtl;
		store.addProvider(rec);
		auto closest = lookup(Key.fromBytes(key), (PeerId p) => findNode(p, key));
		return writeTo(closest, (PeerId p) { sendAddProvider(p, key, ours); });
	}

	/// Where the network says `peer` can be reached: the peerstore first, then a
	/// closest-peers lookup for its id (a peer that serves the DHT turns up in the
	/// tables with its addresses). Null if nobody knows it — a peer behind a NAT
	/// that does not serve the DHT is found through a provider key instead.
	Nullable!PeerInfo findPeer(PeerId peer)
	{
		auto known = host.peerstore.addrs(peer);
		if (known.length)
			return nullable(PeerInfo(peer, known));
		foreach (pi; getClosestPeers(peer.bytes))
			if (pi.peerId == peer && pi.addrs.length)
				return nullable(pi);
		return Nullable!PeerInfo.init;
	}

	void stopProviding(const(ubyte)[] key)
	{
		store.removeProvider(RecordKey.from(key), host.id);
	}

	/// Who provides `key`. The lookup runs to the k closest peers — where the
	/// latest announcement landed — not to the first answer: a peer far from the
	/// key may still hold an earlier copy of the record with addresses the provider
	/// has since left (a relay it no longer sits behind). When several peers name
	/// the same provider, the addresses from the one closest to the key win.
	PeerInfo[] getProviders(const(ubyte)[] key)
	{
		auto rk = RecordKey.from(key);
		auto target = Key.fromBytes(key);
		PeerInfo[PeerId] found;
		Distance[PeerId] bestDist;
		PeerId[] order;
		foreach (p; store.providers(rk))
		{
			found[p.provider] = PeerInfo(p.provider, p.addresses); // our own copy: any network answer beats it
			order ~= p.provider;
		}
		cast(void) lookup(target, (PeerId p) {
			auto reply = request(p, message(MessageType.getProviders, key));
			auto d = Key.fromPeer(p).distance(target);
			foreach (kp; reply.providerPeers)
			{
				if (kp.nodeId !in found)
					order ~= kp.nodeId;
				auto known = kp.nodeId in bestDist;
				if (known is null || d < *known)
				{
					found[kp.nodeId] = PeerInfo(kp.nodeId, kp.multiaddrs);
					bestDist[kp.nodeId] = d;
				}
				if (kp.multiaddrs.length > 0)
					host.peerstore.addAddrs(kp.nodeId, kp.multiaddrs);
			}
			return remember(p, reply);
		});
		PeerInfo[] providers;
		foreach (id; order)
			providers ~= found[id];
		return providers;
	}

	/// Populate the routing table from whatever it holds: a lookup for our own
	/// id. Returns the table size afterwards.
	size_t bootstrap()
	{
		cast(void) lookup(Key.fromPeer(host.id), (PeerId p) => findNode(p, host.id.bytes));
		return table.count;
	}

	/// Start the periodic jobs on a fiber of ours.
	void runJobs(Duration replicate = 1.hours, Duration publish = 24.hours,
		Duration providerRepublish = 12.hours, Duration recordTtl = 36.hours)
	{
		fibers.spawn({
			immutable now = MonoTime.currTime;
			auto put = new PutRecordJob(host.id, replicate, now, true, publish, true, recordTtl);
			auto add = new AddProviderJob(providerRepublish, now);
			immutable tick = (replicate < providerRepublish ? replicate : providerRepublish) / 2;
			for (;;)
			{
				sleep(tick > 50.msecs ? tick : 50.msecs);
				for (;;)
				{
					auto p = put.poll(store, MonoTime.currTime);
					if (!p.ready)
						break;
					auto rec = p.record;
					try
					{
						auto closest = lookup(Key.fromBytes(rec.key.bytes), (PeerId q) => findNode(q, rec.key.bytes));
						writeTo(closest, (PeerId q) { sendPutValue(q, rec); });
					}
					catch (InterruptException e)
						throw e; // the owner is stopping us; not a failed record
					catch (Exception e)
						logDebug("libp2p: kad replication of a record failed: %s", e.msg);
				}
				for (;;)
				{
					auto p = add.poll(store, MonoTime.currTime);
					if (!p.ready)
						break;
					auto rec = p.record;
					try
					{
						auto closest = lookup(Key.fromBytes(rec.key.bytes), (PeerId q) => findNode(q, rec.key.bytes));
						writeTo(closest, (PeerId q) { sendAddProvider(q, rec.key.bytes, rec.addresses); });
					}
					catch (InterruptException e)
						throw e; // the owner is stopping us; not a failed record
					catch (Exception e)
						logDebug("libp2p: kad provider re-announcement failed: %s", e.msg);
				}
			}
		});
	}

	// --- the lookup machinery --------------------------------------------------------------

	private PeerId[] lookup(Key target, PeerId[] delegate(PeerId) contact, bool delegate() satisfied = null)
	{
		PeerId[] seeds;
		foreach (node; table.closest(target, cfg.replicationFactor))
			seeds ~= node.key.peer;
		auto it = new ClosestPeersIter(target, seeds, cfg.parallelism, cfg.replicationFactor);
		return runQuery(it, cfg.parallelism, (PeerId p) {
			auto closer = contact(p);
			if (satisfied !is null && satisfied())
				it.finish();
			return closer;
		}, cfg.queryTimeout);
	}

	private size_t writeTo(PeerId[] peers, void delegate(PeerId) send)
	{
		auto it = new FixedPeersIter(peers, cfg.parallelism);
		return runFixed(it, cfg.parallelism, send).length;
	}

	private PeerId[] findNode(PeerId p, const(ubyte)[] key)
	{
		return remember(p, request(p, message(MessageType.findNode, key)));
	}

	/// Record what a reply taught us, and return the peers it named.
	private PeerId[] remember(PeerId from, KadMessage reply)
	{
		PeerId[] out_;
		foreach (kp; reply.closerPeers)
		{
			if (kp.nodeId == host.id)
				continue;
			if (kp.multiaddrs.length > 0)
				host.peerstore.addAddrs(kp.nodeId, kp.multiaddrs);
			out_ ~= kp.nodeId;
		}
		return out_;
	}

	private PeerInfo[] infos(PeerId[] peers)
	{
		PeerInfo[] out_;
		foreach (p; peers)
			out_ ~= PeerInfo(p, host.peerstore.addrs(p));
		return out_;
	}

	// --- one request -----------------------------------------------------------------------

	private KadMessage request(PeerId peer, KadMessage msg)
	{
		KadMessage reply;
		// Dial AND open the stream inside the deadline: a public DHT peer advertises
		// half a dozen addresses (v6, quic, webtransport, …), each unreachable one
		// costing a full dial timeout in sequence — a lookup over such peers took
		// minutes with the dial outside the budget. And a peer that accepts the
		// connection but stalls the negotiation would otherwise block forever; the
		// query only checks its deadline between requests.
		withTimeout(cfg.requestTimeout, "kad request", {
			auto c = host.connect(peer);
			auto s = c.newStream(kadProtocolId);
			scope (exit)
				s.close();
			s.writeLengthPrefixed(msg.encode);
			reply = KadMessage.decode(s.readLengthPrefixed(cfg.maxPacket));
		});
		learned(peer, host.peerstore.addrs(peer), NodeStatus.connected);
		return reply;
	}

	private void sendPutValue(PeerId peer, Record rec)
	{
		auto msg = message(MessageType.putValue, rec.key.bytes);
		msg.hasRecord = true;
		msg.record = toWire(rec, MonoTime.currTime);
		auto reply = request(peer, msg);
		enforce(reply.type == MessageType.putValue, "kad: the peer did not acknowledge the record");
	}

	private void sendAddProvider(PeerId peer, const(ubyte)[] key, Multiaddr[] addrs)
	{
		auto msg = message(MessageType.addProvider, key);
		msg.providerPeers = [KadPeer(host.id, addrs, ConnectionType.connected)];
		withTimeout(cfg.requestTimeout, "kad add provider", {
			auto c = host.connect(peer); // dial inside the deadline too (see request)
			auto s = c.newStream(kadProtocolId);
			scope (exit)
				s.close();
			s.writeLengthPrefixed(msg.encode);
		});
		learned(peer, host.peerstore.addrs(peer), NodeStatus.connected);
	}

	private static KadMessage message(MessageType type, const(ubyte)[] key)
	{
		KadMessage m;
		m.type = type;
		m.key = key.dup;
		return m;
	}

	// --- serving -----------------------------------------------------------------------------

	private void serve(Stream s, Connection c, string)
	{
		scope (exit)
			s.close();
		learned(c.remotePeer, [c.remoteAddr], NodeStatus.connected);
		try
		{
			for (;;)
			{
				auto msg = KadMessage.decode(s.readLengthPrefixed(cfg.maxPacket));
				bool respond = true;
				auto reply = answer(msg, c, respond);
				if (respond)
					s.writeLengthPrefixed(reply.encode);
			}
		}
		catch (Ending)
		{
			// The peer is done asking.
		}
	}

	private KadMessage answer(KadMessage msg, Connection from, ref bool respond)
	{
		auto reply = msg;
		reply.record = WireRecord.init;
		reply.hasRecord = false;
		reply.closerPeers = null;
		reply.providerPeers = null;
		final switch (msg.type)
		{
		case MessageType.findNode:
			reply.closerPeers = closer(msg.key, from.remotePeer);
			break;
		case MessageType.getValue:
			if (auto r = store.get(RecordKey.from(msg.key)))
			{
				if (!r.isExpired(MonoTime.currTime))
				{
					reply.hasRecord = true;
					reply.record = toWire(*r, MonoTime.currTime);
				}
			}
			reply.closerPeers = closer(msg.key, from.remotePeer);
			break;
		case MessageType.putValue:
			if (msg.hasRecord)
			{
				auto rec = fromWire(msg.record, MonoTime.currTime);
				if (rec.key.bytes == msg.key)
					store.put(rec);
			}
			reply = msg; // the acknowledgement is the message itself
			break;
		case MessageType.addProvider:
			foreach (kp; msg.providerPeers)
			{
				if (kp.nodeId != from.remotePeer)
					continue; // only a peer may announce itself
				auto rec = ProviderRecord(RecordKey.from(msg.key), kp.nodeId, kp.multiaddrs);
				rec.hasExpires = true;
				rec.expires = MonoTime.currTime + cfg.providerTtl;
				store.addProvider(rec);
			}
			respond = false;
			break;
		case MessageType.getProviders:
			foreach (p; store.providers(RecordKey.from(msg.key)))
				if (!p.isExpired(MonoTime.currTime))
					reply.providerPeers ~= KadPeer(p.provider, p.addresses, ConnectionType.canConnect);
			reply.closerPeers = closer(msg.key, from.remotePeer);
			break;
		case MessageType.ping:
			break;
		}
		return reply;
	}

	private KadPeer[] closer(const(ubyte)[] key, PeerId asking)
	{
		KadPeer[] out_;
		foreach (pi; closestKnown(Key.fromBytes(key), cfg.replicationFactor, asking))
		{
			auto addrs = pi.addrs.length > 0 ? pi.addrs : host.peerstore.addrs(pi.peerId);
			immutable ct = host.swarm.isConnected(pi.peerId) ? ConnectionType.connected : ConnectionType.canConnect;
			out_ ~= KadPeer(pi.peerId, addrs, ct);
		}
		return out_;
	}

	// --- records on the wire -------------------------------------------------------------------

	private static WireRecord toWire(Record r, MonoTime now)
	{
		WireRecord w;
		w.key = r.key.bytes.dup;
		w.value = r.value.dup;
		if (r.hasPublisher)
			w.publisher = r.publisher.bytes.dup;
		if (r.hasExpires && r.expires > now)
			w.ttl = cast(uint)((r.expires - now).total!"seconds");
		return w;
	}

	private static Record fromWire(WireRecord w, MonoTime now)
	{
		auto r = Record(RecordKey.from(w.key), w.value.dup);
		if (w.publisher.length > 0)
		{
			try
			{
				r.publisher = PeerId.fromBytes(w.publisher);
				r.hasPublisher = true;
			}
			catch (Exception)
			{
			} // not a peer id we can read; the record is still good
		}
		if (w.ttl > 0)
		{
			r.hasExpires = true;
			r.expires = now + w.ttl.seconds;
		}
		return r;
	}

	private final class Notifier : Notifiee
	{
		private Kademlia kad;

		this(Kademlia kad)
		{
			this.kad = kad;
		}

		void connected(Connection c)
		{
			// Known to the table already? Then it is connected now.
			auto key = Key.fromPeer(c.remotePeer);
			if (kad.table.contains(key))
				kad.table.update(key, NodeStatus.connected);
		}

		void disconnected(Connection c)
		{
			auto key = Key.fromPeer(c.remotePeer);
			if (kad.table.contains(key))
				kad.table.update(key, NodeStatus.disconnected);
		}
	}
}

private Record* fill(Record* target, Record source)
{
	*target = source;
	return target;
}
