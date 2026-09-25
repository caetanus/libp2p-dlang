/**
 * Meeting a peer by a shared key on the public DHT — the entrance of
 * "DHT → punch → connection": the key names a provider record, the side that
 * can be found announces itself under it (its relay circuits, its public
 * addresses), the other side asks who provides it, connects, and lets DCUtR
 * turn the relayed meeting into a direct connection. The application hands over
 * the key and gets a Connection; it never sees a PeerId or an address. The same
 * key names the LAN rendezvous (libp2p.discovery.mdns.LanRendezvous), which
 * skips all of this on one network.
 */
module libp2p.discovery.rendezvous;

import core.time : Duration, MonoTime, seconds, msecs;
import std.algorithm.searching : canFind;

import vibe.core.core : sleep;
import vibe.core.log : logInfo;

import libp2p.core.peer_id : PeerId;
import libp2p.host.host : Host;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.protocol.kad.kad : Kademlia, PeerInfo;
import libp2p.protocol.relay.service : Relay;
import libp2p.swarm.connection : Connection;

/// The DHT key for (`prefix`, `secret`): a CIDv1 of the raw sha256 of
/// `<prefix>:rendezvous:1` ~ secret — a shape every go/rust node stores without
/// question, and nothing of the secret on the wire.
ubyte[] rendezvousKeyFor(string prefix, scope const(ubyte)[] secret)
{
	import std.digest.sha : sha256Of;

	auto h = sha256Of(cast(const(ubyte)[])(prefix ~ ":rendezvous:1") ~ secret);
	return cast(ubyte[])[0x01, 0x55, 0x12, 0x20] ~ h[].dup;
}

/// Announce ourselves under `key` with `addrs` (relay circuits, public
/// addresses — never LAN ones; the DHT filters those out and refuses an empty
/// record). Returns how many DHT peers took it. Repeat when the circuits change
/// and every half hour or so.
size_t announceUnder(Kademlia kad, const(ubyte)[] key, Multiaddr[] addrs, bool allowPrivate = false)
{
	return kad.startProviding(key, addrs, allowPrivate);
}

/// Find whoever provides `key`, connect (its circuits are dialed in parallel,
/// the first live one wins) and come back with a DIRECT connection — the relayed
/// one is upgraded by DCUtR and closed. Retries the lookup with a short back-off
/// until `budget` is spent; throws when nobody could be reached in time.
Connection meetUnder(Host host, Kademlia kad, Relay relay, const(ubyte)[] key, Duration budget = 60.seconds)
{
	import vibe.core.task : InterruptException;
	import libp2p.util.timeout : withTimeout;

	immutable deadline = MonoTime.currTime + budget;
	// What is left of the budget: every blocking step below runs under it, so the
	// call returns when the budget says, not when a DHT walk or a punch does.
	Duration left()
	{
		auto l = deadline - MonoTime.currTime;
		return l < 1.msecs ? 1.msecs : l; // never 0: withTimeout reads 0 as "no deadline"
	}

	// A peer found late still gets a real attempt: the lookup may spend the budget only
	// down to `reach`, which is kept for connecting and punching. Without it the DHT walk
	// ate the budget — on 4G 27 of 30 s — and a found peer had 2.7 s to be reached
	// through its relay, which it never was.
	immutable reach = budget / 2 < 20.seconds ? budget / 2 : 20.seconds;
	// A walk stops ASKING at `cutoff`; the requests still in flight drain within the
	// DHT's request timeout, which is taken off too, so the reach share is really free.
	// (A request timeout switched off still gets a bound here: 10 s.) A budget too short
	// for both — cutoff before we even start — is split in half: walk, then reach.
	immutable drain = kad.requestTimeout > Duration.zero ? kad.requestTimeout : 10.seconds;
	immutable start = MonoTime.currTime;
	immutable cutoff = deadline - reach - drain > start ? deadline - reach - drain : start + budget / 2;
	Duration lookupLeft()
	{
		auto l = cutoff - MonoTime.currTime;
		return l < 1.msecs ? 1.msecs : l;
	}

	Exception last;
	bool looked; // a lookup ran (found someone or not, failed or not)
	auto wait = 500.msecs;
	while (MonoTime.currTime < deadline)
	{
		if (looked && MonoTime.currTime >= cutoff)
			break; // past the cutoff a second walk would drain into the reach share
		PeerInfo[] providers;
		looked = true;
		try
			// soft limit: at lookupLeft the walk stops asking and hands back what it found;
			// the hard one (the whole budget) only guards a walk that would not return
			providers = withTimeout(left(), "rendezvous lookup", () => kad.getProviders(key, lookupLeft()));
		catch (InterruptException e)
			throw e; // the caller gave up: not a failed lookup
		catch (Exception e)
			last = e;
		foreach (pi; providers)
		{
			if (pi.peerId == host.id || pi.addrs.length == 0)
				continue;
			if (MonoTime.currTime >= deadline)
				break;
			try
			{
				withTimeout(left(), "rendezvous connect", { host.connect(pi.peerId, pi.addrs); });
				auto c = withTimeout(left(), "rendezvous punch", () => relay.ensureDirect(pi.peerId));
				logInfo("libp2p: rendezvous: met %s via %s", pi.peerId.toString, c.remoteAddr.toString);
				return c;
			}
			catch (InterruptException e)
				throw e;
			catch (Exception e)
			{
				logInfo("libp2p: rendezvous: %s found but not reached: %s", pi.peerId.toString, e.msg);
				last = e;
			}
		}
		auto pause = wait < left() ? wait : left();
		if (MonoTime.currTime + pause >= deadline)
			break;
		sleep(pause);
		wait = wait * 2 > 8.seconds ? 8.seconds : wait * 2;
	}
	throw new Exception("rendezvous: nobody reachable under the key" ~ (last is null ? "" : ": " ~ last.msg), last);
}
