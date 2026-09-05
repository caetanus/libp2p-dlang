/// What we know about peers: addresses, protocols, keys. In memory, unbounded
/// for now; identify writes it, dialing reads it.
module libp2p.host.peerstore;

import std.algorithm.searching : canFind;
import std.typecons : Nullable;

import libp2p.core.peer_id : PeerId;
import libp2p.crypto.keys : PublicKey;
import libp2p.multiformats.multiaddr : Multiaddr;

final class Peerstore
{
	private Multiaddr[][PeerId] addrs_;
	private string[][PeerId] protocols_;
	private PublicKey[PeerId] keys_;
	private string[PeerId] agents_;

	void addAddrs(PeerId peer, const(Multiaddr)[] addrs)
	{
		auto have = addrs_.get(peer, null);
		foreach (a; addrs)
			if (!have.canFind(a))
				have ~= Multiaddr(a.bytes.dup);
		addrs_[peer] = have;
	}

	Multiaddr[] addrs(PeerId peer)
	{
		return addrs_.get(peer, null).dup;
	}

	void setProtocols(PeerId peer, string[] protocols)
	{
		protocols_[peer] = protocols.dup;
	}

	string[] protocols(PeerId peer)
	{
		return protocols_.get(peer, null).dup;
	}

	bool supports(PeerId peer, string protocol)
	{
		return protocols_.get(peer, null).canFind(protocol);
	}

	void setKey(PeerId peer, PublicKey key)
	{
		keys_[peer] = key;
	}

	Nullable!PublicKey key(PeerId peer)
	{
		if (auto k = peer in keys_)
			return Nullable!PublicKey(*k);
		return Nullable!PublicKey.init;
	}

	void setAgent(PeerId peer, string agent)
	{
		agents_[peer] = agent;
	}

	string agent(PeerId peer)
	{
		return agents_.get(peer, null);
	}

	PeerId[] peers()
	{
		return addrs_.keys;
	}

	void forget(PeerId peer)
	{
		addrs_.remove(peer);
		protocols_.remove(peer);
		keys_.remove(peer);
		agents_.remove(peer);
	}
}
