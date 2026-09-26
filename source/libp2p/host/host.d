/**
 * The host: a thin façade over the swarm plus a peerstore and the node's own
 * description. Protocols depend on this rather than on the pool.
 */
module libp2p.host.host;

import std.algorithm.searching : canFind;
import std.exception : enforce;

import libp2p.core.peer_id : PeerId;
import libp2p.core.stream : Stream;
import libp2p.crypto.keys : Keypair, PublicKey;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.swarm.swarm;
import libp2p.transport.tcp : TcpTransport;
import libp2p.transport.transport : Transport;

public import libp2p.host.peerstore : Peerstore;
public import libp2p.swarm.swarm : Connection, Hold, Notifiee, StreamHandler, SwarmConfig, ConnectionGater;

struct HostConfig
{
	string agentVersion = "libp2p-dlang/0.1.0";
	string protocolVersion = "ipfs/0.1.0";
	SwarmConfig swarm;
}

final class Host
{
	Swarm swarm;
	Peerstore peerstore;
	HostConfig config;

	this(Keypair identity, Transport[] transports, HostConfig cfg = HostConfig.init, ConnectionGater gater = null)
	{
		config = cfg;
		swarm = new Swarm(identity, transports, cfg.swarm, gater);
		peerstore = new Peerstore;
	}

	/// A host with a fresh Ed25519 identity and the TCP transport.
	static Host create(HostConfig cfg = HostConfig.init, ConnectionGater gater = null)
	{
		return new Host(Keypair.generateEd25519, [new TcpTransport], cfg, gater);
	}

	PeerId id() const
	{
		return swarm.localPeer;
	}

	PublicKey key() const
	{
		return swarm.localKey;
	}

	Multiaddr[] addrs()
	{
		return swarm.listenAddrs;
	}

	/// Reflexive addresses (webrtc-direct srflx) for a hole punch, for DCUtR.
	/// The device moved networks: see Swarm.networkChanged. Returns how many
	/// connections (dead paths on the old network) were closed.
	size_t networkChanged()
	{
		return swarm.networkChanged();
	}

	Multiaddr[] reflexiveAddrs()
	{
		return swarm.reflexiveAddrs();
	}

	/// Warm the reflexive-address cache ahead of a hole punch (DCUtR), so the
	/// offer carries a public srflx instead of blocking on STUN when read. Nothrow
	/// and non-blocking: safe to call from the connection-admission path.
	void warmReflexiveAddrs() nothrow
	{
		swarm.startReflexive();
	}

	private Multiaddr[] delegate()[] observedSources;

	/// Register a source of addresses peers have observed us at (identify does).
	void addObservedAddrSource(Multiaddr[] delegate() source)
	{
		observedSources ~= source;
	}

	/// Where peers have seen us from outside: the IP (and the port of whatever
	/// connection they saw) our NAT gave us. Raw material for a hole punch — see
	/// Relay's DCUtR addresses, which pair these IPs with our listen ports.
	Multiaddr[] observedAddrs()
	{
		Multiaddr[] out_;
		foreach (src; observedSources)
			foreach (a; src())
				if (!out_.canFind(a))
					out_ ~= a;
		return out_;
	}

	/// Punch a direct connection to `peer` at a reflexive address, for DCUtR.
	/// `asDialer` splits the securing handshake's roles across the two peers.
	Connection punch(const Multiaddr addr, PeerId peer, bool asDialer)
	{
		return swarm.punch(addr, peer, asDialer);
	}

	void listen(Multiaddr addr)
	{
		swarm.listen(addr);
	}

	/// A connection to `peer`, over `addrs` or over what the peerstore knows.
	/// A new connection to `peer` over `addrs` even if one exists elsewhere (see
	/// Swarm.connectFresh): the roaming path.
	Connection connectFresh(PeerId peer, const(Multiaddr)[] addrs)
	{
		peerstore.addAddrs(peer, addrs);
		return swarm.connectFresh(peer, addrs);
	}

	Connection connect(PeerId peer, const(Multiaddr)[] addrs = null)
	{
		if (addrs.length > 0)
			peerstore.addAddrs(peer, addrs);
		else
			addrs = peerstore.addrs(peer);
		return swarm.connect(peer, addrs);
	}

	Stream newStream(PeerId peer, const(string)[] protocols, out string chosen)
	{
		return connect(peer).newStream(protocols, chosen);
	}

	Stream newStream(PeerId peer, string protocol)
	{
		string chosen;
		return newStream(peer, [protocol], chosen);
	}

	void setStreamHandler(string protocol, StreamHandler handler)
	{
		swarm.setStreamHandler(protocol, handler);
	}

	void removeStreamHandler(string protocol)
	{
		swarm.removeStreamHandler(protocol);
	}

	string[] protocols()
	{
		return swarm.protocols;
	}

	void addNotifiee(Notifiee n)
	{
		swarm.addNotifiee(n);
	}

	void removeNotifiee(Notifiee n)
	{
		swarm.removeNotifiee(n);
	}

	void close() nothrow
	{
		swarm.close();
	}
}
