/**
 * AutoNAT v1: am I reachable from outside?
 *
 * A client sends a server the addresses it thinks it has; the server dials it
 * back and says whether that worked. The server never dials where it is told:
 * the IP in every requested address is replaced with the one the request
 * actually came from, and relayed addresses and addresses naming someone else
 * are dropped, so a client cannot aim a server at a third party. Requests are
 * throttled per peer and globally, and one dial-back per peer runs at a time.
 *
 * The client keeps a confidence-weighted status: repeated agreement raises
 * confidence up to a cap; a contradicting report erodes it, and the status
 * only flips once confidence is exhausted.
 */
module libp2p.protocol.autonat.autonat;

import core.time : Duration, MonoTime, seconds;
import std.algorithm.searching : canFind, countUntil;
import std.exception : enforce;
import std.typecons : Nullable;

import vibe.core.log : logDebug;

import libp2p.core.ending : Ending;
import libp2p.core.peer_id : PeerId;
import libp2p.core.stream;
import libp2p.host.host;
import libp2p.multiformats.multiaddr : Multiaddr, Component;
import libp2p.util.fibers : FiberGroup;
import libp2p.util.timeout : withTimeout;
import wire = libp2p.protocol.autonat.wire;

public import libp2p.protocol.autonat.wire : autonatProtocol;

enum maxAutonatMessage = 4 * 1024;

// --- the messages, decoded ---------------------------------------------------------------

struct DialRequest
{
	PeerId peerId;
	Multiaddr[] addresses;

	ubyte[] encode() const
	{
		wire.Message m;
		m.type = cast(uint) wire.MessageType.DIAL;
		wire.PeerInfo pi;
		pi.id = peerId.bytes.dup;
		foreach (a; addresses)
			pi.addrs ~= a.encode;
		wire.Dial d;
		d.peer = pi;
		m.dial = d;
		return m.encode;
	}

	/// Addresses that do not parse are skipped, not fatal.
	static DialRequest decode(const(ubyte)[] bytes)
	{
		auto m = wire.Message.decode(bytes);
		enforce(!m.type.isNull && m.type.get == wire.MessageType.DIAL, "autonat: not a DIAL");
		enforce(!m.dial.isNull && !m.dial.get.peer.isNull, "autonat: DIAL without a peer");
		auto pi = m.dial.get.peer.get;
		DialRequest r;
		r.peerId = PeerId.fromBytes(pi.id);
		foreach (raw; pi.addrs)
		{
			try
				r.addresses ~= Multiaddr.decode(raw);
			catch (Exception)
			{
			}
		}
		return r;
	}
}

enum ResponseError
{
	dialError,
	dialRefused,
	badRequest,
	internalError,
}

struct DialResponse
{
	bool ok;
	Multiaddr addr; /// on success: the address that answered
	ResponseError error;
	string statusText;

	ubyte[] encode() const
	{
		wire.Message m;
		m.type = cast(uint) wire.MessageType.DIAL_RESPONSE;
		wire.DialResponseWire r;
		if (ok)
		{
			r.status = cast(uint) wire.ResponseStatus.OK;
			r.addr = addr.encode;
		}
		else
		{
			final switch (error)
			{
			case ResponseError.dialError:
				r.status = cast(uint) wire.ResponseStatus.E_DIAL_ERROR;
				break;
			case ResponseError.dialRefused:
				r.status = cast(uint) wire.ResponseStatus.E_DIAL_REFUSED;
				break;
			case ResponseError.badRequest:
				r.status = cast(uint) wire.ResponseStatus.E_BAD_REQUEST;
				break;
			case ResponseError.internalError:
				r.status = cast(uint) wire.ResponseStatus.E_INTERNAL_ERROR;
				break;
			}
			r.statusText = statusText;
		}
		m.dialResponse = r;
		return m.encode;
	}

	static DialResponse decode(const(ubyte)[] bytes)
	{
		auto m = wire.Message.decode(bytes);
		enforce(!m.type.isNull && m.type.get == wire.MessageType.DIAL_RESPONSE, "autonat: not a DIAL_RESPONSE");
		enforce(!m.dialResponse.isNull, "autonat: empty DIAL_RESPONSE");
		auto r = m.dialResponse.get;
		DialResponse out_;
		immutable status = r.status.isNull ? wire.ResponseStatus.OK : cast(wire.ResponseStatus) r.status.get;
		out_.statusText = r.statusText;
		switch (status)
		{
		case wire.ResponseStatus.OK:
			out_.ok = true;
			if (r.addr.length > 0)
				out_.addr = Multiaddr.decode(r.addr);
			break;
		case wire.ResponseStatus.E_DIAL_ERROR:
			out_.error = ResponseError.dialError;
			break;
		case wire.ResponseStatus.E_DIAL_REFUSED:
			out_.error = ResponseError.dialRefused;
			break;
		case wire.ResponseStatus.E_BAD_REQUEST:
			out_.error = ResponseError.badRequest;
			break;
		default:
			out_.error = ResponseError.internalError;
			break;
		}
		return out_;
	}
}

// --- what a client concludes ------------------------------------------------------------------

enum NatKind
{
	unknown,
	publicNat,
	privateNat,
}

struct NatStatus
{
	NatKind kind;
	Multiaddr addr; /// for public: the address seen from outside

	static NatStatus makePublic(Multiaddr addr)
	{
		return NatStatus(NatKind.publicNat, addr);
	}

	static NatStatus makePrivate()
	{
		return NatStatus(NatKind.privateNat);
	}

	bool isPublic() const @safe pure nothrow
	{
		return kind == NatKind.publicNat;
	}

	/// OK → public at the address; a dial error → private; anything else says nothing.
	static NatStatus fromResponse(DialResponse r)
	{
		if (r.ok)
			return makePublic(r.addr);
		if (r.error == ResponseError.dialError)
			return makePrivate();
		return NatStatus.init;
	}
}

struct NatState
{
	NatStatus status;
	size_t confidence;
	enum size_t confidenceMax = 3;

	/// Fold a probe result in. Returns true if the status flipped; `old` is what
	/// it was.
	bool handleReported(NatStatus reported, out NatStatus old)
	{
		old = status;
		if (reported.kind == NatKind.unknown)
			return false;
		if (reported.kind == status.kind)
		{
			if (reported.kind == NatKind.publicNat && reported.addr != status.addr)
			{
				status.addr = reported.addr; // a different public address is still public: not a flip
				return false;
			}
			if (confidence < confidenceMax)
				confidence++;
			return false;
		}
		if (status.kind != NatKind.unknown && confidence > 0)
		{
			confidence--;
			return false;
		}
		status = reported;
		confidence = 0;
		return true;
	}
}

// --- what a server will dial -----------------------------------------------------------------

/// The addresses of `demanded` worth dialing back for `peer`, with every IP
/// replaced by the one in `observed`: relayed addresses and ones naming another
/// peer are dropped, and `/p2p/<peer>` is appended where missing.
Multiaddr[] filterValidAddrs(PeerId peer, const(Multiaddr)[] demanded, Multiaddr observed)
{
	Component[] obs = observed.components;
	immutable ipIdx = obs.countUntil!(c => c.name == "ip4" || c.name == "ip6");
	if (ipIdx < 0)
		return null;
	auto observedIp = obs[ipIdx];

	Multiaddr[] out_;
	foreach (a; demanded)
	{
		auto comps = a.components;
		if (comps.canFind!(c => c.name == "p2p-circuit"))
			continue;
		bool bad;
		Multiaddr rebuilt;
		bool named;
		foreach (c; comps)
		{
			if (c.name == "ip4" || c.name == "ip6")
			{
				rebuilt = rebuilt ~ one(observedIp);
				continue;
			}
			if (c.name == "p2p")
			{
				PeerId who;
				try
					who = PeerId.fromBytes(c.value);
				catch (Exception)
				{
					bad = true;
					break;
				}
				if (who != peer)
				{
					bad = true;
					break;
				}
				named = true;
			}
			rebuilt = rebuilt ~ one(c);
		}
		if (bad)
			continue;
		if (!named)
			rebuilt = rebuilt ~ Multiaddr.parse("/p2p/" ~ peer.toBase58);
		if (!out_.canFind(rebuilt))
			out_ ~= rebuilt;
	}
	return out_;
}

private Multiaddr one(Component c)
{
	return Multiaddr.parse("/" ~ c.name ~ (c.protocol.size != 0 ? "/" ~ c.text : ""));
}

struct Resolved
{
	bool ok;
	ResponseError error;
	Multiaddr[] addrs;
}

/// Decide what a DIAL from `from` (seen at `observed`) asks us to do.
Resolved resolveInboundRequest(PeerId from, DialRequest req, Multiaddr observed)
{
	if (req.peerId != from)
		return Resolved(false, ResponseError.badRequest);
	auto addrs = filterValidAddrs(from, req.addresses, observed);
	if (addrs.length == 0)
		return Resolved(false, ResponseError.dialRefused);
	return Resolved(true, ResponseError.init, addrs);
}

/// At most `peerMax` requests per peer and `globalMax` in all, per rolling `period`.
struct AutoNatThrottle
{
	size_t peerMax = 3;
	size_t globalMax = 30;
	Duration period = 1.seconds;
	private MonoTime[][PeerId] byPeer;
	private MonoTime[] all;

	/// Null if allowed (and counted); otherwise the reason.
	string check(PeerId peer, MonoTime now)
	{
		all = expire(all, now);
		auto mine = expire(byPeer.get(peer, null), now);
		if (mine.length >= peerMax)
		{
			byPeer[peer] = mine;
			return "too many dials for peer";
		}
		if (all.length >= globalMax)
		{
			byPeer[peer] = mine;
			return "too many total dials";
		}
		mine ~= now;
		all ~= now;
		byPeer[peer] = mine;
		return null;
	}

	private MonoTime[] expire(MonoTime[] list, MonoTime now)
	{
		size_t keep;
		while (keep < list.length && now - list[keep] >= period)
			keep++;
		return list[keep .. $];
	}
}

/// One dial-back per peer at a time.
struct OngoingDials
{
	private bool[PeerId] active_;

	bool active(PeerId peer) const
	{
		return (peer in active_) !is null;
	}

	void start(PeerId peer)
	{
		active_[peer] = true;
	}

	void finish(PeerId peer)
	{
		active_.remove(peer);
	}
}

// --- the service -------------------------------------------------------------------------

struct AutoNatConfig
{
	Duration dialTimeout = 15.seconds;
	AutoNatThrottle throttle;
}

final class AutoNat
{
	private Host host;
	private AutoNatConfig cfg;
	private OngoingDials ongoing;
	NatState state;

	/// Called when the client's view of itself flips.
	void delegate(NatStatus old, NatStatus now) onStatusChanged;

	this(Host host, AutoNatConfig cfg = AutoNatConfig.init)
	{
		this.host = host;
		this.cfg = cfg;
		host.setStreamHandler(autonatProtocol, &serve);
	}

	void close() nothrow
	{
		try
			host.removeStreamHandler(autonatProtocol);
		catch (Exception)
		{
		}
	}

	/// Ask the server at `server` to dial us back at `ourAddrs`. Returns what
	/// it found, and folds it into `state`.
	NatStatus probe(Multiaddr server, const(Multiaddr)[] ourAddrs)
	{
		auto c = host.swarm.dial(server);
		auto s = c.newStream(autonatProtocol);
		scope (exit)
			s.close();
		DialRequest req;
		req.peerId = host.id;
		foreach (a; ourAddrs)
			req.addresses ~= Multiaddr(a.bytes.dup);
		s.writeLengthPrefixed(req.encode);
		auto resp = DialResponse.decode(s.readLengthPrefixed(maxAutonatMessage));
		auto status = NatStatus.fromResponse(resp);
		NatStatus old;
		if (state.handleReported(status, old) && onStatusChanged !is null)
			onStatusChanged(old, state.status);
		return status;
	}

	/// The same, to a peer we already know.
	NatStatus probe(PeerId server, const(Multiaddr)[] ourAddrs)
	{
		auto c = host.connect(server);
		auto s = c.newStream(autonatProtocol);
		scope (exit)
			s.close();
		DialRequest req;
		req.peerId = host.id;
		foreach (a; ourAddrs)
			req.addresses ~= Multiaddr(a.bytes.dup);
		s.writeLengthPrefixed(req.encode);
		auto resp = DialResponse.decode(s.readLengthPrefixed(maxAutonatMessage));
		auto status = NatStatus.fromResponse(resp);
		NatStatus old;
		if (state.handleReported(status, old) && onStatusChanged !is null)
			onStatusChanged(old, state.status);
		return status;
	}

	private void serve(Stream s, Connection c, string)
	{
		scope (exit)
			s.close();
		auto peer = c.remotePeer;
		DialRequest req;
		try
			req = DialRequest.decode(s.readLengthPrefixed(maxAutonatMessage));
		catch (Exception e)
		{
			s.writeLengthPrefixed(DialResponse(false, Multiaddr.init, ResponseError.badRequest, e.msg).encode);
			return;
		}
		if (auto why = cfg.throttle.check(peer, MonoTime.currTime))
		{
			s.writeLengthPrefixed(DialResponse(false, Multiaddr.init, ResponseError.dialRefused, why).encode);
			return;
		}
		if (ongoing.active(peer))
		{
			s.writeLengthPrefixed(DialResponse(false, Multiaddr.init, ResponseError.dialRefused, "dial-back in progress").encode);
			return;
		}
		auto resolved = resolveInboundRequest(peer, req, c.remoteAddr);
		if (!resolved.ok)
		{
			s.writeLengthPrefixed(DialResponse(false, Multiaddr.init, resolved.error, "").encode);
			return;
		}

		ongoing.start(peer);
		scope (exit)
			ongoing.finish(peer);
		DialResponse resp;
		resp.ok = false;
		resp.error = ResponseError.dialError;
		foreach (addr; resolved.addrs)
		{
			try
			{
				// A fresh dial, never the connection the request came over: that
				// is the whole question being asked.
				auto back = host.swarm.dial(addr);
				back.close();
				resp = DialResponse(true, addr);
				break;
			}
			catch (Exception e)
			{
				resp.statusText = e.msg;
			}
		}
		s.writeLengthPrefixed(resp.encode);
	}
}
