/**
 * Our end of the interop wire: a D node that speaks the same line protocol as
 * `interop/rust-peer`, so `interop/run-interop.sh` can drive both against each
 * other in either direction.
 *
 *   LISTEN <multiaddr>/p2p/<peer>   ready, this is where to reach me
 *   CONNECTED <peer>
 *   PING <peer> <micros>            a ping round trip completed
 *   IDENTIFY <peer> <agent>         the peer told us who it is
 *   OK                              both happened
 *   CLOSED <peer>
 *   ERROR <what>                    something went wrong; the exit code says so too
 *
 * Modes: `listen`, `listen-webrtc` (a webrtc-direct address instead of TCP),
 * `dial <multiaddr>` (TCP or webrtc-direct, by the address).
 *
 * Stack: TCP -> multistream-select -> Noise XX -> yamux -> ping / identify, or
 * webrtc-direct -> Noise (identity only) -> data channels -> ping / identify.
 */
module interop.dpeer.app;

import core.time : Duration, msecs, seconds, MonoTime;
import std.stdio : writeln, writefln, stdout;

import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;

import libp2p.core.peer_id : PeerId;
import libp2p.crypto.keys : Keypair;
import libp2p.host.host;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.protocol.identify;
import libp2p.protocol.ping;
import libp2p.transport.tcp : TcpTransport;
import libp2p.transport.webrtc.transport : WebRtcTransport;

private enum deadline = 30.seconds;

private void say(Args...)(string fmt, Args args)
{
	writefln(fmt, args);
	stdout.flush();
}

private final class Reporter : Notifiee
{
	bool gone;

	void connected(Connection c)
	{
		say("CONNECTED %s", c.remotePeer);
	}

	void disconnected(Connection c)
	{
		say("CLOSED %s", c.remotePeer);
		gone = true;
	}
}

int main(string[] args)
{
	immutable mode = args.length > 1 ? args[1] : "listen";
	int rc;
	runTask(() nothrow {
		try
			rc = run(mode, args.length > 2 ? args[2] : null);
		catch (Exception e)
		{
			try
				say("ERROR %s", e.msg);
			catch (Exception)
			{
			}
			rc = 1;
		}
		try
			exitEventLoop();
		catch (Exception)
		{
		}
	});
	runEventLoop();
	return rc;
}

private int run(string mode, string target)
{
	HostConfig cfg;
	cfg.agentVersion = "libp2p-dlang/interop";
	cfg.swarm.idleTimeout = 30.seconds;
	auto key = Keypair.generateEd25519;
	auto host = new Host(key, [new TcpTransport], cfg);
	scope (exit)
		host.close();
	host.swarm.addCapableTransport(new WebRtcTransport(key)); // webrtc-direct beside TCP

	bool pinged, identified;
	PingConfig pc;
	pc.interval = 200.msecs;
	pc.timeout = 5.seconds;
	auto ping = new Ping(host, pc);
	ping.onResult = (PeerId p, Duration rtt) {
		say("PING %s %d", p, rtt.total!"usecs");
		pinged = true;
	};
	ping.onFailure = (PeerId p, Exception e) { say("ERROR ping to %s failed: %s", p, e.msg); };
	auto ident = new IdentifyService(host);
	ident.onIdentified = (IdentifyInfo i) {
		say("IDENTIFY %s %s", i.peer, i.agentVersion);
		identified = true;
	};
	auto reporter = new Reporter;
	host.addNotifiee(reporter);

	immutable until = MonoTime.currTime + deadline;
	bool ok;

	switch (mode)
	{
	case "listen":
	case "listen-webrtc":
		// LISTEN_HOST overrides the bind address (default loopback for the local
		// run-interop.sh; set 0.0.0.0 for cross-network conformance).
		import std.process : environment;

		immutable lh = environment.get("LISTEN_HOST", "127.0.0.1");
		host.listen(Multiaddr.parse(mode == "listen" ? "/ip4/" ~ lh ~ "/tcp/0"
				: "/ip4/" ~ lh ~ "/udp/0/webrtc-direct"));
		say("LISTEN %s/p2p/%s", host.addrs[0], host.id);
		// The peer that dials drives; we stay until it leaves, and report OK as
		// soon as our own half is done.
		while (MonoTime.currTime < until && !reporter.gone)
		{
			if (pinged && identified && !ok)
			{
				say("OK");
				ok = true;
			}
			sleep(20.msecs);
		}
		break;

	case "dial":
		if (target is null)
			throw new Exception("dial needs a multiaddr");
		auto full = Multiaddr.parse(target);
		PeerId peer;
		Multiaddr addr;
		foreach (c; full.components)
		{
			if (c.name == "p2p")
				peer = PeerId.fromBytes(c.value);
			else
				addr = addr ~ Multiaddr.parse("/" ~ c.name ~ (c.protocol.size != 0 ? "/" ~ c.text : ""));
		}
		if (peer.bytes.length == 0)
			throw new Exception("dial needs a /p2p/<peer> component");
		host.connect(peer, [addr]);
		while (MonoTime.currTime < until && !(pinged && identified))
			sleep(20.msecs);
		if (pinged && identified)
		{
			say("OK");
			ok = true;
		}
		break;

	default:
		throw new Exception("unknown mode: " ~ mode);
	}

	if (!ok)
	{
		say("ERROR timed out after %s (pinged=%s, identified=%s)", deadline, pinged, identified);
		return 1;
	}
	return 0;
}
