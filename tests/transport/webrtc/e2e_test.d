/**
 * webrtc-direct between two hosts on loopback: the listener advertises an
 * address carrying its certificate hash, the dialer reaches it with nothing
 * else, ICE, DTLS and SCTP come up, Noise proves both identities, and ping runs
 * on a data channel like on any other connection.
 */
module tests.transport.webrtc.e2e_test;

import core.time : Duration, msecs, seconds, MonoTime;
import std.algorithm.searching : canFind;
import vibe.core.core : sleep;

import fluent.asserts;

import libp2p.core.peer_id : PeerId;
import libp2p.crypto.keys : Keypair;
import libp2p.host.host;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.protocol.ping;
import libp2p.transport.tcp : TcpTransport;
import libp2p.transport.webrtc.transport;
import tests.util.loop;

private struct Node
{
	Host host;
	WebRtcTransport rtc;
}

private Node makeNode()
{
	auto key = Keypair.generateEd25519;
	auto h = new Host(key, [new TcpTransport]);
	auto rtc = new WebRtcTransport(key);
	h.swarm.addCapableTransport(rtc);
	return Node(h, rtc);
}

@("webrtc-direct: a listener's address carries its certhash, and a dialer reaches it")
unittest
{
	Multiaddr advertised;
	bool dialed, listenerSeesDialer, viaWebrtc;
	Duration rtt = Duration.min;
	PeerId got, expected;
	onLoop({
		auto b = makeNode();
		scope (exit)
			b.host.close();
		b.host.listen(Multiaddr.parse("/ip4/127.0.0.1/udp/0/webrtc-direct"));
		new Ping(b.host);
		advertised = b.host.addrs[0];
		expected = b.host.id;

		auto a = makeNode();
		scope (exit)
			a.host.close();

		auto c = a.host.connect(b.host.id, [advertised]);
		dialed = true;
		got = c.remotePeer;
		viaWebrtc = c.remoteAddr.toString.canFind("/webrtc-direct/");

		immutable deadline = MonoTime.currTime + 5.seconds;
		while (!b.host.swarm.isConnected(a.host.id) && MonoTime.currTime < deadline)
			sleep(10.msecs);
		listenerSeesDialer = b.host.swarm.isConnected(a.host.id);

		auto s = c.newStream(pingProtocol);
		scope (exit)
			s.close();
		rtt = ping(s);
	});
	advertised.toString.should.contain("/udp/");
	advertised.toString.should.contain("/webrtc-direct/certhash/u");
	dialed.should.equal(true);
	got.should.equal(expected);
	viaWebrtc.should.equal(true);
	listenerSeesDialer.should.equal(true);
	(rtt >= Duration.zero).should.equal(true);
}

@("webrtc-direct: a dialer that is told the wrong certhash is refused")
unittest
{
	bool refused;
	string why;
	onLoop({
		auto b = makeNode();
		scope (exit)
			b.host.close();
		b.host.listen(Multiaddr.parse("/ip4/127.0.0.1/udp/0/webrtc-direct"));
		auto real_ = b.host.addrs[0].toString;
		// Somebody else's certificate hash, at the right place.
		auto other = new WebRtcTransport(Keypair.generateEd25519);
		import libp2p.multiformats.multibase : multibaseEncode;

		auto forged = Multiaddr.parse(real_[0 .. real_.lastIndexOf("/certhash/")] ~ "/certhash/"
				~ multibaseEncode(other.fingerprint.toMultihash.encode));

		auto a = makeNode();
		scope (exit)
			a.host.close();
		try
			a.host.connect(b.host.id, [forged]);
		catch (Exception e)
		{
			refused = true;
			why = e.msg;
		}
	});
	refused.should.equal(true);
	why.should.contain("certificate");
}

import std.string : lastIndexOf;

// Byte `p` of stream `id`'s bulk payload: the little-endian word index, tagged
// with the stream, so a misplaced run names where it came from.
private ubyte bulkByte(size_t p, ubyte id) pure nothrow @nogc @safe
{
	return cast(ubyte)((cast(uint)(p >> 2) | (cast(uint) id << 28)) >> (8 * (p & 3)));
}

// A sustained bulk push, the shape photo sync puts on a connection: several
// streams at once, each writing back-to-back 16 KiB messages, the reader
// answering every MiB with one byte. Every byte must cross, in bounded time,
// with the writers blocking (never failing) while the SCTP send buffer is full.
// Regression: a writer waiting for room used to spin without yielding once the
// first MiB filled the buffer, so no SACK and no ICE consent answer was ever
// read — the link froze, then died with "ICE failed" 30 s later.
@("webrtc-direct: three concurrent bulk streams each move 20 MiB")
unittest
{
	import core.atomic : atomicLoad, atomicStore;
	import core.stdc.stdio : fflush, fprintf, stderr;
	import core.sys.posix.unistd : _exit;
	import core.thread : Thread;
	import core.time : Duration;
	import libp2p.core.stream : Stream, readExact;
	import libp2p.swarm.connection : Connection;

	enum proto = "/test/bulk/1";
	enum size_t perStream = 20 * 1024 * 1024;
	enum size_t msg = 16 * 1024;
	enum size_t ackEvery = 1024 * 1024;
	enum nStreams = 3;

	size_t[nStreams] received;
	size_t[nStreams] acked;
	Duration took;
	string failure;

	// The time bound is kept by a thread, not a fiber: the failure this guards
	// against is a fiber that never yields, which would starve a fiber watchdog
	// along with everything else on the loop.
	shared bool finished;
	auto guard = new Thread({
		immutable deadline = MonoTime.currTime + 90.seconds;
		while (!atomicLoad(finished))
		{
			if (MonoTime.currTime >= deadline)
			{
				fprintf(stderr, "webrtc bulk: no completion within 90 s: the transfer stalled\n");
				fflush(stderr);
				_exit(1);
			}
			Thread.sleep(100.msecs);
		}
	});
	guard.isDaemon = true;
	guard.start();
	scope (exit)
	{
		atomicStore(finished, true);
		guard.join();
	}

	onLoop({
		auto b = makeNode();
		scope (exit)
			b.host.close();
		b.host.setStreamHandler(proto, (Stream s, Connection, string) {
			scope (failure)
				if (failure.length == 0)
					failure = "bulk: the reader failed";
			ubyte[1] idx;
			s.readExact(idx[]);
			auto buf = new ubyte[64 * 1024];
			size_t got, sinceAck;
			while (got < perStream)
			{
				immutable n = s.read(buf);
				foreach (i; 0 .. n)
					if (buf[i] != bulkByte(got + i, idx[0]))
					{
						import std.format : format;

						failure = format("bulk: stream %s corrupt at byte %s: got %s want %s",
							idx[0], got + i, buf[i], bulkByte(got + i, idx[0]));
						throw new Exception(failure);
					}
				got += n;
				sinceAck += n;
				received[idx[0]] = got;
				while (sinceAck >= ackEvery)
				{
					sinceAck -= ackEvery;
					s.write(cast(ubyte[])[1]);
				}
			}
		});
		b.host.listen(Multiaddr.parse("/ip4/127.0.0.1/udp/0/webrtc-direct"));
		auto a = makeNode();
		scope (exit)
			a.host.close();
		auto c = a.host.connect(b.host.id, [b.host.addrs[0]]);

		immutable start = MonoTime.currTime;
		// One pusher per stream. Made by a function, not inline in the loop: a
		// delegate in a loop body shares the loop's variables across iterations.
		Side pusher(ubyte id, Stream s)
		{
			return spawn({
				// the acks are read by a fiber of their own, as a pusher's would be
				auto ackReader = spawn({
					ubyte[1] one;
					while (acked[id] < perStream / ackEvery)
					{
						s.readExact(one[]);
						acked[id]++;
					}
				});
				s.write([id]);
				auto m = new ubyte[msg];
				for (size_t off = 0; off < perStream; off += msg)
				{
					foreach (i; 0 .. msg)
						m[i] = bulkByte(off + i, id);
					s.write(m);
				}
				ackReader.join();
			});
		}

		Side[] sides;
		foreach (k; 0 .. nStreams)
			sides ~= pusher(cast(ubyte) k, c.newStream(proto));
		foreach (sd; sides)
			sd.join();
		took = MonoTime.currTime - start;
	});
	import std.stdio : stdioErr = stderr;

	stdioErr.writefln("webrtc bulk: %s x %s MiB in %s (received %s, acks %s)", nStreams,
		perStream >> 20, took, received, acked);
	failure.should.equal("");
	foreach (k; 0 .. nStreams)
	{
		received[k].should.equal(perStream);
		acked[k].should.equal(perStream / ackEvery);
	}
}
