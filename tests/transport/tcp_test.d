/**
 * TCP over loopback, inside the test binary. Beyond the bytes, what these pin
 * is the ending contract: a peer closing is `EndOfStream`, a listener closing
 * wakes `accept` with `ConnClosed`, and a fiber parked in `read` can be
 * interrupted. The leak gate proves that closing leaves no descriptor behind.
 */
module tests.transport.tcp_test;

import core.time : msecs;
import vibe.core.core : sleep;

import fluent.asserts;

import libp2p.core.ending;
import libp2p.core.stream;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.transport.tcp : TcpTransport;
import libp2p.transport.transport;
import tests.util.loop;

private enum loopback = "/ip4/127.0.0.1/tcp/0";

@("tcp: dial and accept exchange bytes in both directions, and a close is an EndOfStream")
unittest
{
	string gotAtServer, gotAtClient;
	bool serverSawEnd;
	Multiaddr bound;

	onLoop({
		auto t = new TcpTransport;
		auto l = t.listen(Multiaddr.parse(loopback));
		scope (exit)
			l.close();
		bound = l.address;

		auto server = spawn({
			auto c = l.accept();
			scope (exit)
				c.close();
			auto buf = new ubyte[64];
			auto n = c.read(buf);
			gotAtServer = cast(string) buf[0 .. n].idup;
			c.write(cast(const(ubyte)[]) "world");
			try
				c.read(buf);
			catch (EndOfStream)
				serverSawEnd = true;
		});

		auto c = t.dial(bound);
		c.write(cast(const(ubyte)[]) "hello");
		auto buf = new ubyte[64];
		auto n = c.read(buf);
		gotAtClient = cast(string) buf[0 .. n].idup;
		c.close();
		server.join();
	});

	gotAtServer.should.equal("hello");
	gotAtClient.should.equal("world");
	serverSawEnd.should.equal(true);
	bound.toString.should.not.equal(loopback); // a real port was assigned
}

@("tcp: closing the listener wakes a parked accept with ConnClosed")
unittest
{
	bool threw;
	onLoop({
		auto l = (new TcpTransport).listen(Multiaddr.parse(loopback));
		auto acceptor = spawn({
			try
				l.accept();
			catch (ConnClosed)
				threw = true;
		});
		sleep(10.msecs); // let it park
		l.close();
		acceptor.join();
	});
	threw.should.equal(true);
}

@("tcp: a fiber parked in read can be interrupted and unwinds through its cleanup")
unittest
{
	bool cleanedUp, interrupted;
	onLoop({
		auto t = new TcpTransport;
		auto l = t.listen(Multiaddr.parse(loopback));
		scope (exit)
			l.close();

		RawConn serverSide;
		auto server = spawn({ serverSide = l.accept(); });
		auto c = t.dial(l.address);
		server.join();

		auto reader = spawn({
			scope (exit)
				cleanedUp = true;
			auto buf = new ubyte[16];
			c.read(buf); // nothing will ever arrive
		});
		sleep(10.msecs);
		reader.interrupt();
		reader.join();
		interrupted = reader.interrupted;

		c.close();
		serverSide.close();
	});
	cleanedUp.should.equal(true);
	interrupted.should.equal(true);
}

@("tcp: dialing a port nobody listens on throws")
unittest
{
	bool threw;
	onLoop({
		auto t = new TcpTransport;
		auto l = t.listen(Multiaddr.parse(loopback));
		auto addr = l.address;
		l.close(); // now nobody is there
		try
			t.dial(addr);
		catch (Exception)
			threw = true;
	});
	threw.should.equal(true);
}

@("tcp: the stream helpers frame a varint-prefixed message")
unittest
{
	ubyte[] got;
	onLoop({
		auto t = new TcpTransport;
		auto l = t.listen(Multiaddr.parse(loopback));
		scope (exit)
			l.close();
		auto server = spawn({
			auto c = l.accept();
			scope (exit)
				c.close();
			got = c.readLengthPrefixed(1024);
		});
		auto c = t.dial(l.address);
		auto payload = new ubyte[300];
		foreach (i, ref b; payload)
			b = cast(ubyte) i;
		c.writeLengthPrefixed(payload);
		c.close();
		server.join();
	});
	got.length.should.equal(300);
	got[299].should.equal(cast(ubyte) 43);
}
