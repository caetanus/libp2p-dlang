module tests.security.noise_test;

import libp2p.security.noise;
import libp2p.core.stream : ByteStream;
import libp2p.core.peer_id : PeerId;
import libp2p.crypto.keys : Keypair;
import tests.util.fiberpipe : runPair;
import std.digest.sha : sha256Of;
import fluent.asserts;

@("Noise XX authenticates both peers and encrypts a transport message")
unittest
{
	auto aKp = Keypair.generateEd25519;
	auto bKp = Keypair.generateEd25519;
	PeerId aSawB, bSawA;
	ubyte[] echoed;
	runPair(
		(ByteStream s) {
		auto sec = noiseInitiator(s, aKp);
		aSawB = sec.remotePeer;
		sec.writeBytes(cast(ubyte[]) "secret hello".dup);
		auto buf = new ubyte[12];
		sec.readExact(buf);
		echoed = buf;
	},
		(ByteStream s) {
		auto sec = noiseResponder(s, bKp);
		bSawA = sec.remotePeer;
		auto buf = new ubyte[12];
		sec.readExact(buf);
		sec.writeBytes(buf); // echo it back, encrypted
	});
	// Each side learned the OTHER's real libp2p identity from the handshake.
	aSawB.should.equal(PeerId.fromPublicKey(bKp.publicKey));
	bSawA.should.equal(PeerId.fromPublicKey(aKp.publicKey));
	echoed.should.equal(cast(ubyte[]) "secret hello");
}

@("Noise transport round-trips a payload spanning many frames")
unittest
{
	auto aKp = Keypair.generateEd25519;
	auto bKp = Keypair.generateEd25519;
	auto payload = new ubyte[200_000]; // > 3 Noise frames (64511 plaintext each)
	foreach (i, ref b; payload)
		b = cast(ubyte)(i * 17 + 5);

	ubyte[] got;
	runPair(
		(ByteStream s) {
		auto sec = noiseInitiator(s, aKp);
		sec.writeBytes(payload);
		s.close();
	},
		(ByteStream s) {
		auto sec = noiseResponder(s, bKp);
		auto buf = new ubyte[payload.length];
		sec.readExact(buf);
		got = buf;
	});
	got.length.should.equal(payload.length);
	sha256Of(got).should.equal(sha256Of(payload));
}

@("the plaintext never appears on the wire")
unittest
{
	import libp2p.multistream.select : negotiateDialer, negotiateListener;

	// A distinctive marker we can search the raw bytes for.
	auto marker = cast(ubyte[]) "TOPSECRETMARKER".dup;
	auto aKp = Keypair.generateEd25519;
	auto bKp = Keypair.generateEd25519;
	bool leaked;

	// Wrap the responder's raw stream so we can inspect everything it receives.
	runPair(
		(ByteStream s) {
		auto sec = noiseInitiator(s, aKp);
		sec.writeBytes(marker);
		s.close();
	},
		(ByteStream s) {
		auto tap = new TapStream(s);
		auto sec = noiseResponder(tap, bKp);
		auto buf = new ubyte[marker.length];
		sec.readExact(buf);
		// The plaintext marker must NOT be present in the ciphertext bytes seen.
		leaked = containsSub(tap.seen, marker);
	});
	leaked.should.equal(false);
}

// A tampered handshake must be rejected: Noise MACs every handshake message, so
// flipping a single byte of the initiator's first message makes a downstream
// decrypt/verify fail and the handshake throws on both sides.
@("Noise rejects a tampered handshake")
unittest
{
	auto aKp = Keypair.generateEd25519;
	auto bKp = Keypair.generateEd25519;
	({
		runPair(
			(ByteStream s) {
			void safeClose()
			{
				try
					s.close();
				catch (Exception)
				{
				}
			}

			scope (exit)
				safeClose();
			auto sec = noiseInitiator(s, aKp);
			sec.writeBytes(cast(ubyte[]) "hello".dup);
		},
			(ByteStream s) {
			// Corrupt one byte well inside the first message (the ephemeral key).
			auto flip = new FlipStream(s, 10);
			noiseResponder(flip, bKp);
		});
	}).should.throwAnyException;
}

/// A ByteStream wrapper that flips a single byte at a fixed read offset,
/// simulating an on-the-wire corruption/MITM.
private final class FlipStream : ByteStream
{
	private ByteStream inner;
	private size_t offset;
	private size_t flipAt;
	this(ByteStream inner, size_t flipAt)
	{
		this.inner = inner;
		this.flipAt = flipAt;
	}

	void writeBytes(scope const(ubyte)[] d)
	{
		inner.writeBytes(d);
	}

	void readExact(scope ubyte[] buf)
	{
		inner.readExact(buf);
		foreach (ref b; buf)
		{
			if (offset == flipAt)
				b ^= 0xff;
			offset++;
		}
	}

	size_t readAvailable(scope ubyte[] buf)
	{
		immutable n = inner.readAvailable(buf);
		foreach (i; 0 .. n)
		{
			if (offset == flipAt)
				buf[i] ^= 0xff;
			offset++;
		}
		return n;
	}

	void close()
	{
		inner.close();
	}
}

/// A ByteStream wrapper that records every byte read from the underlying stream.
private final class TapStream : ByteStream
{
	private ByteStream inner;
	ubyte[] seen;
	this(ByteStream inner)
	{
		this.inner = inner;
	}

	void writeBytes(scope const(ubyte)[] d)
	{
		inner.writeBytes(d);
	}

	void readExact(scope ubyte[] buf)
	{
		inner.readExact(buf);
		seen ~= buf;
	}

	size_t readAvailable(scope ubyte[] buf)
	{
		immutable n = inner.readAvailable(buf);
		seen ~= buf[0 .. n];
		return n;
	}

	void close()
	{
		inner.close();
	}
}

private bool containsSub(scope const(ubyte)[] hay, scope const(ubyte)[] needle)
{
	if (needle.length == 0 || hay.length < needle.length)
		return false;
	foreach (i; 0 .. hay.length - needle.length + 1)
		if (hay[i .. i + needle.length] == needle)
			return true;
	return false;
}
