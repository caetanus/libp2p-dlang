module tests.security.noise_test;

import libp2p.security.noise;
import libp2p.core.stream;
import libp2p.core.peer_id : PeerId;
import libp2p.crypto.keys : Keypair;
import tests.util.pipe : runPair;
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
		(Stream s) {
		auto sec = noiseInitiator(s, aKp);
		aSawB = sec.remotePeer;
		sec.write(cast(ubyte[]) "secret hello".dup);
		auto buf = new ubyte[12];
		sec.readExact(buf);
		echoed = buf;
	},
		(Stream s) {
		auto sec = noiseResponder(s, bKp);
		bSawA = sec.remotePeer;
		auto buf = new ubyte[12];
		sec.readExact(buf);
		sec.write(buf); // echo it back, encrypted
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
	auto payload = new ubyte[200_000]; // > 3 Noise frames (65519 plaintext each)
	foreach (i, ref b; payload)
		b = cast(ubyte)(i * 17 + 5);

	ubyte[] got;
	runPair(
		(Stream s) {
		auto sec = noiseInitiator(s, aKp);
		sec.write(payload);
	},
		(Stream s) {
		auto sec = noiseResponder(s, bKp);
		auto buf = new ubyte[payload.length];
		sec.readExact(buf);
		got = buf;
	});
	got.length.should.equal(payload.length);
	// Never deep-compare a large array with fluent-asserts (it is quadratic).
	(sha256Of(got) == sha256Of(payload)).should.equal(true);
}

@("the plaintext never appears on the wire")
unittest
{
	// A distinctive marker we can search the raw bytes for.
	auto marker = cast(ubyte[]) "TOPSECRETMARKER".dup;
	auto aKp = Keypair.generateEd25519;
	auto bKp = Keypair.generateEd25519;
	bool leaked;

	// Wrap the responder's raw stream so we can inspect everything it receives.
	runPair(
		(Stream s) {
		auto sec = noiseInitiator(s, aKp);
		sec.write(marker);
	},
		(Stream s) {
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
			(Stream s) {
			auto sec = noiseInitiator(s, aKp);
			sec.write(cast(ubyte[]) "hello".dup);
		},
			(Stream s) {
			// Corrupt one byte well inside the first message (the ephemeral key).
			auto flip = new FlipStream(s, 10);
			noiseResponder(flip, bKp);
		});
	}).should.throwAnyException;
}

@("Noise refuses a peer that is not the one we expected")
unittest
{
	import std.typecons : Nullable, nullable;

	auto aKp = Keypair.generateEd25519;
	auto bKp = Keypair.generateEd25519;
	auto someoneElse = PeerId.fromPublicKey(Keypair.generateEd25519.publicKey);
	bool refused;
	runPair(
		(Stream s) {
		try
			noiseInitiator(s, aKp, nullable(someoneElse));
		catch (Exception)
			refused = true;
	},
		(Stream s) { noiseResponder(s, bKp); });
	refused.should.equal(true);
}

/// A Stream wrapper that flips a single byte at a fixed read offset,
/// simulating an on-the-wire corruption/MITM.
private final class FlipStream : Stream
{
	private Stream inner;
	private size_t offset;
	private size_t flipAt;
	this(Stream inner, size_t flipAt)
	{
		this.inner = inner;
		this.flipAt = flipAt;
	}

	void write(const(ubyte)[] d)
	{
		inner.write(d);
	}

	size_t read(ubyte[] buf)
	{
		immutable n = inner.read(buf);
		foreach (i; 0 .. n)
		{
			if (offset == flipAt)
				buf[i] ^= 0xff;
			offset++;
		}
		return n;
	}

	void close() nothrow
	{
		inner.close();
	}

	void reset() nothrow
	{
		inner.reset();
	}
}

/// A Stream wrapper that records every byte read from the underlying stream.
private final class TapStream : Stream
{
	private Stream inner;
	ubyte[] seen;
	this(Stream inner)
	{
		this.inner = inner;
	}

	void write(const(ubyte)[] d)
	{
		inner.write(d);
	}

	size_t read(ubyte[] buf)
	{
		immutable n = inner.read(buf);
		seen ~= buf[0 .. n];
		return n;
	}

	void close() nothrow
	{
		inner.close();
	}

	void reset() nothrow
	{
		inner.reset();
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
