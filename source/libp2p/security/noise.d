/**
 * Noise `XX_25519_ChaChaPoly_SHA256` with the libp2p handshake payload,
 * entirely on libsodium.
 *
 * Three handshake messages, each `u16be length || body`:
 *
 *   → e
 *   ← e, ee, s, es   + payload: responder's identity key and its signature
 *   → s, se          + payload: initiator's identity key and its signature
 *
 * The payload binds the libp2p identity to the Noise static key: the signature
 * is over `"noise-libp2p-static-key:" || static_public`. After the handshake
 * the stream carries `u16be length || ciphertext` frames of at most 65535
 * bytes, so 65519 bytes of plaintext each.
 */
module libp2p.security.noise;

import std.algorithm.comparison : min;
import std.exception : enforce;
import std.typecons : Nullable;

import libsodium.crypto_aead_chacha20poly1305 : crypto_aead_chacha20poly1305_ietf_encrypt,
	crypto_aead_chacha20poly1305_ietf_decrypt;
import libsodium.crypto_auth_hmacsha256 : crypto_auth_hmacsha256;
import libsodium.crypto_hash_sha256 : crypto_hash_sha256;
import libsodium.crypto_scalarmult_curve25519 : crypto_scalarmult_curve25519, crypto_scalarmult_curve25519_base;
import libsodium.randombytes : randombytes_buf;

import libp2p.core.ending;
import libp2p.core.peer_id : PeerId;
import libp2p.core.stream;
import libp2p.crypto.keys : Keypair, PublicKey;
import libp2p.security.security;
import libp2p.wire.protobuf;

enum noiseProtocolId = "/noise";

final class NoiseTransport : SecureTransport
{
	private Keypair identity;

	this(Keypair identity)
	{
		this.identity = identity;
	}

	string protocolId()
	{
		return noiseProtocolId;
	}

	SecureConn secureOutbound(Stream raw, Nullable!PeerId expected)
	{
		return noiseInitiator(raw, identity, expected);
	}

	SecureConn secureInbound(Stream raw)
	{
		return noiseResponder(raw, identity);
	}
}

SecureConn noiseInitiator(Stream raw, Keypair identity, Nullable!PeerId expected = Nullable!PeerId.init)
{
	auto hs = Handshake(true, identity);

	// → e
	raw.writeFrame(hs.writeMessage([]));

	// ← e, ee, s, es
	auto payload = hs.readMessage(raw.readFrame());
	auto remote = hs.verifyPayload(payload);

	// → s, se
	raw.writeFrame(hs.writeMessage(hs.ownPayload()));

	auto peer = PeerId.fromPublicKey(remote);
	if (!expected.isNull)
		enforce(expected.get == peer, "noise: the peer is " ~ peer.toString ~ ", not " ~ expected.get.toString);
	return hs.finish(raw, remote);
}

SecureConn noiseResponder(Stream raw, Keypair identity)
{
	auto hs = Handshake(false, identity);

	// → e
	cast(void) hs.readMessage(raw.readFrame());

	// ← e, ee, s, es
	raw.writeFrame(hs.writeMessage(hs.ownPayload()));

	// → s, se
	auto payload = hs.readMessage(raw.readFrame());
	auto remote = hs.verifyPayload(payload);

	return hs.finish(raw, remote);
}

/**
 * The XX handshake alone, with a prologue, returning who the peer is. For
 * transports that are already encrypted (webrtc-direct: DTLS) and use Noise
 * only to prove identity.
 */
PublicKey noiseAuthenticate(Stream raw, Keypair identity, bool initiator, const(ubyte)[] prologue)
{
	auto hs = Handshake(initiator, identity, prologue);
	if (initiator)
	{
		raw.writeFrame(hs.writeMessage([]));
		auto remote = hs.verifyPayload(hs.readMessage(raw.readFrame()));
		raw.writeFrame(hs.writeMessage(hs.ownPayload()));
		return remote;
	}
	cast(void) hs.readMessage(raw.readFrame());
	raw.writeFrame(hs.writeMessage(hs.ownPayload()));
	return hs.verifyPayload(hs.readMessage(raw.readFrame()));
}

// --- framing ------------------------------------------------------------------

private enum maxFrame = 65_535;
private enum tagLength = 16;
private enum maxPlaintext = maxFrame - tagLength;

private void writeFrame(Stream s, const(ubyte)[] body_)
{
	enforce(body_.length <= maxFrame, "noise: frame too large");
	auto out_ = new ubyte[2 + body_.length];
	out_[0] = cast(ubyte)(body_.length >> 8);
	out_[1] = cast(ubyte)(body_.length & 0xff);
	out_[2 .. $] = body_;
	s.write(out_);
}

private ubyte[] readFrame(Stream s)
{
	ubyte[2] len;
	s.readExact(len[]);
	version (Libp2pReadTrace)
	{
		import core.stdc.stdio : fprintf, stderr;
		fprintf(stderr, "READTRACE noise frame len=%u\n", cast(uint)((len[0] << 8) | len[1]));
	}
	auto body_ = new ubyte[(len[0] << 8) | len[1]];
	s.readExact(body_);
	return body_;
}

// --- the secured stream -------------------------------------------------------

private final class NoiseConn : SecureConn
{
	private Stream raw;
	private CipherState send, recv;
	private PublicKey remoteKey_;
	private PeerId remotePeer_;
	private ubyte[] pending; // decrypted, not yet read
	private bool closed;

	private this(Stream raw, CipherState send, CipherState recv, PublicKey remote)
	{
		this.raw = raw;
		this.send = send;
		this.recv = recv;
		this.remoteKey_ = remote;
		this.remotePeer_ = PeerId.fromPublicKey(remote);
	}

	size_t read(ubyte[] buf)
	{
		if (buf.length == 0)
			return 0;
		while (pending.length == 0)
		{
			if (closed)
				throw new ConnClosed("noise: closed locally");
			auto frame = raw.readFrame();
			pending = recv.decrypt([], frame);
		}
		immutable n = min(buf.length, pending.length);
		buf[0 .. n] = pending[0 .. n];
		pending = pending[n .. $];
		return n;
	}

	void write(const(ubyte)[] data)
	{
		if (closed)
			throw new ConnClosed("noise: closed locally");
		while (data.length > 0)
		{
			immutable n = min(data.length, maxPlaintext);
			raw.writeFrame(send.encrypt([], data[0 .. n]));
			data = data[n .. $];
		}
	}

	void close() nothrow
	{
		if (closed)
			return;
		closed = true;
		raw.close();
	}

	void reset() nothrow
	{
		if (closed)
			return;
		closed = true;
		raw.reset();
	}

	PeerId remotePeer()
	{
		return remotePeer_;
	}

	PublicKey remoteKey()
	{
		return remoteKey_;
	}
}

// --- the libp2p payload -------------------------------------------------------

private struct HandshakePayload
{
	@field(1) ubyte[] identityKey;
	@field(2) ubyte[] identitySig;
}

private enum signaturePrefix = "noise-libp2p-static-key:";

// --- Noise state --------------------------------------------------------------

private enum hashLength = 32;
private enum keyLength = 32;

private struct CipherState
{
	ubyte[keyLength] k;
	bool hasKey;
	ulong n;

	void initializeKey(const(ubyte)[] key)
	{
		k[] = key[0 .. keyLength];
		hasKey = true;
		n = 0;
	}

	ubyte[] encrypt(const(ubyte)[] ad, const(ubyte)[] plaintext)
	{
		if (!hasKey)
			return plaintext.dup;
		enforce(n != ulong.max, "noise: nonce exhausted");
		auto out_ = new ubyte[plaintext.length + tagLength];
		ulong outLen;
		immutable nonce = nonceBytes(n++);
		immutable rc = crypto_aead_chacha20poly1305_ietf_encrypt(out_.ptr, &outLen,
			plaintext.ptr, plaintext.length, ad.ptr, ad.length, null, nonce.ptr, k.ptr);
		enforce(rc == 0, "noise: encryption failed");
		return out_[0 .. cast(size_t) outLen];
	}

	ubyte[] decrypt(const(ubyte)[] ad, const(ubyte)[] ciphertext)
	{
		if (!hasKey)
			return ciphertext.dup;
		enforce(ciphertext.length >= tagLength, "noise: ciphertext shorter than its tag");
		enforce(n != ulong.max, "noise: nonce exhausted");
		auto out_ = new ubyte[ciphertext.length - tagLength];
		ulong outLen;
		immutable nonce = nonceBytes(n++);
		immutable rc = crypto_aead_chacha20poly1305_ietf_decrypt(out_.ptr, &outLen, null,
			ciphertext.ptr, ciphertext.length, ad.ptr, ad.length, nonce.ptr, k.ptr);
		enforce(rc == 0, "noise: decryption failed (bad tag)");
		return out_[0 .. cast(size_t) outLen];
	}

	private static ubyte[12] nonceBytes(ulong n) @safe pure nothrow @nogc
	{
		ubyte[12] out_;
		foreach (i; 0 .. 8)
			out_[4 + i] = cast(ubyte)(n >> (8 * i)); // little-endian, after 4 zero bytes
		return out_;
	}
}

private struct SymmetricState
{
	CipherState cipher;
	ubyte[hashLength] ck, h;

	void initialize(string protocolName)
	{
		if (protocolName.length <= hashLength)
		{
			h[] = 0;
			h[0 .. protocolName.length] = cast(const(ubyte)[]) protocolName;
		}
		else
			h = sha256(cast(const(ubyte)[]) protocolName);
		ck = h;
	}

	void mixKey(const(ubyte)[] input)
	{
		ubyte[hashLength] tempK;
		hkdf(ck, input, ck, tempK);
		cipher.initializeKey(tempK[]);
	}

	void mixHash(const(ubyte)[] data)
	{
		h = sha256(h[] ~ data);
	}

	ubyte[] encryptAndHash(const(ubyte)[] plaintext)
	{
		auto c = cipher.encrypt(h[], plaintext);
		mixHash(c);
		return c;
	}

	ubyte[] decryptAndHash(const(ubyte)[] ciphertext)
	{
		auto p = cipher.decrypt(h[], ciphertext);
		mixHash(ciphertext);
		return p;
	}

	void split(out CipherState c1, out CipherState c2)
	{
		ubyte[hashLength] k1, k2;
		k1[] = 0;
		k2[] = 0;
		hkdf(ck, [], k1, k2);
		c1.initializeKey(k1[]);
		c2.initializeKey(k2[]);
	}
}

private struct X25519
{
	ubyte[32] secret, pub;

	static X25519 generate() @trusted
	{
		X25519 k;
		randombytes_buf(k.secret.ptr, k.secret.length);
		crypto_scalarmult_curve25519_base(k.pub.ptr, k.secret.ptr);
		return k;
	}

	ubyte[32] dh(const(ubyte)[] theirPub) const @trusted
	{
		ubyte[32] out_;
		immutable rc = crypto_scalarmult_curve25519(out_.ptr, secret.ptr, theirPub.ptr);
		enforce(rc == 0, "noise: invalid public key");
		return out_;
	}
}

package struct Handshake
{
	bool initiator;
	Keypair identity;
	SymmetricState ss;
	X25519 e, s;
	ubyte[32] re, rs;
	bool haveRs;
	int step; // which message is next: 0, 1, 2

	this(bool initiator, Keypair identity, const(ubyte)[] prologue = null)
	{
		this.initiator = initiator;
		this.identity = identity;
		ss.initialize("Noise_XX_25519_ChaChaPoly_SHA256");
		ss.mixHash(prologue); // empty for libp2p noise; webrtc binds both fingerprints here
		s = X25519.generate();
	}

	/// The handshake message this side sends next, carrying `payload`.
	ubyte[] writeMessage(const(ubyte)[] payload)
	{
		ubyte[] out_;
		final switch (step++)
		{
		case 0: // → e
			e = X25519.generate();
			out_ ~= e.pub;
			ss.mixHash(e.pub);
			break;
		case 1: // ← e, ee, s, es
			e = X25519.generate();
			out_ ~= e.pub;
			ss.mixHash(e.pub);
			ss.mixKey(e.dh(re));
			out_ ~= ss.encryptAndHash(s.pub);
			ss.mixKey(s.dh(re)); // es as the responder
			break;
		case 2: // → s, se
			out_ ~= ss.encryptAndHash(s.pub);
			ss.mixKey(s.dh(re)); // se as the initiator
			break;
		}
		out_ ~= ss.encryptAndHash(payload);
		return out_;
	}

	/// Consume the peer's handshake message, returning its payload.
	ubyte[] readMessage(const(ubyte)[] msg)
	{
		final switch (step++)
		{
		case 0: // → e
			enforce(msg.length >= 32, "noise: message 1 too short");
			re[] = msg[0 .. 32];
			ss.mixHash(re);
			msg = msg[32 .. $];
			break;
		case 1: // ← e, ee, s, es
			enforce(msg.length >= 32 + 32 + tagLength, "noise: message 2 too short");
			re[] = msg[0 .. 32];
			ss.mixHash(re);
			msg = msg[32 .. $];
			ss.mixKey(e.dh(re));
			rs[] = ss.decryptAndHash(msg[0 .. 32 + tagLength]);
			haveRs = true;
			msg = msg[32 + tagLength .. $];
			ss.mixKey(e.dh(rs)); // es as the initiator
			break;
		case 2: // → s, se
			enforce(msg.length >= 32 + tagLength, "noise: message 3 too short");
			rs[] = ss.decryptAndHash(msg[0 .. 32 + tagLength]);
			haveRs = true;
			msg = msg[32 + tagLength .. $];
			ss.mixKey(e.dh(rs)); // se as the responder
			break;
		}
		return ss.decryptAndHash(msg);
	}

	ubyte[] ownPayload()
	{
		HandshakePayload p;
		p.identityKey = identity.publicKey.toProtobuf;
		p.identitySig = identity.sign(cast(const(ubyte)[]) signaturePrefix ~ s.pub);
		return encode(p);
	}

	/// Check the peer's payload against the static key it just proved it holds.
	PublicKey verifyPayload(const(ubyte)[] payload)
	{
		enforce(haveRs, "noise: no remote static key yet");
		auto p = decode!HandshakePayload(payload);
		auto key = PublicKey.fromProtobuf(p.identityKey);
		enforce(key.verify(cast(const(ubyte)[]) signaturePrefix ~ rs, p.identitySig),
			"noise: the peer's identity signature does not cover its static key");
		return key;
	}

	SecureConn finish(Stream raw, PublicKey remote)
	{
		enforce(step == 3, "noise: handshake incomplete");
		CipherState c1, c2;
		ss.split(c1, c2);
		return initiator ? new NoiseConn(raw, c1, c2, remote) : new NoiseConn(raw, c2, c1, remote);
	}
}

// --- primitives -----------------------------------------------------------------

private ubyte[hashLength] sha256(scope const(ubyte)[] data) @trusted
{
	ubyte[hashLength] out_;
	crypto_hash_sha256(out_.ptr, data.ptr, data.length);
	return out_;
}

private ubyte[hashLength] hmac(scope const(ubyte)[] key, scope const(ubyte)[] data) @trusted
{
	assert(key.length == hashLength);
	ubyte[hashLength] out_;
	crypto_auth_hmacsha256(out_.ptr, data.ptr, data.length, key.ptr);
	return out_;
}

// `ref`, not `out`: a caller passes its chaining key as both the input and the
// first output, and an `out` parameter is zeroed on entry — before the input
// is read. Everything is computed into temporaries first for the same reason.
private void hkdf(const(ubyte)[] chainingKey, const(ubyte)[] ikm, ref ubyte[hashLength] out1,
	ref ubyte[hashLength] out2) @safe
{
	immutable temp = hmac(chainingKey, ikm);
	immutable a = hmac(temp[], [cast(ubyte) 1]);
	immutable b = hmac(temp[], a[] ~ cast(ubyte) 2);
	out1 = a;
	out2 = b;
}
