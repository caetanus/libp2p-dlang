module tests.transport.webrtc.fingerprint_test;

import std.digest : toHexString;
import libp2p.transport.webrtc.fingerprint;
import libp2p.multiformats.multihash : Multihash;
import fluent.asserts;

// The parity vectors from rust `fingerprint.rs`'s tests.
private enum SDP_FORMAT = "7D:E3:D8:3F:81:A6:80:59:2A:47:1E:6B:6A:BB:07:47:AB:D3:53:85:A8:09:3F:DF:E1:12:C1:EE:BB:6C:C6:AC";
private enum ubyte[32] REGULAR_FORMAT = [
	0x7D, 0xE3, 0xD8, 0x3F, 0x81, 0xA6, 0x80, 0x59, 0x2A, 0x47, 0x1E, 0x6B, 0x6A, 0xBB, 0x07, 0x47,
	0xAB, 0xD3, 0x53, 0x85, 0xA8, 0x09, 0x3F, 0xDF, 0xE1, 0x12, 0xC1, 0xEE, 0xBB, 0x6C, 0xC6, 0xAC];

@("fingerprint sdp_format is uppercase hex colon-separated (rust parity)")
unittest
{
	auto fp = Fingerprint.raw(REGULAR_FORMAT);
	fp.toSdpFormat.should.equal(SDP_FORMAT);
}

@("fingerprint from_sdp round-trips the raw digest (rust parity)")
unittest
{
	// Rebuild the digest from the colon-stripped SDP hex, exactly as rust's test.
	ubyte[32] bytes;
	size_t bi;
	string hex;
	foreach (c; SDP_FORMAT)
		if (c != ':')
			hex ~= c;
	for (size_t i = 0; i < hex.length; i += 2)
	{
		import std.conv : to;

		bytes[bi++] = hex[i .. i + 2].to!ubyte(16);
	}
	Fingerprint.raw(bytes).should.equal(Fingerprint.raw(REGULAR_FORMAT));
}

@("fingerprint from_certificate hashes with SHA-256")
unittest
{
	// SHA-256("abc") — the canonical RFC 6234 vector.
	auto fp = Fingerprint.fromCertificate(cast(ubyte[]) "abc");
	ubyte[32] d = fp.digest;
	d[].toHexString.should.equal(
		"BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD");
	fp.algorithm.should.equal("sha-256");
}

@("fingerprint <-> multihash round-trips, and rejects non-SHA256/wrong length")
unittest
{
	auto fp = Fingerprint.raw(REGULAR_FORMAT);
	auto mh = fp.toMultihash;
	mh.code.should.equal(0x12);
	mh.digest.length.should.equal(32);

	auto back = Fingerprint.tryFromMultihash(mh);
	back.isNull.should.equal(false);
	back.get.should.equal(fp);

	// Wrong code → None.
	Fingerprint.tryFromMultihash(Multihash(0x00, mh.digest)).isNull.should.equal(true);
	// Wrong length → None.
	Fingerprint.tryFromMultihash(Multihash(0x12, mh.digest[0 .. 16])).isNull.should.equal(true);
}

@("fingerprint FF is 32 bytes of 0xFF")
unittest
{
	ubyte[32] ff = Fingerprint.FF.digest;
	ff[].should.equal(
		cast(ubyte[])[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
}
