module tests.protocol.fileshare_test;

import libp2p.protocol.fileshare : sendFile, receiveFile, FileTransfer, fileshareProtocol;
import libp2p.muxer.mplex : Mplex;
import libp2p.core.stream : ByteStream;
import libp2p.multistream.select : negotiateDialer, negotiateListener;
import tests.util.fiberpipe : runPair;
import std.digest.sha : sha256Of;
import fluent.asserts;

@("file transfer round-trips name and contents")
unittest
{
	ubyte[] payload = cast(ubyte[]) "the quick brown fox".dup;
	FileTransfer got;
	runPair(
		(ByteStream s) { sendFile(s, "fox.txt", payload); },
		(ByteStream s) { got = receiveFile(s); });
	got.name.should.equal("fox.txt");
	got.data.should.equal(payload);
}

@("file transfer streams a payload larger than one chunk")
unittest
{
	// 200 KB deterministic pattern spans several 64 KB chunks.
	auto payload = new ubyte[200_000];
	foreach (i, ref b; payload)
		b = cast(ubyte)(i * 7 + 3);

	FileTransfer got;
	runPair(
		(ByteStream s) { sendFile(s, "big.bin", payload); },
		(ByteStream s) { got = receiveFile(s); });
	// NOTE: compare via length + SHA-256, NOT `got.data.should.equal(payload)` —
	// fluent-asserts' array-equality builds a HeapEquable element-by-element and
	// is O(n²), which livelocks on a 200 KB array (found via gdb: a worker thread
	// burning CPU in copyHeapEquableArray). Hashing keeps the check O(n).
	got.data.length.should.equal(payload.length);
	sha256Of(got.data).should.equal(sha256Of(payload));
}

@("full stack: mplex + multistream + file transfer")
unittest
{
	ubyte[] payload = cast(ubyte[]) "hello over mplex".dup;
	FileTransfer got;
	string served;
	runPair(
		(ByteStream c) {
		auto m = new Mplex(c, true);
		auto s = m.openStream();
		negotiateDialer(s, [fileshareProtocol]);
		sendFile(s, "note.txt", payload);
	},
		(ByteStream c) {
		auto m = new Mplex(c, false);
		auto s = m.acceptStream();
		served = negotiateListener(s, [fileshareProtocol]);
		got = receiveFile(s);
	});
	served.should.equal(fileshareProtocol);
	got.name.should.equal("note.txt");
	got.data.should.equal(payload);
}
