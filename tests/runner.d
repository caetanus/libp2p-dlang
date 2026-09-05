/// unit-threaded entry point. Test modules are listed explicitly so the
/// reflection stays fast and the build stays deterministic. A test module
/// imports `fluent.asserts` only — never `unit_threaded`, whose `should`
/// collides with it.
import unit_threaded;
import std.concurrency : scheduler;

int main(string[] args)
{
	// vibe-core installs its own std.concurrency Scheduler in a module ctor.
	// unit-threaded serialises output through a std.concurrency thread that,
	// under vibe's scheduler, parks in the event loop and is never woken. Hand
	// std.concurrency back its default scheduler; vibe's own task scheduler and
	// eventcore driver are untouched, so tests still drive the loop explicitly.
	scheduler = null;

	return args.runTests!(
		"tests.harness_test",
		"tests.core.ending_test",
		"tests.util.select_test",
		"tests.multiformats.varint_test",
		"tests.multiformats.base58_test",
		"tests.multiformats.multihash_test",
		"tests.multiformats.multibase_test",
		"tests.multiformats.multiaddr_test",
		"tests.crypto.keys_test",
		"tests.crypto.keytypes_test",
		"tests.core.peer_id_test",
		"tests.transport.tcp_test",
		"tests.multistream.select_test",
		"tests.security.noise_test",
		"tests.muxer.yamux_test",
		"tests.swarm.swarm_test",
	);
}
