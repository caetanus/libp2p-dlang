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
		"tests.protocol.ping_test",
		"tests.protocol.identify_test",
		"tests.host.host_test",
		"tests.protocol.kad_key_test",
		"tests.protocol.kad_bucket_test",
		"tests.protocol.kad_table_test",
		"tests.protocol.kad_message_test",
		"tests.protocol.kad_query_test",
		"tests.protocol.kad_store_test",
		"tests.protocol.kad_jobs_test",
		"tests.protocol.kad_node_test",
		"tests.protocol.gossipsub_test",
		"tests.protocol.gossipsub_score_test",
		"tests.protocol.gossipsub_promises_test",
		"tests.protocol.gossipsub_service_test",
		"tests.protocol.relay_test",
		"tests.protocol.dcutr_test",
		"tests.protocol.autonat_test",
		"tests.protocol.relay_service_test",
		"tests.protocol.autonat_service_test",
		"tests.security.plaintext_test",
		"tests.transport.dns_test",
		"tests.transport.dns_cares_test",
		"tests.discovery.mdns_test",
		"tests.discovery.mdns_service_test",
		"tests.muxer.mplex_test",
		"tests.muxer.mplex_conn_test",
	);
}
