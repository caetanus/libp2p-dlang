module tests.protocol.kad_store_test;

import core.time : MonoTime, seconds;
import std.algorithm : canFind;
import std.random : Random, uniform;

import libp2p.crypto.keys : Keypair;
import libp2p.core.peer_id : PeerId;
import libp2p.protocol.kad.store;
import fluent.asserts;

private PeerId rp()
{
	return PeerId.fromPublicKey(Keypair.generateEd25519.publicKey);
}

private RecordKey randomKey(ref Random rng)
{
	// rust generates a SHA-256 multihash key; the store treats keys opaquely,
	// so a random 32-byte digest is a faithful stand-in.
	ubyte[] h;
	foreach (_; 0 .. 32)
		h ~= cast(ubyte) uniform(0, 256, rng);
	return RecordKey.from(h);
}

private ubyte[] randomValue(ref Random rng)
{
	ubyte[] v;
	foreach (_; 0 .. uniform(0, 64, rng))
		v ~= cast(ubyte) uniform(0, 256, rng);
	return v;
}

private Record arbitraryRecord(ref Random rng)
{
	auto r = Record(randomKey(rng), randomValue(rng));
	if (uniform(0, 2, rng))
	{
		r.publisher = rp();
		r.hasPublisher = true;
	}
	if (uniform(0, 2, rng))
	{
		r.expires = MonoTime.currTime + uniform(0, 60, rng).seconds;
		r.hasExpires = true;
	}
	return r;
}

private ProviderRecord arbitraryProvider(ref Random rng)
{
	auto r = ProviderRecord(randomKey(rng), rp(), []);
	if (uniform(0, 2, rng))
	{
		r.expires = MonoTime.currTime + uniform(0, 60, rng).seconds;
		r.hasExpires = true;
	}
	return r;
}

// rust `put_get_remove_record` (quickcheck property).
@("kad store: put, get, remove a value-record")
unittest
{
	auto rng = Random(20_260_723);
	foreach (_; 0 .. 100) // rust quickcheck default
	{
		auto r = arbitraryRecord(rng);
		auto store = new MemoryStore(rp());
		store.put(r).should.equal(StoreError.none);
		auto got = store.get(r.key);
		(got !is null).should.equal(true);
		// rust asserts full-record equality (Some(Cow::Borrowed(&r))): the store
		// must round-trip value, publisher AND expiry, not just the value.
		got.value.should.equal(r.value);
		got.hasPublisher.should.equal(r.hasPublisher);
		if (r.hasPublisher)
			(got.publisher == r.publisher).should.equal(true);
		got.hasExpires.should.equal(r.hasExpires);
		if (r.hasExpires)
			(got.expires == r.expires).should.equal(true);
		store.remove(r.key);
		(store.get(r.key) is null).should.equal(true);
	}
}

// rust `add_get_remove_provider` (quickcheck property).
@("kad store: add, get, remove a provider-record")
unittest
{
	auto rng = Random(20_260_724);
	foreach (_; 0 .. 100) // rust quickcheck default
	{
		auto r = arbitraryProvider(rng);
		auto store = new MemoryStore(rp());
		store.addProvider(r).should.equal(StoreError.none);
		store.providers(r.key).canFind(r).should.equal(true);
		store.removeProvider(r.key, r.provider);
		store.providers(r.key).canFind(r).should.equal(false);
	}
}

// rust `provided`.
@("kad store: a record the local node provides shows up in provided()")
unittest
{
	auto id = rp();
	auto store = new MemoryStore(id);
	auto rec = ProviderRecord(RecordKey.from([1, 2, 3, 4]), id, []);
	store.addProvider(rec).should.equal(StoreError.none);
	auto pv = store.provided();
	pv.length.should.equal(1UL);
	pv[0].should.equal(rec);
	store.removeProvider(rec.key, id);
	store.provided().length.should.equal(0UL);
}

// rust `update_provider`.
@("kad store: re-adding a provider updates it in place")
unittest
{
	auto store = new MemoryStore(rp());
	auto key = RecordKey.from([9, 8, 7]);
	auto prv = rp();
	auto rec = ProviderRecord(key, prv, []);
	store.addProvider(rec).should.equal(StoreError.none);
	store.providers(rec.key).should.equal([rec]);

	rec.expires = MonoTime.currTime;
	rec.hasExpires = true;
	store.addProvider(rec).should.equal(StoreError.none);
	// still one entry, and it carries the updated expiry
	auto ps = store.providers(rec.key);
	ps.length.should.equal(1UL);
	ps[0].hasExpires.should.equal(true);
	ps[0].expires.should.equal(rec.expires);
}

// rust `update_provided`.
@("kad store: re-adding a local provider updates the provided() copy")
unittest
{
	auto prv = rp();
	auto store = new MemoryStore(prv);
	auto key = RecordKey.from([4, 5, 6]);
	auto rec = ProviderRecord(key, prv, []);
	store.addProvider(rec).should.equal(StoreError.none);
	store.provided().length.should.equal(1UL);

	rec.expires = MonoTime.currTime;
	rec.hasExpires = true;
	store.addProvider(rec).should.equal(StoreError.none);
	auto pv = store.provided();
	pv.length.should.equal(1UL);
	pv[0].hasExpires.should.equal(true);
	pv[0].expires.should.equal(rec.expires);
}

// rust `max_providers_per_key`.
@("kad store: a saturated provider list silently ignores new providers")
unittest
{
	MemoryStoreConfig config;
	auto key = RecordKey.from([1, 1, 1, 1]);
	auto store = new MemoryStore(rp(), config);

	foreach (_; 0 .. config.maxProvidersPerKey)
	{
		auto rec = ProviderRecord(key, rp(), []);
		store.addProvider(rec).should.equal(StoreError.none);
	}

	// The key is saturated: add_provider returns Ok but drops the new record.
	auto rec = ProviderRecord(key, rp(), []);
	store.addProvider(rec).should.equal(StoreError.none);
	store.providers(rec.key).canFind(rec).should.equal(false);
	store.providers(key).length.should.equal(config.maxProvidersPerKey);
}

// rust `max_provided_keys`.
@("kad store: reaching max_provided_keys rejects further keys")
unittest
{
	auto rng = Random(20_260_725);
	auto store = new MemoryStore(rp());
	foreach (_; 0 .. store.config.maxProvidedKeys)
	{
		auto rec = ProviderRecord(randomKey(rng), rp(), []);
		store.addProvider(rec); // ignore result
	}
	auto rec = ProviderRecord(randomKey(rng), rp(), []);
	store.addProvider(rec).should.equal(StoreError.maxProvidedKeys);
}

// A value at or beyond max_value_bytes is rejected (rust `put` guard).
@("kad store: an over-large value is rejected")
unittest
{
	MemoryStoreConfig config;
	config.maxValueBytes = 8;
	auto store = new MemoryStore(rp(), config);
	auto r = Record(RecordKey.from([1]), new ubyte[8]);
	store.put(r).should.equal(StoreError.valueTooLarge);
	auto ok = Record(RecordKey.from([1]), new ubyte[7]);
	store.put(ok).should.equal(StoreError.none);
}

// Reaching max_records rejects a *new* key but still allows overwriting an
// existing one (rust `put` occupied vs vacant branch).
@("kad store: max_records caps new keys but allows overwrite")
unittest
{
	MemoryStoreConfig config;
	config.maxRecords = 2;
	auto store = new MemoryStore(rp(), config);
	auto a = Record(RecordKey.from([1]), [1]);
	auto b = Record(RecordKey.from([2]), [2]);
	store.put(a).should.equal(StoreError.none);
	store.put(b).should.equal(StoreError.none);

	auto c = Record(RecordKey.from([3]), [3]);
	store.put(c).should.equal(StoreError.maxRecords);

	// Overwriting an existing key is still fine at capacity.
	auto a2 = Record(RecordKey.from([1]), [9, 9]);
	store.put(a2).should.equal(StoreError.none);
	store.get(RecordKey.from([1])).value.should.equal([cast(ubyte) 9, 9]);
}
