/**
 * What a node stores for the DHT: value records and provider records, in
 * memory, with the bounds rust-libp2p's MemoryStore applies. A saturated
 * provider list ignores newcomers: a flood of fake providers cannot push the
 * real ones out.
 */
module libp2p.protocol.kad.store;

import core.time : MonoTime;
import std.algorithm.searching : countUntil;

import libp2p.core.peer_id : PeerId;
import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.protocol.kad.bucket : kValue;

struct RecordKey
{
	ubyte[] bytes;

	static RecordKey from(const(ubyte)[] bytes) @safe pure nothrow
	{
		return RecordKey(bytes.dup);
	}

	bool opEquals(const ref RecordKey o) const @safe pure nothrow
	{
		return bytes == o.bytes;
	}

	size_t toHash() const @safe pure nothrow
	{
		return hashOf(bytes);
	}
}

struct Record
{
	RecordKey key;
	ubyte[] value;
	PeerId publisher;
	bool hasPublisher;
	MonoTime expires;
	bool hasExpires;

	this(RecordKey key, ubyte[] value) @safe pure nothrow
	{
		this.key = key;
		this.value = value;
	}

	bool isExpired(MonoTime now) const @safe pure nothrow @nogc
	{
		return hasExpires && expires <= now;
	}
}

struct ProviderRecord
{
	RecordKey key;
	PeerId provider;
	Multiaddr[] addresses;
	MonoTime expires;
	bool hasExpires;

	this(RecordKey key, PeerId provider, Multiaddr[] addresses) @safe pure nothrow
	{
		this.key = key;
		this.provider = provider;
		this.addresses = addresses;
	}

	bool isExpired(MonoTime now) const @safe pure nothrow @nogc
	{
		return hasExpires && expires <= now;
	}

	/// Identity is (key, provider): re-adding replaces.
	bool opEquals(const ref ProviderRecord o) const @safe pure nothrow
	{
		return key == o.key && provider == o.provider;
	}

	size_t toHash() const @safe pure nothrow
	{
		return hashOf(provider.bytes, key.toHash);
	}
}

struct MemoryStoreConfig
{
	size_t maxRecords = 1024;
	size_t maxValueBytes = 65 * 1024;
	size_t maxProvidersPerKey = kValue;
	size_t maxProvidedKeys = 1024;
}

enum StoreError
{
	none,
	maxRecords,
	valueTooLarge,
	maxProvidedKeys,
}

final class MemoryStore
{
	private PeerId local;
	private MemoryStoreConfig cfg;
	private Record[RecordKey] records_;
	private ProviderRecord[][RecordKey] providers_;
	private ProviderRecord[] provided_; // the ones where provider == local

	this(PeerId local, MemoryStoreConfig cfg = MemoryStoreConfig.init)
	{
		this.local = local;
		this.cfg = cfg;
	}

	MemoryStoreConfig config() const @safe pure nothrow
	{
		return cfg;
	}

	// --- value records -----------------------------------------------------------------

	StoreError put(Record r)
	{
		if (r.value.length >= cfg.maxValueBytes)
			return StoreError.valueTooLarge;
		if (r.key !in records_ && records_.length >= cfg.maxRecords)
			return StoreError.maxRecords;
		records_[r.key] = r;
		return StoreError.none;
	}

	Record* get(RecordKey key)
	{
		return key in records_;
	}

	void remove(RecordKey key)
	{
		records_.remove(key);
	}

	Record[] records()
	{
		return records_.values;
	}

	// --- provider records ----------------------------------------------------------------

	StoreError addProvider(ProviderRecord r)
	{
		immutable numKeys = providers_.length;
		if (r.key !in providers_ && numKeys >= cfg.maxProvidedKeys)
			return StoreError.maxProvidedKeys;

		auto list = providers_.get(r.key, null);
		immutable existing = list.countUntil!(p => p.provider == r.provider);
		if (existing >= 0)
			list[existing] = r; // update in place
		else if (list.length >= cfg.maxProvidersPerKey)
			return StoreError.none; // full: the newcomer is ignored, which blunts a flood of fakes
		else
			list ~= r;
		providers_[r.key] = list;

		if (r.provider == local)
		{
			immutable i = provided_.countUntil!(p => p.key == r.key);
			if (i >= 0)
				provided_[i] = r;
			else
				provided_ ~= r;
		}
		return StoreError.none;
	}

	ProviderRecord[] providers(RecordKey key)
	{
		return providers_.get(key, null).dup;
	}

	/// The provider records this node itself provides.
	ProviderRecord[] provided()
	{
		return provided_.dup;
	}

	void removeProvider(RecordKey key, PeerId provider)
	{
		auto list = providers_.get(key, null);
		immutable i = list.countUntil!(p => p.provider == provider);
		if (i < 0)
			return;
		list = list[0 .. i] ~ list[i + 1 .. $];
		if (list.length == 0)
			providers_.remove(key);
		else
			providers_[key] = list;
		if (provider == local)
			removeProvided(key);
	}

	private void removeProvided(RecordKey key)
	{
		immutable i = provided_.countUntil!(p => p.key == key);
		if (i >= 0)
			provided_ = provided_[0 .. i] ~ provided_[i + 1 .. $];
	}
}
