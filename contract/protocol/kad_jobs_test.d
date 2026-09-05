module tests.protocol.kad_jobs_test;

import core.time : Duration, MonoTime, seconds;
import std.random : Random, uniform;

import libp2p.crypto.keys : Keypair;
import libp2p.core.peer_id : PeerId;
import libp2p.protocol.kad.store : MemoryStore, Record, ProviderRecord, RecordKey;
import libp2p.protocol.kad.jobs;
import fluent.asserts;

private PeerId rp()
{
	return PeerId.fromPublicKey(Keypair.generateEd25519.publicKey);
}

private RecordKey randomKey(ref Random rng)
{
	ubyte[] h;
	foreach (_; 0 .. 32)
		h ~= cast(ubyte) uniform(0, 256, rng);
	return RecordKey.from(h);
}

// rust `new_job_not_running`: a freshly-created job is waiting, not running.
@("kad jobs: a new job is not running")
unittest
{
	auto now = MonoTime.currTime;
	auto put = new PutRecordJob(rp(), 30.seconds, now, true, 120.seconds, true, 300.seconds);
	put.isRunning.should.equal(false);
	auto add = new AddProviderJob(30.seconds, now);
	add.isRunning.should.equal(false);
}

// rust `run_put_record_job`: every non-expired record in the store is yielded by
// the job (which is then running), and once drained the job returns pending and
// is no longer running.
@("kad jobs: PutRecordJob yields every non-expired record then goes pending")
unittest
{
	auto rng = Random(20_260_723);
	immutable interval = 30.seconds;
	foreach (trial; 0 .. 100) // rust quickcheck default: 100 random stores
	{
		auto base = MonoTime.currTime;
		auto localId = rp();
		// publish_interval > replicate_interval so publish=false at pollNow:
		// publisher records would be skipped — but arbitrary records use random
		// publishers that never equal localId, exactly as in rust's property.
		auto job = new PutRecordJob(localId, interval, base, true, 120.seconds, true, 300.seconds);

		auto store = new MemoryStore(localId);
		foreach (_; 0 .. uniform(0, 20, rng)) // arbitrary Vec<Record> length
		{
			auto r = Record(randomKey(rng), [cast(ubyte) uniform(0, 256, rng)]);
			if (uniform(0, 2, rng))
			{
				r.publisher = rp(); // random, never == localId
				r.hasPublisher = true;
			}
			if (uniform(0, 2, rng))
			{
				r.hasExpires = true;
				r.expires = base + uniform(0, 60, rng).seconds;
			}
			store.put(r);
		}

		immutable pollNow = base + interval;
		// Snapshot the store's records BEFORE polling (polling removes expired).
		auto before = store.records();

		foreach (r; before)
		{
			if (!r.isExpired(pollNow))
			{
				auto p = job.poll(store, pollNow);
				p.ready.should.equal(true);
				p.record.key.should.equal(r.key);
				job.isRunning.should.equal(true);
			}
		}
		// Snapshot drained.
		job.poll(store, pollNow).ready.should.equal(false);
		job.isRunning.should.equal(false);
	}
}

// rust `run_add_provider_job`: every non-expired provided record is yielded, then
// the job goes pending and stops running.
@("kad jobs: AddProviderJob yields every non-expired provided record then pends")
unittest
{
	auto rng = Random(20_260_724);
	immutable interval = 30.seconds;
	foreach (trial; 0 .. 100) // rust quickcheck default
	{
		auto base = MonoTime.currTime;
		auto id = rp();
		auto job = new AddProviderJob(interval, base);

		auto store = new MemoryStore(id);
		foreach (_; 0 .. uniform(0, 20, rng))
		{
			auto r = ProviderRecord(randomKey(rng), id, []); // provider = local
			if (uniform(0, 2, rng))
			{
				r.hasExpires = true;
				r.expires = base + uniform(0, 60, rng).seconds;
			}
			store.addProvider(r);
		}

		immutable pollNow = base + interval;
		auto before = store.provided();

		foreach (r; before)
		{
			if (!r.isExpired(pollNow))
			{
				auto p = job.poll(store, pollNow);
				p.ready.should.equal(true);
				(p.record == r).should.equal(true); // eq by (key, provider)
				job.isRunning.should.equal(true);
			}
		}
		job.poll(store, pollNow).ready.should.equal(false);
		job.isRunning.should.equal(false);
	}
}

// The replicate path re-arms after draining: a second interval later it runs
// again and re-yields the surviving records.
@("kad jobs: PutRecordJob re-arms and runs again next interval")
unittest
{
	immutable interval = 10.seconds;
	auto base = MonoTime.currTime;
	auto localId = rp();
	auto job = new PutRecordJob(localId, interval, base); // no publish, no ttl

	auto store = new MemoryStore(localId);
	auto rec = Record(RecordKey.from([1, 2, 3]), [9]); // no expiry
	store.put(rec);

	// First run.
	auto n1 = base + interval;
	job.poll(store, n1).ready.should.equal(true);
	job.poll(store, n1).ready.should.equal(false); // drained, re-armed to n1+interval
	job.isRunning.should.equal(false);

	// Before the next deadline: still pending, nothing yielded.
	job.poll(store, n1 + 1.seconds).ready.should.equal(false);

	// Second interval elapsed: runs again.
	auto n2 = n1 + interval;
	job.poll(store, n2).ready.should.equal(true);
}

// Expired records are removed from the store (and never yielded) as the job runs.
@("kad jobs: PutRecordJob removes expired records from the store")
unittest
{
	immutable interval = 10.seconds;
	auto base = MonoTime.currTime;
	auto localId = rp();
	auto job = new PutRecordJob(localId, interval, base);

	auto store = new MemoryStore(localId);
	auto live = Record(RecordKey.from([1]), [1]);
	auto dead = Record(RecordKey.from([2]), [2]);
	dead.hasExpires = true;
	dead.expires = base + 5.seconds; // expires before pollNow
	store.put(live);
	store.put(dead);

	auto pollNow = base + interval; // > dead.expires
	// Drain: live yielded, dead removed.
	auto p = job.poll(store, pollNow);
	p.ready.should.equal(true);
	p.record.key.should.equal(live.key);
	job.poll(store, pollNow).ready.should.equal(false);

	(store.get(RecordKey.from([2])) is null).should.equal(true); // dead purged
	(store.get(RecordKey.from([1])) !is null).should.equal(true); // live kept
}
