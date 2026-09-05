/**
 * The periodic jobs: re-put every record we hold (replication), re-put the
 * ones we published ourselves (publication, less often), and re-announce the
 * keys we provide. A job is polled with the store and a clock; when its
 * interval has passed it snapshots the store, purges what has expired, and
 * yields the rest one record at a time until drained, then re-arms.
 */
module libp2p.protocol.kad.jobs;

import core.time : Duration, MonoTime;

import libp2p.core.peer_id : PeerId;
import libp2p.protocol.kad.store;

struct PutPoll
{
	bool ready;
	Record record;
}

final class PutRecordJob
{
	private PeerId local;
	private Duration replicateInterval;
	private MonoTime nextRun;
	private bool hasPublish;
	private Duration publishInterval;
	private MonoTime nextPublish;
	private bool hasTtl;
	private Duration ttl;
	private Record[] queue;
	private bool running;

	this(PeerId local, Duration replicateInterval, MonoTime now, bool hasPublish = false,
		Duration publishInterval = Duration.zero, bool hasTtl = false, Duration ttl = Duration.zero)
	{
		this.local = local;
		this.replicateInterval = replicateInterval;
		this.nextRun = now + replicateInterval;
		this.hasPublish = hasPublish;
		this.publishInterval = publishInterval;
		this.nextPublish = now + publishInterval;
		this.hasTtl = hasTtl;
		this.ttl = ttl;
	}

	bool isRunning() const @safe pure nothrow
	{
		return running;
	}

	PutPoll poll(MemoryStore store, MonoTime now)
	{
		if (!running && now >= nextRun)
		{
			immutable publish = hasPublish && now >= nextPublish;
			if (publish)
				nextPublish = now + publishInterval;
			nextRun = now + replicateInterval;
			queue = null;
			foreach (r; store.records)
			{
				if (r.isExpired(now))
				{
					store.remove(r.key);
					continue;
				}
				immutable ours = r.hasPublisher && r.publisher == local;
				if (ours && !publish)
					continue; // our own records go out on the publish interval only
				if (ours && hasTtl)
				{
					r.hasExpires = true;
					r.expires = now + ttl;
				}
				queue ~= r;
			}
			running = true;
		}
		if (running)
		{
			if (queue.length > 0)
			{
				auto r = queue[0];
				queue = queue[1 .. $];
				return PutPoll(true, r);
			}
			running = false;
		}
		return PutPoll(false);
	}
}

struct ProviderPoll
{
	bool ready;
	ProviderRecord record;
}

final class AddProviderJob
{
	private Duration interval;
	private MonoTime nextRun;
	private ProviderRecord[] queue;
	private bool running;

	this(Duration interval, MonoTime now)
	{
		this.interval = interval;
		this.nextRun = now + interval;
	}

	bool isRunning() const @safe pure nothrow
	{
		return running;
	}

	ProviderPoll poll(MemoryStore store, MonoTime now)
	{
		if (!running && now >= nextRun)
		{
			nextRun = now + interval;
			queue = null;
			foreach (r; store.provided)
			{
				if (r.isExpired(now))
				{
					store.removeProvider(r.key, r.provider);
					continue;
				}
				queue ~= r;
			}
			running = true;
		}
		if (running)
		{
			if (queue.length > 0)
			{
				auto r = queue[0];
				queue = queue[1 .. $];
				return ProviderPoll(true, r);
			}
			running = false;
		}
		return ProviderPoll(false);
	}
}
