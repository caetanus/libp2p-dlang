/// A sliding-window rate limit: at most `count` events per `period`, per key.
module libp2p.util.ratelimit;

import core.time : Duration, MonoTime;

struct RateLimit
{
	size_t count;
	Duration period;

	bool enabled() const @safe pure nothrow @nogc
	{
		return count > 0 && period > Duration.zero;
	}
}

struct RateLimiter(K)
{
	RateLimit limit;
	private MonoTime[][K] stamps;

	/// Record an event for `key` if the limit allows it; false if it does not.
	bool allow(K key, MonoTime now)
	{
		if (!limit.enabled)
			return true;
		auto list = stamps.get(key, null);
		size_t keep;
		while (keep < list.length && now - list[keep] >= limit.period)
			keep++;
		list = list[keep .. $];
		if (list.length >= limit.count)
		{
			stamps[key] = list;
			return false;
		}
		list ~= now;
		stamps[key] = list;
		return true;
	}

	void forget(K key)
	{
		stamps.remove(key);
	}
}
