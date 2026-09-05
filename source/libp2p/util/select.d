/**
 * Wait-any and wait-all over ordinary blocking code.
 *
 * On fibers an alternative does not have to be a pollable object; it only has to
 * be given a fiber of its own. `select` spawns one per alternative, the first to
 * finish takes the decision and signals, and every loser is interrupted and
 * joined *before* `select` returns — a loser still running after the decision is
 * a fiber whose owner has moved on, and one parked in an `accept` would wake
 * later, take a value, and drop it.
 *
 * This is the only racing primitive in the codebase, and it lives inside the
 * operations that need it (a read racing the session dying, an accept racing
 * `close()`, a dial racing its deadline). Callers of those operations see one
 * call that returns or throws; the mechanism does not leak upward.
 */
module libp2p.util.select;

import vibe.core.core : runTask;
import vibe.core.sync : LocalManualEvent, createManualEvent;
import vibe.core.task : Task, InterruptException;

/**
 * Run every alternative on its own fiber; return the index of the first to
 * finish. If the winner finished by throwing, that exception is rethrown here:
 * "finishing" includes failing, and the caller decides what a failure means.
 *
 * If the calling fiber is itself interrupted while waiting, all alternatives are
 * cancelled and joined and the interruption propagates.
 */
size_t select(void delegate()[] alternatives...)
{
	assert(alternatives.length > 0, "select over nothing would wait forever");

	auto done = createManualEvent();
	// Captured before anything is spawned: an alternative that finishes
	// synchronously must not signal into a count nobody is holding.
	auto seen = done.emitCount;

	size_t winner = size_t.max;
	Exception winnerErr;
	auto tasks = new Task[alternatives.length];

	scope (exit)
	{
		// Whatever happened — a decision or our own interruption — nothing we
		// spawned may outlive us. The join is uninterruptible on purpose: we
		// are already leaving, and a second interruption here would leave a
		// loser running, which is the one thing this function promises not to do.
		foreach (t; tasks)
			if (t != Task.init && t.running)
				t.interrupt();
		foreach (t; tasks)
			if (t != Task.init)
				t.joinUninterruptible();
	}

	foreach (i, alt; alternatives)
	{
		tasks[i] = runTask((size_t idx, void delegate() body_) nothrow {
			Exception err;
			try
				body_();
			catch (InterruptException)
				return; // a loser being told to stop; not a finish
			catch (Exception e)
				err = e;
			if (winner == size_t.max)
			{
				winner = idx;
				winnerErr = err;
				done.emit();
			}
		}, i, alt);
	}

	while (winner == size_t.max)
		seen = done.wait(seen);

	if (winnerErr !is null)
		throw winnerErr;
	return winner;
}

/**
 * Run every alternative on its own fiber and wait for all of them. The first
 * exception raised is rethrown after every fiber has finished. If the caller is
 * interrupted, the still-running alternatives are cancelled and joined first.
 */
void waitAll(void delegate()[] alternatives...)
{
	auto tasks = new Task[alternatives.length];
	auto errs = new Exception[alternatives.length];

	scope (exit)
	{
		foreach (t; tasks)
			if (t != Task.init && t.running)
				t.interrupt();
		foreach (t; tasks)
			if (t != Task.init)
				t.joinUninterruptible();
	}

	foreach (i, alt; alternatives)
	{
		tasks[i] = runTask((size_t idx, void delegate() body_) nothrow {
			try
				body_();
			catch (InterruptException)
			{
			}
			catch (Exception e)
				errs[idx] = e;
		}, i, alt);
	}

	foreach (t; tasks)
		t.join();

	foreach (e; errs)
		if (e !is null)
			throw e;
}
