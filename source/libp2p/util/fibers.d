/**
 * A group of fibers with one owner.
 *
 * Every fiber in the codebase belongs to a group, and the group belongs to an
 * object whose `close()` calls `stopAll`. The failure policy for the group's
 * fibers is stated once, when the group is made; the work itself throws.
 * `InterruptException` is the owner telling a fiber to leave and is never a
 * failure.
 */
module libp2p.util.fibers;

import vibe.core.core : runTask;
import vibe.core.task : Task, InterruptException;

alias FailurePolicy = void delegate(Exception) nothrow;

final class FiberGroup
{
	private Task[] tasks;
	private FailurePolicy onFailure;
	private void delegate() nothrow onEmpty;

	/**
	 * `onFailure` is what happens to an exception a fiber's body did not handle;
	 * null drops it. `onEmpty` is called when the last fiber leaves.
	 */
	this(FailurePolicy onFailure = null, void delegate() nothrow onEmpty = null) @safe nothrow
	{
		this.onFailure = onFailure;
		this.onEmpty = onEmpty;
	}

	Task spawn(void delegate() body_)
	{
		Task t;
		t = runTask(() nothrow {
			scope (exit)
				leave(t);
			try
				body_();
			catch (InterruptException)
			{
			}
			catch (Exception e)
				if (onFailure !is null)
					onFailure(e);
		});
		// The body may already have finished (it runs until its first yield).
		if (t.running)
			tasks ~= t;
		return t;
	}

	size_t length() const @safe pure nothrow
	{
		return tasks.length;
	}

	/// Interrupt every fiber but the caller and wait for them to leave.
	/// Uninterruptible: the owner is finishing, and a second interruption here
	/// would leave a fiber running, which is the one thing stopAll promises not to.
	void stopAll() nothrow
	{
		auto me = Task.getThis();
		auto snapshot = tasks.dup;
		foreach (t; snapshot)
			if (t != me && t.running)
				t.interrupt();
		foreach (t; snapshot)
			if (t != me)
				t.joinUninterruptible();
	}

	private void leave(Task t) nothrow
	{
		foreach (i, x; tasks)
			if (x == t)
			{
				tasks = tasks[0 .. i] ~ tasks[i + 1 .. $];
				break;
			}
		if (tasks.length == 0 && onEmpty !is null)
			onEmpty();
	}
}
