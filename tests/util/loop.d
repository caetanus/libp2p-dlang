/**
 * Driving the vibe event loop from a test, and keeping assertions out of fibers.
 *
 * `onLoop` runs a body on the loop and rethrows what it raised after the loop
 * has returned, so `.should` calls happen on the test's own stack (they
 * overflow a fiber's). `spawn` gives a body a fiber of its own and carries its
 * failure back through `join`.
 */
module tests.util.loop;

import vibe.core.core : runTask, runEventLoop, exitEventLoop;
import vibe.core.task : Task, InterruptException;

void onLoop(void delegate() body_)
{
	Exception err;
	runTask(() nothrow {
		try
			body_();
		catch (Exception e)
			err = e;
		try
			exitEventLoop();
		catch (Exception)
		{
		}
	});
	runEventLoop();
	if (err !is null)
		throw err;
}

final class Side
{
	Task task;
	private Exception err;
	bool interrupted;

	void join()
	{
		task.join();
		if (err !is null)
			throw err;
	}

	void interrupt() nothrow
	{
		task.interrupt();
	}
}

Side spawn(void delegate() body_)
{
	auto s = new Side;
	s.task = runTask(() nothrow {
		try
			body_();
		catch (InterruptException)
			s.interrupted = true;
		catch (Exception e)
			s.err = e;
	});
	return s;
}
