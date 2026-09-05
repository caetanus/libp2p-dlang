module tests.util.select_test;

import core.time : msecs, seconds, MonoTime;
import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;
import vibe.core.sync : LocalManualEvent, createManualEvent;

import libp2p.util.select : select, waitAll;
import fluent.asserts;

private void onLoop(void delegate() body_)
{
	Exception err;
	runTask(() nothrow{
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

// The whole construction: an ordinary blocking call becomes an alternative just
// by being given a fiber. Nothing here is a pollable object.
@("select: the first alternative to finish wins")
unittest
{
	size_t which = size_t.max;
	onLoop({
		which = select({ sleep(400.msecs); }, { sleep(10.msecs); }, { sleep(400.msecs); });
	});
	which.should.equal(1);
}

// A loser still running after select returns is a fiber whose owner has moved
// on. Worse, a loser can consume a value: one parked in an accept that wakes
// after the decision has taken something and will drop it. So the losers are
// cancelled AND joined before select returns.
@("select: the losers are cancelled before it returns")
unittest
{
	bool loserFinished, loserWasInterrupted;
	onLoop({
		cast(void) select({ sleep(5.msecs); }, {
			try
			{
				sleep(30.seconds); // would outlive the test if not interrupted
				loserFinished = true;
			}
			catch (Exception)
				loserWasInterrupted = true;
		});
	});

	// select returned, so the loser is already gone — not merely signalled.
	loserWasInterrupted.should.equal(true);
	loserFinished.should.equal(false);
}

// An alternative that is already done must not signal into a count nobody is
// holding: the emit count is captured before anything is spawned.
@("select: an alternative that finishes immediately is not lost")
unittest
{
	size_t which = size_t.max;
	onLoop({ which = select({}, { sleep(30.seconds); }); });
	which.should.equal(0);
}

@("select: waiting on an event is an ordinary alternative")
unittest
{
	size_t which = size_t.max;
	onLoop({
		auto ev = createManualEvent();
		immutable ec = ev.emitCount;
		runTask(() nothrow{
			try
			{
				sleep(20.msecs);
				ev.emit();
			}
			catch (Exception)
			{
			}
		});
		which = select({ sleep(2.seconds); }, { ev.wait(ec); });
	});
	which.should.equal(1);
}

// No primitive needed: wait-all is a join over the tasks.
@("waitAll: every alternative runs and all of them are waited for")
unittest
{
	int done;
	onLoop({
		waitAll({ sleep(30.msecs); done++; }, { sleep(10.msecs); done++; }, {
			sleep(20.msecs);
			done++;
		});
	});
	done.should.equal(3);
}

