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

// --- the wrapper shape: race readiness, then do the operation ---------------

// Racing the read *itself* against the cancel is wrong for anything that
// consumes: a fiber parked inside read() that wakes after the decision has
// already taken the data and will drop it. So the race is over readiness, and
// the read happens on the winning branch where it cannot block.
@("guard: readiness wins and the operation still gets its value")
unittest
{
	import libp2p.util.cancel : Cancel, guard, Cancelled;

	int got;
	onLoop({
		auto c = new Cancel;
		auto ev = createManualEvent();
		immutable ec = ev.emitCount;
		int box;
		runTask(() nothrow{
			try
			{
				sleep(10.msecs);
				box = 42; // "the data arrives"
				ev.emit();
			}
			catch (Exception)
			{
			}
		});

		guard(c, { ev.wait(ec); }); // race: ready, or cancelled
		got = box; // no race here — nobody else can be inside this
	});
	got.should.equal(42);
}

// Cancellation throws, so it propagates by unwinding: every scope(exit) on the
// way up runs and the owner learns without anyone threading a status through.
@("guard: cancellation throws, and unwinds through the caller's cleanup")
unittest
{
	import libp2p.util.cancel : Cancel, guard, Cancelled;

	bool cleanedUp, threw;
	string why;
	onLoop({
		auto c = new Cancel;
		runTask(() nothrow{
			try
			{
				sleep(10.msecs);
				c.cancel("the connection went away");
			}
			catch (Exception)
			{
			}
		});

		try
		{
			scope (exit)
				cleanedUp = true; // the propagation this design exists for
			guard(c, { sleep(30.seconds); });
		}
		catch (Cancelled e)
		{
			threw = true;
			why = e.msg;
		}
	});

	threw.should.equal(true);
	cleanedUp.should.equal(true);
	why.should.equal("the connection went away");
}

// Already cancelled means do not start at all.
@("guard: an operation is not begun on an already-cancelled token")
unittest
{
	import libp2p.util.cancel : Cancel, guard, Cancelled;

	bool started, threw;
	onLoop({
		auto c = new Cancel;
		c.cancel();
		try
			guard(c, { started = true; });
		catch (Cancelled)
			threw = true;
	});
	threw.should.equal(true);
	started.should.equal(false);
}
