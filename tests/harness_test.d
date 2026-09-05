/// Proves the harness itself: the unit-threaded runner, fluent-asserts, and a
/// vibe event loop that can be driven from a test and left with nothing behind.
module tests.harness_test;

import fluent.asserts;
import vibe.core.core : runTask, runEventLoop, exitEventLoop;

@("harness: a test can drive the vibe event loop and leave it clean")
unittest
{
	int ran;
	runTask(() nothrow {
		ran = 1;
		try exitEventLoop(); catch (Exception) {}
	});
	runEventLoop();
	ran.should.equal(1);
}
