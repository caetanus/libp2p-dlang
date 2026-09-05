#!/usr/bin/env bash
#
# The test gate: run the suite and fail on anything that should not be there.
#
# `dub run -c ut` on its own only reports assertion failures. Two other things
# can go wrong without turning the run red, and both have bitten this project:
#
#   1. The process dies (a segfault gave exit -11 while the summary line still
#      looked fine in a filtered log) — so the exit code is checked explicitly.
#   2. Resources are leaked. eventcore prints the handles still live at teardown
#      ("FD 12 (streamSocket)"). That list used to hold ~75 entries and was
#      treated as expected noise, which is exactly where a real shutdown
#      regression would hide. It is 0 now, so any entry is a regression.
#
# Usage: tools/run-tests.sh
# Exit:  0 = clean, 1 = failures / crash / leaked handles.
set -uo pipefail

cd "$(dirname "$0")/.."

log=$(mktemp)
trap 'rm -f "$log"' EXIT

dub run -c ut 2>&1 | tee "$log"
rc=${PIPESTATUS[0]}

echo
echo "──────── gate ────────"

status=0

if [ "$rc" -ne 0 ]; then
    echo "FAIL  test runner exited with $rc (a crash or a failing test)"
    status=1
else
    echo "ok    runner exited cleanly"
fi

# The tally, reported but NOT used as the pass/fail signal. unit-threaded writes
# it from several threads, so the line can come out interleaved with others
# ("ng 262 test(s) run, (t0 failedhr.") — matching it strictly once turned a
# green suite into a red gate. The runner's exit code above is the truth; this is
# here to be read, and only its absence (the suite never got to the end) is
# worth flagging.
if grep -q 'test(s) run' "$log"; then
    echo "ok    $(grep -o '[0-9]* test(s) run[^.]*' "$log" | tail -1)"
else
    echo "WARN  no test summary in the output (interleaved?), trusting the exit code"
fi

# Tasks vibe still had running when the process exited. Closing a Host wakes its
# accept loops; if the event loop never gets another turn they sit unfinished.
# Expected to be none (the tests drain the loop after closing).
tasks=$(grep -oE 'still [0-9]+ tasks running at exit' "$log" | tail -1)
if [ -n "$tasks" ]; then
    echo "FAIL  $tasks"
    status=1
else
    echo "ok    no tasks left running at exit"
fi

# Handles still live at teardown: expected to be none.
leaked=$(grep -cE '^[[:space:]]+FD [0-9]+ \(' "$log")
if [ "$leaked" -ne 0 ]; then
    echo "FAIL  $leaked live eventcore handle(s) at teardown:"
    grep -E '^[[:space:]]+FD [0-9]+ \(' "$log" | sort -u | sed 's/^/        /'
    echo "      Re-run with -debug=EventCoreLeakTrace to see where each was opened:"
    echo "        DFLAGS=-debug=EventCoreLeakTrace dub run -c ut --force"
    status=1
else
    echo "ok    no leaked handles"
fi

[ "$status" -eq 0 ] && echo "PASS" || echo "FAILED"
exit "$status"
