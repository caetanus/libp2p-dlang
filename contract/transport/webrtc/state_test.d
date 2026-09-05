module tests.transport.webrtc.state_test;

import libp2p.transport.webrtc.stream.state;
import fluent.asserts;

// Runs `f` (expected to throw a StreamStateException) and returns its io kind.
private IoErrorKind kindOf(scope void delegate() @safe f) @safe
{
	try
		f();
	catch (StreamStateException e)
		return e.kind;
	assert(0, "expected a StreamStateException");
}

@("cannot read after receiving FIN")
unittest
{
	State open;
	ubyte[] buf;
	open.handleInboundFlag(Flag.FIN, buf);
	kindOf(() => open.readBarrier()).should.equal(IoErrorKind.brokenPipe);
}

@("cannot read after closing read")
unittest
{
	State open;
	open.closeReadBarrier();
	open.closeReadMessageSent();
	open.readClosed();
	kindOf(() => open.readBarrier()).should.equal(IoErrorKind.brokenPipe);
}

@("cannot write after receiving STOP_SENDING")
unittest
{
	State open;
	ubyte[] buf;
	open.handleInboundFlag(Flag.STOP_SENDING, buf);
	kindOf(() => open.writeBarrier()).should.equal(IoErrorKind.brokenPipe);
}

@("cannot write after closing write")
unittest
{
	State open;
	open.closeWriteBarrier();
	open.closeWriteMessageSent();
	open.writeClosed();
	kindOf(() => open.writeBarrier()).should.equal(IoErrorKind.brokenPipe);
}

@("everything broken after receiving RESET")
unittest
{
	State open;
	ubyte[] buf;
	open.handleInboundFlag(Flag.RESET, buf);
	kindOf(() => open.readBarrier()).should.equal(IoErrorKind.connectionReset);
	kindOf(() => open.writeBarrier()).should.equal(IoErrorKind.connectionReset);
	kindOf(() { open.closeWriteBarrier(); }).should.equal(IoErrorKind.connectionReset);
	kindOf(() { open.closeReadBarrier(); }).should.equal(IoErrorKind.connectionReset);
}

@("should read flags in async write after read closed")
unittest
{
	State open;
	ubyte[] buf;
	open.handleInboundFlag(Flag.FIN, buf);
	open.readFlagsInAsyncWrite.should.equal(true);
}

@("cannot read or write after receiving FIN and STOP_SENDING")
unittest
{
	State open;
	ubyte[] buf;
	open.handleInboundFlag(Flag.FIN, buf);
	open.handleInboundFlag(Flag.STOP_SENDING, buf);
	kindOf(() => open.readBarrier()).should.equal(IoErrorKind.brokenPipe);
	kindOf(() => open.writeBarrier()).should.equal(IoErrorKind.brokenPipe);
}

@("can read after closing write")
unittest
{
	State open;
	open.closeWriteBarrier();
	open.closeWriteMessageSent();
	open.writeClosed();
	open.readBarrier(); // must not throw
}

@("can write after closing read")
unittest
{
	State open;
	open.closeReadBarrier();
	open.closeReadMessageSent();
	open.readClosed();
	open.writeBarrier(); // must not throw
}

@("cannot write after starting close")
unittest
{
	State open;
	open.closeWriteBarrier();
	kindOf(() => open.writeBarrier()).should.equal(IoErrorKind.brokenPipe);
}

@("cannot read after starting close")
unittest
{
	State open;
	open.closeReadBarrier();
	kindOf(() => open.readBarrier()).should.equal(IoErrorKind.brokenPipe);
}

@("can read in open")
unittest
{
	State open;
	open.readBarrier(); // must not throw
}

@("can write in open")
unittest
{
	State open;
	open.writeBarrier(); // must not throw
}

@("write close barrier returns none when closed")
unittest
{
	State open;
	open.closeWriteBarrier();
	open.closeWriteMessageSent();
	open.writeClosed();
	open.closeWriteBarrier().isNull.should.equal(true);
}

@("read close barrier returns none when closed")
unittest
{
	State open;
	open.closeReadBarrier();
	open.closeReadMessageSent();
	open.readClosed();
	open.closeReadBarrier().isNull.should.equal(true);
}

@("RESET flag clears the buffer")
unittest
{
	State open;
	ubyte[] buffer = cast(ubyte[]) "foobar".dup;
	open.handleInboundFlag(Flag.RESET, buffer);
	buffer.length.should.equal(0);
}
