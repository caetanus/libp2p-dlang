/**
 * Dial a TCP connection *from a chosen local port* with address/port reuse — the
 * primitive a TCP hole punch needs. libp2p TCP simultaneous-open works only if the
 * outbound connect egresses from the very port the listener is bound to, so the
 * peer's NAT sees the mapping it was told to expect. vibe's `connectTCP` can bind a
 * local port but eventcore never sets SO_REUSEPORT on the connector before its bind,
 * so a bind to the in-use listen port fails EADDRINUSE. Here we build the socket by
 * hand — socket / setsockopt(SO_REUSEADDR|SO_REUSEPORT) / bind(listenPort) /
 * non-blocking connect (driven cooperatively by polling writability and yielding to
 * vibe) — then adopt the connected fd into the event loop as a `TCPConnection`.
 */
module libp2p.transport.tcp_reuse;

import std.exception : enforce;
import std.socket : AddressFamily;
import std.format : format;
import core.time : Duration, MonoTime, msecs;
import core.stdc.errno : errno, EINPROGRESS;

import core.sys.posix.sys.socket : socket, setsockopt, bind, connect, getsockopt,
    SOL_SOCKET, SO_REUSEADDR, SO_ERROR, SOCK_STREAM, socklen_t, sockaddr;
import core.sys.posix.fcntl : fcntl, F_GETFL, F_SETFL, O_NONBLOCK;
import core.sys.posix.poll : poll, pollfd, POLLOUT;
import core.sys.posix.unistd : close;

import vibe.core.net : NetworkAddress, TCPConnection, createStreamConnection, resolveHost;
import vibe.core.core : sleep;

import eventcore.core : eventDriver;

// SO_REUSEPORT is not surfaced by druntime's posix headers; it is 15 on Linux.
version (linux)
    private enum SO_REUSEPORT = 15;
else
    static assert(false, "tcp_reuse: SO_REUSEPORT value only defined for Linux");

/// Connect to `peer`, egressing from local port `localPort` with SO_REUSEADDR |
/// SO_REUSEPORT (so it can share the listener's port). Blocks — cooperatively —
/// until connected or `budget` elapses. Returns a live vibe `TCPConnection`.
TCPConnection connectReusingPort(ushort localPort, NetworkAddress peer, Duration budget)
{
    immutable family = peer.family;
    auto fd = socket(family, SOCK_STREAM, 0);
    enforce(fd >= 0, "tcp_reuse: socket() failed");
    bool adopted;
    scope (exit)
        if (!adopted)
            close(fd);

    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, one.sizeof);
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, one.sizeof);

    // Bind the wildcard address on this family with the chosen port.
    auto local = resolveHost(family == AddressFamily.INET6 ? "::" : "0.0.0.0", family, false);
    local.port = localPort;
    enforce(bind(fd, local.sockAddr, local.sockAddrLen) == 0,
        format("tcp_reuse: bind(:%d) failed (errno %d)", localPort, errno));

    // Non-blocking connect; poll writability, yielding to the event loop.
    immutable fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    immutable rc = connect(fd, peer.sockAddr, peer.sockAddrLen);
    if (rc != 0)
        enforce(errno == EINPROGRESS, format("tcp_reuse: connect failed (errno %d)", errno));

    immutable deadline = MonoTime.currTime + budget;
    for (;;)
    {
        pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLOUT;
        immutable pr = poll(&pfd, 1, 0);
        if (pr > 0 && (pfd.revents & POLLOUT))
        {
            int err;
            socklen_t elen = err.sizeof;
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
            enforce(err == 0, format("tcp_reuse: connect error (errno %d)", err));
            break; // connected
        }
        enforce(MonoTime.currTime < deadline, "tcp_reuse: connect timed out");
        sleep(10.msecs);
    }

    auto sfd = eventDriver.sockets.adoptStream(fd);
    enforce(sfd != typeof(sfd).invalid, "tcp_reuse: adoptStream failed");
    adopted = true; // eventcore owns the fd now
    return createStreamConnection(sfd);
}
