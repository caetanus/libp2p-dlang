/// DNS resolution validation: resolve real multiaddr names against live DNS through
/// the c-ares resolver — /dns4 (A records) and /dnsaddr (TXT zone) — and confirm each
/// yields concrete addresses. This is the resolution path the swarm uses to dial
/// named peers (e.g. the IPFS bootstrap /dnsaddr's). Self-standing: no rust; live DNS.
/// Exit 0 = PASS, 1 = FAIL.
///
///   dns-resolve
module app;

import std.stdio : writeln, stderr, stdout;

import vibe.core.core : runTask, runEventLoop, exitEventLoop;

import libp2p.multiformats.multiaddr : Multiaddr;
import libp2p.transport.dns : resolve;
import libp2p.transport.dns_cares : CaresDns;

int main()
{
    int result = 1;
    runTask(() nothrow {
        try
        {
            auto dns = new CaresDns;

            // /dns4 → A records replace the name with /ip4/… keeping /tcp/443.
            // (bootstrap.libp2p.io is a dnsaddr/TXT-only zone with no A record; use a
            // host that actually has one.)
            auto a = resolve(Multiaddr.parse("/dns4/one.one.one.one/tcp/443"), dns);
            writeln("/dns4/one.one.one.one/tcp/443 → ", a.length, " addr(s)");
            foreach (m; a)
                writeln("   ", m.toString);

            // /dnsaddr → TXT zone yields full bootstrap multiaddrs (with /p2p/…).
            auto d = resolve(Multiaddr.parse("/dnsaddr/bootstrap.libp2p.io"), dns);
            writeln("/dnsaddr/bootstrap.libp2p.io → ", d.length, " addr(s)");
            foreach (m; d[0 .. (d.length > 3 ? 3 : d.length)])
                writeln("   ", m.toString);

            if (a.length > 0 && d.length > 0)
            {
                writeln("PASS: DNS resolves /dns4 (A) and /dnsaddr (TXT) against live DNS");
                result = 0;
            }
            else
                writeln("FAIL: dns (dns4=", a.length, " dnsaddr=", d.length, ")");
        }
        catch (Exception e)
        {
            try
                stderr.writeln("dns-resolve error: ", e.msg);
            catch (Exception)
            {
            }
        }
        try
            stdout.flush();
        catch (Exception)
        {
        }
        try
            exitEventLoop();
        catch (Exception)
        {
        }
    });
    runEventLoop();
    return result;
}
