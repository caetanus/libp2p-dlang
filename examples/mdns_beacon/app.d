/// A LAN beacon from the command line — to see mDNS discovery work (or not) on a
/// given network without an application in the way.
///   mdns-beacon --announce --secret S [--txt port=1234 --txt pk=abcd]
///   mdns-beacon --browse --secret S [--seconds N]
module app;

import core.time : seconds, msecs, MonoTime;
import std.getopt : getopt;
import std.stdio : writeln, stdout;

import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;
import vibe.core.net : NetworkAddress;

import libp2p.discovery.mdns : MdnsBeacon, mdnsServiceFor, ipv4Interfaces;

int main(string[] args)
{
    bool announce, browse; string secret = "test"; string[] txt; uint secs = 20;
    getopt(args, "announce", &announce, "browse", &browse, "secret", &secret, "txt", &txt, "seconds", &secs);
    { import vibe.core.log : setLogLevel, LogLevel; import std.process : environment; if (environment.get("MDNS_DEBUG").length) setLogLevel(LogLevel.debug_); }
    immutable label = mdnsServiceFor("pwhs", cast(const(ubyte)[]) secret);
    writeln("service: ", label);
    foreach (i; ipv4Interfaces())
        writeln("  interface ", i.name, " ", i.ip, " (#", i.index, ")");
    stdout.flush();
    int result = 1;
    runTask(() nothrow {
        try
        {
            auto b = new MdnsBeacon(label, announce ? () => txt : null);
            scope (exit)
                b.close();
            if (browse)
                b.onFound = (NetworkAddress from, string[] t) nothrow {
                    try { writeln("FOUND from ", from.toAddressString, " txt=", t); stdout.flush(); } catch (Exception) {}
                    result = 0;
                };
            else
                result = 0;
            immutable end = MonoTime.currTime + secs.seconds;
            while (MonoTime.currTime < end)
                sleep(500.msecs); // the beacon probes on its own cadence
        }
        catch (Exception e)
        {
            try writeln("mdns-beacon: ", e.msg); catch (Exception) {}
        }
        try exitEventLoop(); catch (Exception) {}
    });
    runEventLoop();
    return result;
}
