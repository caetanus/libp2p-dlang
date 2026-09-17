/// Live smoke for server-reflexive gathering: drive the ICE agent over a real UDP
/// socket against a public STUN server and print the public mapping it learns.
/// Proves the engine's srflx gathering works out a real socket, in context — the
/// same property the WebRTC transport relies on. Compare the result to a plain
/// STUN NAT probe from the same box; they should match.
module app;

import webrtc.ice.agent : Agent, Role, Credentials, TransportAddr;
import webrtc.ice.candidate : Candidate, CandidateType;
import vibe.core.net : listenUDP, resolveHost, NetworkAddress;
import vibe.core.core : runTask, runEventLoop, exitEventLoop, sleep;
import core.time : msecs;
import std.socket : AddressFamily;
import std.algorithm.searching : find;
import std.range : empty, front;
import std.stdio : writeln;

int main()
{
    int result = 1;
    runTask(() nothrow {
        try
        {
            auto sock = listenUDP(0, "0.0.0.0");
            immutable localPort = sock.localAddress.port;

            auto stun = resolveHost("stun.l.google.com", AddressFamily.INET, true);
            immutable stunIp = stun.toAddressString;

            auto agent = new Agent(Role.controlling, Credentials("SMOKEUFR", "smokepasswordsmokepassw"), 1);
            agent.addLocalCandidate(Candidate.host("0.0.0.0", localPort));
            agent.addStunServer(TransportAddr(stunIp, 19302));
            writeln("probing stun.l.google.com (", stunIp, ":19302) from local udp port ", localPort);

            // reader: feed inbound STUN responses to the agent
            runTask(() nothrow {
                auto buf = new ubyte[2048];
                while (true)
                {
                    NetworkAddress from;
                    ubyte[] got;
                    try
                        got = sock.recv(buf, &from);
                    catch (Exception)
                        break;
                    if (got is null)
                        continue;
                    try
                        agent.handleInbound(got, TransportAddr(from.toAddressString, from.port),
                            TransportAddr("0.0.0.0", localPort), 0);
                    catch (Exception)
                    {
                    }
                }
            });

            long now = 0;
            for (int i = 0; i < 300 && result != 0; i++)
            {
                foreach (o; agent.gatherOutbound(now))
                {
                    auto dst = resolveHost(o.dst.ip, AddressFamily.INET, false);
                    dst.port = o.dst.port;
                    try
                        sock.send(o.data, &dst);
                    catch (Exception)
                    {
                    }
                }
                auto srflx = agent.gatheredCandidates.find!(c => c.typ == CandidateType.serverReflexive);
                if (!srflx.empty)
                {
                    writeln("OK srflx gathered: ", srflx.front.address, ":", srflx.front.port);
                    result = 0;
                }
                sleep(20.msecs);
                now += 20;
            }
            if (result != 0)
                writeln("FAIL: no srflx gathered (STUN unreachable?)");
        }
        catch (Exception e)
        {
            try
                writeln("FAIL ", e.msg);
            catch (Exception)
            {
            }
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
