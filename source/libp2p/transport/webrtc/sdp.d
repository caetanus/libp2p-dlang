/**
 * The session descriptions webrtc-direct never sends over the wire but both
 * sides must agree on: the client's offer names the server's address and a
 * placeholder fingerprint; the server's answer is synthesised from the
 * client's ufrag, its own certificate and its address. Both use the ufrag as
 * the ICE password too.
 */
module libp2p.transport.webrtc.sdp;

import std.array : replace;
import std.random : uniform;

import libp2p.transport.webrtc.fingerprint : Fingerprint;

enum ufragPrefix = "libp2p+webrtc+v1/";

private enum serverTemplate = "v=0
o=- 0 0 IN {ip_version} {target_ip}
s=-
t=0 0
a=ice-lite
m=application {target_port} UDP/DTLS/SCTP webrtc-datachannel
c=IN {ip_version} {target_ip}
a=mid:0
a=ice-options:ice2
a=ice-ufrag:{ufrag}
a=ice-pwd:{pwd}
a=fingerprint:{fingerprint_algorithm} {fingerprint_value}
a=setup:passive
a=sctp-port:5000
a=max-message-size:16384
a=candidate:1467250027 1 UDP 1467250027 {target_ip} {target_port} typ host
a=end-of-candidates
";

private enum clientTemplate = "v=0
o=- 0 0 IN {ip_version} {target_ip}
s=-
c=IN {ip_version} {target_ip}
t=0 0
m=application {target_port} UDP/DTLS/SCTP webrtc-datachannel
a=mid:0
a=ice-options:ice2
a=ice-ufrag:{ufrag}
a=ice-pwd:{pwd}
a=fingerprint:{fingerprint_algorithm} {fingerprint_value}
a=setup:actpass
a=sctp-port:5000
a=max-message-size:16384
";

/// The server's answer for a client at nothing in particular, listening at `ip:port`.
string answer(string ip, ushort port, bool ipv6, Fingerprint serverFingerprint, string clientUfrag)
{
	return render(serverTemplate, ip, port, ipv6, serverFingerprint, clientUfrag);
}

/// The client's offer towards `ip:port`, with the all-ones placeholder fingerprint.
string offer(string ip, ushort port, bool ipv6, string clientUfrag)
{
	return render(clientTemplate, ip, port, ipv6, Fingerprint.FF, clientUfrag);
}

private string render(string tpl, string ip, ushort port, bool ipv6, Fingerprint fp, string ufrag)
{
	import std.conv : to;

	return tpl.replace("{ip_version}", ipv6 ? "IP6" : "IP4").replace("{target_ip}", ip)
		.replace("{target_port}", port.to!string).replace("{ufrag}", ufrag).replace("{pwd}", ufrag)
		.replace("{fingerprint_algorithm}", Fingerprint.algorithm)
		.replace("{fingerprint_value}", fp.toSdpFormat);
}

/// `libp2p+webrtc+v1/` and 64 alphanumerics.
string randomUfrag()
{
	enum alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	char[] s = new char[64];
	foreach (ref c; s)
		c = alphabet[uniform(0, alphabet.length)];
	return ufragPrefix ~ s.idup;
}
