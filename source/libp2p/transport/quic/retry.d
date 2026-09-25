/// QUIC address validation via Retry (RFC 9000 §8.1.2), server side. A spoofed
/// source address cannot complete the round trip, so validating it BEFORE building
/// a full connection (ngtcp2 conn + OpenSSL session + timer + fiber) denies a
/// flood of forged Initials the ability to pin server resources. ngtcp2's crypto
/// helpers do the token AEAD + timestamp + address + odcid binding; we only choose
/// when to challenge and carry the recovered original DCID into the accept.
///
/// Scoped to the OPEN listener path: an expected punch (a peer we already met over
/// the DHT and are actively punching toward) skips Retry so the punch keeps its
/// single-round-trip latency.
module libp2p.transport.quic.retry;

version (Libp2pQuic):

import libp2p.transport.quic.ngtcp2;
import libp2p.transport.quic.ngtcp2_crypto;
import libp2p.transport.quic.engine : randomCid;
import libp2p.transport.quic.connection : ensureCryptoInit;

/// The server's Retry-token secret: 32 random bytes, generated once. A token is an
/// AEAD sealed by keys derived from this, so only this server accepts back its own.
struct RetrySecret
{
    ubyte[32] key;
    static RetrySecret random() @trusted
    {
        import std.random : uniform;
        RetrySecret s;
        foreach (ref b; s.key)
            b = cast(ubyte) uniform(0, 256);
        return s;
    }
}

/// How to handle an inbound Initial from an unvalidated address.
struct RetryOutcome
{
    enum Kind
    {
        drop, /// not an acceptable Initial, or a bad/expired token — ignore it
        challenge, /// send `packet` (a Retry) and allocate nothing
        proceed /// address validated: build the server conn with these retry params
    }

    Kind kind;
    ubyte[] packet; /// the Retry datagram to send (challenge)
    ngtcp2_cid odcid; /// original DCID recovered from the token (proceed)
    ngtcp2_cid retryScid; /// the SCID we put in the Retry, echoed as the client's DCID (proceed)
    ubyte[] token; /// the validated token, handed to ngtcp2 settings (proceed)
}

private enum ulong retryTokenTimeoutNs = 10UL * 1_000_000_000; // a token is good for 10 s

/// Decide what to do with `pkt` (a datagram from `remoteSa`, an unvalidated source).
/// `nowNs` is the ngtcp2 clock. Never throws.
RetryOutcome evaluateInitial(scope const(ubyte)[] pkt, scope const(ubyte)[] remoteSa,
    ref const RetrySecret secret, ulong nowNs) @trusted
{
    RetryOutcome outc;
    // The Retry integrity tag + token AEAD use ngtcp2's crypto backend; make sure it
    // is initialised (accept() also does, but a challenge happens BEFORE any accept).
    try
        ensureCryptoInit();
    catch (Exception)
    {
    }
    ngtcp2_pkt_hd hd;
    // Only a well-formed Initial that a server should answer gets past here.
    if (ngtcp2_accept(&hd, pkt.ptr, pkt.length) != 0)
    {
        outc.kind = RetryOutcome.Kind.drop;
        return outc;
    }
    auto ra = cast(const(ngtcp2_sockaddr)*) remoteSa.ptr;
    immutable ral = cast(ngtcp2_socklen) remoteSa.length;

    if (hd.tokenlen == 0)
    {
        // No token: challenge. Choose a fresh SCID for the Retry; the client must
        // echo it as its DCID in the next Initial, which binds the token to it.
        auto rscid = randomCid();
        ubyte[256] tokbuf;
        immutable tl = ngtcp2_crypto_generate_retry_token(tokbuf.ptr, secret.key.ptr,
            secret.key.length, hd.version_, ra, ral, &rscid, &hd.dcid, nowNs);
        if (tl < 0)
        {
            outc.kind = RetryOutcome.Kind.drop;
            return outc;
        }
        ubyte[256] pktbuf;
        immutable pl = ngtcp2_crypto_write_retry(pktbuf.ptr, pktbuf.length, hd.version_,
            &hd.scid, &rscid, &hd.dcid, tokbuf.ptr, cast(size_t) tl);
        if (pl < 0)
        {
            outc.kind = RetryOutcome.Kind.drop;
            return outc;
        }
        outc.kind = RetryOutcome.Kind.challenge;
        outc.packet = pktbuf[0 .. cast(size_t) pl].dup;
        return outc;
    }

    // Has a token: validate it against this source + the DCID it now carries (which
    // is the SCID we chose in the Retry). On success the original DCID comes back.
    ngtcp2_cid odcid;
    immutable ok = ngtcp2_crypto_verify_retry_token(&odcid, hd.token, hd.tokenlen,
        secret.key.ptr, secret.key.length, hd.version_, ra, ral, &hd.dcid,
        retryTokenTimeoutNs, nowNs);
    if (ok != 0)
    {
        outc.kind = RetryOutcome.Kind.drop; // forged / expired / wrong address
        return outc;
    }
    outc.kind = RetryOutcome.Kind.proceed;
    outc.odcid = odcid;
    outc.retryScid = hd.dcid; // the client echoed our Retry SCID here
    outc.token = hd.token[0 .. hd.tokenlen].dup;
    return outc;
}
