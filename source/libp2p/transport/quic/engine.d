/// QUIC engine glue: the small D pieces ngtcp2 needs that aren't crypto — a CSPRNG
/// callback, connection-id minting, monotonic time, random CIDs, and the two
/// `ngtcp2_callbacks` tables (client/server) that wire ngtcp2_crypto's helpers plus
/// these D callbacks. Assigning each `&fn` into a callbacks field is the ABI check.
/// Opt-in behind version(Libp2pQuic).
module libp2p.transport.quic.engine;

version (Libp2pQuic):

import libsodium : randombytes_buf;

import libp2p.transport.quic.ngtcp2;
import libp2p.transport.quic.ngtcp2_crypto;

/// Monotonic nanoseconds — ngtcp2's timestamp domain.
ulong nowNanos() nothrow @nogc
{
    import core.sys.posix.time : clock_gettime, timespec, CLOCK_MONOTONIC;

    timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return cast(ulong) t.tv_sec * 1_000_000_000UL + cast(ulong) t.tv_nsec;
}

/// A fresh random 16-byte connection id.
ngtcp2_cid randomCid()
{
    ubyte[16] bytes;
    randombytes_buf(bytes.ptr, bytes.length);
    ngtcp2_cid cid;
    ngtcp2_cid_init(&cid, bytes.ptr, bytes.length);
    return cid;
}

// ngtcp2's CSPRNG hook — fill dest with random bytes (libsodium).
extern (C) void quicRand(ubyte* dest, size_t destlen, const(ngtcp2_rand_ctx)* rand_ctx)
{
    randombytes_buf(dest, destlen);
}

// ngtcp2 asks us to mint a new connection id + its stateless-reset token.
extern (C) int quicGetNewConnectionId(ngtcp2_conn* conn, ngtcp2_cid* cid, ubyte* token,
    size_t cidlen, void* user_data)
{
    ubyte[NGTCP2_MAX_CIDLEN] buf;
    randombytes_buf(buf.ptr, cidlen);
    ngtcp2_cid_init(cid, buf.ptr, cidlen);
    randombytes_buf(token, NGTCP2_STATELESS_RESET_TOKENLEN);
    return 0;
}

/// Transport-params defaults set every flow-control/stream limit to 0; without these
/// no stream opens (STREAM_ID_BLOCKED) and no data flows.
void setStreamLimits(ref ngtcp2_transport_params p) nothrow @nogc
{
    // Spare connection ids for the peer to move to: a connection that follows its
    // peer through NAT rebindings spends one per move (RFC 9000 §9.5).
    p.active_connection_id_limit = 4;
    p.initial_max_streams_bidi = 128;
    p.initial_max_streams_uni = 128;
    p.initial_max_stream_data_bidi_local = 1024 * 1024;
    p.initial_max_stream_data_bidi_remote = 1024 * 1024;
    p.initial_max_stream_data_uni = 1024 * 1024;
    p.initial_max_data = 4 * 1024 * 1024;
    // A quiet but LIVE connection stays open as long as the application likes: the
    // keep-alive PING (quicKeepAliveNs, set on the conn) refreshes it well before this
    // runs out. What the idle timeout catches is the peer no ownership path can see —
    // one killed or roamed to another network, which never sends CONNECTION_CLOSE.
    // Without it (0 = none) such a connection, its pump and ngtcp2/TLS state are held
    // forever.
    p.max_idle_timeout = quicIdleTimeoutNs;
}

/// Transport-param idle timeout (ngtcp2 durations are nanoseconds).
enum ulong quicIdleTimeoutNs = 120UL * 1_000_000_000;
/// Keep-alive: PING after this much quiet, so a healthy idle link never reaches the
/// idle timeout — ours, or a peer's shorter one.
enum ulong quicKeepAliveNs = 20UL * 1_000_000_000;

/// The client callbacks table: ngtcp2_crypto's TLS helpers + our D rand/cid.
ngtcp2_callbacks clientCallbacks()
{
    ngtcp2_callbacks cb;
    cb.client_initial = &ngtcp2_crypto_client_initial_cb;
    cb.recv_crypto_data = &ngtcp2_crypto_recv_crypto_data_cb;
    cb.encrypt = &ngtcp2_crypto_encrypt_cb;
    cb.decrypt = &ngtcp2_crypto_decrypt_cb;
    cb.hp_mask = &ngtcp2_crypto_hp_mask_cb;
    cb.recv_retry = &ngtcp2_crypto_recv_retry_cb;
    cb.update_key = &ngtcp2_crypto_update_key_cb;
    cb.delete_crypto_aead_ctx = &ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    cb.delete_crypto_cipher_ctx = &ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    cb.get_path_challenge_data = &ngtcp2_crypto_get_path_challenge_data_cb;
    cb.version_negotiation = &ngtcp2_crypto_version_negotiation_cb;
    cb.rand = &quicRand;
    cb.get_new_connection_id = &quicGetNewConnectionId;
    return cb;
}

/// The server callbacks table: like the client's, but recv_client_initial replaces
/// client_initial.
ngtcp2_callbacks serverCallbacks()
{
    ngtcp2_callbacks cb;
    cb.recv_client_initial = &ngtcp2_crypto_recv_client_initial_cb;
    cb.recv_crypto_data = &ngtcp2_crypto_recv_crypto_data_cb;
    cb.encrypt = &ngtcp2_crypto_encrypt_cb;
    cb.decrypt = &ngtcp2_crypto_decrypt_cb;
    cb.hp_mask = &ngtcp2_crypto_hp_mask_cb;
    cb.recv_retry = &ngtcp2_crypto_recv_retry_cb;
    cb.update_key = &ngtcp2_crypto_update_key_cb;
    cb.delete_crypto_aead_ctx = &ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    cb.delete_crypto_cipher_ctx = &ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    cb.get_path_challenge_data = &ngtcp2_crypto_get_path_challenge_data_cb;
    cb.version_negotiation = &ngtcp2_crypto_version_negotiation_cb;
    cb.rand = &quicRand;
    cb.get_new_connection_id = &quicGetNewConnectionId;
    return cb;
}
