/// ngtcp2_crypto binding — the bridge from ngtcp2 (transport) to OpenSSL's TLS 1.3
/// QUIC handshake (libngtcp2_crypto_ossl). Hand-bound extern(C) declarations — the C
/// ABI, translated straight from /usr/include/ngtcp2/ngtcp2_crypto{,_ossl}.h (1.25.0);
/// dstep would drag in all of OpenSSL. Needs OpenSSL 3.5+ (the QUIC-TLS API).
///
/// The callback helpers below (ngtcp2_crypto_*_cb) are C functions in
/// libngtcp2_crypto_ossl whose signatures MATCH the ngtcp2_callbacks fields in
/// ngtcp2.d — assigning `&ngtcp2_crypto_encrypt_cb` into a callbacks struct is itself
/// the ABI check (a mismatch is a compile error). Opt-in behind version(Libp2pQuic).
module libp2p.transport.quic.ngtcp2_crypto;

version (Libp2pQuic):

import deimos.openssl.ssl : SSL;
import libp2p.transport.quic.ngtcp2;

// SSL <-> ngtcp2_conn back-reference. ngtcp2_crypto_ossl reads SSL_get_ex_data(ssl,0)
// (== app_data), expecting an ngtcp2_crypto_conn_ref*, then get_conn() for the conn.
extern (C) alias ngtcp2_crypto_get_conn = ngtcp2_conn* function(ngtcp2_crypto_conn_ref* conn_ref);

struct ngtcp2_crypto_conn_ref
{
    ngtcp2_crypto_get_conn get_conn;
    void* user_data;
}

extern (C):

// --- libngtcp2_crypto_ossl (OpenSSL glue) ---
struct ngtcp2_crypto_ossl_ctx;

ngtcp2_encryption_level ngtcp2_crypto_ossl_from_ossl_encryption_level(uint ossl_level);
uint ngtcp2_crypto_ossl_from_ngtcp2_encryption_level(ngtcp2_encryption_level level);
int ngtcp2_crypto_ossl_ctx_new(ngtcp2_crypto_ossl_ctx** pctx, SSL* ssl);
void ngtcp2_crypto_ossl_ctx_del(ngtcp2_crypto_ossl_ctx* ctx);
void ngtcp2_crypto_ossl_ctx_set_ssl(ngtcp2_crypto_ossl_ctx* ctx, SSL* ssl);
SSL* ngtcp2_crypto_ossl_ctx_get_ssl(ngtcp2_crypto_ossl_ctx* ctx);
int ngtcp2_crypto_ossl_init();
void ngtcp2_crypto_ossl_free();
int ngtcp2_crypto_ossl_configure_server_session(SSL* ssl);
int ngtcp2_crypto_ossl_configure_client_session(SSL* ssl);

// --- ngtcp2_crypto callback helpers (fill one ngtcp2_callbacks field each) ---
int ngtcp2_crypto_client_initial_cb(ngtcp2_conn* conn, void* user_data);
int ngtcp2_crypto_recv_client_initial_cb(ngtcp2_conn* conn, const(ngtcp2_cid)* dcid,
    void* user_data);
int ngtcp2_crypto_recv_crypto_data_cb(ngtcp2_conn* conn,
    ngtcp2_encryption_level encryption_level, ulong offset, const(ubyte)* data,
    size_t datalen, void* user_data);
int ngtcp2_crypto_encrypt_cb(ubyte* dest, const(ngtcp2_crypto_aead)* aead,
    const(ngtcp2_crypto_aead_ctx)* aead_ctx, const(ubyte)* plaintext,
    size_t plaintextlen, const(ubyte)* nonce, size_t noncelen, const(ubyte)* aad,
    size_t aadlen);
int ngtcp2_crypto_decrypt_cb(ubyte* dest, const(ngtcp2_crypto_aead)* aead,
    const(ngtcp2_crypto_aead_ctx)* aead_ctx, const(ubyte)* ciphertext,
    size_t ciphertextlen, const(ubyte)* nonce, size_t noncelen, const(ubyte)* aad,
    size_t aadlen);
int ngtcp2_crypto_hp_mask_cb(ubyte* dest, const(ngtcp2_crypto_cipher)* hp,
    const(ngtcp2_crypto_cipher_ctx)* hp_ctx, const(ubyte)* sample);
int ngtcp2_crypto_recv_retry_cb(ngtcp2_conn* conn, const(ngtcp2_pkt_hd)* hd,
    void* user_data);

// Retry / address-validation token helpers (server side). generate_retry_token +
// write_retry produce a Retry packet; verify_retry_token validates the echoed token
// and recovers the original DCID. Keyed by a server-held secret.
ngtcp2_ssize ngtcp2_crypto_generate_retry_token(ubyte* token, const(ubyte)* secret,
    size_t secretlen, uint version_, const(ngtcp2_sockaddr)* remote_addr,
    ngtcp2_socklen remote_addrlen, const(ngtcp2_cid)* retry_scid,
    const(ngtcp2_cid)* odcid, ngtcp2_tstamp ts);
int ngtcp2_crypto_verify_retry_token(ngtcp2_cid* odcid, const(ubyte)* token,
    size_t tokenlen, const(ubyte)* secret, size_t secretlen, uint version_,
    const(ngtcp2_sockaddr)* remote_addr, ngtcp2_socklen remote_addrlen,
    const(ngtcp2_cid)* dcid, ngtcp2_duration timeout, ngtcp2_tstamp ts);
ngtcp2_ssize ngtcp2_crypto_write_retry(ubyte* dest, size_t destlen, uint version_,
    const(ngtcp2_cid)* dcid, const(ngtcp2_cid)* scid, const(ngtcp2_cid)* odcid,
    const(ubyte)* token, size_t tokenlen);
int ngtcp2_crypto_update_key_cb(ngtcp2_conn* conn, ubyte* rx_secret, ubyte* tx_secret,
    ngtcp2_crypto_aead_ctx* rx_aead_ctx, ubyte* rx_iv, ngtcp2_crypto_aead_ctx* tx_aead_ctx,
    ubyte* tx_iv, const(ubyte)* current_rx_secret, const(ubyte)* current_tx_secret,
    size_t secretlen, void* user_data);
void ngtcp2_crypto_delete_crypto_aead_ctx_cb(ngtcp2_conn* conn,
    ngtcp2_crypto_aead_ctx* aead_ctx, void* user_data);
void ngtcp2_crypto_delete_crypto_cipher_ctx_cb(ngtcp2_conn* conn,
    ngtcp2_crypto_cipher_ctx* cipher_ctx, void* user_data);
int ngtcp2_crypto_get_path_challenge_data_cb(ngtcp2_conn* conn, ubyte* data,
    void* user_data);
int ngtcp2_crypto_version_negotiation_cb(ngtcp2_conn* conn, uint version_,
    const(ngtcp2_cid)* client_dcid, void* user_data);
