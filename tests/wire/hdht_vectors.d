// GENERATED from hyperdht messages.js/persistent.js logic.
module tests.wire.hdht_vectors;

struct HDVec{string name;string hex;}

immutable HDVec[] hdhtVectors=[
    HDVec("ns_announce", "36386adddf9f6fd60db83a6f42fc159d1146aa8644037664230aaa1f0179d497"),
    HDVec("pubkey_seed3", "ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d1"),
    HDVec("peer_enc", "ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d101010203040500"),
    HDVec("sign_announce", "bfee57d455fa70e4ae159252e9876c866ddd566188c26de78aec598dd21f657368e33111e042b642bd53a8927f2ed0579b08ff0d68788ffba235717b2097b20f"),
    HDVec("announce_signed", "05ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d101010203040500bfee57d455fa70e4ae159252e9876c866ddd566188c26de78aec598dd21f657368e33111e042b642bd53a8927f2ed0579b08ff0d68788ffba235717b2097b20f"),
];
