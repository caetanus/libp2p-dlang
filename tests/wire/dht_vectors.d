// GENERATED from dht-rpc io.js/peer.js logic via compact-encoding.
module tests.wire.dht_vectors;

struct DVec{string name;string hex;}

immutable DVec[] dhtVectors=[
    DVec("req:findnode", "030ccdab0102030449c2020707070707070707070707070707070707070707070707070707070707070707"),
    DVec("nodeid", "0d9535fc6d01006576c9e1923a4375cb3f12899e2d12d2d78ebd32197acbfb24"),
    DVec("req:ping", "030402010102030449c200"),
];
