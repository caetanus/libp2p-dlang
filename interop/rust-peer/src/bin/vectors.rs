//! Emit signature test vectors, produced by rust-libp2p itself.
//!
//! The point is provenance. A vector this repository generates and then asserts
//! against proves only that the code agrees with itself — and if a key format
//! was read wrongly, it was read wrongly at both ends. These come out of the
//! reference implementation, so they disagree with us when we are wrong.
//!
//! Prints, per key type: the `PublicKey` protobuf as libp2p serialises it, the
//! message, a signature over it, and the PeerId it derives. Hex.

use libp2p::identity::Keypair;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn emit(name: &str, kp: &Keypair) {
    let msg = b"libp2p-dlang interop vector";
    let sig = kp.sign(msg).expect("signing");
    println!("{name} pubkey {}", hex(&kp.public().encode_protobuf()));
    println!("{name} msg {}", hex(msg));
    println!("{name} sig {}", hex(&sig));
    println!("{name} peerid {}", kp.public().to_peer_id());
}

fn main() {
    emit("ed25519", &Keypair::generate_ed25519());
    emit("secp256k1", &Keypair::generate_secp256k1());
    emit("ecdsa", &Keypair::generate_ecdsa());
}
