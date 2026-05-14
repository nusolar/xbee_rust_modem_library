//! Signed handshake to establish a shared AES-256-GCM session key.
//!
//! We do:
//! 1) X25519 ephemeral key exchange -> shared secret
//! 2) Ed25519 signatures authenticate ephemeral pubkeys (prevents spoofing / wrong sender)
//! 3) HKDF-SHA256 derives a 32-byte AES key from the shared secret + transcript
//!
//! The result is a per-run session key. That makes nonce/seq management MUCH easier.

use aes_gcm::{Aes256Gcm, Key};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};

/// Handshake messages are COBS-framed with postcard.
#[derive(Debug, Serialize, Deserialize)]
pub enum HandshakeMsg {
    /// Sent by the initiator (sender)
    ClientHello {
        client_identity_pub: [u8; 32], // Ed25519 public key
        client_eph_pub: [u8; 32],      // X25519 public key
        sig: Vec<u8>,                  // 64 bytes: Ed25519 signature
    },
    /// Sent by the responder (receiver)
    ServerHello {
        server_identity_pub: [u8; 32],
        server_eph_pub: [u8; 32],
        sig: Vec<u8>, // 64 bytes
    },
}

/// Domain separation labels to avoid cross-protocol signature confusion.
const CLIENT_LABEL: &[u8] = b"XBeeSecure/ClientHello/v1";
const SERVER_LABEL: &[u8] = b"XBeeSecure/ServerHello/v1";

fn sign_client(sk: &SigningKey, client_id_pub: [u8; 32], client_eph_pub: [u8; 32]) -> Vec<u8> {
    // Sign(label || client_id_pub || client_eph_pub)
    let mut msg = Vec::with_capacity(CLIENT_LABEL.len() + 32 + 32);
    msg.extend_from_slice(CLIENT_LABEL);
    msg.extend_from_slice(&client_id_pub);
    msg.extend_from_slice(&client_eph_pub);

    sk.sign(&msg).to_bytes().to_vec()
}

fn verify_client(
    pk: &VerifyingKey,
    client_id_pub: [u8; 32],
    client_eph_pub: [u8; 32],
    sig: &[u8],
) -> bool {
    if sig.len() != 64 {
        return false;
    }
    let Ok(sig_arr) = <[u8; 64]>::try_from(sig) else {
        return false;
    };
    let sig = Signature::from_bytes(&sig_arr);

    let mut msg = Vec::with_capacity(CLIENT_LABEL.len() + 32 + 32);
    msg.extend_from_slice(CLIENT_LABEL);
    msg.extend_from_slice(&client_id_pub);
    msg.extend_from_slice(&client_eph_pub);

    pk.verify(&msg, &sig).is_ok()
}

fn sign_server(
    sk: &SigningKey,
    server_id_pub: [u8; 32],
    server_eph_pub: [u8; 32],
    // Bind to client's values too, so server signature is tied to this exact session
    client_id_pub: [u8; 32],
    client_eph_pub: [u8; 32],
) -> Vec<u8> {
    // Sign(label || server_id_pub || server_eph_pub || client_id_pub || client_eph_pub)
    let mut msg = Vec::with_capacity(SERVER_LABEL.len() + 32 + 32 + 32 + 32);
    msg.extend_from_slice(SERVER_LABEL);
    msg.extend_from_slice(&server_id_pub);
    msg.extend_from_slice(&server_eph_pub);
    msg.extend_from_slice(&client_id_pub);
    msg.extend_from_slice(&client_eph_pub);

    sk.sign(&msg).to_bytes().to_vec()
}

fn verify_server(
    pk: &VerifyingKey,
    server_id_pub: [u8; 32],
    server_eph_pub: [u8; 32],
    client_id_pub: [u8; 32],
    client_eph_pub: [u8; 32],
    sig: &[u8],
) -> bool {
    if sig.len() != 64 {
        return false;
    }
    let Ok(sig_arr) = <[u8; 64]>::try_from(sig) else {
        return false;
    };
    let sig = Signature::from_bytes(&sig_arr);

    let mut msg = Vec::with_capacity(SERVER_LABEL.len() + 32 + 32 + 32 + 32);
    msg.extend_from_slice(SERVER_LABEL);
    msg.extend_from_slice(&server_id_pub);
    msg.extend_from_slice(&server_eph_pub);
    msg.extend_from_slice(&client_id_pub);
    msg.extend_from_slice(&client_eph_pub);

    pk.verify(&msg, &sig).is_ok()
}

/// Derive a 32-byte AES key using HKDF from:
/// - shared_secret (X25519)
/// - transcript data (both identity pubkeys + both eph pubkeys)
fn derive_aes_key(
    shared_secret: [u8; 32],
    client_id_pub: [u8; 32],
    server_id_pub: [u8; 32],
    client_eph_pub: [u8; 32],
    server_eph_pub: [u8; 32],
) -> Key<Aes256Gcm> {
    // "salt" can be empty for HKDF, but transcript as "info" is essential
    let hk = Hkdf::<Sha256>::new(None, &shared_secret);

    let mut info = Vec::with_capacity(32 * 4);
    info.extend_from_slice(&client_id_pub);
    info.extend_from_slice(&server_id_pub);
    info.extend_from_slice(&client_eph_pub);
    info.extend_from_slice(&server_eph_pub);

    let mut out = [0u8; 32];
    hk.expand(&info, &mut out).expect("hkdf expand");

    *Key::<Aes256Gcm>::from_slice(&out)
}

/// Initiator side (your "sender") creates a ClientHello.
pub fn make_client_hello(identity_sk: &SigningKey) -> (HandshakeMsg, EphemeralSecret, [u8; 32]) {
    let rng = OsRng;

    let client_eph_secret = EphemeralSecret::random_from_rng(rng);
    let client_eph_pub = PublicKey::from(&client_eph_secret).to_bytes();

    let client_id_pub = identity_sk.verifying_key().to_bytes();
    let sig = sign_client(identity_sk, client_id_pub, client_eph_pub);

    (
        HandshakeMsg::ClientHello {
            client_identity_pub: client_id_pub,
            client_eph_pub,
            sig,
        },
        client_eph_secret,
        client_id_pub,
    )
}

/// Responder side (your "receiver") verifies ClientHello and creates ServerHello.
/// `authorized_client` is the public key you trust for the sender.
pub fn respond_server_hello(
    identity_sk: &SigningKey,
    authorized_client: &VerifyingKey,
    client_msg: HandshakeMsg,
) -> Option<(HandshakeMsg, EphemeralSecret, [u8; 32], [u8; 32])> {
    let HandshakeMsg::ClientHello {
        client_identity_pub,
        client_eph_pub,
        sig,
    } = client_msg
    else {
        return None;
    };

    // Enforce "which sender is allowed":
    // client_identity_pub must match the authorized_client.
    if authorized_client.to_bytes() != client_identity_pub {
        return None;
    }

    if !verify_client(
        authorized_client,
        client_identity_pub,
        client_eph_pub,
        sig.as_slice(),
    ) {
        return None;
    }

    // Generate server ephemeral key
    let rng = OsRng;
    let server_eph_secret = EphemeralSecret::random_from_rng(rng);
    let server_eph_pub = PublicKey::from(&server_eph_secret).to_bytes();

    let server_id_pub = identity_sk.verifying_key().to_bytes();
    let server_sig = sign_server(
        identity_sk,
        server_id_pub,
        server_eph_pub,
        client_identity_pub,
        client_eph_pub,
    );

    Some((
        HandshakeMsg::ServerHello {
            server_identity_pub: server_id_pub,
            server_eph_pub,
            sig: server_sig,
        },
        server_eph_secret,
        client_identity_pub,
        client_eph_pub,
    ))
}

/// Client verifies ServerHello and derives the session AES key.
/// `authorized_server` is the public key you trust for the receiver.
pub fn finish_client(
    authorized_server: &VerifyingKey,
    client_eph_secret: EphemeralSecret,
    client_id_pub: [u8; 32],
    client_eph_pub: [u8; 32],
    server_msg: HandshakeMsg,
) -> Option<(Key<Aes256Gcm>, [u8; 32])> {
    let HandshakeMsg::ServerHello {
        server_identity_pub,
        server_eph_pub,
        sig,
    } = server_msg
    else {
        return None;
    };

    if authorized_server.to_bytes() != server_identity_pub {
        return None;
    }

    if !verify_server(
        authorized_server,
        server_identity_pub,
        server_eph_pub,
        client_id_pub,
        client_eph_pub,
        sig.as_slice(),
    ) {
        return None;
    }

    let server_pub = PublicKey::from(server_eph_pub);
    let shared = client_eph_secret.diffie_hellman(&server_pub).to_bytes();

    let key = derive_aes_key(
        shared,
        client_id_pub,
        server_identity_pub,
        client_eph_pub,
        server_eph_pub,
    );
    Some((key, server_identity_pub))
}

/// Server derives the session AES key after sending ServerHello.
pub fn finish_server(
    server_eph_secret: EphemeralSecret,
    server_id_pub: [u8; 32],
    server_eph_pub: [u8; 32],
    client_id_pub: [u8; 32],
    client_eph_pub: [u8; 32],
) -> Key<Aes256Gcm> {
    let client_pub = PublicKey::from(client_eph_pub);
    let shared = server_eph_secret.diffie_hellman(&client_pub).to_bytes();
    derive_aes_key(
        shared,
        client_id_pub,
        server_id_pub,
        client_eph_pub,
        server_eph_pub,
    )
}
