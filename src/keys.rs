//! Identity key management.
//! We use Ed25519 for device identity.
//! - Each side has a SigningKey (private) and VerifyingKey (public).
//! - Keys are stored on disk in base64 to keep provisioning simple for a lab.

use std::{fs, io, path::Path};

use base64ct::{Base64, Encoding};
use ed25519_dalek::{SigningKey, VerifyingKey};

/// Load an Ed25519 signing key from `path`, or generate and save one if missing.
/// Also writes a `.pub` file next to it for convenience.
pub fn load_or_generate_ed25519_signing_key(path: &Path) -> io::Result<SigningKey> {
    if let Ok(s) = fs::read_to_string(path) {
        let bytes = Base64::decode_vec(s.trim())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("base64 decode: {e}")))?;
        let sk_bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "signing key must be 32 bytes"))?;
        let sk = SigningKey::from_bytes(&sk_bytes);
        return Ok(sk);
    }

    // Missing key -> generate a new one
    let mut rng = rand_core::OsRng;
    let sk = SigningKey::generate(&mut rng);

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Save private key (32 bytes)
    let b64 = Base64::encode_string(sk.to_bytes().as_slice());
    fs::write(path, b64)?;

    // Save public key next to it
    let pk_path = path.with_extension("pub");
    let pk = sk.verifying_key();
    let pk_b64 = Base64::encode_string(pk.to_bytes().as_slice());
    fs::write(pk_path, pk_b64)?;

    Ok(sk)
}

/// Load an Ed25519 verifying key (public key) from a base64 file.
pub fn load_ed25519_public_key(path: &Path) -> io::Result<VerifyingKey> {
    let s = fs::read_to_string(path)?;
    let bytes = Base64::decode_vec(s.trim())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("base64 decode: {e}")))?;
    let pk_bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "public key must be 32 bytes"))?;
    Ok(VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("bad public key: {e}")))?)
}

/// A small “sender id” used in headers/logging.
/// This is NOT security-critical; it’s just an identifier.
/// We derive it from the public key bytes.
pub fn sender_id_from_pubkey(pk: &VerifyingKey) -> [u8; 4] {
    use sha2::{Digest, Sha256};
    let h = Sha256::digest(pk.to_bytes());
    [h[0], h[1], h[2], h[3]]
}