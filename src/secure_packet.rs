//! Secure data packets:
//! - seq: sequence number used for replay protection
//! - nonce: derived from (sender_id || seq) -> 12 bytes
//! - AES-256-GCM encrypts payload (confidentiality) and authenticates (integrity)
//! - AAD authenticates header fields (sender_id, seq) without encrypting them
//!
//! We send `ciphertext_with_tag` using heapless Vec.
//! For aes-gcm in-place API, the tag is appended to the buffer automatically.

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{AeadInPlace, KeyInit},
};
use serde::{Deserialize, Serialize};

use aes_gcm::aead::heapless::Vec as HeapVec;

/// Keep secured frames small enough to fit typical XBee 802.15.4 RF payloads.
/// The encrypted frame adds sender_id, seq, nonce, tag, and postcard/COBS overhead.
pub const MAX_PLAINTEXT: usize = 64;
/// AES-GCM adds a 16-byte authentication tag.
pub const TAG_SIZE: usize = 16;
/// Buffer capacity for ciphertext+tag.
pub const MAX_CIPHERTEXT: usize = MAX_PLAINTEXT + TAG_SIZE;

/// This is the on-the-wire secured frame.
/// It is *already encrypted*. Receiver decrypts to recover the plaintext.
#[derive(Debug, Serialize, Deserialize)]
pub struct SecureFrame {
    pub sender_id: [u8; 4],
    pub seq: u64,
    pub nonce: [u8; 12],
    pub ciphertext_with_tag: HeapVec<u8, MAX_CIPHERTEXT>,
}

/// Derive a deterministic nonce from sender_id + seq.
/// Because we use a new AES session key per run, seq can start at 0 each run safely.
/// Nonce uniqueness requirement is per (key, nonce), so per-run key rotation makes this easy.
pub fn derive_nonce(sender_id: [u8; 4], seq: u64) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[0..4].copy_from_slice(&sender_id);
    n[4..12].copy_from_slice(&seq.to_be_bytes());
    n
}

/// Build AAD: authenticate header fields without encrypting them.
/// This means attacker/corruption cannot modify sender_id/seq without failing auth.
fn build_aad(sender_id: [u8; 4], seq: u64) -> [u8; 12] {
    let mut aad = [0u8; 12];
    aad[0..4].copy_from_slice(&sender_id);
    aad[4..12].copy_from_slice(&seq.to_be_bytes());
    aad
}

/// Encrypt plaintext into a SecureFrame.
pub fn seal(
    aes_key: &Key<Aes256Gcm>,
    sender_id: [u8; 4],
    seq: u64,
    plaintext: &[u8],
) -> Result<SecureFrame, &'static str> {
    if plaintext.len() > MAX_PLAINTEXT {
        return Err("plaintext too large");
    }

    let cipher = Aes256Gcm::new(aes_key);

    let nonce_bytes = derive_nonce(sender_id, seq);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let aad = build_aad(sender_id, seq);

    // Use heapless Vec buffer so we avoid heap alloc.
    let mut buf: HeapVec<u8, MAX_CIPHERTEXT> = HeapVec::new();
    buf.extend_from_slice(plaintext)
        .map_err(|_| "buffer overflow")?;

    // Encrypt in-place: replaces plaintext with ciphertext and appends tag to end of buf.
    cipher
        .encrypt_in_place(nonce, &aad, &mut buf)
        .map_err(|_| "encrypt failed")?;

    Ok(SecureFrame {
        sender_id,
        seq,
        nonce: nonce_bytes,
        ciphertext_with_tag: buf,
    })
}

/// Decrypt a SecureFrame to plaintext.
pub fn open(
    aes_key: &Key<Aes256Gcm>,
    frame: &SecureFrame,
) -> Result<HeapVec<u8, MAX_PLAINTEXT>, &'static str> {
    let cipher = Aes256Gcm::new(aes_key);

    // Verify nonce matches our derivation rule (optional but good sanity check).
    let expected = derive_nonce(frame.sender_id, frame.seq);
    if frame.nonce != expected {
        return Err("bad nonce");
    }

    let nonce = Nonce::from_slice(&frame.nonce);
    let aad = build_aad(frame.sender_id, frame.seq);

    // Copy ciphertext+tag into a mutable buffer for in-place decrypt.
    let mut buf: HeapVec<u8, MAX_CIPHERTEXT> = HeapVec::new();
    buf.extend_from_slice(frame.ciphertext_with_tag.as_slice())
        .map_err(|_| "buffer overflow")?;

    cipher
        .decrypt_in_place(nonce, &aad, &mut buf)
        .map_err(|_| "auth/decrypt failed")?;

    // After decrypt_in_place, buf contains plaintext.
    let mut out: HeapVec<u8, MAX_PLAINTEXT> = HeapVec::new();
    out.extend_from_slice(buf.as_slice())
        .map_err(|_| "overflow")?;
    Ok(out)
}
