use aes_gcm::{Aes256Gcm, Key};
use aes_gcm::aead::KeyInit;

use xbee_rust_modem_library::secure_packet::{seal, open};

#[test]
fn encrypt_decrypt_roundtrip() {
    let key = *Key::<Aes256Gcm>::from_slice(&[0x42u8; 32]);

    let sender_id = [1, 2, 3, 4];
    let seq = 0u64;
    let plaintext = b"hello secure world";

    let frame = seal(&key, sender_id, seq, plaintext)
        .expect("seal failed");

    let recovered = open(&key, &frame)
        .expect("open failed");

    assert_eq!(recovered.as_slice(), plaintext);
}

#[test]
fn tamper_detection() {
    let key = *Key::<Aes256Gcm>::from_slice(&[0x11u8; 32]);

    let sender_id = [9, 9, 9, 9];
    let seq = 5;
    let plaintext = b"attack at dawn";

    let mut frame = seal(&key, sender_id, seq, plaintext)
        .expect("seal failed");

    // flip 1 bit
    frame.ciphertext_with_tag[0] ^= 0x01;

    assert!(open(&key, &frame).is_err());
}

#[test]
fn wrong_key_fails() {
    let key1 = *Key::<Aes256Gcm>::from_slice(&[0xAAu8; 32]);
    let key2 = *Key::<Aes256Gcm>::from_slice(&[0xBBu8; 32]);

    let sender_id = [7, 7, 7, 7];
    let seq = 42;
    let plaintext = b"super secret";

    let frame = seal(&key1, sender_id, seq, plaintext)
        .expect("seal failed");

    assert!(open(&key2, &frame).is_err());
}