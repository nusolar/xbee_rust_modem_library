use aes_gcm::{Aes256Gcm, Key};

use xbee_rust_modem_library::secure_packet::{MAX_PLAINTEXT, open, seal};

#[test]
fn encrypt_decrypt_roundtrip() {
    let key = *Key::<Aes256Gcm>::from_slice(&[0x42u8; 32]);

    let sender_id = [1, 2, 3, 4];
    let seq = 0u64;
    let plaintext = b"hello secure world";

    let frame = seal(&key, sender_id, seq, plaintext).expect("seal failed");

    let recovered = open(&key, &frame).expect("open failed");

    assert_eq!(recovered.as_slice(), plaintext);
}

#[test]
fn tamper_detection() {
    let key = *Key::<Aes256Gcm>::from_slice(&[0x11u8; 32]);

    let sender_id = [9, 9, 9, 9];
    let seq = 5;
    let plaintext = b"attack at dawn";

    let mut frame = seal(&key, sender_id, seq, plaintext).expect("seal failed");

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

    let frame = seal(&key1, sender_id, seq, plaintext).expect("seal failed");

    assert!(open(&key2, &frame).is_err());
}

#[test]
fn nonce_tampering_fails_before_decrypt() {
    let key = *Key::<Aes256Gcm>::from_slice(&[0xCCu8; 32]);
    let mut frame = seal(&key, [1, 1, 1, 1], 10, b"nonce matters").expect("seal failed");

    frame.nonce[0] ^= 0x01;

    assert_eq!(open(&key, &frame), Err("bad nonce"));
}

#[test]
fn sender_id_tampering_fails_nonce_check() {
    let key = *Key::<Aes256Gcm>::from_slice(&[0xDDu8; 32]);
    let mut frame = seal(&key, [2, 2, 2, 2], 11, b"sender matters").expect("seal failed");

    frame.sender_id[0] ^= 0x01;

    assert_eq!(open(&key, &frame), Err("bad nonce"));
}

#[test]
fn plaintext_size_limit_is_enforced() {
    let key = *Key::<Aes256Gcm>::from_slice(&[0xEEu8; 32]);
    let at_limit = vec![0xAB; MAX_PLAINTEXT];
    let over_limit = vec![0xAB; MAX_PLAINTEXT + 1];

    assert!(seal(&key, [3, 3, 3, 3], 0, &at_limit).is_ok());
    assert_eq!(
        seal(&key, [3, 3, 3, 3], 1, &over_limit).expect_err("over-limit plaintext should fail"),
        "plaintext too large"
    );
}
