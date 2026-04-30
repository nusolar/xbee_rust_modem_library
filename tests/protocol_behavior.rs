use std::fs;
use std::io;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::{Aes256Gcm, Key};
use base64ct::{Base64, Encoding};
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

use xbee_rust_modem_library::framing::{decode_cobs, encode_cobs};
use xbee_rust_modem_library::handshake::{
    HandshakeMsg, finish_client, finish_server, make_client_hello, respond_server_hello,
};
use xbee_rust_modem_library::keys::{
    load_ed25519_public_key, load_or_generate_ed25519_signing_key,
};
use xbee_rust_modem_library::replay::{InOrder, InOrderDecision};
use xbee_rust_modem_library::secure_packet::{open, seal};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct TestMessage {
    id: u32,
    payload: heapless::Vec<u8, 16>,
}

#[test]
fn cobs_framing_roundtrip_preserves_message() {
    let mut payload = heapless::Vec::<u8, 16>::new();
    payload.extend_from_slice(b"xbee").unwrap();
    let msg = TestMessage { id: 7, payload };

    let mut out = [0u8; 64];
    let framed = encode_cobs(&msg, &mut out).expect("encode failed");

    assert_eq!(framed.last(), Some(&0));
    assert!(!framed[..framed.len() - 1].contains(&0));

    let mut owned = framed.to_vec();
    let decoded: TestMessage = decode_cobs(&mut owned).expect("decode failed");

    assert_eq!(decoded, msg);
}

#[test]
fn replay_gate_accepts_only_strict_in_order_sequences() {
    let mut replay = InOrder::default();

    assert_eq!(replay.expected(), None);
    assert_eq!(replay.decide_and_update(0), InOrderDecision::Accept);
    assert_eq!(replay.expected(), Some(1));
    assert_eq!(
        replay.decide_and_update(0),
        InOrderDecision::DropOldOrDuplicate
    );
    assert_eq!(
        replay.decide_and_update(2),
        InOrderDecision::DropOutOfOrderAhead
    );
    assert_eq!(replay.expected(), Some(1));
    assert_eq!(replay.decide_and_update(1), InOrderDecision::Accept);
    assert_eq!(replay.expected(), Some(2));
}

#[test]
fn failed_authentication_does_not_need_to_advance_replay_state() {
    let key = *Key::<Aes256Gcm>::from_slice(&[0xA5u8; 32]);
    let mut replay = InOrder::default();

    let mut forged = seal(&key, [4, 4, 4, 4], 0, b"fake").expect("seal failed");
    forged.ciphertext_with_tag[0] ^= 0x01;

    assert!(open(&key, &forged).is_err());
    assert_eq!(replay.expected(), None);

    let valid = seal(&key, [4, 4, 4, 4], 0, b"real").expect("seal failed");
    assert!(open(&key, &valid).is_ok());
    assert_eq!(replay.decide_and_update(valid.seq), InOrderDecision::Accept);
    assert_eq!(replay.expected(), Some(1));
}

#[test]
fn signed_handshake_derives_matching_session_keys() {
    let mut rng = OsRng;
    let client_sk = SigningKey::generate(&mut rng);
    let server_sk = SigningKey::generate(&mut rng);

    let (client_hello, client_eph_secret, client_id_pub) = make_client_hello(&client_sk);
    let client_eph_pub = match &client_hello {
        HandshakeMsg::ClientHello { client_eph_pub, .. } => *client_eph_pub,
        _ => unreachable!(),
    };

    let (server_hello, server_eph_secret, client_id_pub_server, client_eph_pub_server) =
        respond_server_hello(&server_sk, &client_sk.verifying_key(), client_hello)
            .expect("server should accept authorized client");

    assert_eq!(client_id_pub_server, client_id_pub);
    assert_eq!(client_eph_pub_server, client_eph_pub);

    let (server_id_pub, server_eph_pub) = match &server_hello {
        HandshakeMsg::ServerHello {
            server_identity_pub,
            server_eph_pub,
            ..
        } => (*server_identity_pub, *server_eph_pub),
        _ => unreachable!(),
    };

    let (client_key, verified_server_id) = finish_client(
        &server_sk.verifying_key(),
        client_eph_secret,
        client_id_pub,
        client_eph_pub,
        server_hello,
    )
    .expect("client should accept authorized server");

    let server_key = finish_server(
        server_eph_secret,
        server_id_pub,
        server_eph_pub,
        client_id_pub_server,
        client_eph_pub_server,
    );

    assert_eq!(verified_server_id, server_id_pub);
    assert_eq!(client_key.as_slice(), server_key.as_slice());
}

#[test]
fn handshake_rejects_unauthorized_identities() {
    let mut rng = OsRng;
    let client_sk = SigningKey::generate(&mut rng);
    let server_sk = SigningKey::generate(&mut rng);
    let other_client_sk = SigningKey::generate(&mut rng);
    let other_server_sk = SigningKey::generate(&mut rng);

    let (client_hello, _, _) = make_client_hello(&client_sk);
    assert!(
        respond_server_hello(&server_sk, &other_client_sk.verifying_key(), client_hello).is_none()
    );

    let (client_hello, client_eph_secret, client_id_pub) = make_client_hello(&client_sk);
    let client_eph_pub = match &client_hello {
        HandshakeMsg::ClientHello { client_eph_pub, .. } => *client_eph_pub,
        _ => unreachable!(),
    };
    let (server_hello, _, _, _) =
        respond_server_hello(&server_sk, &client_sk.verifying_key(), client_hello)
            .expect("server should accept authorized client");

    assert!(
        finish_client(
            &other_server_sk.verifying_key(),
            client_eph_secret,
            client_id_pub,
            client_eph_pub,
            server_hello,
        )
        .is_none()
    );
}

#[test]
fn signing_key_is_generated_loaded_and_not_regenerated_for_invalid_data() {
    let dir = unique_test_dir("keys");
    fs::create_dir_all(&dir).expect("create test dir");
    let key_path = dir.join("device_ed25519.key");

    let generated = load_or_generate_ed25519_signing_key(&key_path).expect("generate key");
    assert!(key_path.exists());
    assert!(key_path.with_extension("pub").exists());

    let loaded = load_or_generate_ed25519_signing_key(&key_path).expect("load key");
    assert_eq!(generated.to_bytes(), loaded.to_bytes());

    let public_key = load_ed25519_public_key(&key_path.with_extension("pub")).expect("load pub");
    assert_eq!(public_key.to_bytes(), generated.verifying_key().to_bytes());

    fs::write(&key_path, "not base64").expect("write invalid key");
    let err = load_or_generate_ed25519_signing_key(&key_path).expect_err("invalid key should fail");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    assert_eq!(fs::read_to_string(&key_path).unwrap(), "not base64");

    fs::remove_dir_all(&dir).ok();
}

#[test]
fn public_key_loader_rejects_wrong_length_data() {
    let dir = unique_test_dir("bad-public-key");
    fs::create_dir_all(&dir).expect("create test dir");
    let key_path = dir.join("bad.pub");
    fs::write(&key_path, Base64::encode_string(&[1, 2, 3])).expect("write bad public key");

    let err = load_ed25519_public_key(&key_path).expect_err("short key should fail");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);

    fs::remove_dir_all(&dir).ok();
}

fn unique_test_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before unix epoch")
        .as_nanos();
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("test-data")
        .join(format!("{name}-{}-{nanos}", std::process::id()))
}
