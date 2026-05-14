use serialport::{DataBits, StopBits};
use std::io::{self, Write};
use std::path::Path;
use std::time::{Duration, Instant};

use xbee_rust_modem_library::framing::{decode_cobs, encode_cobs};
use xbee_rust_modem_library::handshake::{finish_server, respond_server_hello, HandshakeMsg};
use xbee_rust_modem_library::keys::{
    load_ed25519_public_key, load_or_generate_ed25519_signing_key, sender_id_from_pubkey,
};
use xbee_rust_modem_library::replay::{InOrder, InOrderDecision};
use xbee_rust_modem_library::secure_packet::{open, SecureFrame};
use xbee_rust_modem_library::serial::{discover_xbee_ports, XBeeDevice};

const BAUD: u32 = 9600;
const MAX_ENCODED_FRAME: usize = 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Default)]
struct RxStats {
    ok: u64,
    auth_fail: u64,
    dup_or_old_drop: u64,
    missed_frames: u64,
    decode_fail: u64,
    rx_overflow: u64,
}

fn main() {
    // ---- Serial port selection ----
    let ports = discover_xbee_ports();
    let port_name = ports
        .first()
        .cloned()
        .expect("No XBee device found. Check USB connection and permissions.");
    println!("Receiver using port: {}", port_name);

    let mut dev = XBeeDevice::new(port_name, BAUD, StopBits::One, DataBits::Eight).unwrap();

    // ---- Identity keys (Ed25519) ----
    let signing_key_path = Path::new("keys/receiver_ed25519.key");
    let receiver_sk = load_or_generate_ed25519_signing_key(signing_key_path).unwrap();
    let receiver_pk = receiver_sk.verifying_key();
    let receiver_id = sender_id_from_pubkey(&receiver_pk);

    // ---- Trust anchor: authorized sender public key ----
    // Copy sender_ed25519.pub into keys/authorized_sender.pub
    let authorized_sender = load_ed25519_public_key(Path::new("keys/authorized_sender.pub"))
        .expect("Missing keys/authorized_sender.pub (copy sender_ed25519.pub into it)");

    // ---- Handshake ----
    // 1) Receive ClientHello
    let client_hello: HandshakeMsg = recv_msg_blocking(&mut dev, HANDSHAKE_TIMEOUT)
        .expect("Timed out waiting for ClientHello during handshake");

    // 2) Verify + respond with ServerHello
    let (server_hello, server_eph_secret, client_id_pub, client_eph_pub) =
        respond_server_hello(&receiver_sk, &authorized_sender, client_hello)
            .expect("ClientHello invalid or sender not authorized");

    // Need our own server eph pub to finish on server side:
    let (server_id_pub, server_eph_pub) = match &server_hello {
        HandshakeMsg::ServerHello {
            server_identity_pub,
            server_eph_pub,
            ..
        } => (*server_identity_pub, *server_eph_pub),
        _ => unreachable!(),
    };

    send_msg(&mut dev, &server_hello);

    // 3) Derive session key
    let aes_key = finish_server(
        server_eph_secret,
        server_id_pub,
        server_eph_pub,
        client_id_pub,
        client_eph_pub,
    );

    println!(
        "Handshake complete. Authorized sender established session. receiver_id={:02x?}",
        receiver_id
    );

    // ---- Receive loop: decode -> in-order gate -> decrypt/auth ----
    let mut inorder = InOrder::default();
    let mut stats = RxStats::default();
    let mut last_print = Instant::now();

    let mut chunk = [0u8; 512];
    let mut rx: Vec<u8> = Vec::new();

    loop {
        match dev.receive(&mut chunk) {
            Ok(n) if n > 0 => {
                if rx.len() + n > MAX_ENCODED_FRAME {
                    stats.rx_overflow += 1;
                    rx.clear();
                }

                rx.extend_from_slice(&chunk[..n]);

                while let Some(pos) = rx.iter().position(|b| *b == 0x00) {
                    let mut frame_bytes: Vec<u8> = rx.drain(..=pos).collect();

                    // Decode SecureFrame
                    let frame: SecureFrame = match decode_cobs(frame_bytes.as_mut_slice()) {
                        Ok(f) => f,
                        Err(_) => {
                            stats.decode_fail += 1;
                            continue;
                        }
                    };

                    // Strict in-order gate BEFORE decrypt (cheap)
                    match inorder.decide(frame.seq) {
                        InOrderDecision::Accept => {}
                        InOrderDecision::DropOldOrDuplicate => {
                            stats.dup_or_old_drop += 1;
                            continue;
                        }
                        InOrderDecision::AcceptWithGap { missed } => {
                            stats.missed_frames += missed;
                        }
                    }

                    // Decrypt/authenticate
                    match open(&aes_key, &frame) {
                        Ok(plaintext) => {
                            inorder.mark_accepted(frame.seq);
                            stats.ok += 1;
                            io::stdout().write_all(plaintext.as_slice()).unwrap();
                            io::stdout().write_all(b"\n").unwrap();
                            io::stdout().flush().unwrap();
                        }
                        Err(_) => {
                            stats.auth_fail += 1;
                        }
                    }
                }
            }
            Ok(_) => {}
            Err(ref e) if e.kind() == io::ErrorKind::TimedOut => {}
            Err(e) => eprintln!("serial err: {e:?}"),
        }

        // Simple live “visualization” every 1 second
        if last_print.elapsed() >= Duration::from_secs(1) {
            eprint!(
                "\rRX ok={} auth_fail={} dup/old_drop={} missed={} decode_fail={} rx_overflow={}     ",
                stats.ok,
                stats.auth_fail,
                stats.dup_or_old_drop,
                stats.missed_frames,
                stats.decode_fail,
                stats.rx_overflow
            );
            io::stderr().flush().ok();
            last_print = Instant::now();
        }
    }
}

fn send_msg<T: serde::Serialize>(dev: &mut XBeeDevice, msg: &T) {
    let mut out = [0u8; 1024];
    let framed = encode_cobs(msg, &mut out).expect("encode_cobs failed");
    dev.send(framed).unwrap();
}

fn recv_msg_blocking<T: serde::de::DeserializeOwned>(
    dev: &mut XBeeDevice,
    timeout: Duration,
) -> io::Result<T> {
    let deadline = Instant::now() + timeout;
    let mut chunk = [0u8; 512];
    let mut rx: Vec<u8> = Vec::new();

    while Instant::now() < deadline {
        match dev.receive(&mut chunk) {
            Ok(n) if n > 0 => {
                if rx.len() + n > MAX_ENCODED_FRAME {
                    rx.clear();
                }

                rx.extend_from_slice(&chunk[..n]);
                if let Some(pos) = rx.iter().position(|b| *b == 0x00) {
                    let mut frame: Vec<u8> = rx.drain(..=pos).collect();
                    match decode_cobs(frame.as_mut_slice()) {
                        Ok(msg) => return Ok(msg),
                        Err(_) => continue,
                    }
                }
            }
            Ok(_) => {}
            Err(ref e) if e.kind() == io::ErrorKind::TimedOut => {}
            Err(e) => return Err(e),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "timed out waiting for framed handshake message",
    ))
}
