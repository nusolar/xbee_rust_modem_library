use serialport::{DataBits, StopBits};
use std::io::{self, Write};
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use xbee_rust_modem_library::framing::{decode_cobs, encode_cobs};
use xbee_rust_modem_library::handshake::{finish_client, make_client_hello, HandshakeMsg};
use xbee_rust_modem_library::keys::{
    load_ed25519_public_key, load_or_generate_ed25519_signing_key, sender_id_from_pubkey,
};
use xbee_rust_modem_library::secure_packet::seal;
use xbee_rust_modem_library::serial::{discover_xbee_ports, XBeeDevice};

const BAUD: u32 = 9600;
const SEND_SETTLE_MS: u64 = 50;
const MAX_ENCODED_FRAME: usize = 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

fn main() {
    // ---- Serial port selection ----
    let ports = discover_xbee_ports();
    let port_name = ports
        .first()
        .cloned()
        .expect("No XBee device found. Check USB connection and permissions.");
    println!("Sender using port: {}", port_name);

    let mut dev = XBeeDevice::new(port_name, BAUD, StopBits::One, DataBits::Eight).unwrap();

    // ---- Identity keys (Ed25519) ----
    let signing_key_path = Path::new("keys/sender_ed25519.key");
    let sender_sk = load_or_generate_ed25519_signing_key(signing_key_path).unwrap();
    let sender_pk = sender_sk.verifying_key();
    let sender_id = sender_id_from_pubkey(&sender_pk);

    // ---- Trust anchor: authorized receiver public key ----
    // Copy receiver_ed25519.pub into keys/authorized_receiver.pub
    let authorized_receiver =
        load_ed25519_public_key(Path::new("keys/authorized_receiver.pub"))
            .expect("Missing keys/authorized_receiver.pub (copy receiver_ed25519.pub into it)");

    // ---- Handshake: derive AES-GCM session key ----
    // 1) Send ClientHello
    let (client_hello, client_eph_secret, client_id_pub) = make_client_hello(&sender_sk);
    send_msg(&mut dev, &client_hello);

    // 2) Receive ServerHello
    let server_hello: HandshakeMsg = recv_msg_blocking(&mut dev, HANDSHAKE_TIMEOUT)
        .expect("Timed out waiting for ServerHello during handshake");

    // Pull client ephemeral pub from the hello we already built
    let client_eph_pub = match &client_hello {
        HandshakeMsg::ClientHello { client_eph_pub, .. } => *client_eph_pub,
        _ => unreachable!(),
    };

    let (aes_key, _server_identity_pub) = finish_client(
        &authorized_receiver,
        client_eph_secret,
        client_id_pub,
        client_eph_pub,
        server_hello,
    )
    .expect("Handshake failed (bad receiver signature or wrong authorized receiver key)");

    println!("Handshake complete. Session AES-256-GCM key established.");

    // ---- Main send loop ----
    let mut seq: u64 = 0;

    loop {
        print!("Enter message to send (or 'quit'): ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin().read_line(&mut input).expect("read_line failed");
        let msg = input.trim_end_matches(['\n', '\r']);

        if msg == "quit" {
            return;
        }

        // Encrypt the plaintext (UTF-8 bytes are fine).
        let frame = seal(&aes_key, sender_id, seq, msg.as_bytes()).expect("seal failed");
        send_msg(&mut dev, &frame);

        println!("Sent seq={} ({} bytes plaintext).", seq, msg.len());
        seq = seq.wrapping_add(1);

        thread::sleep(Duration::from_millis(SEND_SETTLE_MS));
    }
}

/// Send any postcard-serializable message as COBS framed bytes.
fn send_msg<T: serde::Serialize>(dev: &mut XBeeDevice, msg: &T) {
    let mut out = [0u8; 1024];
    let framed = encode_cobs(msg, &mut out).expect("encode_cobs failed");
    dev.send(framed).unwrap();
}

/// Receive one COBS-framed message by scanning for 0x00 delimiter.
/// This is a blocking helper used during handshake.
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
