use serialport::{DataBits, StopBits};
use std::io::{self, Write};
use std::path::Path;
use std::time::{Duration, Instant};

use xbee_rust_modem_library::keys::{
    load_ed25519_public_key, load_or_generate_ed25519_signing_key, sender_id_from_pubkey,
};
use xbee_rust_modem_library::serial::{discover_xbee_ports, XBeeDevice};
use xbee_rust_modem_library::session::SecureReceiver;
use xbee_rust_modem_library::transport::{xbee_destination, ApiModeTransport};

// Default UART baud — must match XCTU **BD** on both radios.
// API mode (AP=2) is used; raise baud after verifying the link end-to-end.
const BAUD: u32 = 9600;

fn main() {
    // ---- Serial port selection ----
    let ports = discover_xbee_ports();
    let port_name = ports
        .first()
        .cloned()
        .expect("No XBee device found. Check USB connection and permissions.");
    println!("Receiver using port: {}", port_name);

    let dev = XBeeDevice::new(port_name, BAUD, StopBits::One, DataBits::Eight).unwrap();
    // Default is broadcast; the session locks onto the sender's address once
    // its ClientHello arrives, so XBEE_DEST64 is optional on this side.
    let (dest64, dest16) = xbee_destination();
    let dev = ApiModeTransport::new(dev, dest64, dest16);

    // ---- Identity keys (Ed25519) ----
    let signing_key_path = Path::new("keys/receiver_ed25519.key");
    let receiver_sk = load_or_generate_ed25519_signing_key(signing_key_path).unwrap();
    let receiver_id = sender_id_from_pubkey(&receiver_sk.verifying_key());

    // ---- Trust anchor: authorized sender public key ----
    // Copy sender_ed25519.pub into keys/authorized_sender.pub
    let authorized_sender = load_ed25519_public_key(Path::new("keys/authorized_sender.pub"))
        .expect("Missing keys/authorized_sender.pub (copy sender_ed25519.pub into it)");

    // ---- Handshake ----
    let mut receiver = SecureReceiver::establish(dev, receiver_sk, authorized_sender)
        .expect("Handshake failed");
    println!(
        "Handshake complete. Authorized sender established session. receiver_id={:02x?}",
        receiver_id
    );

    // ---- Receive loop: decode -> in-order gate -> decrypt/auth ----
    let mut last_print = Instant::now();

    loop {
        match receiver.recv_payload(Some(Duration::from_millis(200))) {
            Ok(Some(plaintext)) => {
                io::stdout().write_all(plaintext.as_slice()).unwrap();
                io::stdout().write_all(b"\n").unwrap();
                io::stdout().flush().unwrap();
            }
            Ok(None) => {} // timeout: fall through to the stats line
            Err(e) => eprintln!("serial err: {e:?}"),
        }

        // Simple live “visualization” every 1 second
        if last_print.elapsed() >= Duration::from_secs(1) {
            let s = &receiver.stats;
            eprint!(
                "\rRX ok={} auth_fail={} dup/old_drop={} skipped={} decode_fail={} rehandshakes={}     ",
                s.ok, s.auth_fail, s.dup_or_old_drop, s.skipped_packets, s.decode_fail, s.rehandshakes
            );
            io::stderr().flush().ok();
            last_print = Instant::now();
        }
    }
}
