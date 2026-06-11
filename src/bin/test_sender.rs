use serialport::{DataBits, StopBits};
use std::path::Path;
use std::thread;
use std::time::Duration;

use xbee_rust_modem_library::keys::{
    load_ed25519_public_key, load_or_generate_ed25519_signing_key,
};
use xbee_rust_modem_library::serial::{discover_xbee_ports, XBeeDevice};
use xbee_rust_modem_library::session::SecureSender;
use xbee_rust_modem_library::transport::{xbee_destination, ApiModeTransport};

// Default UART baud — must match XCTU **BD** on both radios.
// 115200 keeps the UART from bottlenecking the RF link; set BD=7 in XCTU.
const BAUD: u32 = 115_200;
const SEND_INTERVAL_MS: u64 = 50;
const HANDSHAKE_RETRY: Duration = Duration::from_secs(2);

fn main() {
    // ---- Serial port selection ----
    let ports = discover_xbee_ports();
    let port_name = ports
        .first()
        .cloned()
        .expect("No XBee device found. Check USB connection and permissions.");
    println!("Sender using port: {}", port_name);

    let dev = XBeeDevice::new(port_name, BAUD, StopBits::One, DataBits::Eight).unwrap();
    let (dest64, dest16) = xbee_destination();
    eprintln!(
        "API mode (AP=2): RF dest 64-bit {dest64:#018x}, 16-bit {dest16:#06x} \
         (--xbee-dest64=<peer SH+SL> or XBEE_DEST64 env)"
    );
    let dev = ApiModeTransport::new(dev, dest64, dest16);

    // ---- Identity keys (Ed25519) ----
    let signing_key_path = Path::new("keys/sender_ed25519.key");
    let sender_sk = load_or_generate_ed25519_signing_key(signing_key_path).unwrap();

    // ---- Trust anchor: authorized receiver public key ----
    // Copy receiver_ed25519.pub into keys/authorized_receiver.pub
    let authorized_receiver = load_ed25519_public_key(Path::new("keys/authorized_receiver.pub"))
        .expect("Missing keys/authorized_receiver.pub (copy receiver_ed25519.pub into it)");

    // ---- Handshake: derive AES-GCM session key ----
    let mut sender = SecureSender::establish(dev, &sender_sk, &authorized_receiver, HANDSHAKE_RETRY)
        .expect("Handshake failed");
    println!("Handshake complete. Session AES-256-GCM key established.");

    // ---- Main send loop ----
    let mut n: u64 = 0;
    loop {
        let msg = n.to_string();
        sender.send_payload(msg.as_bytes()).expect("send failed");

        println!("Sent {msg}");
        n = n.wrapping_add(1);
        thread::sleep(Duration::from_millis(SEND_INTERVAL_MS));
    }
}
