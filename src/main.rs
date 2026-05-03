use serialport::{DataBits, StopBits};
use std::env;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::thread;
use std::time::{Duration, Instant};

use xbee_rust_modem_library::framing::{decode_cobs, encode_cobs};
use xbee_rust_modem_library::handshake::{
    HandshakeMsg, finish_client, finish_server, make_client_hello, respond_server_hello,
};
use xbee_rust_modem_library::keys::{
    load_ed25519_public_key, load_or_generate_ed25519_signing_key, sender_id_from_pubkey,
};
use xbee_rust_modem_library::replay::{InOrder, InOrderDecision};
use xbee_rust_modem_library::secure_packet::{MAX_PLAINTEXT, SecureFrame, open, seal};
use xbee_rust_modem_library::serial::{TransparentRadioConfig, XBeeDevice, discover_xbee_ports};

const BAUD: u32 = 9600;
const SEND_SETTLE_MS: u64 = 50;
const RADIO_CONFIG: TransparentRadioConfig = TransparentRadioConfig {
    packetization_timeout: 0x14,
    xbee_retries: 0x03,
    mac_mode: 0x00,
    channel: 0x19,
};

#[derive(Clone, Copy)]
enum Role {
    Sender,
    Receiver,
}

#[derive(Default)]
struct RxStats {
    ok: u64,
    auth_fail: u64,
    dup_or_old_drop: u64,
    out_of_order_drop: u64,
    decode_fail: u64,
}

fn main() {
    match parse_role(env::args().skip(1)) {
        Ok(Role::Sender) => run_sender(),
        Ok(Role::Receiver) => run_receiver(),
        Err(message) => {
            eprintln!("{message}");
            eprintln!();
            print_usage();
            process::exit(2);
        }
    }
}

fn parse_role(args: impl IntoIterator<Item = String>) -> Result<Role, String> {
    let mut role = None;
    let mut args = args.into_iter();

    while let Some(arg) = args.next() {
        let parsed = match arg.as_str() {
            "--sender" | "-s" => Some(Role::Sender),
            "--receiver" | "-r" => Some(Role::Receiver),
            "--role" => {
                let value = args
                    .next()
                    .ok_or_else(|| "missing value after --role".to_string())?;
                Some(parse_role_value(&value)?)
            }
            "--help" | "-h" => {
                print_usage();
                process::exit(0);
            }
            _ if arg.starts_with("--role=") => Some(parse_role_value(&arg["--role=".len()..])?),
            _ => return Err(format!("unknown argument: {arg}")),
        };

        if let Some(parsed) = parsed {
            if role.is_some() {
                return Err("role was specified more than once".to_string());
            }
            role = Some(parsed);
        }
    }

    role.ok_or_else(|| "missing role flag".to_string())
}

fn parse_role_value(value: &str) -> Result<Role, String> {
    match value {
        "sender" => Ok(Role::Sender),
        "receiver" => Ok(Role::Receiver),
        _ => Err(format!("invalid role: {value}")),
    }
}

fn print_usage() {
    eprintln!("Usage:");
    eprintln!("  cargo run -- --sender");
    eprintln!("  cargo run -- --receiver");
    eprintln!("  cargo run -- --role sender");
    eprintln!("  cargo run -- --role receiver");
}

fn key_path(file_name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("keys")
        .join(file_name)
}

fn run_sender() {
    let ports = discover_xbee_ports();
    let port_name = ports
        .first()
        .cloned()
        .expect("No XBee device found. Check USB connection and permissions.");
    println!("Sender using port: {}", port_name);

    let mut dev = XBeeDevice::new(port_name, BAUD, StopBits::One, DataBits::Eight).unwrap();
    configure_radio_or_exit(&mut dev);

    let signing_key_path = key_path("sender_ed25519.key");
    let sender_sk = load_or_generate_ed25519_signing_key(&signing_key_path).unwrap();
    let sender_pk = sender_sk.verifying_key();
    let sender_id = sender_id_from_pubkey(&sender_pk);

    let authorized_receiver = load_ed25519_public_key(&key_path("authorized_receiver.pub"))
        .expect("Missing keys/authorized_receiver.pub (copy receiver_ed25519.pub into it)");

    let (client_hello, client_eph_secret, client_id_pub) = make_client_hello(&sender_sk);
    send_msg(&mut dev, &client_hello);

    let server_hello: HandshakeMsg = recv_msg_blocking(&mut dev);

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

        let frame = match seal(&aes_key, sender_id, seq, msg.as_bytes()) {
            Ok(frame) => frame,
            Err(err) => {
                eprintln!(
                    "Message not sent: {err}; max plaintext is {MAX_PLAINTEXT} bytes after UTF-8 encoding."
                );
                continue;
            }
        };
        send_msg(&mut dev, &frame);

        println!("Sent seq={} ({} bytes plaintext).", seq, msg.len());
        seq = seq.wrapping_add(1);

        thread::sleep(Duration::from_millis(SEND_SETTLE_MS));
    }
}

fn run_receiver() {
    let ports = discover_xbee_ports();
    let port_name = ports
        .first()
        .cloned()
        .expect("No XBee device found. Check USB connection and permissions.");
    println!("Receiver using port: {}", port_name);

    let mut dev = XBeeDevice::new(port_name, BAUD, StopBits::One, DataBits::Eight).unwrap();
    configure_radio_or_exit(&mut dev);

    let signing_key_path = key_path("receiver_ed25519.key");
    let receiver_sk = load_or_generate_ed25519_signing_key(&signing_key_path).unwrap();
    let receiver_pk = receiver_sk.verifying_key();
    let receiver_id = sender_id_from_pubkey(&receiver_pk);

    let authorized_sender = load_ed25519_public_key(&key_path("authorized_sender.pub"))
        .expect("Missing keys/authorized_sender.pub (copy sender_ed25519.pub into it)");

    let client_hello: HandshakeMsg = recv_msg_blocking(&mut dev);

    let (server_hello, server_eph_secret, client_id_pub, client_eph_pub) =
        respond_server_hello(&receiver_sk, &authorized_sender, client_hello)
            .expect("ClientHello invalid or sender not authorized");

    let (server_id_pub, server_eph_pub) = match &server_hello {
        HandshakeMsg::ServerHello {
            server_identity_pub,
            server_eph_pub,
            ..
        } => (*server_identity_pub, *server_eph_pub),
        _ => unreachable!(),
    };

    send_msg(&mut dev, &server_hello);

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

    let mut inorder = InOrder::default();
    let mut stats = RxStats::default();
    let mut last_print = Instant::now();

    let mut chunk = [0u8; 512];
    let mut rx: Vec<u8> = Vec::new();

    loop {
        match dev.receive(&mut chunk) {
            Ok(n) if n > 0 => {
                rx.extend_from_slice(&chunk[..n]);

                while let Some(pos) = rx.iter().position(|b| *b == 0x00) {
                    let mut frame_bytes: Vec<u8> = rx.drain(..=pos).collect();

                    let frame: SecureFrame = match decode_cobs(frame_bytes.as_mut_slice()) {
                        Ok(f) => f,
                        Err(_) => {
                            stats.decode_fail += 1;
                            continue;
                        }
                    };

                    match inorder.decide_and_update(frame.seq) {
                        InOrderDecision::Accept => {}
                        InOrderDecision::DropOldOrDuplicate => {
                            stats.dup_or_old_drop += 1;
                            continue;
                        }
                        InOrderDecision::DropOutOfOrderAhead => {
                            stats.out_of_order_drop += 1;
                            continue;
                        }
                    }

                    match open(&aes_key, &frame) {
                        Ok(plaintext) => {
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

        if last_print.elapsed() >= Duration::from_secs(1) {
            eprint!(
                "\rRX ok={} auth_fail={} dup/old_drop={} ooo_drop={} decode_fail={}     ",
                stats.ok,
                stats.auth_fail,
                stats.dup_or_old_drop,
                stats.out_of_order_drop,
                stats.decode_fail
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

fn configure_radio_or_exit(dev: &mut XBeeDevice) {
    if let Err(err) = dev.configure_transparent_radio(&RADIO_CONFIG) {
        eprintln!("Failed to configure local XBee radio: {err}");
        process::exit(1);
    }

    println!(
        "XBee configured: RO={:X} RR={:X} MM={:X} CH={:X}",
        RADIO_CONFIG.packetization_timeout,
        RADIO_CONFIG.xbee_retries,
        RADIO_CONFIG.mac_mode,
        RADIO_CONFIG.channel
    );
}

fn recv_msg_blocking<T: serde::de::DeserializeOwned>(dev: &mut XBeeDevice) -> T {
    let mut chunk = [0u8; 512];
    let mut rx: Vec<u8> = Vec::new();

    loop {
        match dev.receive(&mut chunk) {
            Ok(n) if n > 0 => {
                rx.extend_from_slice(&chunk[..n]);

                if let Some(pos) = rx.iter().position(|b| *b == 0x00) {
                    let mut frame: Vec<u8> = rx.drain(..=pos).collect();
                    return decode_cobs(frame.as_mut_slice()).expect("decode_cobs failed");
                }
            }
            Ok(_) => {}
            Err(ref e) if e.kind() == io::ErrorKind::TimedOut => {}
            Err(e) => panic!("serial error: {e:?}"),
        }
    }
}
