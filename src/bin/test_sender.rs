use serialport::{DataBits, StopBits};
use std::io::{self, Write};
use std::thread;
use std::time::Duration;
use xbee_rust_modem_library::{XBeeDevice, discover_xbee_ports, encode_cobs_frame};

const FINAL_TX_DRAIN_MS: u64 = 1000;

pub fn main() {
    let ports = discover_xbee_ports();
    let port_name = if ports.len() > 1 {
        ports[1].clone()
    } else if let Some(port) = ports.first() {
        port.clone()
    } else {
        panic!("No XBee device found. Check USB connection and permissions.");
    };
    println!("Sender using port: {}", port_name);

    let mut sender = XBeeDevice::new(port_name, 9600, StopBits::One, DataBits::Eight).unwrap();

    print!("Enter message to send: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read input");

    let payload = input.trim().as_bytes().to_vec();
    let framed = encode_cobs_frame(&payload);

    sender.send(&framed).unwrap();
    thread::sleep(Duration::from_millis(FINAL_TX_DRAIN_MS));
    println!("Sent {} payload bytes as {} framed bytes.", payload.len(), framed.len());
}
