use serialport::{DataBits, StopBits};
use std::io::{self, Write};
use std::thread;
use std::time::Duration;
use xbee_rust_modem_library::{Packet, XBeeDevice, discover_xbee_ports, serialize_packet};
use heapless::Vec as HeaplessVec;

const SEND_SETTLE_MS: u64 = 50;

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

    let mut packet_id = 0u32;
    loop {
        print!("Enter message to send (or 'quit'): ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .expect("Failed to read input");
        let message = input.trim_end_matches(['\n', '\r']);
        if message == "quit" {
            return;
        }

        let Ok(payload) = HeaplessVec::<u8, 256>::from_slice(message.as_bytes()) else {
            eprintln!("Message too long. Max payload is 256 bytes.");
            continue;
        };

        let packet = Packet {
            id: packet_id,
            payload,
        };
        let mut frame_buffer = [0u8; 512];
        let framed = serialize_packet(&packet, &mut frame_buffer).unwrap();
        sender.send(framed).unwrap();
        thread::sleep(Duration::from_millis(SEND_SETTLE_MS));
        println!("Sent packet id={} ({} payload bytes).", packet_id, message.len());
        packet_id = packet_id.wrapping_add(1);
    }
}
