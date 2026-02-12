use serialport::{DataBits, StopBits};
use std::io::{self, Write};
use xbee_rust_modem_library::{XBeeDevice, discover_xbee_ports};

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
    let baud_rate = 9600;
    let stop_bits = StopBits::One;
    let data_bits = DataBits::Eight;

    let mut sender = XBeeDevice::new(
        port_name, baud_rate, stop_bits, data_bits).unwrap();

    // Prompt user
    print!("Enter message to send: ");
    io::stdout().flush().unwrap();

    // Read input
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read input");

    // Remove trailing newline
    let message = input.trim();

    loop {
        match sender.send(message.as_bytes()) {
            Ok(_) => {
                println!("Sent!");
                return;
            }
            Err(ref e) if e.kind() == io::ErrorKind::TimedOut => (),
            Err(e) => {
                eprintln!("{:?}", e);
                return;
            }
        }
    }
}
