use serialport::{DataBits, FlowControl, Parity, StopBits, available_ports};
use std::io::{self, Write};
use xbee_rust_modem_library::XBeeDevice;

pub fn main() {
    let port = &available_ports().unwrap()[0].port_name;
    let baud_rate = 9600;
    let stop_bits = StopBits::One;
    let data_bits = DataBits::Eight;
    let flow_control = FlowControl::None;
    let parity = Parity::None;

    let mut sender = XBeeDevice::new(port.to_string(), baud_rate, stop_bits, data_bits).unwrap();

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
