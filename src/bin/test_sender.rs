use serialport::{DataBits, FlowControl, Parity, StopBits, available_ports, SerialPortType};
use std::io::{self, Write};
use xbee_rust_modem_library::XBeeDevice;

fn find_xbee_port() -> Option<String> {
    if let Ok(ports) = available_ports() {
        for p in ports {
            if let SerialPortType::UsbPort(info) = &p.port_type {
                if (info.vid == 0x0403 || info.vid == 0x10C4) {
                    return Some(p.port_name.clone());
                }
            }   
        }
    }
    None
}

pub fn main() {
    let port_name = find_xbee_port()
        .expect("No XBee device found. Check USB connection and permissions.");
    let baud_rate = 9600;
    let stop_bits = StopBits::One;
    let data_bits = DataBits::Eight;
    let flow_control = FlowControl::None;
    let parity = Parity::None;

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
