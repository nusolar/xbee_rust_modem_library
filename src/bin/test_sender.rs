use serialport::{DataBits, FlowControl, Parity, StopBits};
use std::io::{self, Write};
use xbee_rust_modem_library::XBeeDevice;

pub fn main() {
    let port = "COM5";
    let baud_rate = 9600;
    let stop_bits = StopBits::One;
    let data_bits = DataBits::Eight;
    let flow_control = FlowControl::None;
    let parity = Parity::None;

    let mut sender = XBeeDevice::new(port.to_string(), baud_rate, stop_bits, data_bits).unwrap();

    let to_send = "Hello world!";
    loop {
        match sender.send(to_send.as_bytes()) {
            Ok(_) => {
                println!("Sent!");
                io::stdout().flush().unwrap();
                return;
            }
            Err(ref e) if e.kind() == io::ErrorKind::TimedOut => (),
            Err(e) => eprintln!("{:?}", e),
        }
    }
}
