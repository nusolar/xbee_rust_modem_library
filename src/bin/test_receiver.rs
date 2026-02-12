use serialport::{DataBits, StopBits};
use std::io::{self, Write};
use xbee_rust_modem_library::{XBeeDevice, discover_xbee_ports};

pub fn main() {
    let ports = discover_xbee_ports();
    let port_name = ports.first().cloned().expect(
        "No XBee device found. Check USB connection and permissions.",
    );
    println!("Receiver using port: {}", port_name);
    let baud_rate = 9600;
    let stop_bits = StopBits::One;
    let data_bits = DataBits::Eight;

    let mut receiver = XBeeDevice::new(port_name, baud_rate, stop_bits, data_bits).unwrap();

    let mut buf = vec![0; 1000];
    loop {
        match receiver.receive(buf.as_mut_slice()) {
            Ok(t) => {
                io::stdout().write_all(&buf[..t]).unwrap();
                io::stdout().flush().unwrap();
            }
            Err(ref e) if e.kind() == io::ErrorKind::TimedOut => (),
            Err(e) => eprintln!("{:?}", e),
        }
    }
}
