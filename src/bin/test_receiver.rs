use serialport::{DataBits, StopBits};
use std::io::{self, Write};
use xbee_rust_modem_library::{XBeeDevice, discover_xbee_ports, drain_cobs_frames};

pub fn main() {
    let ports = discover_xbee_ports();
    let port_name = ports.first().cloned().expect(
        "No XBee device found. Check USB connection and permissions.",
    );
    println!("Receiver using port: {}", port_name);

    let mut receiver = XBeeDevice::new(port_name, 9600, StopBits::One, DataBits::Eight).unwrap();
    let mut chunk_buffer = vec![0; 512];
    let mut rx_buffer: Vec<u8> = Vec::new();

    loop {
        match receiver.receive(chunk_buffer.as_mut_slice()) {
            Ok(t) => {
                rx_buffer.extend_from_slice(&chunk_buffer[..t]);

                for frame in drain_cobs_frames(&mut rx_buffer) {
                    io::stdout().write_all(&frame).unwrap();
                    io::stdout().write_all(b"\n").unwrap();
                    io::stdout().flush().unwrap();
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::TimedOut => (),
            Err(e) => eprintln!("{:?}", e),
        }
    }
}
