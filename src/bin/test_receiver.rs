use serialport::{DataBits, StopBits};
use std::io::{self, Write};
use xbee_rust_modem_library::{XBeeDevice, deserialize_packet, discover_xbee_ports};

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

                while let Some(delimiter_pos) = rx_buffer.iter().position(|b| *b == 0x00) {
                    let mut frame: Vec<u8> = rx_buffer.drain(..=delimiter_pos).collect();
                    match deserialize_packet(frame.as_mut_slice()) {
                        Ok(packet) => {
                            io::stdout().write_all(&packet.payload).unwrap();
                            io::stdout().write_all(b"\n").unwrap();
                            io::stdout().flush().unwrap();
                        }
                        Err(e) => eprintln!("Failed to decode packet: {:?}", e),
                    }
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::TimedOut => (),
            Err(e) => eprintln!("{:?}", e),
        }
    }
}
