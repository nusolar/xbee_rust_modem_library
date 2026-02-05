use serialport::{DataBits, FlowControl, Parity, StopBits, available_ports, SerialPortType};
use std::io::{self, Write};
use xbee_rust_modem_library::{XBeeDevice, Packet, serialize_packet, deserialize_packet};
use heapless::Vec;

fn find_xbee_port() -> Option<String> {
    if let Ok(ports) = available_ports() {
        for p in ports {
            if let SerialPortType::UsbPort(info) = &p.port_type {

                if info.vid == 0x0403 || info.vid == 0x10C4 {
                    return Some(p.port_name.clone());
                }
            }
        }
    }
    None
}

pub fn main() {
    let port_name = find_xbee_port().expect("No XBee device found.");
    let baud_rate = 9600;
    let stop_bits = StopBits::One;
    let data_bits = DataBits::Eight;
    let flow_control = FlowControl::None;
    let parity = Parity::None;

    let mut receiver = XBeeDevice::new(port_name, baud_rate, stop_bits, data_bits).unwrap();

    let mut buf = vec![0; 1000];
    loop {
        match receiver.receive(buf.as_mut_slice()) {
            Ok(t) => {
                let packet_slice = &mut buf[..t];
                match deserialize_packet(packet_slice) {
                    Ok(packet) => {
                        println!("Received packet: {:?}", packet);
                    }
                    Err(e) => eprintln!("Failed to deserialize packet: {:?}", e),
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::TimedOut => (),
            Err(e) => eprintln!("{:?}", e),
        }
    }
}
