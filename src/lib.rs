use std::{
    io::{Read, Result, Write},
    time::Duration,
};

use serialport::{DataBits, SerialPort, SerialPortType, StopBits, available_ports};
use std::collections::BTreeMap;

pub mod packet;
pub use packet::{Packet, deserialize_packet, serialize_packet};

pub struct XBeeDevice {
    port: Box<dyn SerialPort>,
}

impl XBeeDevice {
    pub fn new(port: String, baud: u32, stop_bits: StopBits, data_bits: DataBits) -> Result<Self> {
        let port = serialport::new(port, baud)
            .stop_bits(stop_bits)
            .data_bits(data_bits)
            .timeout(Duration::from_millis(10))
            .open()?;

        Ok(Self { port })
    }

    pub fn send(&mut self, data: &[u8]) -> Result<()> {
        self.port.write_all(data)?;
        self.port.flush()?;
        Ok(())
    }

    pub fn receive(&mut self, buffer: &mut [u8]) -> Result<usize> {
        self.port.read(buffer)
    }
}

pub fn discover_xbee_ports() -> Vec<String> {
    let Ok(ports) = available_ports() else {
        return Vec::new();
    };

    // Group candidate nodes by physical adapter so /dev/cu.* and /dev/tty.*
    // for the same USB-serial device do not look like two separate XBees.
    let mut adapters: BTreeMap<String, String> = BTreeMap::new();
    for port in ports {
        let SerialPortType::UsbPort(info) = &port.port_type else {
            continue;
        };
        if info.vid != 0x0403 && info.vid != 0x10C4 {
            continue;
        }

        let adapter_key = info
            .serial_number
            .clone()
            .unwrap_or_else(|| normalize_port_key(&port.port_name));
        let preferred_port = adapters
            .entry(adapter_key)
            .or_insert_with(|| port.port_name.clone());

        if is_better_port_choice(&port.port_name, preferred_port) {
            *preferred_port = port.port_name.clone();
        }
    }

    adapters.into_values().collect()
}

fn normalize_port_key(port_name: &str) -> String {
    if let Some(stripped) = port_name.strip_prefix("/dev/cu.") {
        return stripped.to_string();
    }
    if let Some(stripped) = port_name.strip_prefix("/dev/tty.") {
        return stripped.to_string();
    }
    port_name.to_string()
}

fn is_better_port_choice(candidate: &str, current: &str) -> bool {
    // Prefer callout devices on macOS because they are typically used
    // for active outbound connections.
    candidate.starts_with("/dev/cu.") && !current.starts_with("/dev/cu.")
}
