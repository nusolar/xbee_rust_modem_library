use std::collections::BTreeMap;
use std::{
    io::{Read, Result, Write},
    time::Duration,
};

use serialport::{DataBits, SerialPort, SerialPortType, StopBits, available_ports};

/// Simple serial wrapper for your XBee device.
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

/// Find likely XBee serial ports (USB-serial adapters).
/// We de-duplicate macOS /dev/cu.* and /dev/tty.* for the same adapter.
pub fn discover_xbee_ports() -> Vec<String> {
    let Ok(ports) = available_ports() else {
        return Vec::new();
    };

    let mut adapters: BTreeMap<String, String> = BTreeMap::new();
    for port in ports {
        let SerialPortType::UsbPort(info) = &port.port_type else {
            continue;
        };

        // Common USB-serial adapter VIDs:
        // - FTDI (0x0403)
        // - Silicon Labs CP210x (0x10C4)
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
    // Prefer callout devices on macOS for outbound connections.
    candidate.starts_with("/dev/cu.") && !current.starts_with("/dev/cu.")
}
