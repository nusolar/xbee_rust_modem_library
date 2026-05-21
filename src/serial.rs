use std::collections::BTreeMap;
use std::{
    io::{self, Read, Result, Write},
    thread,
    time::{Duration, Instant},
};

use serialport::{DataBits, SerialPort, SerialPortType, StopBits, available_ports};

/// Simple serial wrapper for your XBee device.
pub struct XBeeDevice {
    port: Box<dyn SerialPort>,
}

pub struct TransparentRadioConfig {
    pub packetization_timeout: u8,
    pub xbee_retries: u8,
    pub mac_mode: u8,
    pub channel: u8,
}

pub struct TransparentRadioReport {
    pub mac_mode_applied: bool,
    pub channel_applied: bool,
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

    pub fn configure_transparent_radio(
        &mut self,
        config: &TransparentRadioConfig,
    ) -> Result<TransparentRadioReport> {
        self.enter_command_mode()?;

        let result = (|| {
            self.expect_ok("RO", &format!("{:X}", config.packetization_timeout))?;
            self.expect_ok("RR", &format!("{:X}", config.xbee_retries))?;
            let mac_mode_applied =
                self.expect_ok_or_unsupported("MM", &format!("{:X}", config.mac_mode))?;
            let channel_applied =
                self.expect_ok_or_unsupported("CH", &format!("{:X}", config.channel))?;
            self.expect_ok("AC", "")?;
            Ok(TransparentRadioReport {
                mac_mode_applied,
                channel_applied,
            })
        })();

        let exit_result = self.expect_ok("CN", "");
        match (result, exit_result) {
            (Ok(report), Ok(())) => Ok(report),
            (Err(err), _) => Err(err),
            (Ok(_), Err(err)) => Err(err),
        }
    }

    fn enter_command_mode(&mut self) -> Result<()> {
        self.drain_input()?;
        thread::sleep(Duration::from_millis(1100));
        self.port.write_all(b"+++")?;
        self.port.flush()?;
        thread::sleep(Duration::from_millis(1100));

        let response = self.read_at_response(Duration::from_secs(2))?;
        if response.trim() == "OK" {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "failed to enter XBee command mode: {response:?}"
            )))
        }
    }

    fn expect_ok(&mut self, command: &str, value: &str) -> Result<()> {
        let response = self.send_at_command(command, value)?;
        if response.trim() == "OK" {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "AT{command}{value} failed: {response:?}"
            )))
        }
    }

    fn expect_ok_or_unsupported(&mut self, command: &str, value: &str) -> Result<bool> {
        let response = self.send_at_command(command, value)?;
        match response.trim() {
            "OK" => Ok(true),
            "ERROR" => Ok(false),
            _ => Err(io::Error::other(format!(
                "AT{command}{value} failed: {response:?}"
            ))),
        }
    }

    fn send_at_command(&mut self, command: &str, value: &str) -> Result<String> {
        self.port.write_all(b"AT")?;
        self.port.write_all(command.as_bytes())?;
        self.port.write_all(value.as_bytes())?;
        self.port.write_all(b"\r")?;
        self.port.flush()?;
        self.read_at_response(Duration::from_secs(2))
    }

    fn read_at_response(&mut self, timeout: Duration) -> Result<String> {
        let deadline = Instant::now() + timeout;
        let mut out = Vec::new();
        let mut byte = [0u8; 1];

        while Instant::now() < deadline {
            match self.port.read(&mut byte) {
                Ok(1) => {
                    out.push(byte[0]);
                    if byte[0] == b'\r' {
                        return Ok(String::from_utf8_lossy(&out).into_owned());
                    }
                }
                Ok(_) => {}
                Err(ref e) if e.kind() == io::ErrorKind::TimedOut => {}
                Err(e) => return Err(e),
            }
        }

        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "timed out waiting for XBee AT response; partial response: {:?}",
                String::from_utf8_lossy(&out)
            ),
        ))
    }

    fn drain_input(&mut self) -> Result<()> {
        let mut buf = [0u8; 128];
        loop {
            match self.port.read(&mut buf) {
                Ok(0) => return Ok(()),
                Ok(_) => {}
                Err(ref e) if e.kind() == io::ErrorKind::TimedOut => return Ok(()),
                Err(e) => return Err(e),
            }
        }
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
