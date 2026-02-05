use std::{
    io::{Read, Result, Write},
    time::Duration,
};

pub mod packet; 
pub use packet::{Packet, serialize_packet, deserialize_packet};

use serialport::{DataBits, SerialPort, StopBits};

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
