//! Transport abstraction over the XBee UART.
//!
//! ## API mode (AP=2)
//!
//! Set the module in **XCTU** to **AP = API 2 (escaped)** and match **BD**
//! (baud) to the host (e.g. `9600` in the demo binaries).
//!
//! **Unicast:** set environment variable **`XBEE_DEST64`** to the peer’s
//! 64-bit address as **16 hex digits** (same value as XCTU **SH** high +
//! **SL** low concatenated). Optional **`XBEE_DEST16`** (4 hex digits,
//! default `FFFE`).
//!
//! **Broadcast:** leave `XBEE_DEST64` unset; the library uses
//! [`crate::api_mode::BROADCAST_ADDR_64`] and [`crate::api_mode::UNKNOWN_ADDR_16`].
//!
//! COBS + postcard + AES-GCM payloads are carried inside the **RF data**
//! field of **0x10 / 0x90** frames; the library strips API framing for you.

use std::io;

use crate::api_mode::{encode_tx_request_ap2, ApiParser, PushOutcome};
use crate::serial::XBeeDevice;

/// Minimal serial transport contract used by the demo sender / receiver.
///
/// Implementations carry **RF payload bytes** only. COBS / postcard / GCM
/// live above this layer.
pub trait Transport {
    fn send(&mut self, data: &[u8]) -> io::Result<()>;
    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize>;
}

/// Pass-through transport over [`XBeeDevice`] (transparent UART mode).
pub struct TransparentTransport {
    dev: XBeeDevice,
}

impl TransparentTransport {
    pub fn new(dev: XBeeDevice) -> Self {
        Self { dev }
    }

    pub fn into_inner(self) -> XBeeDevice {
        self.dev
    }
}

impl Transport for TransparentTransport {
    fn send(&mut self, data: &[u8]) -> io::Result<()> {
        self.dev.send(data)
    }

    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.dev.receive(buf)
    }
}

/// API mode (AP=2) transport: **0x10** transmit, **0x90** receive RF payload.
pub struct ApiModeTransport {
    dev: XBeeDevice,
    parser: ApiParser,
    dest_addr_64: u64,
    dest_addr_16: u16,
    last_rx_source: Option<(u64, u16)>,
    next_frame_id: u8,
}

impl ApiModeTransport {
    /// `dest_addr_64` / `dest_addr_16` are the RF destination (see module docs).
    pub fn new(dev: XBeeDevice, dest_addr_64: u64, dest_addr_16: u16) -> Self {
        Self {
            dev,
            parser: ApiParser::new(),
            dest_addr_64,
            dest_addr_16,
            last_rx_source: None,
            next_frame_id: 1,
        }
    }

    pub fn set_destination(&mut self, dest_addr_64: u64, dest_addr_16: u16) {
        self.dest_addr_64 = dest_addr_64;
        self.dest_addr_16 = dest_addr_16;
    }

    pub fn last_rx_source(&self) -> Option<(u64, u16)> {
        self.last_rx_source
    }

    pub fn set_destination_to_last_rx_source(&mut self) -> Option<(u64, u16)> {
        let (dest_addr_64, dest_addr_16) = self.last_rx_source?;
        self.set_destination(dest_addr_64, dest_addr_16);
        Some((dest_addr_64, dest_addr_16))
    }

    pub fn into_inner(self) -> XBeeDevice {
        self.dev
    }
}

impl Transport for ApiModeTransport {
    fn send(&mut self, data: &[u8]) -> io::Result<()> {
        let mut buf = [0u8; 4096];
        let frame_id = self.next_frame_id;
        self.next_frame_id = if self.next_frame_id == 255 {
            1
        } else {
            self.next_frame_id + 1
        };
        let wire = encode_tx_request_ap2(
            &mut buf,
            frame_id,
            self.dest_addr_64,
            self.dest_addr_16,
            0,
            0,
            data,
        )
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("{e:?}")))?;
        self.dev.send(wire)
    }

    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut scratch = [0u8; 512];
        loop {
            let n = self.dev.receive(&mut scratch)?;
            if n == 0 {
                return Ok(0);
            }
            for &b in &scratch[..n] {
                match self.parser.push(b) {
                    Ok(PushOutcome::RfPayload(packet)) => {
                        self.last_rx_source =
                            Some((packet.source_addr_64, packet.source_addr_16));
                        if packet.payload.len() > buf.len() {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "RF payload larger than recv buffer",
                            ));
                        }
                        buf[..packet.payload.len()].copy_from_slice(packet.payload.as_slice());
                        return Ok(packet.payload.len());
                    }
                    Ok(PushOutcome::Continue | PushOutcome::IgnoredFrame) => {}
                    Err(crate::api_mode::ApiError::PayloadTooLarge) => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "API frame length exceeds parser limit",
                        ));
                    }
                    Err(_) => {
                        self.parser.reset();
                    }
                }
            }
        }
    }
}

/// Read destination addresses from **`XBEE_DEST64`** / **`XBEE_DEST16`**.
///
/// `XBEE_DEST64`: 16 hex digits, optional `0x` prefix (e.g. peer SH+SL).
/// `XBEE_DEST16`: 4 hex digits, optional `0x` prefix; defaults to `FFFE`.
pub fn xbee_destination_from_env() -> (u64, u16) {
    let d64 = std::env::var("XBEE_DEST64")
        .ok()
        .and_then(|s| parse_u64_hex(&s))
        .unwrap_or(crate::api_mode::BROADCAST_ADDR_64);
    let d16 = std::env::var("XBEE_DEST16")
        .ok()
        .and_then(|s| parse_u16_hex(&s))
        .unwrap_or(crate::api_mode::UNKNOWN_ADDR_16);
    (d64, d16)
}

fn parse_u64_hex(s: &str) -> Option<u64> {
    let s = s.trim();
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if s.len() != 16 {
        return None;
    }
    u64::from_str_radix(s, 16).ok()
}

fn parse_u16_hex(s: &str) -> Option<u16> {
    let s = s.trim();
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if s.len() != 4 {
        return None;
    }
    u16::from_str_radix(s, 16).ok()
}
