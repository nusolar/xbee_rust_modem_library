//! Transport abstraction over the XBee UART.
//!
//! ## API mode (AP=2)
//!
//! Set the module in **XCTU** to **AP = API 2 (escaped)** and match **BD**
//! (baud) to the host (e.g. `9600` in the demo binaries).
//!
//! **Unicast:** pass the peer’s 64-bit address (XCTU **SH** + **SL**, 16 hex
//! digits) on the command line or via environment:
//!
//! - `--xbee-dest64=0013a20041aeb54e` (also `--XBEE_DEST64=...`, `--xbee-dest64 ...`)
//! - optional `--xbee-dest16=fffe` (default `FFFE`)
//!
//! CLI flags override **`XBEE_DEST64`** / **`XBEE_DEST16`** env vars.
//!
//! **Broadcast:** omit both; the library uses
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

/// Resolve RF destination: **CLI flags first**, then env vars, else broadcast.
pub fn xbee_destination() -> (u64, u16) {
    let args: Vec<String> = std::env::args().collect();
    xbee_destination_from_args(&args)
}

/// Same as [`xbee_destination`] but uses an explicit argument list (for tests).
pub fn xbee_destination_from_args(args: &[String]) -> (u64, u16) {
    let cli = parse_cli_destination(args);

    let d64 = match cli.dest64 {
        CliDest64::Value(v) => v,
        CliDest64::Unset => std::env::var("XBEE_DEST64")
            .ok()
            .and_then(|s| parse_u64_hex(&s))
            .unwrap_or(crate::api_mode::BROADCAST_ADDR_64),
    };

    let d16 = match cli.dest16 {
        CliDest16::Value(v) => v,
        CliDest16::Unset => std::env::var("XBEE_DEST16")
            .ok()
            .and_then(|s| parse_u16_hex(&s))
            .unwrap_or(crate::api_mode::UNKNOWN_ADDR_16),
    };

    (d64, d16)
}

/// Read destination addresses from **`XBEE_DEST64`** / **`XBEE_DEST16`** only.
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum CliDest64 {
    #[default]
    Unset,
    Value(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum CliDest16 {
    #[default]
    Unset,
    Value(u16),
}

#[derive(Debug, Default)]
struct CliDestination {
    dest64: CliDest64,
    dest16: CliDest16,
}

fn parse_cli_destination(args: &[String]) -> CliDestination {
    let mut out = CliDestination::default();
    let mut i = 1;
    while i < args.len() {
        let arg = args[i].as_str();
        if let Some((key, value)) = split_long_flag(arg) {
            apply_cli_flag(&mut out, key, value);
            i += 1;
            continue;
        }
        if let Some(key) = long_flag_name_only(arg) {
            i += 1;
            if i < args.len() {
                apply_cli_flag(&mut out, key, args[i].as_str());
            }
            i += 1;
            continue;
        }
        i += 1;
    }
    out
}

fn apply_cli_flag(out: &mut CliDestination, key: &str, value: &str) {
    match normalize_flag_key(key).as_str() {
        "xbee_dest64" => match parse_u64_hex(value) {
            Some(v) => out.dest64 = CliDest64::Value(v),
            None => {
                eprintln!(
                    "error: invalid --xbee-dest64 value {value:?} (need 16 hex digits: XCTU SH+SL)"
                );
                std::process::exit(1);
            }
        },
        "xbee_dest16" => match parse_u16_hex(value) {
            Some(v) => out.dest16 = CliDest16::Value(v),
            None => {
                eprintln!("error: invalid --xbee-dest16 value {value:?} (need 4 hex digits)");
                std::process::exit(1);
            }
        },
        _ => {}
    }
}

fn normalize_flag_key(key: &str) -> String {
    key.trim()
        .trim_start_matches('-')
        .replace('-', "_")
        .to_ascii_lowercase()
}

fn split_long_flag(arg: &str) -> Option<(&str, &str)> {
    let arg = arg.trim();
    if !arg.starts_with("--") {
        return None;
    }
    let rest = arg.get(2..)?;
    let (key, value) = rest.split_once('=')?;
    Some((key, value))
}

fn long_flag_name_only(arg: &str) -> Option<&str> {
    let arg = arg.trim();
    if !arg.starts_with("--") || arg.contains('=') {
        return None;
    }
    arg.get(2..)
}

fn normalize_hex_digits(s: &str) -> String {
    let s = s.trim();
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    s.chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
}

pub fn parse_u64_hex(s: &str) -> Option<u64> {
    let digits = normalize_hex_digits(s);
    if digits.len() != 16 {
        return None;
    }
    u64::from_str_radix(&digits, 16).ok()
}

pub fn parse_u16_hex(s: &str) -> Option<u16> {
    let digits = normalize_hex_digits(s);
    if digits.len() != 4 {
        return None;
    }
    u16::from_str_radix(&digits, 16).ok()
}

#[cfg(test)]
mod cli_tests {
    use super::*;

    #[test]
    fn cli_equals_form_overrides_env() {
        let args = vec![
            "test_sender".into(),
            "--XBEE_DEST64=0013a20041aeb54e".into(),
        ];
        let (d64, _) = xbee_destination_from_args(&args);
        assert_eq!(d64, 0x0013a20041aeb54e);
    }

    #[test]
    fn cli_space_form() {
        let args = vec![
            "test_receiver".into(),
            "--xbee-dest64".into(),
            "0013A20041AEB54E".into(),
        ];
        let (d64, d16) = xbee_destination_from_args(&args);
        assert_eq!(d64, 0x0013a20041aeb54e);
        assert_eq!(d16, 0xFFFE);
    }

    #[test]
    fn hex_with_colons() {
        assert_eq!(
            parse_u64_hex("00:13:A2:00:41:AE:B5:4E"),
            Some(0x0013a20041aeb54e)
        );
    }
}
