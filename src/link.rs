//! Framed message I/O over any [`Transport`]:
//! postcard + COBS on the wire, one 0x00-delimited frame per message.
//!
//! This is the layer the demo binaries used to implement privately
//! (`send_msg` / `recv_msg_blocking`); it is shared here so external
//! consumers (e.g. a CAN telemetry bridge) can reuse it.

use serde::{Serialize, de::DeserializeOwned};
use std::io;
use std::time::{Duration, Instant};

use crate::framing::{decode_cobs, encode_cobs};
use crate::transport::Transport;

/// Max encoded frame size we will send (postcard + COBS).
const MAX_TX_FRAME: usize = 1024;

/// Serialize `msg` with postcard, COBS-frame it, and send it over `t`.
pub fn send_framed<M: Serialize, T: Transport>(t: &mut T, msg: &M) -> io::Result<()> {
    let mut out = [0u8; MAX_TX_FRAME];
    let framed = encode_cobs(msg, &mut out)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("encode_cobs: {e:?}")))?;
    t.send(framed)
}

/// Accumulates transport bytes and splits them into COBS frames.
///
/// Keep one reader per transport for the life of the connection: bytes that
/// arrive after a frame's 0x00 delimiter are retained for the next call,
/// which a stateless helper would silently drop.
#[derive(Default)]
pub struct FrameReader {
    rx: Vec<u8>,
}

impl FrameReader {
    pub fn new() -> Self {
        Self::default()
    }

    /// Block until one complete COBS frame (including the 0x00 delimiter) is
    /// available, or until `timeout` elapses (`None` = wait forever).
    ///
    /// Returns `Ok(None)` on timeout. The serial layer's short read timeout
    /// (`io::ErrorKind::TimedOut`) is treated as "no data yet", not an error.
    pub fn next_frame<T: Transport>(
        &mut self,
        t: &mut T,
        timeout: Option<Duration>,
    ) -> io::Result<Option<Vec<u8>>> {
        let deadline = timeout.map(|d| Instant::now() + d);
        let mut chunk = [0u8; 512];

        loop {
            if let Some(pos) = self.rx.iter().position(|b| *b == 0x00) {
                return Ok(Some(self.rx.drain(..=pos).collect()));
            }

            if let Some(deadline) = deadline {
                if Instant::now() >= deadline {
                    return Ok(None);
                }
            }

            match t.recv(&mut chunk) {
                Ok(n) if n > 0 => self.rx.extend_from_slice(&chunk[..n]),
                Ok(_) => {}
                Err(ref e) if e.kind() == io::ErrorKind::TimedOut => {}
                Err(e) => return Err(e),
            }
        }
    }

    /// Receive and decode one message.
    ///
    /// - `Ok(Some(msg))` — a frame arrived and decoded as `M`
    /// - `Ok(None)` — timeout
    /// - `Err(InvalidData)` — a frame arrived but did not decode as `M`
    ///   (corruption or a different message type); callers may count and retry
    pub fn recv_framed<M: DeserializeOwned, T: Transport>(
        &mut self,
        t: &mut T,
        timeout: Option<Duration>,
    ) -> io::Result<Option<M>> {
        match self.next_frame(t, timeout)? {
            Some(mut frame) => decode_cobs(frame.as_mut_slice())
                .map(Some)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("decode_cobs: {e:?}"))),
            None => Ok(None),
        }
    }
}
