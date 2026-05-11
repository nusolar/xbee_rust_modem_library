//! XBee API mode **AP=2 (escaped)** framing for XBee / XBee-PRO SX.
//!
//! Configure the module in XCTU with **AP = API 2 (escaped)** and the same
//! **BD** (baud) as the host. Set **64-bit destination** for unicast via
//! environment variables [`xbee_destination_from_env`](crate::transport::xbee_destination_from_env)
//! (see [`crate::transport`]).
//!
//! Wire format (after escaping):
//!
//! `0x7E` | escaped LEN_MSB | escaped LEN_LSB | escaped *frame data* | escaped *checksum*
//!
//! **LEN** = number of bytes in *frame data* (frame type through last RF /
//! payload byte). **Checksum** = `0xFF - (sum(frame data) mod 256)`.
//!
//! Bytes `0x7E`, `0x7D`, `0x11`, `0x13` in LEN, frame data, and checksum are
//! sent as `0x7D` followed by `(byte XOR 0x20)`.

pub const START_DELIMITER: u8 = 0x7E;
pub const ESCAPE: u8 = 0x7D;
pub const XON: u8 = 0x11;
pub const XOFF: u8 = 0x13;
pub const ESCAPE_XOR: u8 = 0x20;

pub const FRAME_TX_REQUEST: u8 = 0x10;
pub const FRAME_TX_STATUS_EXT: u8 = 0x8B;
pub const FRAME_TX_STATUS: u8 = 0x89;
pub const FRAME_RX_PACKET: u8 = 0x90;
pub const FRAME_MODEM_STATUS: u8 = 0x8A;

/// Broadcast 64-bit destination (Digi SX / DigiMesh style).
pub const BROADCAST_ADDR_64: u64 = 0x0000_0000_0000_FFFF;
/// Typical “reserved / unknown” 16-bit field in 0x10 / 0x90.
pub const UNKNOWN_ADDR_16: u16 = 0xFFFE;

/// Max *unescaped* API frame data (frame type … last payload byte) we buffer.
pub const MAX_API_BODY: usize = 1024;

/// 0x10: type + id + dest64 + reserved16 + radius + options = 14 bytes before RF payload.
pub const TX_REQUEST_HEADER_LEN: usize = 14;
/// 0x90: type + src64 + reserved16 + options = 12 bytes before RF payload (SX user guide).
pub const RX_PACKET_HEADER_LEN: usize = 12;

/// Max RF payload bytes we accept in one 0x90 / one `encode_tx_request_ap2` call.
pub const MAX_RF_PAYLOAD: usize = MAX_API_BODY - TX_REQUEST_HEADER_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiError {
    BadEscape,
    PayloadTooLarge,
    OutputBufferTooSmall,
}

#[inline]
pub const fn needs_escape(b: u8) -> bool {
    matches!(b, START_DELIMITER | ESCAPE | XON | XOFF)
}

#[inline]
fn unescape_second(second: u8) -> Result<u8, ApiError> {
    let v = second ^ ESCAPE_XOR;
    if needs_escape(v) {
        Ok(v)
    } else {
        Err(ApiError::BadEscape)
    }
}

/// API checksum over *frame data* only (not length, not checksum byte).
#[inline]
pub fn api_checksum(frame_data: &[u8]) -> u8 {
    let sum: u32 = frame_data.iter().map(|&b| b as u32).sum();
    (0xFFu32.wrapping_sub(sum & 0xFF)) as u8
}

#[inline]
fn push_escaped(out: &mut [u8], pos: &mut usize, b: u8) -> Result<(), ApiError> {
    if needs_escape(b) {
        let p = *pos;
        let s = out
            .get_mut(p..p + 2)
            .ok_or(ApiError::OutputBufferTooSmall)?;
        s[0] = ESCAPE;
        s[1] = b ^ ESCAPE_XOR;
        *pos += 2;
    } else {
        *out.get_mut(*pos).ok_or(ApiError::OutputBufferTooSmall)? = b;
        *pos += 1;
    }
    Ok(())
}

/// Encode a **Transmit Request 0x10** frame (AP=2 escaped) into `out`.
///
/// `broadcast_radius`: `0` = use module **NH** (recommended for broadcast).
/// `transmit_options`: `0` = use module **TO** for option bits.
///
/// Returns the slice of `out` written (starts with `0x7E`).
pub fn encode_tx_request_ap2<'a>(
    out: &'a mut [u8],
    frame_id: u8,
    dest_addr_64: u64,
    dest_addr_16: u16,
    broadcast_radius: u8,
    transmit_options: u8,
    rf_data: &[u8],
) -> Result<&'a [u8], ApiError> {
    if rf_data.len() > MAX_RF_PAYLOAD {
        return Err(ApiError::PayloadTooLarge);
    }

    let mut inner = heapless::Vec::<u8, MAX_API_BODY>::new();
    inner
        .push(FRAME_TX_REQUEST)
        .map_err(|_| ApiError::PayloadTooLarge)?;
    inner
        .push(frame_id)
        .map_err(|_| ApiError::PayloadTooLarge)?;
    for b in dest_addr_64.to_be_bytes() {
        inner.push(b).map_err(|_| ApiError::PayloadTooLarge)?;
    }
    for b in dest_addr_16.to_be_bytes() {
        inner.push(b).map_err(|_| ApiError::PayloadTooLarge)?;
    }
    inner
        .push(broadcast_radius)
        .map_err(|_| ApiError::PayloadTooLarge)?;
    inner
        .push(transmit_options)
        .map_err(|_| ApiError::PayloadTooLarge)?;
    inner
        .extend_from_slice(rf_data)
        .map_err(|_| ApiError::PayloadTooLarge)?;

    let inner = inner.as_slice();
    let len: u16 = inner
        .len()
        .try_into()
        .map_err(|_| ApiError::PayloadTooLarge)?;
    let chk = api_checksum(inner);

    let mut pos = 0usize;
    *out.get_mut(pos).ok_or(ApiError::OutputBufferTooSmall)? = START_DELIMITER;
    pos += 1;

    for b in len.to_be_bytes() {
        push_escaped(out, &mut pos, b)?;
    }
    for &b in inner {
        push_escaped(out, &mut pos, b)?;
    }
    push_escaped(out, &mut pos, chk)?;

    Ok(out.get(..pos).ok_or(ApiError::OutputBufferTooSmall)?)
}

/// Result of [`ApiParser::push`]: RF payload from a **0x90 Receive Packet**, or
/// `None` if the byte completed a non-RF frame (or checksum failure → reset).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushOutcome {
    /// Still assembling a frame, or consumed an escape byte.
    Continue,
    /// A full API frame was processed; it was not user RF data (modem status,
    /// TX status, unknown type, etc.).
    IgnoredFrame,
    /// Decoded **0x90** RF payload (copy is owned; safe to use across parser resets).
    RfPayload(heapless::Vec<u8, MAX_API_BODY>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParserState {
    WaitStart,
    LenHi,
    LenLo,
    Body,
    Checksum,
}

/// Streaming AP=2 parser: feed raw UART bytes from the XBee.
pub struct ApiParser {
    state: ParserState,
    len_msb: u8,
    declared_len: u16,
    body_read: u16,
    body: heapless::Vec<u8, MAX_API_BODY>,
    escape_next: bool,
}

impl Default for ApiParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ApiParser {
    pub const fn new() -> Self {
        Self {
            state: ParserState::WaitStart,
            len_msb: 0,
            declared_len: 0,
            body_read: 0,
            body: heapless::Vec::new(),
            escape_next: false,
        }
    }

    pub fn reset(&mut self) {
        self.state = ParserState::WaitStart;
        self.len_msb = 0;
        self.declared_len = 0;
        self.body_read = 0;
        self.body.clear();
        self.escape_next = false;
    }

    fn feed_escape(&mut self, byte: u8) -> Result<Option<u8>, ApiError> {
        if self.escape_next {
            self.escape_next = false;
            return Ok(Some(unescape_second(byte)?));
        }
        if byte == ESCAPE {
            self.escape_next = true;
            return Ok(None);
        }
        Ok(Some(byte))
    }

    fn resync_on_start_delimiter(&mut self) {
        self.escape_next = false;
        self.body.clear();
        self.body_read = 0;
        self.state = ParserState::LenHi;
    }

    /// Feed one raw UART byte. On **0x90** completion returns [`PushOutcome::RfPayload`].
    pub fn push(&mut self, byte: u8) -> Result<PushOutcome, ApiError> {
        if byte == START_DELIMITER {
            self.resync_on_start_delimiter();
            return Ok(PushOutcome::Continue);
        }

        match self.state {
            ParserState::WaitStart => Ok(PushOutcome::Continue),

            ParserState::LenHi => {
                let u = match self.feed_escape(byte) {
                    Ok(Some(u)) => u,
                    Ok(None) => return Ok(PushOutcome::Continue),
                    Err(_) => {
                        self.reset();
                        return Ok(PushOutcome::IgnoredFrame);
                    }
                };
                self.len_msb = u;
                self.state = ParserState::LenLo;
                Ok(PushOutcome::Continue)
            }

            ParserState::LenLo => {
                let u = match self.feed_escape(byte) {
                    Ok(Some(u)) => u,
                    Ok(None) => return Ok(PushOutcome::Continue),
                    Err(_) => {
                        self.reset();
                        return Ok(PushOutcome::IgnoredFrame);
                    }
                };
                self.declared_len = ((self.len_msb as u16) << 8) | u as u16;
                if self.declared_len as usize > MAX_API_BODY {
                    self.reset();
                    return Err(ApiError::PayloadTooLarge);
                }
                self.body.clear();
                self.body_read = 0;
                if self.declared_len == 0 {
                    self.state = ParserState::Checksum;
                } else {
                    self.state = ParserState::Body;
                }
                Ok(PushOutcome::Continue)
            }

            ParserState::Body => {
                let u = match self.feed_escape(byte) {
                    Ok(Some(u)) => u,
                    Ok(None) => return Ok(PushOutcome::Continue),
                    Err(_) => {
                        self.reset();
                        return Ok(PushOutcome::IgnoredFrame);
                    }
                };
                self.body.push(u).map_err(|_| ApiError::PayloadTooLarge)?;
                self.body_read = self.body_read.saturating_add(1);
                if self.body_read >= self.declared_len {
                    self.state = ParserState::Checksum;
                }
                Ok(PushOutcome::Continue)
            }

            ParserState::Checksum => {
                let u = match self.feed_escape(byte) {
                    Ok(Some(u)) => u,
                    Ok(None) => return Ok(PushOutcome::Continue),
                    Err(_) => {
                        self.reset();
                        return Ok(PushOutcome::IgnoredFrame);
                    }
                };
                let frame_data = self.body.as_slice();
                let expected = api_checksum(frame_data);
                if u != expected {
                    self.reset();
                    return Ok(PushOutcome::IgnoredFrame);
                }

                let outcome = Self::extract_rf_payload(frame_data);
                self.reset();
                match outcome {
                    Some(pl) => Ok(PushOutcome::RfPayload(pl)),
                    None => Ok(PushOutcome::IgnoredFrame),
                }
            }
        }
    }

    fn extract_rf_payload(frame_data: &[u8]) -> Option<heapless::Vec<u8, MAX_API_BODY>> {
        if frame_data.is_empty() {
            return None;
        }
        match frame_data[0] {
            FRAME_RX_PACKET if frame_data.len() >= RX_PACKET_HEADER_LEN => {
                let mut out = heapless::Vec::new();
                out.extend_from_slice(&frame_data[RX_PACKET_HEADER_LEN..])
                    .ok()?;
                Some(out)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_digi_spec() {
        assert_eq!(START_DELIMITER, 0x7E);
        assert_eq!(ESCAPE, 0x7D);
        assert_eq!(ESCAPE_XOR, 0x20);
        assert_eq!(FRAME_TX_REQUEST, 0x10);
        assert_eq!(FRAME_TX_STATUS_EXT, 0x8B);
        assert_eq!(FRAME_RX_PACKET, 0x90);
    }

    #[test]
    fn extended_tx_status_ap1_example_parses() {
        let wire = [
            0x7E, 0x00, 0x07, 0x8B, 0x01, 0xFF, 0xFE, 0x00, 0x00, 0x00, 0x76,
        ];
        let mut p = ApiParser::new();
        for (i, &b) in wire.iter().enumerate() {
            let r = p.push(b).unwrap();
            if i + 1 < wire.len() {
                assert_eq!(r, PushOutcome::Continue);
            } else {
                assert_eq!(r, PushOutcome::IgnoredFrame);
            }
        }
    }

    #[test]
    fn encode_then_feed_no_escape_small_payload() {
        let mut out = [0u8; 512];
        let dest = 0x0013A20041AEB54E_u64;
        let rf = [0x54, 0x78, 0x44, 0x61, 0x74, 0x61];
        let wire = encode_tx_request_ap2(&mut out, 0x52, dest, UNKNOWN_ADDR_16, 0, 0, &rf).unwrap();

        assert_eq!(wire[0], START_DELIMITER);
        assert!(wire.len() > 20);

        let mut p = ApiParser::new();
        for &b in wire {
            let _ = p.push(b).unwrap();
        }
    }

    #[test]
    fn receive_packet_minimal_rf() {
        let frame_data: [u8; 13] = [
            0x90, 0x00, 0x13, 0xA2, 0x00, 0x87, 0x65, 0x43, 0x21, 0xFF, 0xFE, 0x01, 0xAB,
        ];
        let chk = api_checksum(&frame_data);
        let len = frame_data.len() as u16;
        let mut wire = heapless::Vec::<u8, 32>::new();
        wire.push(START_DELIMITER).unwrap();
        for b in len.to_be_bytes() {
            wire.push(b).unwrap();
        }
        for &b in &frame_data {
            wire.push(b).unwrap();
        }
        wire.push(chk).unwrap();

        let mut p = ApiParser::new();
        let mut got = None;
        for &b in wire.iter() {
            match p.push(b).unwrap() {
                PushOutcome::RfPayload(v) => got = Some(v),
                PushOutcome::Continue | PushOutcome::IgnoredFrame => {}
            }
        }
        assert_eq!(got.as_ref().map(|v| v.as_slice()), Some(&[0xAB][..]));
    }

    #[test]
    fn escape_special_bytes_in_rf_payload() {
        let mut out = [0u8; 512];
        let rf = [0x7E, 0x7D, 0x11, 0x13, 0x00];
        let wire =
            encode_tx_request_ap2(&mut out, 1, BROADCAST_ADDR_64, UNKNOWN_ADDR_16, 0, 0, &rf)
                .unwrap();
        assert_eq!(wire[0], START_DELIMITER);
        assert!(
            !wire[1..].contains(&START_DELIMITER),
            "no unescaped 0x7E inside the frame after the start delimiter"
        );
    }
}
