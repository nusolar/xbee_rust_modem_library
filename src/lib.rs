//! xbee_secure library:
//! - Serial discovery + I/O
//! - COBS framing via postcard
//! - Ed25519 identity keys (load or generate)
//! - Signed X25519 handshake to establish an AES-256-GCM session key
//! - Secure packet sealing/opening with replay protection

pub mod framing;
pub mod handshake;
pub mod keys;
pub mod replay;
pub mod secure_packet;
pub mod serial;

#[cfg(test)]
mod tests {
    mod crypto_roundtrip;
}
