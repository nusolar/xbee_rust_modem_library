//! xbee_secure library:
//! - Serial discovery + I/O
//! - COBS framing via postcard
//! - Ed25519 identity keys (load or generate)
//! - Signed X25519 handshake to establish an AES-256-GCM session key
//! - Secure packet sealing/opening with replay protection

pub mod serial;
pub mod framing;
pub mod keys;
pub mod replay;
pub mod handshake;
pub mod secure_packet;

pub mod api_mode;
pub mod transport;

pub mod link;
pub mod session;

// Re-exported so consumers don't have to pin a matching ed25519-dalek version
// just to hold the key types our API takes.
pub use ed25519_dalek::{SigningKey, VerifyingKey};
