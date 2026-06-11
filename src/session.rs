//! Secure session layer: handshake + sequence numbers + AES-256-GCM,
//! exposed as payload-agnostic byte pipes.
//!
//! [`SecureSender`] (handshake client) and [`SecureReceiver`] (handshake
//! server) wrap a [`Transport`] and carry opaque `&[u8]` payloads — this
//! library knows nothing about what is inside them.

use std::io;
use std::time::{Duration, Instant};

use aes_gcm::{Aes256Gcm, Key};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::handshake::{
    HandshakeMsg, finish_client, finish_server, make_client_hello, respond_server_hello,
};
use crate::keys::sender_id_from_pubkey;
use crate::link::{FrameReader, send_framed};
use crate::replay::{InOrder, InOrderDecision};
use crate::secure_packet::{MAX_PLAINTEXT, SecureFrame, open, seal};
use crate::transport::Transport;

pub use crate::secure_packet::MAX_PLAINTEXT as MAX_PAYLOAD;

/// Decrypted payload bytes (capacity bounded by [`MAX_PAYLOAD`]).
pub type Payload = aes_gcm::aead::heapless::Vec<u8, MAX_PLAINTEXT>;

/// Everything a session puts on the wire, tagged so handshake and data frames
/// can never be confused: postcard tolerates trailing bytes, so trial-decoding
/// untagged messages can spuriously "succeed" on the wrong type.
#[derive(Serialize, Deserialize)]
enum WireMsg {
    Handshake(HandshakeMsg),
    Data(SecureFrame),
}

/// Handshake initiator + encrypting sender.
pub struct SecureSender<T: Transport> {
    transport: T,
    aes_key: Key<Aes256Gcm>,
    sender_id: [u8; 4],
    seq: u64,
}

impl<T: Transport> SecureSender<T> {
    /// Run the client handshake and return a ready-to-send session.
    ///
    /// Sends a ClientHello and waits for a valid ServerHello, resending the
    /// hello every `retry` until the peer answers — the peer radio may not be
    /// powered yet (e.g. car boots before the chase laptop is listening).
    /// Garbage frames and invalid responses are ignored and retried.
    pub fn establish(
        mut transport: T,
        signing_key: &SigningKey,
        authorized_peer: &VerifyingKey,
        retry: Duration,
    ) -> io::Result<Self> {
        let sender_id = sender_id_from_pubkey(&signing_key.verifying_key());
        let mut reader = FrameReader::new();

        loop {
            // Fresh ephemeral each attempt: finish_client consumes the secret,
            // and the signature binds the hello to this exact ephemeral key.
            let (client_hello, client_eph_secret, client_id_pub) = make_client_hello(signing_key);
            let client_eph_pub = match &client_hello {
                HandshakeMsg::ClientHello { client_eph_pub, .. } => *client_eph_pub,
                _ => unreachable!(),
            };
            send_framed(&mut transport, &WireMsg::Handshake(client_hello))?;

            match reader.recv_framed::<WireMsg, _>(&mut transport, Some(retry)) {
                Ok(Some(WireMsg::Handshake(server_hello))) => {
                    if let Some((aes_key, _server_identity_pub)) = finish_client(
                        authorized_peer,
                        client_eph_secret,
                        client_id_pub,
                        client_eph_pub,
                        server_hello,
                    ) {
                        return Ok(Self {
                            transport,
                            aes_key,
                            sender_id,
                            seq: 0,
                        });
                    }
                    // Bad signature / wrong peer / stale reply: retry.
                }
                Ok(Some(WireMsg::Data(_))) => {} // stale data frame: ignore
                Ok(None) => {} // timeout: resend hello
                Err(ref e) if e.kind() == io::ErrorKind::InvalidData => {} // garbage frame
                Err(e) => return Err(e),
            }
        }
    }

    /// Encrypt `plaintext` (≤ [`MAX_PAYLOAD`] bytes) and send it as one frame.
    /// Returns the sequence number used.
    pub fn send_payload(&mut self, plaintext: &[u8]) -> io::Result<u64> {
        let frame = seal(&self.aes_key, self.sender_id, self.seq, plaintext)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        send_framed(&mut self.transport, &WireMsg::Data(frame))?;
        let used = self.seq;
        self.seq = self.seq.wrapping_add(1);
        Ok(used)
    }

    pub fn sender_id(&self) -> [u8; 4] {
        self.sender_id
    }

    pub fn into_inner(self) -> T {
        self.transport
    }
}

/// Receive-side counters, exposed for status displays / health telemetry.
#[derive(Debug, Default, Clone)]
pub struct RxStats {
    pub ok: u64,
    pub auth_fail: u64,
    pub dup_or_old_drop: u64,
    pub skipped_packets: u64,
    pub decode_fail: u64,
    pub rehandshakes: u64,
}

/// Handshake responder + decrypting receiver.
pub struct SecureReceiver<T: Transport> {
    transport: T,
    reader: FrameReader,
    aes_key: Key<Aes256Gcm>,
    signing_key: SigningKey,
    authorized_peer: VerifyingKey,
    inorder: InOrder,
    pub stats: RxStats,
}

impl<T: Transport> SecureReceiver<T> {
    /// Wait (forever) for a valid ClientHello from the authorized sender,
    /// answer it, and return a ready-to-receive session.
    ///
    /// Owns `signing_key` / `authorized_peer` so it can transparently accept a
    /// new handshake mid-stream when the sender restarts (see [`Self::recv_payload`]).
    pub fn establish(
        mut transport: T,
        signing_key: SigningKey,
        authorized_peer: VerifyingKey,
    ) -> io::Result<Self> {
        let mut reader = FrameReader::new();

        loop {
            match reader.recv_framed::<WireMsg, _>(&mut transport, None) {
                Ok(Some(WireMsg::Handshake(hello))) => {
                    if let Some(aes_key) =
                        respond_handshake(&mut transport, &signing_key, &authorized_peer, hello)?
                    {
                        return Ok(Self {
                            transport,
                            reader,
                            aes_key,
                            signing_key,
                            authorized_peer,
                            inorder: InOrder::default(),
                            stats: RxStats::default(),
                        });
                    }
                }
                Ok(Some(WireMsg::Data(_))) => {} // no session yet: drop
                Ok(None) => unreachable!("no timeout was set"),
                Err(ref e) if e.kind() == io::ErrorKind::InvalidData => {}
                Err(e) => return Err(e),
            }
        }
    }

    /// Receive the next authenticated payload, or `None` if `timeout` elapses
    /// (`None` timeout = wait forever).
    ///
    /// Handles the full pipeline per frame: COBS decode → replay gate →
    /// AES-GCM open. Frames that fail any stage bump [`Self::stats`] and the
    /// wait continues. A frame that instead decodes as a valid ClientHello
    /// triggers a transparent re-handshake (sender restarted): the session is
    /// rekeyed, the replay gate resets, and waiting resumes.
    pub fn recv_payload(&mut self, timeout: Option<Duration>) -> io::Result<Option<Payload>> {
        let deadline = timeout.map(|d| Instant::now() + d);

        loop {
            let remaining = match deadline {
                Some(d) => {
                    let now = Instant::now();
                    if now >= d {
                        return Ok(None);
                    }
                    Some(d - now)
                }
                None => None,
            };

            let frame = match self
                .reader
                .recv_framed::<WireMsg, _>(&mut self.transport, remaining)
            {
                Ok(Some(WireMsg::Data(frame))) => frame,
                Ok(Some(WireMsg::Handshake(hello))) => {
                    // Sender restarted and is re-keying: answer and reset.
                    match respond_handshake(
                        &mut self.transport,
                        &self.signing_key,
                        &self.authorized_peer,
                        hello,
                    )? {
                        Some(aes_key) => {
                            self.aes_key = aes_key;
                            self.inorder = InOrder::default();
                            self.stats.rehandshakes += 1;
                        }
                        None => self.stats.decode_fail += 1,
                    }
                    continue;
                }
                Ok(None) => return Ok(None),
                Err(ref e) if e.kind() == io::ErrorKind::InvalidData => {
                    self.stats.decode_fail += 1;
                    continue;
                }
                Err(e) => return Err(e),
            };

            // Reject old frames before decrypting. Commit newer seq values only
            // after authentication succeeds (seq is authenticated via GCM AAD).
            let skipped = match self.inorder.decide(frame.seq) {
                InOrderDecision::Accept => 0,
                InOrderDecision::AcceptWithGap { skipped } => skipped,
                InOrderDecision::DropOldOrDuplicate => {
                    self.stats.dup_or_old_drop += 1;
                    continue;
                }
            };

            match open(&self.aes_key, &frame) {
                Ok(plaintext) => {
                    self.inorder.accept(frame.seq);
                    self.stats.skipped_packets += skipped;
                    self.stats.ok += 1;
                    return Ok(Some(plaintext));
                }
                Err(_) => {
                    self.stats.auth_fail += 1;
                }
            }
        }
    }

    pub fn into_inner(self) -> T {
        self.transport
    }
}

/// Verify a ClientHello, send the ServerHello, and derive the session key.
/// Returns `Ok(None)` if the hello is invalid or from an unauthorized sender.
fn respond_handshake<T: Transport>(
    transport: &mut T,
    signing_key: &SigningKey,
    authorized_peer: &VerifyingKey,
    hello: HandshakeMsg,
) -> io::Result<Option<Key<Aes256Gcm>>> {
    let Some((server_hello, server_eph_secret, client_id_pub, client_eph_pub)) =
        respond_server_hello(signing_key, authorized_peer, hello)
    else {
        return Ok(None);
    };

    let (server_id_pub, server_eph_pub) = match &server_hello {
        HandshakeMsg::ServerHello {
            server_identity_pub,
            server_eph_pub,
            ..
        } => (*server_identity_pub, *server_eph_pub),
        _ => unreachable!(),
    };

    send_framed(transport, &WireMsg::Handshake(server_hello))?;

    Ok(Some(finish_server(
        server_eph_secret,
        server_id_pub,
        server_eph_pub,
        client_id_pub,
        client_eph_pub,
    )))
}
