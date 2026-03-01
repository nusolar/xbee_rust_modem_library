# XBee Rust Modem Library

** Overview

Directory Layout:
xbee_secure/
  Cargo.toml
  src/
    lib.rs
    serial.rs
    framing.rs
    keys.rs
    replay.rs
    handshake.rs
    secure_packet.rs
  src/bin/
    sender.rs
    receiver.rs
  keys/
    sender_ed25519.key        (auto-generated if missing)
    sender_ed25519.pub        (auto-generated)
    receiver_ed25519.key      (auto-generated if missing)
    receiver_ed25519.pub      (auto-generated)
    authorized_sender.pub     (copy sender pub here for receiver)
    authorized_receiver.pub   (copy receiver pub here for sender)