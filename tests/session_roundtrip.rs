//! End-to-end session test over an in-memory transport: handshake,
//! encrypted payload round-trip, and mid-stream re-handshake. No hardware.

use std::io;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread;
use std::time::Duration;

use xbee_rust_modem_library::SigningKey;
use xbee_rust_modem_library::session::{SecureReceiver, SecureSender};
use xbee_rust_modem_library::transport::Transport;

/// One end of an in-memory radio link. `recv` mimics the serial layer's
/// behavior: short blocking reads that fail with `TimedOut` when idle.
struct MockTransport {
    tx: Sender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
    pending: Vec<u8>,
}

fn transport_pair() -> (MockTransport, MockTransport) {
    let (tx_a, rx_b) = mpsc::channel();
    let (tx_b, rx_a) = mpsc::channel();
    (
        MockTransport { tx: tx_a, rx: rx_a, pending: Vec::new() },
        MockTransport { tx: tx_b, rx: rx_b, pending: Vec::new() },
    )
}

impl Transport for MockTransport {
    fn send(&mut self, data: &[u8]) -> io::Result<()> {
        self.tx
            .send(data.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "peer dropped"))
    }

    fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pending.is_empty() {
            match self.rx.recv_timeout(Duration::from_millis(10)) {
                Ok(bytes) => self.pending = bytes,
                Err(RecvTimeoutError::Timeout) => {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "no data"));
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(io::Error::new(io::ErrorKind::BrokenPipe, "peer dropped"));
                }
            }
        }
        let n = buf.len().min(self.pending.len());
        buf[..n].copy_from_slice(&self.pending[..n]);
        self.pending.drain(..n);
        Ok(n)
    }
}

const RETRY: Duration = Duration::from_millis(200);
const RECV_TIMEOUT: Duration = Duration::from_secs(5);

#[test]
fn handshake_and_payload_roundtrip() {
    let (car_side, chase_side) = transport_pair();

    let sender_sk = SigningKey::generate(&mut rand_core::OsRng);
    let receiver_sk = SigningKey::generate(&mut rand_core::OsRng);
    let sender_pk = sender_sk.verifying_key();
    let receiver_pk = receiver_sk.verifying_key();

    let rx_thread = thread::spawn(move || {
        let mut rx = SecureReceiver::establish(chase_side, receiver_sk, sender_pk).unwrap();
        let mut got = Vec::new();
        for _ in 0..5 {
            let payload = rx.recv_payload(Some(RECV_TIMEOUT)).unwrap().expect("timed out");
            got.push(payload.as_slice().to_vec());
        }
        (got, rx.stats.clone())
    });

    let mut tx = SecureSender::establish(car_side, &sender_sk, &receiver_pk, RETRY).unwrap();
    for i in 0..5 {
        tx.send_payload(format!("msg {i}").as_bytes()).unwrap();
    }

    let (got, stats) = rx_thread.join().unwrap();
    let want: Vec<Vec<u8>> = (0..5).map(|i| format!("msg {i}").into_bytes()).collect();
    assert_eq!(got, want);
    assert_eq!(stats.ok, 5);
    assert_eq!(stats.auth_fail, 0);
    assert_eq!(stats.decode_fail, 0);
    assert_eq!(stats.rehandshakes, 0);
}

#[test]
fn sender_restart_triggers_transparent_rehandshake() {
    let (car_side, chase_side) = transport_pair();

    let sender_sk = SigningKey::generate(&mut rand_core::OsRng);
    let receiver_sk = SigningKey::generate(&mut rand_core::OsRng);
    let sender_pk = sender_sk.verifying_key();
    let receiver_pk = receiver_sk.verifying_key();

    let rx_thread = thread::spawn(move || {
        let mut rx = SecureReceiver::establish(chase_side, receiver_sk, sender_pk).unwrap();
        let mut got = Vec::new();
        // 2 messages from the first session + 2 from the restarted sender;
        // the re-handshake in between must be invisible to this loop.
        for _ in 0..4 {
            let payload = rx.recv_payload(Some(RECV_TIMEOUT)).unwrap().expect("timed out");
            got.push(payload.as_slice().to_vec());
        }
        (got, rx.stats.clone())
    });

    let mut tx = SecureSender::establish(car_side, &sender_sk, &receiver_pk, RETRY).unwrap();
    tx.send_payload(b"first session 0").unwrap();
    tx.send_payload(b"first session 1").unwrap();

    // Simulate a bridge restart: same wire, brand-new session (new key, seq=0).
    let transport = tx.into_inner();
    let mut tx = SecureSender::establish(transport, &sender_sk, &receiver_pk, RETRY).unwrap();
    tx.send_payload(b"second session 0").unwrap();
    tx.send_payload(b"second session 1").unwrap();

    let (got, stats) = rx_thread.join().unwrap();
    assert_eq!(
        got,
        vec![
            b"first session 0".to_vec(),
            b"first session 1".to_vec(),
            b"second session 0".to_vec(),
            b"second session 1".to_vec(),
        ]
    );
    assert_eq!(stats.ok, 4);
    assert_eq!(stats.rehandshakes, 1);
    // seq reset to 0 after rekey must not be dropped as a replay
    assert_eq!(stats.dup_or_old_drop, 0);
}

#[test]
fn unauthorized_sender_is_rejected() {
    let (car_side, chase_side) = transport_pair();

    let impostor_sk = SigningKey::generate(&mut rand_core::OsRng);
    let real_sender_pk = SigningKey::generate(&mut rand_core::OsRng).verifying_key();
    let receiver_sk = SigningKey::generate(&mut rand_core::OsRng);
    let receiver_pk = receiver_sk.verifying_key();

    // Receiver only trusts real_sender_pk, so the impostor's hellos must never
    // be answered and both establish() calls must stay blocked.
    let rx_thread = thread::spawn(move || {
        SecureReceiver::establish(chase_side, receiver_sk, real_sender_pk).ok();
    });
    let impostor_thread = thread::spawn(move || {
        SecureSender::establish(car_side, &impostor_sk, &receiver_pk, Duration::from_millis(50))
            .ok();
    });

    thread::sleep(Duration::from_millis(500));
    assert!(
        !rx_thread.is_finished(),
        "receiver accepted an unauthorized sender"
    );
    assert!(
        !impostor_thread.is_finished(),
        "impostor completed a handshake"
    );
    // Both threads are deliberately leaked; they die with the test process.
}
