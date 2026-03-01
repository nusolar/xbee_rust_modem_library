//! Replay protection.
//!
//! We implement a sliding window over sequence numbers.
//! - Accept new seqs greater than the max, shifting the window.
//! - Accept out-of-order seqs within the window if not already seen.
//! - Reject old seqs outside the window.
//! - Reject duplicates already seen.
//!
//! This is the standard approach used in many protocols.

#[derive(Debug, Clone)]
pub struct ReplayWindow {
    /// Highest sequence number accepted so far.
    max_seq: u64,
    /// Bitmask of which sequence numbers in the window have been seen.
    /// Bit 0 corresponds to max_seq, bit 1 to max_seq-1, etc.
    seen_mask: u64,
    /// Whether we've accepted any packet yet.
    initialized: bool,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self {
            max_seq: 0,
            seen_mask: 0,
            initialized: false,
        }
    }
}

impl ReplayWindow {
    /// Window size is 64 (because mask is u64).
    pub const WINDOW: u64 = 64;

    /// Returns true if this sequence number should be accepted.
    /// If accepted, internal state is updated.
    pub fn accept(&mut self, seq: u64) -> bool {
        if !self.initialized {
            self.initialized = true;
            self.max_seq = seq;
            self.seen_mask = 1; // mark max_seq as seen
            return true;
        }

        if seq > self.max_seq {
            // Advance max_seq forward and shift the mask.
            let shift = seq - self.max_seq;
            if shift >= Self::WINDOW {
                // Jumped beyond entire window: forget history.
                self.seen_mask = 1;
            } else {
                self.seen_mask <<= shift;
                self.seen_mask |= 1; // mark new max as seen
            }
            self.max_seq = seq;
            return true;
        }

        // seq <= max_seq: check if within window
        let diff = self.max_seq - seq;
        if diff >= Self::WINDOW {
            return false; // too old
        }

        let bit = 1u64 << diff;
        if (self.seen_mask & bit) != 0 {
            return false; // duplicate replay
        }

        // Mark as seen
        self.seen_mask |= bit;
        true
    }
}