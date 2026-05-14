#[derive(Debug, Clone, Default)]
pub struct InOrder {
    expected_seq: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InOrderDecision {
    Accept,
    DropOldOrDuplicate,
    AcceptWithGap { missed: u64 },
}

impl InOrder {
    pub fn decide(&self, seq: u64) -> InOrderDecision {
        if seq == self.expected_seq {
            return InOrderDecision::Accept;
        }

        if seq < self.expected_seq {
            InOrderDecision::DropOldOrDuplicate
        } else {
            InOrderDecision::AcceptWithGap {
                missed: seq - self.expected_seq,
            }
        }
    }

    pub fn mark_accepted(&mut self, seq: u64) {
        if seq >= self.expected_seq {
            self.expected_seq = seq.wrapping_add(1);
        }
    }

    pub fn decide_and_update(&mut self, seq: u64) -> InOrderDecision {
        let decision = self.decide(seq);
        match decision {
            InOrderDecision::Accept | InOrderDecision::AcceptWithGap { .. } => {
                self.mark_accepted(seq);
            }
            InOrderDecision::DropOldOrDuplicate => {}
        }
        decision
    }

    pub fn expected(&self) -> u64 {
        self.expected_seq
    }
}

#[cfg(test)]
mod tests {
    use super::{InOrder, InOrderDecision};

    #[test]
    fn starts_at_zero_and_accepts_ahead_packets_with_gap() {
        let replay = InOrder::default();

        assert_eq!(replay.expected(), 0);
        assert_eq!(replay.decide(0), InOrderDecision::Accept);
        assert_eq!(
            replay.decide(1),
            InOrderDecision::AcceptWithGap { missed: 1 }
        );
    }

    #[test]
    fn advances_past_authenticated_gap() {
        let mut replay = InOrder::default();

        assert_eq!(replay.decide(0), InOrderDecision::Accept);
        assert_eq!(replay.expected(), 0);

        replay.mark_accepted(0);

        assert_eq!(replay.expected(), 1);
        assert_eq!(replay.decide(0), InOrderDecision::DropOldOrDuplicate);
        assert_eq!(
            replay.decide(2),
            InOrderDecision::AcceptWithGap { missed: 1 }
        );

        replay.mark_accepted(2);

        assert_eq!(replay.expected(), 3);
        assert_eq!(replay.decide(1), InOrderDecision::DropOldOrDuplicate);
    }

    #[test]
    fn decide_and_update_does_not_advance_on_duplicates() {
        let mut replay = InOrder::default();

        assert_eq!(
            replay.decide_and_update(2),
            InOrderDecision::AcceptWithGap { missed: 2 }
        );
        assert_eq!(replay.expected(), 3);
        assert_eq!(
            replay.decide_and_update(2),
            InOrderDecision::DropOldOrDuplicate
        );
        assert_eq!(replay.expected(), 3);
    }
}
