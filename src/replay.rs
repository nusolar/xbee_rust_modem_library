#[derive(Debug, Clone, Default)]
pub struct InOrder {
    expected_seq: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InOrderDecision {
    Accept,
    DropOldOrDuplicate,
    DropOutOfOrderAhead,
}

impl InOrder {
    pub fn decide(&self, seq: u64) -> InOrderDecision {
        if seq == self.expected_seq {
            return InOrderDecision::Accept;
        }

        if seq < self.expected_seq {
            InOrderDecision::DropOldOrDuplicate
        } else {
            InOrderDecision::DropOutOfOrderAhead
        }
    }

    pub fn mark_accepted(&mut self, seq: u64) {
        if seq == self.expected_seq {
            self.expected_seq = self.expected_seq.wrapping_add(1);
        }
    }

    pub fn decide_and_update(&mut self, seq: u64) -> InOrderDecision {
        let decision = self.decide(seq);
        if decision == InOrderDecision::Accept {
            self.mark_accepted(seq);
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
    fn starts_at_zero_and_drops_ahead_packets() {
        let replay = InOrder::default();

        assert_eq!(replay.expected(), 0);
        assert_eq!(replay.decide(0), InOrderDecision::Accept);
        assert_eq!(replay.decide(1), InOrderDecision::DropOutOfOrderAhead);
    }

    #[test]
    fn only_advances_when_marked_accepted() {
        let mut replay = InOrder::default();

        assert_eq!(replay.decide(0), InOrderDecision::Accept);
        assert_eq!(replay.expected(), 0);

        replay.mark_accepted(0);

        assert_eq!(replay.expected(), 1);
        assert_eq!(replay.decide(0), InOrderDecision::DropOldOrDuplicate);
        assert_eq!(replay.decide(2), InOrderDecision::DropOutOfOrderAhead);
    }
}
