#[derive(Debug, Clone, Default)]
pub struct InOrder {
    expected_seq: u64,
    initialized: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InOrderDecision {
    Accept,
    AcceptWithGap { skipped: u64 },
    DropOldOrDuplicate,
}

impl InOrder {
    pub fn decide(&self, seq: u64) -> InOrderDecision {
        if !self.initialized {
            return InOrderDecision::Accept;
        }

        if seq == self.expected_seq {
            return InOrderDecision::Accept;
        }

        if seq < self.expected_seq {
            InOrderDecision::DropOldOrDuplicate
        } else {
            let skipped = seq - self.expected_seq;
            InOrderDecision::AcceptWithGap { skipped }
        }
    }

    pub fn accept(&mut self, seq: u64) {
        self.initialized = true;
        self.expected_seq = seq.wrapping_add(1);
    }

    pub fn decide_and_update(&mut self, seq: u64) -> InOrderDecision {
        let decision = self.decide(seq);
        if !matches!(decision, InOrderDecision::DropOldOrDuplicate) {
            self.accept(seq);
        }
        decision
    }

    pub fn expected(&self) -> Option<u64> {
        self.initialized.then_some(self.expected_seq)
    }
}

#[cfg(test)]
mod tests {
    use super::{InOrder, InOrderDecision};

    #[test]
    fn accepts_contiguous_sequences() {
        let mut inorder = InOrder::default();

        assert_eq!(inorder.decide_and_update(0), InOrderDecision::Accept);
        assert_eq!(inorder.decide_and_update(1), InOrderDecision::Accept);
        assert_eq!(inorder.decide_and_update(2), InOrderDecision::Accept);
        assert_eq!(inorder.expected(), Some(3));
    }

    #[test]
    fn accepts_newer_sequences_with_gap() {
        let mut inorder = InOrder::default();

        assert_eq!(inorder.decide_and_update(10), InOrderDecision::Accept);
        assert_eq!(
            inorder.decide_and_update(13),
            InOrderDecision::AcceptWithGap { skipped: 2 }
        );
        assert_eq!(inorder.expected(), Some(14));
    }

    #[test]
    fn drops_old_or_duplicate_sequences() {
        let mut inorder = InOrder::default();

        assert_eq!(inorder.decide_and_update(5), InOrderDecision::Accept);
        assert_eq!(
            inorder.decide_and_update(5),
            InOrderDecision::DropOldOrDuplicate
        );
        assert_eq!(
            inorder.decide_and_update(4),
            InOrderDecision::DropOldOrDuplicate
        );
    }

    #[test]
    fn decide_does_not_update_until_accepted() {
        let mut inorder = InOrder::default();

        assert_eq!(inorder.decide(7), InOrderDecision::Accept);
        assert_eq!(inorder.expected(), None);

        inorder.accept(7);
        assert_eq!(inorder.expected(), Some(8));
    }
}
