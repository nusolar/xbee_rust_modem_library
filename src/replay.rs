#[derive(Debug, Clone, Default)]
pub struct InOrder {
    expected_seq: u64,
    initialized: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InOrderDecision {
    Accept,
    DropOldOrDuplicate,
    DropOutOfOrderAhead,
}

impl InOrder {
    pub fn decide_and_update(&mut self, seq: u64) -> InOrderDecision {
        if !self.initialized {
            self.initialized = true;
            self.expected_seq = seq.wrapping_add(1);
            return InOrderDecision::Accept;
        }

        if seq == self.expected_seq {
            self.expected_seq = self.expected_seq.wrapping_add(1);
            return InOrderDecision::Accept;
        }

        if seq < self.expected_seq {
            InOrderDecision::DropOldOrDuplicate
        } else {
            InOrderDecision::DropOutOfOrderAhead
        }
    }

    pub fn expected(&self) -> Option<u64> {
        self.initialized.then_some(self.expected_seq)
    }
}
