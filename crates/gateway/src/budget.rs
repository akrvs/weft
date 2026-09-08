use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use weft_core::PublicKey;

pub const DEFAULT_BYTES: u64 = 64 * 1024 * 1024;
pub const WINDOW: u64 = 3600;

#[derive(Debug, Clone, Copy)]
struct Spend {
    since: u64,
    bytes: u64,
}

#[derive(Debug)]
pub struct Budget {
    bytes: u64,
    window: u64,
    spent: Mutex<HashMap<PublicKey, Spend>>,
}

impl Budget {
    #[must_use]
    pub fn new(bytes: u64, window: u64) -> Self {
        Self { bytes, window, spent: Mutex::new(HashMap::new()) }
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<PublicKey, Spend>> {
        self.spent.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn spent(&self, author: &PublicKey, now: u64) -> Option<u64> {
        if self.bytes == 0 {
            return None;
        }
        let table = self.lock();
        let spend = table.get(author)?;
        let reset = spend.since.saturating_add(self.window);
        (now < reset && spend.bytes >= self.bytes).then_some(reset)
    }

    pub fn charge(&self, author: PublicKey, now: u64, bytes: u64) {
        if self.bytes == 0 || bytes == 0 {
            return;
        }
        let mut table = self.lock();
        let window = self.window;
        table.retain(|_, s| now < s.since.saturating_add(window));
        let spend = table.entry(author).or_insert(Spend { since: now, bytes: 0 });
        spend.bytes = spend.bytes.saturating_add(bytes);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use weft_core::SecretKey;

    fn who(n: u8) -> PublicKey {
        SecretKey::from_seed([n; 32]).public()
    }

    #[test]
    fn a_window_fills_then_resets() {
        let budget = Budget::new(100, 60);
        let (a, b) = (who(1), who(2));
        assert_eq!(budget.spent(&a, 10), None);
        budget.charge(a, 10, 60);
        assert_eq!(budget.spent(&a, 20), None, "under budget");
        budget.charge(a, 20, 40);
        assert_eq!(budget.spent(&a, 30), Some(70), "at budget, resets at since plus window");
        assert_eq!(budget.spent(&b, 30), None, "identities are separate");
        assert_eq!(budget.spent(&a, 70), None, "the window has passed");
        budget.charge(a, 70, 1);
        assert_eq!(budget.spent(&a, 71), None);
        budget.charge(a, 71, 99);
        assert_eq!(budget.spent(&a, 72), Some(130), "a new window opened at the first charge");
    }

    #[test]
    fn zero_disables_and_stale_entries_go() {
        let budget = Budget::new(0, 60);
        budget.charge(who(1), 0, u64::MAX);
        assert_eq!(budget.spent(&who(1), 1), None);
        assert!(budget.lock().is_empty());
        let budget = Budget::new(10, 60);
        budget.charge(who(1), 0, 10);
        budget.charge(who(2), 0, 1);
        budget.charge(who(3), 61, 1);
        assert_eq!(budget.lock().len(), 1, "expired windows are pruned on charge");
        assert_eq!(budget.spent(&who(1), 61), None);
    }
}
