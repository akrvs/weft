use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use weft_core::PublicKey;

use crate::login::Refusal;
use crate::state::State;

pub const DEFAULT_BYTES: u64 = 64 * 1024 * 1024;
pub const WINDOW: u64 = 3600;
pub const DEFAULT_IDENTITIES: usize = 4096;

#[derive(Debug, Clone, Copy)]
struct Spend {
    since: u64,
    bytes: u64,
}

type Table = BTreeMap<[u8; 32], Spend>;

#[derive(Debug)]
pub struct Budget {
    bytes: u64,
    window: u64,
    cap: usize,
    state: Arc<State>,
    spent: Mutex<Table>,
}

fn expired(table: &Table, now: u64, window: u64) -> Vec<[u8; 32]> {
    table.iter().filter(|(_, s)| now >= s.since.saturating_add(window)).map(|(k, _)| *k).collect()
}

fn oldest(table: &Table, cap: usize) -> Vec<[u8; 32]> {
    let mut by_age: Vec<(u64, [u8; 32])> = table.iter().map(|(k, s)| (s.since, *k)).collect();
    by_age.sort_unstable();
    by_age.iter().take(table.len().saturating_sub(cap)).map(|(_, k)| *k).collect()
}

impl Budget {
    pub fn open(
        state: Arc<State>,
        bytes: u64,
        window: u64,
        cap: usize,
        now: u64,
    ) -> Result<Self, Refusal> {
        let mut table = Table::new();
        for (author, since, bytes) in state.spends()? {
            PublicKey::from_bytes(&author).map_err(|e| Refusal::State(e.to_string()))?;
            table.insert(author, Spend { since, bytes });
        }
        let mut gone = expired(&table, now, window);
        for k in &gone {
            table.remove(k);
        }
        let evicted = oldest(&table, cap);
        for k in &evicted {
            table.remove(k);
        }
        gone.extend(evicted);
        state.remove_spends(gone.iter())?;
        Ok(Self { bytes, window, cap, state, spent: Mutex::new(table) })
    }

    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    pub fn set_bytes(&mut self, bytes: u64) {
        self.bytes = bytes;
    }

    fn lock(&self) -> MutexGuard<'_, Table> {
        self.spent.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn spent(&self, author: &PublicKey, now: u64) -> Option<u64> {
        if self.bytes == 0 {
            return None;
        }
        let table = self.lock();
        let spend = table.get(author.bytes())?;
        let reset = spend.since.saturating_add(self.window);
        (now < reset && spend.bytes >= self.bytes).then_some(reset)
    }

    pub fn charge(&self, author: PublicKey, now: u64, bytes: u64) -> Result<(), Refusal> {
        if self.bytes == 0 || bytes == 0 {
            return Ok(());
        }
        let mut table = self.lock();
        let mut gone = expired(&table, now, self.window);
        for k in &gone {
            table.remove(k);
        }
        if !table.contains_key(author.bytes()) {
            let evicted = oldest(&table, self.cap.saturating_sub(1));
            for k in &evicted {
                table.remove(k);
            }
            gone.extend(evicted);
        }
        if !gone.is_empty() {
            self.state.remove_spends(gone.iter())?;
        }
        let spend = table.entry(*author.bytes()).or_insert(Spend { since: now, bytes: 0 });
        spend.bytes = spend.bytes.saturating_add(bytes);
        self.state.put_spend(author.bytes(), spend.since, spend.bytes)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use weft_core::SecretKey;

    fn who(n: u8) -> PublicKey {
        SecretKey::from_seed([n; 32]).public()
    }

    fn home(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("weft-budget-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn open(home: &Path, bytes: u64, now: u64) -> Budget {
        capped(home, bytes, 3, now)
    }

    fn capped(home: &Path, bytes: u64, cap: usize, now: u64) -> Budget {
        Budget::open(Arc::new(State::open(home).unwrap()), bytes, 60, cap, now).unwrap()
    }

    #[test]
    fn a_window_fills_then_resets() {
        let budget = open(&home("window"), 100, 0);
        let (a, b) = (who(1), who(2));
        assert_eq!(budget.spent(&a, 10), None);
        budget.charge(a, 10, 60).unwrap();
        assert_eq!(budget.spent(&a, 20), None, "under budget");
        budget.charge(a, 20, 40).unwrap();
        assert_eq!(budget.spent(&a, 30), Some(70), "at budget, resets at since plus window");
        assert_eq!(budget.spent(&b, 30), None, "identities are separate");
        assert_eq!(budget.spent(&a, 70), None, "the window has passed");
        budget.charge(a, 70, 1).unwrap();
        assert_eq!(budget.spent(&a, 71), None);
        budget.charge(a, 71, 99).unwrap();
        assert_eq!(budget.spent(&a, 72), Some(130), "a new window opened at the first charge");
    }

    #[test]
    fn zero_disables_and_stale_entries_go() {
        let dir = home("zero");
        let budget = open(&dir, 0, 0);
        budget.charge(who(1), 0, u64::MAX).unwrap();
        assert_eq!(budget.spent(&who(1), 1), None);
        assert!(budget.lock().is_empty());
        assert!(budget.state.spends().unwrap().is_empty(), "an unlimited budget writes nothing");
        drop(budget);
        let budget = open(&dir, 10, 0);
        budget.charge(who(1), 0, 10).unwrap();
        budget.charge(who(2), 0, 1).unwrap();
        budget.charge(who(3), 61, 1).unwrap();
        assert_eq!(budget.lock().len(), 1, "expired windows are pruned on charge");
        assert_eq!(budget.state.spends().unwrap().len(), 1, "and leave the table");
    }

    #[test]
    fn spent_windows_survive_a_restart_and_expired_ones_do_not() {
        let dir = home("restart");
        let budget = open(&dir, 100, 0);
        budget.charge(who(1), 10, 100).unwrap();
        budget.charge(who(2), 20, 1).unwrap();
        drop(budget);
        let again = open(&dir, 100, 30);
        assert_eq!(again.spent(&who(1), 30), Some(70), "the spent window is back");
        assert_eq!(again.spent(&who(2), 30), None);
        assert_eq!(again.lock().len(), 2);
        drop(again);
        let later = open(&dir, 100, 85);
        assert!(later.lock().is_empty(), "windows past their reset are dropped on load");
        assert_eq!(later.spent(&who(1), 85), None);
        assert!(later.state.spends().unwrap().is_empty());
    }

    #[test]
    fn a_bad_file_refuses_and_the_table_is_capped() {
        let dir = home("bad");
        let budget = open(&dir, 100, 0);
        budget.charge(who(1), 0, 1).unwrap();
        drop(budget);
        let path = dir.join(crate::state::FILE);
        let good = std::fs::read(&path).unwrap();
        std::fs::write(&path, &good[..64]).unwrap();
        assert!(matches!(State::open(&dir).unwrap_err(), Refusal::State(_)));
        std::fs::write(&path, good).unwrap();
        let budget = open(&dir, 100, 0);
        for n in 0..3 {
            let mut seed = [0u8; 32];
            seed[..8].copy_from_slice(&u64::try_from(n).unwrap().saturating_add(100).to_be_bytes());
            budget.charge(SecretKey::from_seed(seed).public(), 1, 1).unwrap();
        }
        assert_eq!(budget.lock().len(), 3);
        assert!(!budget.lock().contains_key(who(1).bytes()), "the oldest window made room");
        drop(budget);
        let lowered = capped(&dir, 100, 1, 2);
        assert_eq!(lowered.lock().len(), 1, "a lower cap keeps the newest window");
        assert_eq!(lowered.state.spends().unwrap().len(), 1);
        drop(lowered);
        assert_eq!(capped(&dir, 100, 100_000, 2).lock().len(), 1, "no cap ceiling");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
