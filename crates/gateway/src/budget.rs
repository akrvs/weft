use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use weft_core::PublicKey;
use weft_core::cbor::{self, Value};

use crate::login::Refusal;

pub const DEFAULT_BYTES: u64 = 64 * 1024 * 1024;
pub const WINDOW: u64 = 3600;
pub const MAX_ENTRIES: usize = 1024;
pub const FILE: &str = "gateway/budget";

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
    path: PathBuf,
    spent: Mutex<Table>,
}

fn state(e: impl core::fmt::Display) -> Refusal {
    Refusal::State(e.to_string())
}

fn parse(path: &Path, now: u64, window: u64) -> Result<Table, Refusal> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Table::new()),
        Err(e) => return Err(state(e)),
    };
    let value = cbor::decode(&bytes).map_err(state)?;
    let items = value.as_array().ok_or_else(|| state("not an array"))?;
    if items.len() > MAX_ENTRIES {
        return Err(state("too many identities"));
    }
    let mut table = Table::new();
    for item in items {
        let map = item.as_map().ok_or_else(|| state("spend is not a map"))?;
        cbor::only(map, &["author", "bytes", "since"]).map_err(state)?;
        let author: [u8; 32] = cbor::field(map, "author")
            .map_err(state)?
            .as_bytes()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| state("author is not 32 bytes"))?;
        PublicKey::from_bytes(&author).map_err(state)?;
        let bytes = cbor::field(map, "bytes")
            .map_err(state)?
            .as_uint()
            .ok_or_else(|| state("bytes is not an integer"))?;
        let since = cbor::field(map, "since")
            .map_err(state)?
            .as_uint()
            .ok_or_else(|| state("since is not an integer"))?;
        if now < since.saturating_add(window)
            && table.insert(author, Spend { since, bytes }).is_some()
        {
            return Err(state("duplicate author"));
        }
    }
    Ok(table)
}

fn save(path: &Path, table: &Table) -> Result<(), Refusal> {
    let items = table
        .iter()
        .map(|(author, s)| {
            Value::Map(vec![
                ("author".into(), Value::Bytes(author.to_vec())),
                ("bytes".into(), Value::Uint(s.bytes)),
                ("since".into(), Value::Uint(s.since)),
            ])
        })
        .collect();
    weft_home::fs::replace_private(path, &Value::Array(items).encode()).map_err(state)
}

impl Budget {
    pub fn open(path: PathBuf, bytes: u64, window: u64, now: u64) -> Result<Self, Refusal> {
        let spent =
            parse(&path, now, window).map_err(|e| state(format!("{}: {e}", path.display())))?;
        Ok(Self { bytes, window, path, spent: Mutex::new(spent) })
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
        let window = self.window;
        table.retain(|_, s| now < s.since.saturating_add(window));
        if !table.contains_key(author.bytes()) && table.len() >= MAX_ENTRIES {
            let oldest = table.iter().min_by_key(|(_, s)| s.since).map(|(k, _)| *k);
            if let Some(k) = oldest {
                table.remove(&k);
            }
        }
        let spend = table.entry(*author.bytes()).or_insert(Spend { since: now, bytes: 0 });
        spend.bytes = spend.bytes.saturating_add(bytes);
        save(&self.path, &table)
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

    fn path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("weft-budget-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir.join(FILE)
    }

    fn open(path: &Path, bytes: u64, now: u64) -> Budget {
        Budget::open(path.to_path_buf(), bytes, 60, now).unwrap()
    }

    #[test]
    fn a_window_fills_then_resets() {
        let budget = open(&path("window"), 100, 0);
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
        let path = path("zero");
        let budget = open(&path, 0, 0);
        budget.charge(who(1), 0, u64::MAX).unwrap();
        assert_eq!(budget.spent(&who(1), 1), None);
        assert!(budget.lock().is_empty());
        assert!(!path.exists(), "an unlimited budget writes nothing");
        let budget = open(&path, 10, 0);
        budget.charge(who(1), 0, 10).unwrap();
        budget.charge(who(2), 0, 1).unwrap();
        budget.charge(who(3), 61, 1).unwrap();
        assert_eq!(budget.lock().len(), 1, "expired windows are pruned on charge");
    }

    #[test]
    fn spent_windows_survive_a_restart_and_expired_ones_do_not() {
        let path = path("restart");
        let budget = open(&path, 100, 0);
        budget.charge(who(1), 10, 100).unwrap();
        budget.charge(who(2), 20, 1).unwrap();
        drop(budget);
        let again = open(&path, 100, 30);
        assert_eq!(again.spent(&who(1), 30), Some(70), "the spent window is back");
        assert_eq!(again.spent(&who(2), 30), None);
        assert_eq!(again.lock().len(), 2);
        let later = open(&path, 100, 85);
        assert!(later.lock().is_empty(), "windows past their reset are dropped on load");
        assert_eq!(later.spent(&who(1), 85), None);
    }

    #[test]
    fn a_bad_file_refuses_and_the_table_is_capped() {
        let path = path("bad");
        let budget = open(&path, 100, 0);
        budget.charge(who(1), 0, 1).unwrap();
        let good = std::fs::read(&path).unwrap();
        std::fs::write(&path, &good[..good.len() - 1]).unwrap();
        assert!(matches!(Budget::open(path.clone(), 100, 60, 0).unwrap_err(), Refusal::State(_)));
        let extra = Value::Array(vec![Value::Map(vec![
            ("author".into(), Value::Bytes(who(1).bytes().to_vec())),
            ("bytes".into(), Value::Uint(1)),
            ("extra".into(), Value::Uint(1)),
            ("since".into(), Value::Uint(0)),
        ])]);
        std::fs::write(&path, extra.encode()).unwrap();
        assert!(matches!(Budget::open(path.clone(), 100, 60, 0).unwrap_err(), Refusal::State(_)));
        std::fs::write(&path, good).unwrap();
        let budget = open(&path, 100, 0);
        for n in 0..MAX_ENTRIES {
            let mut seed = [0u8; 32];
            seed[..8].copy_from_slice(&u64::try_from(n).unwrap().saturating_add(100).to_be_bytes());
            budget.charge(SecretKey::from_seed(seed).public(), 1, 1).unwrap();
        }
        assert_eq!(budget.lock().len(), MAX_ENTRIES);
        assert!(!budget.lock().contains_key(who(1).bytes()), "the oldest window made room");
        let _ = std::fs::remove_dir_all(path.parent().unwrap().parent().unwrap());
    }
}
