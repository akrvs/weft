use std::path::{Path, PathBuf};

use serde::Serialize;
use weft_core::{Address, PublicKey};
use weft_home::{Result, fail, fs};

pub const DIR: &str = "browser";
pub const HISTORY: &str = "history";
pub const BOOKMARKS: &str = "bookmarks";
pub const MAX_HISTORY: usize = 1024;
pub const MAX_TITLE: usize = 128;
pub const MAX_TARGET: usize = 2048;
pub const LABELERS: &str = "labelers";
pub const ACTIONS: &str = "actions";
pub const MAX_LABELERS: usize = 64;
pub const REACH: &str = "reach";
pub const DEFAULT_REACH: Reach = Reach::Within(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    Within(u8),
    Any,
}

impl Serialize for Reach {
    fn serialize<S: serde::Serializer>(&self, s: S) -> core::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.line())
    }
}

impl Reach {
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "any" => Some(Self::Any),
            "1" => Some(Self::Within(1)),
            "2" => Some(Self::Within(2)),
            "3" => Some(Self::Within(3)),
            _ => None,
        }
    }

    pub fn admits(self, distance: Option<u8>) -> bool {
        match self {
            Self::Any => true,
            Self::Within(max) => distance.is_some_and(|d| d <= max),
        }
    }

    fn line(self) -> String {
        match self {
            Self::Any => "any".to_owned(),
            Self::Within(d) => d.to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Highlight,
    Warn,
    Blur,
    Hide,
}

impl Action {
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "highlight" => Some(Self::Highlight),
            "warn" => Some(Self::Warn),
            "blur" => Some(Self::Blur),
            "hide" => Some(Self::Hide),
            _ => None,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Highlight => "highlight",
            Self::Warn => "warn",
            Self::Blur => "blur",
            Self::Hide => "hide",
        }
    }
}

#[derive(Debug)]
pub struct Marks {
    dir: PathBuf,
}

fn field(value: &str, what: &str, max: usize) -> Result<()> {
    if value.is_empty() || value.len() > max || value.contains(['\t', '\n', '\r']) {
        return fail(format!("{what} must be one line of at most {max} bytes"));
    }
    Ok(())
}

impl Marks {
    pub fn new(home: &Path) -> Self {
        Self { dir: home.join(DIR) }
    }

    fn read(&self, name: &str) -> Result<String> {
        match std::fs::read_to_string(self.dir.join(name)) {
            Ok(text) => Ok(text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
            Err(e) => Err(e.into()),
        }
    }

    fn write(&self, name: &str, lines: &[String]) -> Result<()> {
        let mut text = lines.join("\n");
        if !text.is_empty() {
            text.push('\n');
        }
        fs::replace_private(&self.dir.join(name), text.as_bytes())
    }

    pub fn history(&self) -> Result<Vec<(u64, String)>> {
        Ok(self
            .read(HISTORY)?
            .lines()
            .filter_map(|l| l.split_once('\t'))
            .filter_map(|(t, target)| t.parse().ok().map(|t| (t, target.to_owned())))
            .collect())
    }

    pub fn visit(&self, target: &str, now: u64) -> Result<()> {
        field(target, "target", MAX_TARGET)?;
        let mut lines: Vec<String> = self.read(HISTORY)?.lines().map(str::to_owned).collect();
        if lines.last().and_then(|l| l.split_once('\t')).is_some_and(|(_, t)| t == target) {
            return Ok(());
        }
        lines.push(format!("{now}\t{target}"));
        let excess = lines.len().saturating_sub(MAX_HISTORY);
        lines.drain(..excess);
        self.write(HISTORY, &lines)
    }

    pub fn clear_history(&self) -> Result<()> {
        self.write(HISTORY, &[])
    }

    pub fn bookmarks(&self) -> Result<Vec<(String, String)>> {
        Ok(self
            .read(BOOKMARKS)?
            .lines()
            .filter_map(|l| l.split_once('\t'))
            .map(|(target, title)| (target.to_owned(), title.to_owned()))
            .collect())
    }

    pub fn bookmark(&self, target: &str, title: &str) -> Result<()> {
        field(target, "target", MAX_TARGET)?;
        field(title, "title", MAX_TITLE)?;
        let mut lines = self.others(target)?;
        lines.push(format!("{target}\t{title}"));
        self.write(BOOKMARKS, &lines)
    }

    pub fn unbookmark(&self, target: &str) -> Result<()> {
        let lines = self.others(target)?;
        self.write(BOOKMARKS, &lines)
    }

    pub fn labelers(&self) -> Result<Vec<PublicKey>> {
        Ok(self
            .read(LABELERS)?
            .lines()
            .filter_map(|l| l.parse::<Address>().ok())
            .filter(|a| a.kind() == weft_core::address::Kind::Key)
            .filter_map(|a| PublicKey::from_bytes(a.bytes()).ok())
            .take(MAX_LABELERS)
            .collect())
    }

    pub fn subscribe(&self, key: &PublicKey) -> Result<bool> {
        let mut keys = self.labelers()?;
        if keys.contains(key) {
            return Ok(false);
        }
        if keys.len() >= MAX_LABELERS {
            return fail(format!("at most {MAX_LABELERS} labelers"));
        }
        keys.push(*key);
        self.write_labelers(&keys)?;
        Ok(true)
    }

    pub fn unsubscribe(&self, key: &PublicKey) -> Result<()> {
        let keys: Vec<PublicKey> = self.labelers()?.into_iter().filter(|k| k != key).collect();
        self.write_labelers(&keys)
    }

    fn write_labelers(&self, keys: &[PublicKey]) -> Result<()> {
        let lines: Vec<String> = keys.iter().map(|k| k.address().to_string()).collect();
        self.write(LABELERS, &lines)
    }

    pub fn actions(&self) -> Result<Vec<(String, Action)>> {
        Ok(self
            .read(ACTIONS)?
            .lines()
            .filter_map(|l| l.split_once('\t'))
            .filter_map(|(v, a)| Action::parse(a).map(|a| (v.to_owned(), a)))
            .collect())
    }

    pub fn set_action(&self, value: &str, action: Option<Action>) -> Result<()> {
        if !weft_core::record::valid_kind(value) {
            return fail("a label value is 1 to 32 bytes of a-z, 0-9, _");
        }
        let mut actions: Vec<(String, Action)> =
            self.actions()?.into_iter().filter(|(v, _)| v != value).collect();
        actions.extend(action.map(|a| (value.to_owned(), a)));
        actions.sort_unstable();
        let lines: Vec<String> =
            actions.iter().map(|(v, a)| format!("{v}\t{}", a.name())).collect();
        self.write(ACTIONS, &lines)
    }

    pub fn reach(&self) -> Result<Reach> {
        let text = self.read(REACH)?;
        if text.is_empty() {
            return Ok(DEFAULT_REACH);
        }
        match text.strip_suffix('\n').and_then(Reach::parse) {
            Some(reach) => Ok(reach),
            None => fail(format!("{REACH} holds neither 1, 2, 3, nor any")),
        }
    }

    pub fn set_reach(&self, reach: Reach) -> Result<()> {
        self.write(REACH, &[reach.line()])
    }

    fn others(&self, target: &str) -> Result<Vec<String>> {
        Ok(self
            .read(BOOKMARKS)?
            .lines()
            .filter(|l| l.split_once('\t').is_none_or(|(t, _)| t != target))
            .map(str::to_owned)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn marks(name: &str) -> Marks {
        let dir = std::env::temp_dir().join(format!("weft-marks-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Marks::new(&dir)
    }

    #[test]
    fn history_appends_dedups_and_caps() {
        let m = marks("history");
        assert!(m.history().unwrap().is_empty());
        m.visit("a/home", 10).unwrap();
        m.visit("a/home", 11).unwrap();
        m.visit("b/home", 12).unwrap();
        assert_eq!(
            m.history().unwrap(),
            vec![(10, "a/home".to_owned()), (12, "b/home".to_owned())]
        );
        for i in 0..MAX_HISTORY + 5 {
            m.visit(&format!("n{i}"), 100 + i as u64).unwrap();
        }
        let history = m.history().unwrap();
        assert_eq!(history.len(), MAX_HISTORY);
        assert_eq!(history[0].1, "n5");
        assert_eq!(history.last().unwrap().1, format!("n{}", MAX_HISTORY + 4));
        let mode = std::fs::metadata(m.dir.join(HISTORY)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let dir = std::fs::metadata(&m.dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir, 0o700);
        m.clear_history().unwrap();
        assert!(m.history().unwrap().is_empty());
    }

    #[test]
    fn bookmarks_replace_by_target_and_reject_bad_fields() {
        let m = marks("bookmarks");
        m.bookmark("a/home", "A").unwrap();
        m.bookmark("b/home", "B").unwrap();
        m.bookmark("a/home", "A again").unwrap();
        assert_eq!(
            m.bookmarks().unwrap(),
            vec![
                ("b/home".to_owned(), "B".to_owned()),
                ("a/home".to_owned(), "A again".to_owned())
            ]
        );
        m.unbookmark("b/home").unwrap();
        assert_eq!(m.bookmarks().unwrap().len(), 1);
        assert!(m.bookmark("x\ty", "t").is_err());
        assert!(m.bookmark("x", "line\nbreak").is_err());
        assert!(m.bookmark("", "t").is_err());
        assert!(m.bookmark("x", &"t".repeat(MAX_TITLE + 1)).is_err());
        assert!(m.visit(&"x".repeat(MAX_TARGET + 1), 1).is_err());
        assert_eq!(m.bookmarks().unwrap().len(), 1);
    }

    #[test]
    fn labelers_dedup_cap_and_skip_junk() {
        let m = marks("labelers");
        let key = |n: u8| weft_core::SecretKey::from_seed([n; 32]).public();
        assert!(m.labelers().unwrap().is_empty());
        assert!(m.subscribe(&key(1)).unwrap());
        assert!(!m.subscribe(&key(1)).unwrap());
        assert!(m.subscribe(&key(2)).unwrap());
        assert_eq!(m.labelers().unwrap(), vec![key(1), key(2)]);
        m.unsubscribe(&key(1)).unwrap();
        assert_eq!(m.labelers().unwrap(), vec![key(2)]);
        for n in 3..=65u8 {
            m.subscribe(&key(n)).unwrap();
        }
        assert!(m.subscribe(&key(200)).is_err());
        let path = m.dir.join(LABELERS);
        let mut text = std::fs::read_to_string(&path).unwrap();
        text.push_str("junk\n");
        text.push_str(&Address::of(b"x").to_string());
        std::fs::write(&path, text).unwrap();
        assert_eq!(m.labelers().unwrap().len(), MAX_LABELERS);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn actions_replace_by_value_and_reject_bad_values() {
        let m = marks("actions");
        m.set_action("spam", Some(Action::Hide)).unwrap();
        m.set_action("nsfw", Some(Action::Blur)).unwrap();
        m.set_action("spam", Some(Action::Warn)).unwrap();
        assert_eq!(
            m.actions().unwrap(),
            vec![("nsfw".to_owned(), Action::Blur), ("spam".to_owned(), Action::Warn)]
        );
        m.set_action("nsfw", None).unwrap();
        assert_eq!(m.actions().unwrap(), vec![("spam".to_owned(), Action::Warn)]);
        assert!(m.set_action("no-go", Some(Action::Hide)).is_err());
        assert!(m.set_action("", Some(Action::Hide)).is_err());
        assert!(m.set_action("a\tb", Some(Action::Hide)).is_err());
        assert_eq!(Action::parse("shout"), None);
        assert!(Action::Hide > Action::Blur && Action::Blur > Action::Warn);
        assert!(Action::Warn > Action::Highlight);
    }

    #[test]
    fn reach_defaults_to_two_and_rejects_junk() {
        let m = marks("reach");
        assert_eq!(m.reach().unwrap(), Reach::Within(2));
        m.set_reach(Reach::Any).unwrap();
        assert_eq!(m.reach().unwrap(), Reach::Any);
        m.set_reach(Reach::Within(3)).unwrap();
        assert_eq!(m.reach().unwrap(), Reach::Within(3));
        std::fs::write(m.dir.join(REACH), "4\n").unwrap();
        assert!(m.reach().is_err());
        std::fs::write(m.dir.join(REACH), "2").unwrap();
        assert!(m.reach().is_err());
        assert_eq!(Reach::parse("0"), None);
        assert!(Reach::Within(2).admits(Some(2)) && !Reach::Within(2).admits(Some(3)));
        assert!(!Reach::Within(3).admits(None) && Reach::Any.admits(None));
    }
}
