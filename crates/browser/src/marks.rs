use std::path::{Path, PathBuf};

use weft_home::{Result, fail, fs};

pub const DIR: &str = "browser";
pub const HISTORY: &str = "history";
pub const BOOKMARKS: &str = "bookmarks";
pub const MAX_HISTORY: usize = 1024;
pub const MAX_TITLE: usize = 128;
pub const MAX_TARGET: usize = 2048;

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
}
