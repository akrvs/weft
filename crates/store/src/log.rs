use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub const FILE: &str = "store.log";
pub const ROTATED: &str = "store.log.1";
pub const MAX_BYTES: u64 = 1 << 20;
pub const TAIL: u64 = 16 * 1024;

#[derive(Debug)]
pub struct Log {
    path: PathBuf,
    lock: Mutex<()>,
}

impl Log {
    pub fn new(home: &Path) -> Self {
        Self { path: home.join(FILE), lock: Mutex::new(()) }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn line(&self, text: &str) {
        let Ok(_held) = self.lock.lock() else { return };
        if std::fs::metadata(&self.path).is_ok_and(|m| m.len() > MAX_BYTES) {
            let _ = std::fs::rename(&self.path, self.path.with_file_name(ROTATED));
        }
        let Ok(mut file) =
            OpenOptions::new().append(true).create(true).mode(0o600).open(&self.path)
        else {
            return;
        };
        let stamp = weft_home::now().unwrap_or(0);
        let _ = writeln!(file, "{stamp} {text}");
    }
}

pub fn tail(home: &Path) -> String {
    let Ok(bytes) = std::fs::read(home.join(FILE)) else { return String::new() };
    let skip = bytes.len().saturating_sub(usize::try_from(TAIL).unwrap_or(usize::MAX));
    let cut = bytes.get(skip..).unwrap_or_default();
    let start = if skip == 0 {
        0
    } else {
        cut.iter().position(|b| *b == b'\n').map_or(cut.len(), |i| i.saturating_add(1))
    };
    String::from_utf8_lossy(cut.get(start..).unwrap_or_default()).into_owned()
}
