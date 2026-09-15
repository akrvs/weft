use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde::Serialize;
use weft_core::Address;
use weft_home::{Result, fail};

pub const MAX_TEXT: usize = 65_536;
pub const USER_DIRS: &str = ".config/user-dirs.dirs";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Sniff {
    Image,
    Text,
    Binary,
}

pub fn sniff(data: &[u8]) -> Sniff {
    let image = data.starts_with(b"\x89PNG\r\n\x1a\n")
        || data.starts_with(b"\xff\xd8\xff")
        || data.starts_with(b"GIF87a")
        || data.starts_with(b"GIF89a")
        || (data.starts_with(b"RIFF") && data.get(8..12) == Some(b"WEBP".as_slice()));
    if image {
        return Sniff::Image;
    }
    let text = data.len() <= MAX_TEXT && !data.contains(&0) && core::str::from_utf8(data).is_ok();
    if text { Sniff::Text } else { Sniff::Binary }
}

pub fn downloads_dir(home: &Path, xdg: Option<&str>, user_dirs: Option<&str>) -> PathBuf {
    if let Some(dir) = xdg.filter(|d| !d.is_empty()) {
        return PathBuf::from(dir);
    }
    let configured = user_dirs
        .into_iter()
        .flat_map(str::lines)
        .filter_map(|l| l.trim().strip_prefix("XDG_DOWNLOAD_DIR="))
        .map(|v| v.trim_matches('"'))
        .find(|v| !v.is_empty())
        .map(|v| match v.strip_prefix("$HOME/") {
            Some(rest) => home.join(rest),
            None => PathBuf::from(v),
        });
    configured.unwrap_or_else(|| home.join("Downloads"))
}

pub fn downloads() -> Result<PathBuf> {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return fail("HOME is not set");
    };
    let xdg = std::env::var("XDG_DOWNLOAD_DIR").ok();
    let user_dirs = std::fs::read_to_string(home.join(USER_DIRS)).ok();
    Ok(downloads_dir(&home, xdg.as_deref(), user_dirs.as_deref()))
}

pub fn save(dir: &Path, address: Address, data: &[u8]) -> Result<PathBuf> {
    if Address::of(data) != address {
        return fail("blob does not match its address");
    }
    if !dir.is_dir() {
        return fail(format!("{} is not a directory", dir.display()));
    }
    let path = dir.join(address.to_string());
    let opened = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o644).open(&path);
    let mut file = match opened {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return fail(format!("{} already exists, nothing written", path.display()));
        }
        Err(e) => return Err(e.into()),
    };
    file.write_all(data)?;
    file.sync_all()?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn sniff_by_magic_then_text() {
        assert_eq!(sniff(b"\x89PNG\r\n\x1a\n...."), Sniff::Image);
        assert_eq!(sniff(b"\xff\xd8\xff\xe0"), Sniff::Image);
        assert_eq!(sniff(b"GIF89a"), Sniff::Image);
        assert_eq!(sniff(b"RIFF\0\0\0\0WEBPVP8 "), Sniff::Image);
        assert_eq!(sniff(b"RIFF\0\0\0\0WAVE"), Sniff::Binary);
        assert_eq!(sniff("plain text\n".as_bytes()), Sniff::Text);
        assert_eq!(sniff(b"text\0with nul"), Sniff::Binary);
        assert_eq!(sniff(&[0xff, 0xfe, 0x00]), Sniff::Binary);
        assert_eq!(sniff(&vec![b'a'; MAX_TEXT]), Sniff::Text);
        assert_eq!(sniff(&vec![b'a'; MAX_TEXT + 1]), Sniff::Binary);
    }

    #[test]
    fn downloads_dir_prefers_env_then_user_dirs_then_default() {
        let home = Path::new("/h");
        assert_eq!(downloads_dir(home, Some("/dl"), None), PathBuf::from("/dl"));
        let dirs = "# comment\nXDG_DESKTOP_DIR=\"$HOME/Desktop\"\nXDG_DOWNLOAD_DIR=\"$HOME/Get\"\n";
        assert_eq!(downloads_dir(home, None, Some(dirs)), PathBuf::from("/h/Get"));
        assert_eq!(downloads_dir(home, Some(""), Some(dirs)), PathBuf::from("/h/Get"));
        let abs = "XDG_DOWNLOAD_DIR=\"/mnt/dl\"";
        assert_eq!(downloads_dir(home, None, Some(abs)), PathBuf::from("/mnt/dl"));
        assert_eq!(downloads_dir(home, None, None), PathBuf::from("/h/Downloads"));
    }

    #[test]
    fn save_writes_once_and_checks_the_hash() {
        let dir = std::env::temp_dir().join(format!("weft-save-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let data = b"hello blob";
        let address = Address::of(data);
        let path = save(&dir, address, data).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), data);
        assert!(save(&dir, address, data).unwrap_err().to_string().contains("already exists"));
        assert!(save(&dir, Address::of(b"other"), data).is_err());
        assert!(save(&dir.join("missing"), Address::of(b"x"), b"x").is_err());
    }
}
