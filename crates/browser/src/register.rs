use std::path::{Path, PathBuf};
use std::process::Command;

use weft_home::{Result, fail, fs};

pub const DESKTOP: &str = "weft.desktop";
pub const SCHEME: &str = "x-scheme-handler/weft";
pub const ICON: &[u8] = include_bytes!("../icons/icon.png");

pub fn desktop_entry(exe: &Path) -> String {
    let exe = exe.display().to_string().replace('\\', "\\\\").replace('"', "\\\"");
    format!(
        "[Desktop Entry]\nType=Application\nName=weft\nComment=One address bar for signed records and the old web\nExec=\"{exe}\" %u\nIcon=weft\nTerminal=false\nCategories=Network;WebBrowser;\nMimeType={SCHEME};\n"
    )
}

pub fn data_home(xdg_data_home: Option<&str>, home: &Path) -> PathBuf {
    match xdg_data_home.filter(|d| !d.is_empty()) {
        Some(dir) => PathBuf::from(dir),
        None => home.join(".local/share"),
    }
}

pub fn register() -> Result<PathBuf> {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return fail("HOME is not set");
    };
    let exe = std::env::current_exe()?;
    let data = data_home(std::env::var("XDG_DATA_HOME").ok().as_deref(), &home);
    let applications = data.join("applications");
    let entry = applications.join(DESKTOP);
    fs::write(&entry, desktop_entry(&exe).as_bytes())?;
    fs::write(&data.join("icons/hicolor/256x256/apps/weft.png"), ICON)?;
    match Command::new("xdg-mime").args(["default", DESKTOP, SCHEME]).status() {
        Ok(s) if s.success() => {}
        Ok(s) => return fail(format!("xdg-mime exited with {s}")),
        Err(e) => return fail(format!("xdg-mime: {e}; is xdg-utils installed?")),
    }
    let _ = Command::new("update-desktop-database").arg(&applications).status();
    Ok(entry)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn entry_names_the_binary_and_the_scheme() {
        let entry = desktop_entry(Path::new("/opt/we ft/weft-browser"));
        assert!(entry.starts_with("[Desktop Entry]\n"));
        assert!(entry.contains("Exec=\"/opt/we ft/weft-browser\" %u\n"));
        assert!(entry.contains("MimeType=x-scheme-handler/weft;\n"));
        assert!(entry.lines().all(|l| l.contains('=') || l.starts_with('[')));
    }

    #[test]
    fn data_home_follows_xdg() {
        let home = Path::new("/h");
        assert_eq!(data_home(Some("/d"), home), PathBuf::from("/d"));
        assert_eq!(data_home(Some(""), home), PathBuf::from("/h/.local/share"));
        assert_eq!(data_home(None, home), PathBuf::from("/h/.local/share"));
    }
}
